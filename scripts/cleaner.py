import asyncio
import aiohttp
import ipaddress
import bisect
import json
import os
import time

# --- 核心配置 ---
# 网络
TIMEOUT_SEC = 5
RETRIES = 2
CONCURRENCY = 64

# 路径
RAW_DIR = "raw_data"
DATA_DIR = "data"
# 注入路径：builder.py 会扫描此目录
INJECT_DIR = "temp_source/rule/Clash/DigitalArchitect"

# 文件
CACHE_FILE = os.path.join(DATA_DIR, "domain_cache.json")
LOG_UNRESOLVED = os.path.join(DATA_DIR, "dns_unresolved.txt")   # 观察期死链
LOG_ABANDONED = os.path.join(DATA_DIR, "dns_abandoned.txt")     # 冷宫死链
LOG_NON_CN = os.path.join(DATA_DIR, "resolved_non_cn.txt")      # 境外/黑名单

# 黑名单与指纹
BLACKLIST_KEYWORDS = [
    "google", "youtube", "facebook", "twitter", "instagram", "telegram",
    "github", "apple", "microsoft", "amazon", "aws", "azure",
    "adobe", "steam", "netflix", "tesla", "nvidia", "pornhub",
    "epicgames", "ubisoft", "discord", "dropbox"
]
FOREIGN_CDN_FINGERPRINTS = [
    "akamai", "edgekey", "akadns", "cloudfront", "aws", "azureedge", 
    "fastly", "cloudflare", "edgecast", "zenlayer", "google", "gvt1.com", 
    "apigee", "facebook", "cdn77"
]

# --- 1. GeoIP 引擎 (支持减法清洗) ---
class GeoIPEngine:
    def __init__(self, cn_path, black_paths):
        print("🛡️ [GeoIP] 初始化清洗引擎...")
        self.cn_intervals = self._load(cn_path)
        self.black_intervals = []
        for p in black_paths: self.black_intervals.extend(self._load(p))
        self.black_intervals.sort()
        print(f"   - 原始 CN 段: {len(self.cn_intervals)}")
        print(f"   - 黑名单 IP 段: {len(self.black_intervals)}")

    def _load(self, path):
        intervals = []
        if not os.path.exists(path): return intervals
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or not line[0].isdigit(): continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    intervals.append((int(net.network_address), int(net.broadcast_address)))
                except: pass
        intervals.sort()
        return intervals

    def _contains(self, intervals, ip_int):
        keys = [x[0] for x in intervals]
        idx = bisect.bisect_right(keys, ip_int) - 1
        if idx < 0: return False
        return intervals[idx][0] <= ip_int <= intervals[idx][1]

    def is_pure_cn(self, ip_str):
        try:
            ip_int = int(ipaddress.ip_address(ip_str))
            # 逻辑：在 CN 白名单 AND 不在 黑名单
            return self._contains(self.cn_intervals, ip_int) and \
                   not self._contains(self.black_intervals, ip_int)
        except: return False

    def export_clean_list(self, raw_cn_path, output_path):
        """生成清洗后的 GeoIP_CN.list"""
        print("🧹 [GeoIP] 执行 IP 减法清洗...")
        clean_lines = []
        with open(raw_cn_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    # 采样检查：如果网段的网络地址在黑名单里，则剔除
                    # (简化逻辑：不处理拆分，只要重叠就剔除)
                    net = ipaddress.ip_network(line, strict=False)
                    ip_int = int(net.network_address)
                    if not self._contains(self.black_intervals, ip_int):
                        clean_lines.append(line)
                except: pass
        
        with open(output_path, 'w') as f:
            f.write("# NAME: GeoIP:CN\n")
            f.write("\n".join(clean_lines))
        print(f"✅ 生成规则: {output_path} (保留: {len(clean_lines)} 条)")

# --- 2. 域名清洗器 (含三振出局逻辑) ---
class Cleaner:
    def __init__(self, geoip_engine):
        self.geoip = geoip_engine
        self.sem = asyncio.Semaphore(CONCURRENCY)
        self.cache = self._load_cache()
        # 结果容器
        self.valid_domains = set()
        self.unresolved = []    # 观察期
        self.abandoned = []     # 冷宫
        self.non_cn = []        # 境外

    def _load_cache(self):
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, 'r') as f: return json.load(f)
            except: pass
        return {}

    async def resolve(self, session, domain):
        url = f"https://dns.alidns.com/resolve?name={domain}&type=A"
        for _ in range(RETRIES + 1):
            try:
                async with self.sem:
                    async with session.get(url, timeout=TIMEOUT_SEC) as resp:
                        if resp.status == 200: return await resp.json()
            except: await asyncio.sleep(1)
        return None

    async def inspect(self, session, domain):
        domain = domain.lower().strip()
        if not domain: return

        # --- A. 缓存分级检查 ---
        cached = self.cache.get(domain)
        if cached:
            ts = cached['ts']
            status = cached['status']
            fail_count = cached.get('failures', 0)
            age_days = (time.time() - ts) / 86400
            
            # TTL 策略
            ttl = 0
            if status == 'valid': ttl = 180         # Valid: 半年
            elif status == 'non_cn': ttl = 365      # Non-CN: 一年
            elif status == 'dead': ttl = 3          # Dead(观察期): 3天
            elif status == 'abandoned': ttl = 180   # Abandoned(冷宫): 半年

            if age_days < ttl:
                # 缓存命中，直接归类
                if status == 'valid': self.valid_domains.add(domain)
                elif status == 'dead': self.unresolved.append(domain)
                elif status == 'abandoned': self.abandoned.append(domain)
                else: self.non_cn.append(f"{domain} # {cached['reason']}")
                return
            
            # 如果是 Dead 且过期了，说明要复查，保留 fail_count
            # 其他状态过期，重置 fail_count
            if status != 'dead': fail_count = 0
        else:
            fail_count = 0

        # --- B. 静态黑名单 ---
        for kw in BLACKLIST_KEYWORDS:
            if kw in domain:
                self._record(domain, 'non_cn', f"Blacklist: {kw}")
                return

        # --- C. 网络验活 ---
        data = await self.resolve(session, domain)
        
        # [三振出局逻辑]
        if not data or 'Answer' not in data:
            new_fail_count = fail_count + 1
            if new_fail_count >= 3:
                # 三振出局 -> 冷宫
                self._record(domain, 'abandoned', 'Three Strikes', failures=new_fail_count)
            else:
                # 观察期
                self._record(domain, 'dead', 'NXDOMAIN/Timeout', failures=new_fail_count)
            return

        # --- D. 深度审计 ---
        has_cn_ip = False
        reject = None
        for rec in data['Answer']:
            if rec['type'] == 5: # CNAME
                t = rec['data'].lower()
                for fp in FOREIGN_CDN_FINGERPRINTS:
                    if fp in t: reject = f"CDN: {fp}"; break
            if rec['type'] == 1: # IP
                if self.geoip.is_pure_cn(rec['data']): has_cn_ip = True
            if reject: break

        if reject: 
            self._record(domain, 'non_cn', reject)
        elif has_cn_ip: 
            # 复活/通过 -> 失败计数归零
            self._record(domain, 'valid', 'Verified', failures=0)
        else: 
            self._record(domain, 'non_cn', 'Foreign IP')

    def _record(self, domain, status, reason, failures=0):
        self.cache[domain] = {
            "status": status, 
            "ts": int(time.time()), 
            "reason": reason,
            "failures": failures
        }
        if status == 'valid': self.valid_domains.add(domain)
        elif status == 'dead': self.unresolved.append(domain)
        elif status == 'abandoned': self.abandoned.append(domain)
        else: self.non_cn.append(f"{domain} # {reason}")

    def optimize_subdomains(self):
        print("✂️ [GeoSite] 泛域名塌陷优化...")
        sorted_d = sorted(list(self.valid_domains))
        final = []
        if not sorted_d: return []
        prev = sorted_d[0]
        final.append(prev)
        for i in range(1, len(sorted_d)):
            curr = sorted_d[i]
            if curr.endswith("." + prev) or curr == prev: continue
            final.append(curr)
            prev = curr
        return final

    def save(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        # 保存缓存
        with open(CACHE_FILE, 'w') as f: json.dump(self.cache, f)
        # 保存审计日志
        with open(LOG_UNRESOLVED, 'w') as f: f.write("\n".join(sorted(self.unresolved)))
        with open(LOG_ABANDONED, 'w') as f: f.write("\n".join(sorted(self.abandoned)))
        with open(LOG_NON_CN, 'w') as f: f.write("\n".join(sorted(self.non_cn)))
        
        # 注入给 builder.py
        os.makedirs(INJECT_DIR, exist_ok=True)
        final_domains = self.optimize_subdomains()
        domain_path = os.path.join(INJECT_DIR, "GeoSite_CN.list")
        with open(domain_path, 'w') as f:
            f.write("# NAME: GeoSite:CN\n")
            f.write("\n".join(final_domains))
        print(f"✅ 生成规则: {domain_path} (数量: {len(final_domains)})")

async def main():
    # 路径需与 Workflow 对应
    raw_cn_ip = os.path.join(RAW_DIR, "geoip_cn.txt")
    raw_black_ip = os.path.join(RAW_DIR, "geoip_black.txt") # 各种黑名单合并的文件
    
    # 1. 启动 GeoIP 引擎
    engine = GeoIPEngine(raw_cn_ip, [raw_black_ip])
    # 导出清洗后的 IP 列表
    engine.export_clean_list(raw_cn_ip, os.path.join(INJECT_DIR, "GeoIP_CN.list"))

    # 2. 启动域名清洗
    cleaner = Cleaner(engine)
    domains = set()
    if os.path.exists(os.path.join(RAW_DIR, "geosite_cn.txt")):
        with open(os.path.join(RAW_DIR, "geosite_cn.txt")) as f:
            for l in f: domains.add(l.strip())
    
    print(f"🚀 开始清洗 {len(domains)} 个域名...")
    async with aiohttp.ClientSession() as session:
        tasks = [cleaner.inspect(session, d) for d in domains if d]
        done = 0
        for f in asyncio.as_completed(tasks):
            await f
            done += 1
            if done % 500 == 0: print(f"   进度: {done}/{len(tasks)}...", end='\r')
            
    cleaner.save()
    print("\n🎉 清洗流程结束")

if __name__ == "__main__":
    asyncio.run(main())
