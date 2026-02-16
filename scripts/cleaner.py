import asyncio
import aiohttp
import ipaddress
import bisect
import json
import os
import time

# --- 核心配置 ---
TIMEOUT_SEC = 5
RETRIES = 2
CONCURRENCY = 64

RAW_DIR = "raw_data"
DATA_DIR = "data"
# 注入路径：builder.py 会扫描此目录
INJECT_DIR = "temp_source/rule/Clash/DigitalArchitect"

CACHE_FILE = os.path.join(DATA_DIR, "domain_cache.json")
LOG_UNRESOLVED = os.path.join(DATA_DIR, "dns_unresolved.txt")   
LOG_ABANDONED = os.path.join(DATA_DIR, "dns_abandoned.txt")     
LOG_NON_CN = os.path.join(DATA_DIR, "resolved_non_cn.txt")      

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
        with open(path, 'r', encoding='utf-8') as f:
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
        print("🧹 [GeoIP] 执行 IP 减法清洗...")
        clean_lines = []
        if os.path.exists(raw_cn_path):
            with open(raw_cn_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    try:
                        # 简单的剔除逻辑：如果该网段的网络地址在黑名单中，则剔除
                        net = ipaddress.ip_network(line, strict=False)
                        ip_int = int(net.network_address)
                        if not self._contains(self.black_intervals, ip_int):
                            clean_lines.append(line)
                    except: pass
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# NAME: GeoIP:CN\n")
            f.write("\n".join(clean_lines))
        print(f"✅ 生成规则: {output_path} (保留: {len(clean_lines)} 条)")

class Cleaner:
    def __init__(self, geoip_engine):
        self.geoip = geoip_engine
        self.sem = asyncio.Semaphore(CONCURRENCY)
        self.cache = self._load_cache()
        self.valid_domains = set()
        self.unresolved = []    
        self.abandoned = []     
        self.non_cn = []        

    def _load_cache(self):
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, 'r', encoding='utf-8') as f: return json.load(f)
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

    async def inspect(self, session, raw_domain):
        # 🔥 关键修正：剥离所有前缀，只保留纯域名用于 DNS 解析
        # 例子：+.google.com -> google.com
        domain = raw_domain.lower().strip().replace("+.", "").replace("*.", "")
        if not domain: return

        # A. 缓存检查
        cached = self.cache.get(domain)
        if cached:
            ts = cached['ts']
            status = cached['status']
            fail_count = cached.get('failures', 0)
            age_days = (time.time() - ts) / 86400
            
            ttl = 0
            if status == 'valid': ttl = 180         
            elif status == 'non_cn': ttl = 365      
            elif status == 'dead': ttl = 3          
            elif status == 'abandoned': ttl = 180   

            if age_days < ttl:
                if status == 'valid': self.valid_domains.add(domain)
                elif status == 'dead': self.unresolved.append(domain)
                elif status == 'abandoned': self.abandoned.append(domain)
                else: self.non_cn.append(f"{domain} # {cached['reason']}")
                return
            
            # 如果不是 Dead 状态且缓存过期，重置失败计数
            if status != 'dead': fail_count = 0
        else:
            fail_count = 0

        # B. 静态黑名单
        for kw in BLACKLIST_KEYWORDS:
            if kw in domain:
                self._record(domain, 'non_cn', f"Blacklist: {kw}")
                return

        # C. 网络验活
        data = await self.resolve(session, domain)
        
        # [三振出局逻辑]
        if not data or 'Answer' not in data:
            new_fail_count = fail_count + 1
            if new_fail_count >= 3:
                self._record(domain, 'abandoned', 'Three Strikes', failures=new_fail_count)
            else:
                self._record(domain, 'dead', 'NXDOMAIN/Timeout', failures=new_fail_count)
            return

        # D. 深度审计
        has_cn_ip = False
        reject = None
        for rec in data['Answer']:
            if rec['type'] == 5: 
                t = rec['data'].lower()
                for fp in FOREIGN_CDN_FINGERPRINTS:
                    if fp in t: reject = f"CDN: {fp}"; break
            if rec['type'] == 1: 
                if self.geoip.is_pure_cn(rec['data']): has_cn_ip = True
            if reject: break

        if reject: 
            self._record(domain, 'non_cn', reject)
        elif has_cn_ip: 
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
        # 排序：短域名在前 (baidu.com 在 tieba.baidu.com 之前)
        sorted_d = sorted(list(self.valid_domains), key=lambda x: (len(x), x))
        final = []
        if not sorted_d: return []
        
        final_set = set()
        
        for domain in sorted_d:
            parts = domain.split('.')
            is_redundant = False
            # 检查是否有父级域名已存在
            for i in range(len(parts) - 1):
                parent = ".".join(parts[i+1:])
                if parent in final_set:
                    is_redundant = True
                    break
            
            if not is_redundant:
                final.append(domain)
                final_set.add(domain)
                
        return sorted(final)

    def save(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CACHE_FILE, 'w', encoding='utf-8') as f: json.dump(self.cache, f)
        with open(LOG_UNRESOLVED, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(self.unresolved)))
        with open(LOG_ABANDONED, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(self.abandoned)))
        with open(LOG_NON_CN, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(self.non_cn)))
        
        os.makedirs(INJECT_DIR, exist_ok=True)
        final_domains = self.optimize_subdomains()
        domain_path = os.path.join(INJECT_DIR, "GeoSite_CN.list")
        with open(domain_path, 'w', encoding='utf-8') as f:
            f.write("# NAME: GeoSite:CN\n")
            f.write("\n".join(final_domains))
        print(f"✅ 生成规则: {domain_path} (数量: {len(final_domains)})")

async def main():
    # 路径需与 Workflow 对应
    raw_cn_ip = os.path.join(RAW_DIR, "geoip_cn.txt")
    raw_black_ip = os.path.join(RAW_DIR, "geoip_black.txt")
    
    # 1. 启动 GeoIP 引擎与清洗
    engine = GeoIPEngine(raw_cn_ip, [raw_black_ip])
    engine.export_clean_list(raw_cn_ip, os.path.join(INJECT_DIR, "GeoIP_CN.list"))

    # 2. 启动域名清洗
    cleaner = Cleaner(engine)
    domains = set()
    if os.path.exists(os.path.join(RAW_DIR, "geosite_cn.txt")):
        with open(os.path.join(RAW_DIR, "geosite_cn.txt"), 'r', encoding='utf-8') as f:
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
