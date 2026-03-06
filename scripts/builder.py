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
INJECT_ROOT = "temp_source/rule/Clash"

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
            return self._contains(self.cn_intervals, ip_int) and \
                   not self._contains(self.black_intervals, ip_int)
        except: return False

    def export_clean_list(self, raw_cn_path):
        output_path = os.path.join(INJECT_ROOT, "GeoIP_CN", "list.txt")
        print(f"🧹 [GeoIP] 导出到: {output_path}")
        
        clean_lines = []
        if os.path.exists(raw_cn_path):
            with open(raw_cn_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                        ip_int = int(net.network_address)
                        if not self._contains(self.black_intervals, ip_int):
                            clean_lines.append(line)
                    except: pass
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# NAME: GeoIP:CN\n") 
            f.write("\n".join(clean_lines))
        print(f"✅ 生成 IP 规则 (保留: {len(clean_lines)} 条)")

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
        # 💡 核心修复 1：利用 edns_client_subnet 伪装国内 IP 防止海外测拨误杀
        url = f"https://dns.alidns.com/resolve?name={domain}&type=A&edns_client_subnet=114.114.114.114"
        for _ in range(RETRIES + 1):
            try:
                async with self.sem:
                    async with session.get(url, timeout=TIMEOUT_SEC) as resp:
                        if resp.status == 200: return await resp.json()
            except: await asyncio.sleep(1)
        return None

    async def inspect(self, session, raw_domain):
        domain = raw_domain.lower().strip().replace("+.", "").replace("*.", "")
        if not domain: return

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
            
            if status != 'dead': fail_count = 0
        else:
            fail_count = 0

        for kw in BLACKLIST_KEYWORDS:
            if kw in domain:
                self._record(domain, 'non_cn', f"Blacklist: {kw}")
                return

        data = await self.resolve(session, domain)
        
        # 💡 核心修复 2：根域名查不到时，智能回退查询 www. 子域名防死链误判
        if not data or 'Answer' not in data:
            data = await self.resolve(session, f"www.{domain}")

        if not data or 'Answer' not in data:
            new_fail_count = fail_count + 1
            if new_fail_count >= 3:
                self._record(domain, 'abandoned', 'Three Strikes', failures=new_fail_count)
            else:
                self._record(domain, 'dead', 'NXDOMAIN/Timeout', failures=new_fail_count)
            return

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
        sorted_d = sorted(list(self.valid_domains), key=lambda x: (len(x), x))
        final = []
        if not sorted_d: return []
        final_set = set()
        for domain in sorted_d:
            parts = domain.split('.')
            is_redundant = False
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
        
        output_path = os.path.join(INJECT_ROOT, "GeoSite_CN", "list.txt")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        final_domains = self.optimize_subdomains()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# NAME: GeoSite:CN\n")
            f.write("\n".join(final_domains))
        print(f"✅ 生成域名规则: {output_path} (数量: {len(final_domains)})")

async def main():
    raw_cn_ip = os.path.join(RAW_DIR, "geoip_cn.txt")
    raw_black_ip = os.path.join(RAW_DIR, "geoip_black.txt")
    
    engine = GeoIPEngine(raw_cn_ip, [raw_black_ip])
    engine.export_clean_list(raw_cn_ip) 

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
