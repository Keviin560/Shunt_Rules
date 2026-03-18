import asyncio
import aiohttp
import ipaddress
import bisect
import json
import os
import time

TIMEOUT_SEC = 5
RETRIES = 2
CONCURRENCY = 128  

RAW_DIR = "raw_data"
DATA_DIR = "data"
INJECT_ROOT = "temp_source/rule/Clash"

CACHE_FILE = os.path.join(DATA_DIR, "domain_cache.json")
LOG_NON_CN = os.path.join(DATA_DIR, "resolved_non_cn.txt")      

BLACKLIST_KEYWORDS = [
    "youtube", "facebook", "twitter", "instagram", "telegram",
    "pornhub", "netflix", "xvideos", "phncdn", "google"
]
FOREIGN_CDN_FINGERPRINTS = [
    "cloudflare", "fastly", "cdn77", "gvt1.com", "fbcdn"
]

# 🚨 核心提取函数：适用于 AI、Game、Global_CN (保留格式，仅杀广告)
def process_vip_channel(input_file, output_dir, rule_name, ads_bh):
    if not os.path.exists(input_file): return
    valid_rules = set()
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            if '@ads' in line: continue  # 显式广告剔除
            
            line = line.split(' @')[0].strip() # 剥离附加属性
            
            rule_type = "DOMAIN-SUFFIX"
            val = line
            if line.startswith("full:"):
                rule_type, val = "DOMAIN", line[5:]
            elif line.startswith("domain:"):
                rule_type, val = "DOMAIN-SUFFIX", line[7:]
            elif line.startswith("keyword:"):
                rule_type, val = "DOMAIN-KEYWORD", line[8:]
            elif line.startswith("regexp:"):
                rule_type, val = "DOMAIN-REGEX", line[7:]
            
            # 🚨 只拿域名去纯广告库里比对，绝对不碰海外隔离库！
            if val.lower() in ads_bh:
                continue
            
            valid_rules.add(f"{rule_type},{val}")
    
    if len(valid_rules) == 0: return

    output_path = os.path.join(output_dir, "list.txt")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"# NAME: {rule_name}\n")
        f.write("\n".join(sorted(list(valid_rules))))
    print(f"✅ 生成规则: {output_path} (数量: {len(valid_rules)})")

class GeoIPEngine:
    def __init__(self, cn_path, black_paths):
        self.cn_intervals = self._load(cn_path)
        self.black_intervals = []
        for p in black_paths: self.black_intervals.extend(self._load(p))
        self.black_intervals.sort()

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

    def is_blacklisted(self, ip_str):
        try:
            ip_int = int(ipaddress.ip_address(ip_str))
            return self._contains(self.black_intervals, ip_int)
        except: return False

    def export_clean_list(self, raw_cn_path):
        output_path = os.path.join(INJECT_ROOT, "GeoIP_CN", "list.txt")
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

class Cleaner:
    def __init__(self, geoip_engine):
        self.geoip = geoip_engine
        self.sem = asyncio.Semaphore(CONCURRENCY)
        self.cache = self._load_cache()
        # 🚨 加载两个绝对独立的黑洞！
        self.ads_bh = self._load_set("blackhole_ads.txt")
        self.foreign_bh = self._load_set("blackhole_foreign.txt")
        self.valid_rules = set()
        self.non_cn = []        

    def _load_cache(self):
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, 'r', encoding='utf-8') as f: return json.load(f)
            except: pass
        return {}

    def _load_set(self, filename):
        bh = set()
        path = os.path.join(DATA_DIR, filename)
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    line = line.split(' @')[0].strip()
                    val = line
                    if line.startswith("full:"): val = line[5:]
                    elif line.startswith("domain:"): val = line[7:]
                    elif line.startswith("keyword:"): val = line[8:]
                    elif line.startswith("regexp:"): val = line[7:]
                    bh.add(val.lower())
        return bh

    async def resolve(self, session, domain):
        url = f"https://dns.alidns.com/resolve?name={domain}&type=A&edns_client_subnet=114.114.114.114"
        for _ in range(RETRIES):
            try:
                async with self.sem:
                    async with session.get(url, timeout=TIMEOUT_SEC) as resp:
                        if resp.status == 200: return await resp.json()
            except: await asyncio.sleep(1)
        return None

    async def inspect(self, session, raw_line):
        line = raw_line.strip()
        if not line or line.startswith('#'): return

        if '@ads' in line or '@!cn' in line: return
        line = line.split(' @')[0].strip()

        rule_type = "DOMAIN-SUFFIX"
        val = line
        if line.startswith("full:"):
            rule_type = "DOMAIN"
            val = line[5:]
        elif line.startswith("domain:"):
            rule_type = "DOMAIN-SUFFIX"
            val = line[7:]
        elif line.startswith("keyword:"):
            rule_type = "DOMAIN-KEYWORD"
            val = line[8:]
        elif line.startswith("regexp:"):
            rule_type = "DOMAIN-REGEX"
            val = line[7:]
        
        val_lower = val.lower()
        formatted_rule = f"{rule_type},{val}"

        # 🚨 国内主干道专用：必须双杀！既不是广告，也不是海外！
        if val_lower in self.ads_bh:
            self.non_cn.append(f"{formatted_rule} # 命中广告剧毒库")
            return
        if val_lower in self.foreign_bh:
            self.non_cn.append(f"{formatted_rule} # 命中海外防线")
            return

        if rule_type in ["DOMAIN-REGEX", "DOMAIN-KEYWORD"]:
            self.valid_rules.add(formatted_rule)
            return

        for kw in BLACKLIST_KEYWORDS:
            if kw in val_lower:
                self.non_cn.append(f"{formatted_rule} # Blacklist keyword: {kw}")
                return

        cached = self.cache.get(val_lower)
        if cached:
            age_days = (time.time() - cached['ts']) / 86400
            if age_days < 7:
                if cached['status'] == 'valid':
                    self.valid_rules.add(formatted_rule)
                else:
                    self.non_cn.append(f"{formatted_rule} # {cached['reason']}")
                return

        data = await self.resolve(session, val_lower)
        if not data or 'Answer' not in data:
            self._record(val_lower, 'valid', 'Unresolvable/Innocent', formatted_rule)
            return

        reject_reason = None
        for rec in data['Answer']:
            if rec['type'] == 5: 
                t = rec['data'].lower()
                for fp in FOREIGN_CDN_FINGERPRINTS:
                    if fp in t: 
                        reject_reason = f"Blocked CDN: {fp}"
                        break
            elif rec['type'] == 1: 
                if self.geoip.is_blacklisted(rec['data']): 
                    reject_reason = f"Blacklisted IP: {rec['data']}"
                    break
            if reject_reason: break

        if reject_reason: 
            self._record(val_lower, 'rejected', reject_reason, formatted_rule)
        else: 
            self._record(val_lower, 'valid', 'Clean IP', formatted_rule)

    def _record(self, domain, status, reason, formatted_rule):
        self.cache[domain] = {
            "status": status, 
            "ts": int(time.time()), 
            "reason": reason
        }
        if status == 'valid':
            self.valid_rules.add(formatted_rule)
        else:
            self.non_cn.append(f"{formatted_rule} # {reason}")

    def save(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CACHE_FILE, 'w', encoding='utf-8') as f: json.dump(self.cache, f)
        with open(LOG_NON_CN, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(self.non_cn)))
        
        output_path = os.path.join(INJECT_ROOT, "GeoSite_CN", "list.txt")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# NAME: GeoSite:CN\n")
            f.write("\n".join(sorted(list(self.valid_rules))))
        print(f"✅ 生成主干道规则: {output_path} (数量: {len(self.valid_rules)})")

async def main():
    raw_cn_ip = os.path.join(RAW_DIR, "geoip_cn.txt")
    raw_black_ip = os.path.join(RAW_DIR, "geoip_black.txt")
    
    engine = GeoIPEngine(raw_cn_ip, [raw_black_ip])
    engine.export_clean_list(raw_cn_ip) 

    cleaner = Cleaner(engine)

    print("🚀 开始处理 VIP 免检与跨国直连通道...")
    # 🚨 极其关键：AI、Game 和 Global_CN 统统只传 cleaner.ads_bh 进去，只清广告！绝对不碰海外隔离库！
    process_vip_channel(os.path.join(RAW_DIR, "ai_rules.txt"), os.path.join(INJECT_ROOT, "AI_Rules"), "AI_Rules", cleaner.ads_bh)
    process_vip_channel(os.path.join(RAW_DIR, "geosite_category-games-!cn.txt"), os.path.join(INJECT_ROOT, "Game_Proxy"), "Game_Proxy", cleaner.ads_bh)
    process_vip_channel(os.path.join(RAW_DIR, "geosite_category-games-cn.txt"), os.path.join(INJECT_ROOT, "Game_CN"), "Game_CN", cleaner.ads_bh)
    
    # 🚨 加入 Global_CN 处理，读取 data 目录下的增量数据！
    process_vip_channel(os.path.join(DATA_DIR, "global_cn_raw.txt"), os.path.join(INJECT_ROOT, "Global_CN"), "Global_CN", cleaner.ads_bh)
    print("-" * 40)

    lines = set()
    if os.path.exists(os.path.join(RAW_DIR, "geosite_cn.txt")):
        with open(os.path.join(RAW_DIR, "geosite_cn.txt"), 'r', encoding='utf-8') as f:
            for l in f: lines.add(l.strip())
    
    print(f"🚀 开始转换与验活 {len(lines)} 条上游主干道规则...")
    async with aiohttp.ClientSession() as session:
        tasks = [cleaner.inspect(session, l) for l in lines if l]
        done = 0
        for f in asyncio.as_completed(tasks):
            await f
            done += 1
            if done % 2000 == 0: print(f"   进度: {done}/{len(tasks)}...", end='\r')
            
    cleaner.save()
    print("\n🎉 清洗与转译流程结束")

if __name__ == "__main__":
    asyncio.run(main())
