import os
import yaml
import hashlib
import subprocess
import logging
import shutil
import re
import ipaddress
import json
import requests
import time
import socket
import dns.message
import dns.query
import dns.rdatatype
import dns.flags
import dns.edns
import geoip2.database
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- ⚡️ v3.1 Phase 2: 纯净自研 + 极致收纳 + 熔断保护 ---
GENERATOR_VERSION = "v3.1_PHASE2_FINAL" 

# 📂 目录结构配置
DATA_DIR = "data"
TARGET_DIR_MIHOMO = "rule/Mihomo"
TARGET_DIR_LOON = "rule/Loon"

# 📄 关键文件路径 (全部收纳进 data/)
CACHE_FILE = os.path.join(DATA_DIR, "domain_cache.json")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
GEOIP_DB_PATH = os.path.join(DATA_DIR, "GeoLite2-Country.mmdb")
MIHOMO_BIN = "./mihomo"

# 🛑 变体剔除黑名单 (文件名包含这些则跳过)
IGNORE_KEYWORDS = ["Classical", "Domain", "For_Clash", "No_Resolve", "Clash"]

# 🎯 权威源配置 (MetaCubeX)
SOURCE_URLS = {
    "CN": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.list",
    "LAN": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/private.list"
}

# 🏴‍☠️ 静态净化规则 (秒杀名单)
NON_CN_TLDS = {'.hk', '.tw', '.mo', '.sg', '.us', '.uk', '.jp', '.kr', '.au', '.ca', '.de', '.fr', '.in'}
OVERSEA_KEYWORDS = ['-us-', '.us.', 'oversea', 'global', 'eu-central', 'us-west', 'us-east', 'hk-azure']
TRAITOR_DOMAINS = {'tiktok.com', 'kwai.com', 'telegram.org', 'telegram.dog'}

# 🧬 DNS / ECS 配置
DNS_SERVER = '8.8.8.8'   # Google DNS
FAKE_CN_IP = '223.5.5.5' # 伪装阿里北京 DNS
MAX_WORKERS = 32         # 🔥 32线程并发
DNS_TIMEOUT = 1.5        # ⚡️ 1.5秒超时 (快速失败)
FAILURE_THRESHOLD = 0.20 # 🛡️ 熔断阈值 (错误率 > 20% 触发降级)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DigitalArchitect")

filename_registry = {}
geo_reader = None

# --- 1. 历史与缓存管理 (收纳版) ---
class HistoryManager:
    def __init__(self):
        self.history = {}
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, 'r') as f: self.history = json.load(f)
            except: pass
        self.current_time = int(datetime.now().timestamp())

    def get_file_hash(self, content):
        return hashlib.md5(content.encode('utf-8')).hexdigest()

    def update_record(self, name, src_hash):
        self.history[name] = {
            'src_hash': src_hash,
            'updated_at': self.current_time,
            'gen_ver': GENERATOR_VERSION
        }

    def save(self):
        with open(HISTORY_FILE, 'w') as f: json.dump(self.history, f, indent=2)

class DomainCache:
    def __init__(self):
        self.data = {}
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, 'r') as f: self.data = json.load(f)
            except: pass
    
    def get(self, domain):
        return self.data.get(domain) 
        
    def set(self, domain, is_cn):
        self.data[domain] = {
            'is_cn': is_cn,
            'ts': int(time.time())
        }
    
    def save(self):
        sorted_data = dict(sorted(self.data.items()))
        with open(CACHE_FILE, 'w') as f:
            json.dump(sorted_data, f, indent=None, separators=(',', ':'))

# --- 2. 核心清洗逻辑 ---
def robust_download(url):
    cdn_url = url.replace("raw.githubusercontent.com", "cdn.jsdelivr.net/gh").replace("/meta/", "@meta/")
    targets = [url, cdn_url]
    for target in targets:
        for attempt in range(2):
            try:
                resp = requests.get(target, timeout=10)
                if resp.status_code == 200: return resp.text
            except: pass
    logger.warning(f"⚠️ 下载失败: {url}")
    return ""

def check_domain_static(domain, cache):
    domain = domain.strip().lower()
    
    cached = cache.get(domain)
    # 缓存有效期 60 天
    if cached and (time.time() - cached['ts'] < 60 * 86400):
        return domain, cached['is_cn'], False 

    if domain.endswith('.cn'): 
        cache.set(domain, True)
        return domain, True, False
        
    for traitor in TRAITOR_DOMAINS:
        if traitor in domain:
            cache.set(domain, False)
            return domain, False, False
            
    for tld in NON_CN_TLDS:
        if domain.endswith(tld):
            cache.set(domain, False)
            return domain, False, False
            
    for kw in OVERSEA_KEYWORDS:
        if kw in domain:
            cache.set(domain, False)
            return domain, False, False

    return domain, None, True

def worker_dns_check(domain):
    try:
        query = dns.message.make_query(domain, dns.rdatatype.A)
        ecs = dns.edns.ECSOption(socket.inet_aton(FAKE_CN_IP), 24)
        query.use_edns(options=[ecs])
        
        response = dns.query.udp(query, DNS_SERVER, timeout=DNS_TIMEOUT)
        
        has_ip = False
        for answer in response.answer:
            for item in answer:
                if item.rdtype == dns.rdatatype.A:
                    has_ip = True
                    ip = item.address
                    if geo_reader:
                        try:
                            match = geo_reader.country(ip)
                            if match.country.iso_code == 'CN':
                                return domain, True, False 
                        except: pass
        
        if not has_ip:
            return domain, False, False 
            
        return domain, False, False 

    except Exception:
        return domain, False, True 

# --- 3. 构建流程 ---
def build_china_list(cache):
    logger.info("🚀 开始构建 China 列表 (v3.1 Phase 2)...")
    
    content = robust_download(SOURCE_URLS["CN"])
    candidates = set()
    for line in content.splitlines():
        line = line.strip()
        line = re.sub(r'^(full:|domain:)', '', line)
        if line and ',' not in line and '.' in line and not line.startswith('#') and not line.startswith('regexp:'):
            candidates.add(line)
            
    logger.info(f"📥 主源待处理: {len(candidates)} 条")

    final_cn_domains = set()
    pending_domains = []

    for domain in candidates:
        d, is_cn, need_dns = check_domain_static(domain, cache)
        if not need_dns:
            if is_cn: final_cn_domains.add(d)
        else:
            pending_domains.append(d)

    logger.info(f"⚡️ 静态过滤完成。需 DNS 清洗: {len(pending_domains)} 条")

    if pending_domains:
        network_errors = 0
        processed_count = 0
        circuit_broken = False
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_domain = {executor.submit(worker_dns_check, d): d for d in pending_domains}
            
            for future in as_completed(future_to_domain):
                d, is_cn, is_net_err = future.result()
                processed_count += 1
                
                if is_net_err:
                    network_errors += 1
                
                current_fail_rate = network_errors / processed_count
                if not circuit_broken and processed_count > 100 and current_fail_rate > FAILURE_THRESHOLD:
                    logger.warning(f"⚠️ 触发网络熔断! 错误率 {current_fail_rate:.2%} > {FAILURE_THRESHOLD:.0%}")
                    circuit_broken = True
                    executor.shutdown(wait=False, cancel_futures=True)
                    break 

                if circuit_broken: break

                if not is_net_err:
                    cache.set(d, is_cn)
                
                if is_cn:
                    final_cn_domains.add(d)
                
                if processed_count % 200 == 0:
                    print(f"   ⏳ 清洗进度: {processed_count}/{len(pending_domains)}...", end='\r')

        if circuit_broken:
            for d in pending_domains:
                if d not in final_cn_domains:
                    cached = cache.get(d)
                    if cached and cached['is_cn']: 
                        final_cn_domains.add(d)
                    else:
                        final_cn_domains.add(d) 

    return sorted(list(final_cn_domains))

# --- 4. 编译与工具类 ---
class KernelIntrospector:
    def __init__(self, bin_path): self.bin_path = bin_path
    def get_cmd(self, behavior, src, dst): return [self.bin_path, "convert-ruleset", behavior, "yaml", src, dst]

def compile_mrs(kernel, name, rules, behavior):
    os.makedirs(TARGET_DIR_MIHOMO, exist_ok=True)
    tmp = f"temp_{name}.yaml"
    dst = os.path.join(TARGET_DIR_MIHOMO, f"{name}.mrs")
    try:
        with open(tmp, 'w', encoding='utf-8') as f: yaml.dump({'payload': rules}, f)
        subprocess.run(kernel.get_cmd(behavior, tmp, dst), check=True)
        return True
    except: return False
    finally:
        if os.path.exists(tmp): os.remove(tmp)

def generate_readme(stats):
    md = [
        "# 🤖 Auto Shunt Rules",
        f"Update: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        "| Rule | Status |",
        "| :--- | :--- |"
    ]
    for name, count in stats:
        md.append(f"| {name} | {count} entries |")
    with open("README.md", 'w') as f: f.write("\n".join(md))

# --- 主入口 ---
def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(TARGET_DIR_MIHOMO, exist_ok=True)
    os.makedirs(TARGET_DIR_LOON, exist_ok=True)
    
    global geo_reader
    try:
        geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        logger.info("🌍 GeoIP 数据库就绪")
    except:
        logger.warning("⚠️ GeoIP 缺失，IP 判定功能受限")

    cache = DomainCache()
    history = HistoryManager()
    kernel = KernelIntrospector(MIHOMO_BIN)
    stats = []
    
    cn_domains = build_china_list(cache)
    if cn_domains:
        compile_mrs(kernel, "China", cn_domains, 'domain')
        with open(os.path.join(TARGET_DIR_LOON, "China.lsr"), 'w') as f:
            f.write("\n".join([f"DOMAIN-SUFFIX,{d}" for d in cn_domains]))
        stats.append(("China", len(cn_domains)))
        logger.info(f"✅ China 构建完成: {len(cn_domains)} 条")

    lan_content = robust_download(SOURCE_URLS["LAN"])
    ip_list = []
    for line in lan_content.splitlines():
        if 'IP-CIDR' in line or '/' in line:
            ip_list.append(line.strip().replace("'", ""))
    
    if ip_list:
        compile_mrs(kernel, "China_IP", ip_list, 'ipcidr')
        with open(os.path.join(TARGET_DIR_LOON, "China_IP.lsr"), 'w') as f:
            f.write("\n".join([f"IP-CIDR,{ip}" for ip in ip_list]))
        stats.append(("China_IP", len(ip_list)))

    cache.save()
    history.save()
    generate_readme(stats)
    logger.info("💾 缓存与历史记录已保存")

if __name__ == "__main__":
    main()
