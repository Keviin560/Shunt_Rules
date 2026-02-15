import os
import yaml
import hashlib
import subprocess
import logging
import shutil
import re
import ipaddress
import json
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

# --- ⚡️ v3.5 FINAL FIX: 回归系统级下载 + README 自动修复 ---
GENERATOR_VERSION = "v3.5_SYSTEM_CURL" 

# 📂 目录配置
DATA_DIR = "data"
TARGET_DIR_MIHOMO = "rule/Mihomo"
TARGET_DIR_LOON = "rule/Loon"
CACHE_FILE = os.path.join(DATA_DIR, "domain_cache.json")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
GEOIP_DB_PATH = os.path.join(DATA_DIR, "GeoLite2-Country.mmdb")
MIHOMO_BIN = "./mihomo"

# 🛑 常量定义
IGNORE_KEYWORDS = ["Classical", "Domain", "For_Clash", "No_Resolve", "Clash"]
SOURCE_URLS = {
    "CN": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.list",
    "LAN": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/private.list"
}
NON_CN_TLDS = {'.hk', '.tw', '.mo', '.sg', '.us', '.uk', '.jp', '.kr', '.au', '.ca', '.de', '.fr', '.in'}
OVERSEA_KEYWORDS = ['-us-', '.us.', 'oversea', 'global', 'eu-central', 'us-west', 'us-east', 'hk-azure']
TRAITOR_DOMAINS = {'tiktok.com', 'kwai.com', 'telegram.org', 'telegram.dog'}
DNS_SERVER = '8.8.8.8' 
FAKE_CN_IP = '223.5.5.5'
MAX_WORKERS = 32
DNS_TIMEOUT = 1.5
FAILURE_THRESHOLD = 0.20

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DigitalArchitect")

filename_registry = {}
geo_reader = None

# --- 1. 基础类 ---
class HistoryManager:
    def __init__(self):
        self.history = {}
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, 'r') as f: self.history = json.load(f)
            except: pass
        self.current_time = int(datetime.now().timestamp())
    def update_record(self, name, src_hash):
        self.history[name] = {'src_hash': src_hash, 'updated_at': self.current_time}
    def save(self):
        with open(HISTORY_FILE, 'w') as f: json.dump(self.history, f, indent=2)

class DomainCache:
    def __init__(self):
        self.data = {}
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, 'r') as f: self.data = json.load(f)
            except: pass
    def get(self, domain): return self.data.get(domain)
    def set(self, domain, is_cn): self.data[domain] = {'is_cn': is_cn, 'ts': int(time.time())}
    def save(self):
        sorted_data = dict(sorted(self.data.items()))
        with open(CACHE_FILE, 'w') as f: json.dump(sorted_data, f, indent=None, separators=(',', ':'))

# --- 2. 🔥 核心修复：使用系统 Curl 下载 (跟wget一样稳) ---
def robust_download(url):
    """
    既然 Python requests 不行，我们就用系统级的 curl。
    日志里显示 wget 下载 GeoIP 成功了，那 curl 下载规则也一定能行。
    """
    # 自动尝试原始链接和 CDN 镜像
    cdn_url = url.replace("raw.githubusercontent.com", "cdn.jsdelivr.net/gh").replace("/meta/", "@meta/")
    targets = [url, cdn_url]
    
    for target in targets:
        try:
            # -s: 静默
            # -L: 跟随跳转
            # --fail: 404报错
            # --retry: 重试3次
            # --max-time: 20秒超时
            cmd = ["curl", "-s", "-L", "--fail", "--retry", "3", "--max-time", "20", target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                continue
                
            text = result.stdout
            
            # 🔥 垃圾拦截网：检查是否下载到了 HTML
            # 如果包含 <html 或 <!doctype，说明被劫持了，不要用！
            head = text[:500].lower()
            if "<html" in head or "<!doctype" in head or "<body>" in head:
                logger.warning(f"⚠️ 拦截到网页垃圾数据，跳过: {target}")
                continue
                
            return text
        except Exception as e:
            logger.warning(f"⚠️ 下载异常: {e}")

    logger.error(f"❌ 下载彻底失败: {url}")
    return ""

# --- 3. 清洗逻辑 (保持完美逻辑) ---
def check_domain_static(domain, cache):
    domain = domain.strip().lower()
    cached = cache.get(domain)
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
                            if match.country.iso_code == 'CN': return domain, True, False 
                        except: pass
        if not has_ip: return domain, False, False 
        return domain, False, False 
    except: return domain, False, True 

def build_china_list(cache):
    logger.info("🚀 开始构建 China 列表...")
    
    # 使用 curl 下载
    content = robust_download(SOURCE_URLS["CN"])
    
    # 🔥 熔断点 1：下载为空
    if not content:
        logger.error("☠️ 下载内容为空，跳过构建！")
        return []

    candidates = set()
    for line in content.splitlines():
        line = line.strip()
        line = re.sub(r'^(full:|domain:)', '', line)
        if line and ',' not in line and '.' in line and ' ' not in line and len(line) < 100:
            if not line.startswith('#') and not line.startswith('regexp:'):
                candidates.add(line)
            
    logger.info(f"📥 主源有效域名: {len(candidates)} 条")
    
    # 🔥 熔断点 2：数据量异常暴增 (防止 HTML 注入，正常也就7000条左右)
    if len(candidates) > 20000:
        logger.error(f"☠️ 域名数量 {len(candidates)} 异常，判定为下载中毒！强制停止！")
        return []

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
                if is_net_err: network_errors += 1
                
                # 🔥 熔断点 3：网络错误率过高
                current_fail_rate = network_errors / processed_count
                if not circuit_broken and processed_count > 100 and current_fail_rate > FAILURE_THRESHOLD:
                    logger.warning(f"⚠️ 网络错误率 {current_fail_rate:.2%} 过高，触发熔断！")
                    circuit_broken = True
                    executor.shutdown(wait=False, cancel_futures=True)
                    break 
                
                if circuit_broken: break
                if not is_net_err: cache.set(d, is_cn)
                if is_cn: final_cn_domains.add(d)
                
                if processed_count % 200 == 0:
                    print(f"   ⏳ 清洗进度: {processed_count}/{len(pending_domains)}...", end='\r')

        if circuit_broken:
            # 熔断后，将剩余未检测域名默认保留，防止误杀
            for d in pending_domains:
                if d not in final_cn_domains: final_cn_domains.add(d)

    return sorted(list(final_cn_domains))

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

# --- 🔥 核心修复：README 自动再生 ---
def auto_fix_readme(stats):
    """
    因为上一次运行把 README 弄坏了，这里必须自动检测并修复。
    如果发现 README 没有锚点或者内容太少，直接重写一个标准的。
    """
    readme_path = "README.md"
    needs_rebuild = False
    
    # 1. 检测是否需要重建
    if not os.path.exists(readme_path) or os.path.getsize(readme_path) < 50:
        needs_rebuild = True
    else:
        with open(readme_path, 'r') as f:
            content = f.read()
            if "" not in content:
                needs_rebuild = True

    # 2. 如果需要重建，写入标准模板 (恢复第一阶段的样子)
    if needs_rebuild:
        logger.warning("⚠️ 检测到 README 损坏，正在自动修复...")
        base_content = """# 🤖 Auto Shunt Rules

High-performance, auto-updated China domain & IP rules for Mihomo/Clash.
Powered by ECS Fake-IP & GeoIP validation.

### 📊 Rule Statistics
### 🚀 Usage
- **China List**: `https://raw.githubusercontent.com/{repo}/main/rule/Mihomo/China.mrs`
- **China IP**: `https://raw.githubusercontent.com/{repo}/main/rule/Mihomo/China_IP.mrs`

> Auto-generated by v3.5 Builder
""".format(repo=os.getenv("GITHUB_REPOSITORY", "Your/Repo"))
    else:
        with open(readme_path, 'r') as f:
            base_content = f.read()

    # 3. 生成统计表格
    table_md = [
        f"\nUpdate: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n",
        "| Rule Name | Count | Status |",
        "| :--- | :--- | :--- |"
    ]
    for name, count in stats:
        status = "✅ Active" if count > 0 else "❌ Error"
        table_md.append(f"| {name} | {count} | {status} |")
    
    insert_block = "\n".join(table_md)
    
    # 4. 注入内容 (正则替换)
    pattern = r"()(.*?)()"
    # 如果正则匹配不到，说明模板可能刚写进去还不是正则格式，兜底处理
    if re.search(pattern, base_content, flags=re.DOTALL):
        new_content = re.sub(pattern, f"\\1\n{insert_block}\n\\3", base_content, flags=re.DOTALL)
    else:
        # 兜底：直接追加
        new_content = base_content + "\n" + insert_block
    
    with open(readme_path, 'w') as f:
        f.write(new_content)
    logger.info("✅ README 已更新")

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
        logger.warning("⚠️ GeoIP 缺失")

    cache = DomainCache()
    history = HistoryManager()
    kernel = KernelIntrospector(MIHOMO_BIN)
    stats = []
    
    # China
    cn_domains = build_china_list(cache)
    if cn_domains:
        compile_mrs(kernel, "China", cn_domains, 'domain')
        with open(os.path.join(TARGET_DIR_LOON, "China.lsr"), 'w') as f:
            f.write("\n".join([f"DOMAIN-SUFFIX,{d}" for d in cn_domains]))
        stats.append(("China", len(cn_domains)))
        logger.info(f"✅ China 构建完成: {len(cn_domains)} 条")
    else:
        stats.append(("China", 0))

    # IP
    lan_content = robust_download(SOURCE_URLS["LAN"])
    if lan_content:
        ip_list = []
        for line in lan_content.splitlines():
            if 'IP-CIDR' in line or '/' in line:
                ip_list.append(line.strip().replace("'", ""))
        if ip_list:
            compile_mrs(kernel, "China_IP", ip_list, 'ipcidr')
            with open(os.path.join(TARGET_DIR_LOON, "China_IP.lsr"), 'w') as f:
                f.write("\n".join([f"IP-CIDR,{ip}" for ip in ip_list]))
            stats.append(("China_IP", len(ip_list)))
    else:
        stats.append(("China_IP", 0))

    cache.save()
    history.save()
    
    # 自动修复并更新 README
    auto_fix_readme(stats)
    
    logger.info("💾 全流程结束")

if __name__ == "__main__":
    main()
