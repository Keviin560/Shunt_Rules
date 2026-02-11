import os
import yaml
import hashlib
import subprocess
import logging
import shutil
import re
import ipaddress
from datetime import datetime, timedelta, timezone
from collections import defaultdict

# --- 全局配置 ---
SOURCE_DIR = "temp_source/rule/Clash"
TARGET_DIR_MIHOMO = "rule/Mihomo"
TARGET_DIR_LOON = "rule/Loon"
MIHOMO_BIN = "./mihomo"

# 变体剔除黑名单
IGNORE_KEYWORDS = ["Classical", "Domain", "For_Clash", "No_Resolve", "Clash"]

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DigitalArchitect")

filename_registry = {}

# --- 动态元数据获取 ---
def get_metadata():
    # GitHub Actions 会自动注入 GITHUB_REPOSITORY (格式: Keviin560/Shunt_Rules)
    repo_full = os.getenv('GITHUB_REPOSITORY')
    
    if repo_full and "/" in repo_full:
        author = repo_full.split("/")[0]
        repo_url = f"https://github.com/{repo_full}"
    else:
        # 本地测试或获取失败时的兜底
        author = "Unknown"
        repo_url = "https://github.com/Local/Test"
        
    return author, repo_url

AUTHOR_NAME, REPO_URL = get_metadata()

class KernelIntrospector:
    """Mihomo 内核参数探测"""
    def __init__(self, bin_path):
        self.bin_path = bin_path
        if not os.path.exists(bin_path): raise FileNotFoundError(f"内核缺失: {bin_path}")
        self.needs_format_arg = self._detect()

    def _detect(self):
        try:
            res = subprocess.run([self.bin_path, "convert-ruleset"], capture_output=True, text=True, timeout=5)
            out = res.stderr + res.stdout
            return "<format>" in out or " [format] " in out
        except: return False

    def get_cmd(self, behavior, src, dst):
        cmd = [self.bin_path, "convert-ruleset", behavior]
        if self.needs_format_arg: cmd.append("yaml")
        cmd.append(src)
        cmd.append(dst)
        return cmd

class RuleSet:
    def __init__(self):
        # 存储结构: set( (type_str, value_str) )
        # 例如: {('DOMAIN-SUFFIX', 'google.com'), ('DOMAIN', 'baidu.com')}
        self.domain_entries = set()
        
        # 存储结构: dict( ip_str -> is_no_resolve_bool )
        # 例如: {'1.1.1.1/32': True}
        self.ip_entries = defaultdict(bool)

    def add_domain(self, line):
        # 预处理
        line = line.strip().strip("'").strip('"')
        if not line or line.startswith('#'): return
        
        # 识别类型
        rule_type = "DOMAIN-SUFFIX" # 默认
        value = line
        
        # 处理 DOMAIN-SUFFIX,google.com 格式
        if ',' in line:
            parts = line.split(',')
            if len(parts) >= 2:
                # 简单的类型映射清洗
                t = parts[0].upper().strip()
                v = parts[1].strip()
                if 'DOMAIN' in t: 
                    rule_type = t
                    value = v
        
        # 简单过滤
        if len(value) > 3:
            self.domain_entries.add((rule_type, value))

    def add_ip(self, ip_line):
        if not ip_line: return
        clean_line = ip_line.replace("'", "").replace('"', "").strip()
        parts = re.split(r'[,\s]+', clean_line)
        
        target_ip = None
        has_no_resolve = False
        
        for p in parts:
            p = p.strip()
            if not p: continue
            if 'IP-' in p.upper(): continue # 跳过前缀
            
            if p.lower() == 'no-resolve':
                has_no_resolve = True
                continue
                
            # 尝试解析 IP
            try:
                ipaddress.ip_network(p, strict=False)
                target_ip = p
            except ValueError: continue
            
        if target_ip:
            # 状态合并：只要出现过一次 no-resolve，就标记为 True
            if self.ip_entries[target_ip]:
                pass # 已经是 True 了
            else:
                self.ip_entries[target_ip] = has_no_resolve

def get_smart_filename(rel_path):
    parts = rel_path.split(os.sep)
    base = os.path.splitext(parts[-1])[0]
    cand = base
    stack = parts[:-1]
    while cand in filename_registry:
        if filename_registry[cand] == rel_path: return cand
        if not stack:
            cand = f"{cand}_{hashlib.md5(rel_path.encode()).hexdigest()[:4]}"
            break
        cand = f"{stack.pop()}_{cand}"
    filename_registry[cand] = rel_path
    return cand

def should_skip(fname):
    base = os.path.splitext(fname)[0]
    for k in IGNORE_KEYWORDS:
        if k in base: return True
    return False

def parse_file(path, ruleset):
    """文件解析路由"""
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            if path.endswith(('.yaml', '.yml')):
                try:
                    data = yaml.safe_load(f)
                    if data and 'payload' in data:
                        for l in data['payload']: process_entry(str(l), ruleset)
                except: pass
            else:
                for l in f: process_entry(l, ruleset)
    except: pass

def process_entry(line, ruleset):
    line = line.strip()
    if not line or line.startswith('#'): return
    if line.startswith("['"): line = line.replace('[','').replace(']','').replace("'", "")
    
    upper = line.upper()
    # 区分 IP 和 域名
    if 'DOMAIN' in upper or (not 'IP-' in upper and '.' in line and not line[0].isdigit()):
        ruleset.add_domain(line)
    else:
        ruleset.add_ip(line)

# --- 构建器：Mihomo ---
def verify_mrs(filepath):
    if not os.path.exists(filepath): return False
    if os.path.getsize(filepath) == 0: return False
    return True

def build_mihomo(kernel, name, ruleset):
    # 1. 域名 (behavior: domain)
    if ruleset.domain_entries:
        # 提取纯值
        clean_domains = sorted(list(set([v for t, v in ruleset.domain_entries])))
        _compile_mihomo(kernel, name, clean_domains, 'domain')
    
    # 2. IP (behavior: ipcidr)
    if ruleset.ip_entries:
        # 提取纯 IP (Mihomo 不支持 no-resolve 存储)
        clean_ips = sorted(ruleset.ip_entries.keys())
        _compile_mihomo(kernel, f"{name}_IP", clean_ips, 'ipcidr')

def _compile_mihomo(kernel, name, rules, behavior):
    tmp = f"temp_{name}.yaml"
    dst = os.path.join(TARGET_DIR_MIHOMO, f"{name}.mrs")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            yaml.dump({'payload': rules}, f)
        
        res = subprocess.run(kernel.get_cmd(behavior, tmp, dst), capture_output=True, text=True, timeout=20)
        
        if res.returncode != 0:
            if "unknown field" not in res.stderr:
                logger.error(f"❌ [Mihomo] 转换失败 [{name}]: {res.stderr.strip()}")
            if os.path.exists(dst): os.remove(dst)
        elif not verify_mrs(dst):
            if os.path.exists(dst): os.remove(dst)
    except:
        if os.path.exists(dst): os.remove(dst)
    finally:
        if os.path.exists(tmp): os.remove(tmp)

# --- 构建器：Loon (五层漏斗排序) ---
def get_loon_priority(line):
    """Loon 规则优先级计算"""
    # Tier 1: no-resolve IP (最高优先级，直接跳过DNS)
    if line.startswith("IP-CIDR") and "no-resolve" in line: return 0
    # Tier 2: 精确域名 (O(1) 匹配)
    if line.startswith("DOMAIN,"): return 10
    # Tier 3: 泛域名 (树状匹配)
    if line.startswith("DOMAIN-SUFFIX"): return 20
    # Tier 4: 关键词/正则 (全扫描，开销大)
    if "KEYWORD" in line or "REGEX" in line: return 30
    # Tier 5: 普通 IP (需要 DNS 解析，最后匹配)
    if line.startswith("IP-CIDR"): return 99
    return 50

def build_loon(name, ruleset):
    count = len(ruleset.domain_entries) + len(ruleset.ip_entries)
    if count == 0: return

    dst = os.path.join(TARGET_DIR_LOON, f"{name}.lsr")
    os.makedirs(os.path.dirname(dst), exist_ok=True)

    # 构造 Loon 规则列表
    lines = []
    
    # 1. 处理 IP
    for ip, no_res in ruleset.ip_entries.items():
        # 这里统一使用 IP-CIDR，Loon 支持自动识别 IPv6
        suffix = ",no-resolve" if no_res else ""
        lines.append(f"IP-CIDR,{ip}{suffix}")
        
    # 2. 处理 域名
    for r_type, r_val in ruleset.domain_entries:
        lines.append(f"{r_type},{r_val}")
        
    # 3. 核心排序 (Stable Sort)
    # 先按字母序排(保持同类规则整洁)，再按优先级排
    lines.sort() 
    lines.sort(key=get_loon_priority)

    # 4. 生成元数据 (北京时间 UTC+8)
    bj_time = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        with open(dst, 'w', encoding='utf-8') as f:
            f.write(f"# Name = {name}\n")
            f.write(f"# Author = {AUTHOR_NAME}\n")
            f.write(f"# REPO = {REPO_URL}\n")
            f.write(f"# Update = {bj_time}\n")
            f.write(f"# Total = {count}\n\n")
            
            for line in lines:
                f.write(line + "\n")
                
        if os.path.getsize(dst) < 20: os.remove(dst)
    except:
        if os.path.exists(dst): os.remove(dst)

def main():
    # 1. 清理旧产物
    for d in [TARGET_DIR_MIHOMO, TARGET_DIR_LOON]:
        if os.path.exists(d): 
            try: shutil.rmtree(d)
            except: pass
        os.makedirs(d, exist_ok=True)
    
    if not os.path.exists(SOURCE_DIR): return

    kernel = KernelIntrospector(MIHOMO_BIN)
    aggregated = defaultdict(RuleSet)
    
    logger.info("🔍 扫描中...")
    cnt = 0
    skip = 0
    for root, _, files in os.walk(SOURCE_DIR):
        rel = os.path.relpath(root, SOURCE_DIR)
        if rel == '.': continue
        current = aggregated[rel]
        for f in files:
            if not f.lower().endswith(('.yaml','.yml','.list','.txt')): continue
            if should_skip(f): 
                skip += 1
                continue
            parse_file(os.path.join(root, f), current)
            cnt += 1
            if cnt % 200 == 0: logger.info(f"⏳ 解析: {cnt} (跳过: {skip})...")

    logger.info(f"✅ 解析完成。规则组: {len(aggregated)}")
    
    done = 0
    for rel, rs in aggregated.items():
        name = get_smart_filename(rel)
        
        # Mihomo (物理隔离)
        build_mihomo(kernel, name, rs)
        
        # Loon (混合+排序+元数据)
        build_loon(name, rs)
        
        done += 1
        if done % 50 == 0: logger.info(f"🚀 编译: {done}/{len(aggregated)}")

    logger.info("🎉 完成")

if __name__ == "__main__":
    main()
