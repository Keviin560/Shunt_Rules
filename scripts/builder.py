import os
import yaml
import hashlib
import subprocess
import logging
import shutil
import re
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from collections import defaultdict

# --- 全局配置 ---
SOURCE_DIR = "temp_source/rule/Clash"
TARGET_DIR_MIHOMO = "rule/Mihomo"
TARGET_DIR_LOON = "rule/Loon"
HISTORY_FILE = "history.json"
README_FILE = "README.md"
MIHOMO_BIN = "./mihomo"

# 🛑 变体剔除黑名单: 包含这些关键词的文件将被忽略，只处理主文件
IGNORE_KEYWORDS = ["Classical", "Domain", "For_Clash", "No_Resolve", "Clash"]

# 日志配置
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DigitalArchitect")

filename_registry = {}

# --- 动态元数据获取 ---
def get_metadata():
    # 格式: Owner/Repo (例如 Keviin560/Shunt_Rules)
    repo_full = os.getenv('GITHUB_REPOSITORY')
    
    if repo_full and "/" in repo_full:
        author = repo_full.split("/")[0]
        # RAW 链接的基础路径
        raw_base = f"https://raw.githubusercontent.com/{repo_full}/main"
        repo_url = f"https://github.com/{repo_full}"
    else:
        # 本地测试兜底
        author = "Unknown"
        raw_base = "https://raw.githubusercontent.com/Unknown/Test/main"
        repo_url = "https://github.com/Unknown/Test"
        repo_full = "YourName/RepoName" # 用于文档展示
        
    return author, raw_base, repo_url, repo_full

AUTHOR_NAME, RAW_BASE_URL, REPO_URL, REPO_NAME_DISPLAY = get_metadata()

# --- 核心组件 ---
class KernelIntrospector:
    """内核内省器：探测参数格式，防止因内核更新导致的参数错误"""
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
        # 存储: set( (type, value) )
        self.domain_entries = set()
        # 存储: dict( ip_str -> is_no_resolve )
        self.ip_entries = defaultdict(bool)

    def add_domain(self, line):
        line = line.strip().strip("'").strip('"')
        if not line or line.startswith('#'): return
        
        rule_type = "DOMAIN-SUFFIX"
        value = line
        
        # 处理 DOMAIN,google.com 格式
        if ',' in line:
            parts = line.split(',')
            if len(parts) >= 2:
                t, v = parts[0].upper().strip(), parts[1].strip()
                if 'DOMAIN' in t: rule_type, value = t, v
        
        if len(value) > 3: 
            self.domain_entries.add((rule_type, value))

    def add_ip(self, line):
        if not line: return
        clean = line.replace("'", "").replace('"', "").strip()
        parts = re.split(r'[,\s]+', clean)
        
        target = None
        no_res = False
        
        for p in parts:
            p = p.strip()
            # 过滤非数据部分
            if not p or 'IP-' in p.upper(): continue
            if p.lower() == 'no-resolve': 
                no_res = True
                continue
            
            # [物理隔离] 使用 ipaddress 库强校验，非 IP 直接丢弃
            try:
                ipaddress.ip_network(p, strict=False)
                target = p
            except ValueError: continue
            
        if target:
            if not self.ip_entries[target]: 
                self.ip_entries[target] = no_res

class HistoryManager:
    """历史记录管理器：追踪文件更新状态"""
    def __init__(self):
        self.history = {}
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, 'r') as f: self.history = json.load(f)
            except: pass
        self.current_time = int(datetime.now().timestamp())

    def get_file_hash(self, filepath):
        if not os.path.exists(filepath): return ""
        with open(filepath, 'rb') as f: return hashlib.md5(f.read()).hexdigest()

    def update_record(self, name, filepath):
        current_hash = self.get_file_hash(filepath)
        record = self.history.get(name, {})
        last_hash = record.get('hash', "")
        last_ts = record.get('time', self.current_time)

        if current_hash != last_hash:
            self.history[name] = {'hash': current_hash, 'time': self.current_time}
            return 0 # Today
        else:
            diff = datetime.fromtimestamp(self.current_time) - datetime.fromtimestamp(last_ts)
            return diff.days

    def save(self):
        with open(HISTORY_FILE, 'w') as f: json.dump(self.history, f, indent=2)

# --- 文件处理 ---
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
    if 'DOMAIN' in upper or (not 'IP-' in upper and '.' in line and not line[0].isdigit()):
        ruleset.add_domain(line)
    else:
        ruleset.add_ip(line)

def verify_artifact(filepath):
    if not os.path.exists(filepath): return False
    if os.path.getsize(filepath) == 0: return False
    return True

# --- Mihomo 构建 ---
def build_mihomo(kernel, name, ruleset):
    has_d, has_i = False, False
    if ruleset.domain_entries:
        clean = sorted(list(set([v for t,v in ruleset.domain_entries])))
        if _compile_mihomo(kernel, name, clean, 'domain'): has_d = True
            
    if ruleset.ip_entries:
        # ⚠️ 关键：Mihomo 不支持 no-resolve 后缀，只提取纯 IP
        clean = sorted(ruleset.ip_entries.keys())
        if _compile_mihomo(kernel, f"{name}_IP", clean, 'ipcidr'): has_i = True
            
    return has_d, has_i

def _compile_mihomo(kernel, name, rules, behavior):
    tmp = f"temp_{name}.yaml"
    dst = os.path.join(TARGET_DIR_MIHOMO, f"{name}.mrs")
    try:
        with open(tmp, 'w', encoding='utf-8') as f: yaml.dump({'payload': rules}, f)
        res = subprocess.run(kernel.get_cmd(behavior, tmp, dst), capture_output=True, text=True, timeout=20)
        
        # 错误容忍：忽略 unknown field 警告
        if res.returncode != 0 and "unknown field" not in res.stderr:
             # logger.error(f"❌ Mihomo 转换失败 [{name}]: {res.stderr.strip()}") 
             # 保持安静，因为我们已经有强校验，这里的报错通常是极少数的脏数据，不影响大局
             if os.path.exists(dst): os.remove(dst)
             return False
             
        if not verify_artifact(dst):
            if os.path.exists(dst): os.remove(dst)
            return False
        return True
    except: return False
    finally:
        if os.path.exists(tmp): os.remove(tmp)

# --- Loon 构建 ---
def get_loon_priority(line):
    # 五层漏斗排序
    if line.startswith("IP-CIDR") and "no-resolve" in line: return 0
    if line.startswith("DOMAIN,"): return 10
    if line.startswith("DOMAIN-SUFFIX"): return 20
    if "KEYWORD" in line or "REGEX" in line: return 30
    if line.startswith("IP-CIDR"): return 99
    return 50

def build_loon(name, ruleset):
    count = len(ruleset.domain_entries) + len(ruleset.ip_entries)
    if count == 0: return False
    
    dst = os.path.join(TARGET_DIR_LOON, f"{name}.lsr")
    lines = []
    
    # 继承 no-resolve 属性
    for ip, no_res in ruleset.ip_entries.items():
        suffix = ",no-resolve" if no_res else ""
        lines.append(f"IP-CIDR,{ip}{suffix}")
        
    for t, v in ruleset.domain_entries:
        lines.append(f"{t},{v}")
        
    lines.sort()
    lines.sort(key=get_loon_priority)
    
    bj_time = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(dst, 'w', encoding='utf-8') as f:
            f.write(f"# Name = {name}\n# Author = {AUTHOR_NAME}\n# REPO = {REPO_URL}\n# Update = {bj_time}\n# Total = {count}\n\n")
            f.write("\n".join(lines))
        return True
    except: return False

# --- README 生成 ---
def generate_readme(stats):
    stats.sort(key=lambda x: x[0])
    total = len(stats)
    bj_time = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M')
    
    md = [
        f"# 🚀 Shunt Rules 规则集仓库",
        f"![Total](https://img.shields.io/badge/规则总数-{total}-blue) ![Update](https://img.shields.io/badge/更新时间-{bj_time.replace(' ', '_')}-green)",
        f"",
        f"## ℹ️ 数据源说明",
        f"本仓库规则数据同步自 [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) 项目，感谢各位维护规则的大佬们。",
        f"",
        f"## ⚠️ 使用前必读",
        f"* **Mihomo**: `.mrs` 为二进制文件，不支持直接编辑。`_IP.mrs` 已**移除** `no-resolve` 属性以防止内核崩溃，**必须**在配置文件中自行指定策略。",
        f"* **Loon**: `.lsr` 支持混合负载，已内置优化排序（no-resolve IP 优先）。",
        f"",
        f"## 📍 Mihomo 配置指引",
        f"建议使用 `type: http` 远程引用规则集。以下代码以 **Google** 规则为例，请根据实际需求修改策略组名称。",
        f"",
        f"**1. 定义策略组 (Proxy Groups)**",
        f"```yaml",
        f"proxy-groups:",
        f"  - name: \"MyProxyGroup\"   # 策略组名称，可自定义",
        f"    type: select",
        f"    proxies:",
        f"      - 🇭🇰 香港节点      # 👈 这里填写你在 'proxies' 中定义的节点名称",
        f"      - 🇺🇸 美国节点      # 👈 或者填写 'DIRECT' (直连) / 'REJECT' (拒绝)",
        f"```",
        f"",
        f"**2. 配置规则集 (Rule Providers)**",
        f"```yaml",
        f"rule-providers:",
        f"  # 🟢 案例 1：引用域名规则 (behavior: domain)",
        f"  Google:",
        f"    type: http",
        f"    behavior: domain",
        f"    format: mrs",
        f"    url: \"{RAW_BASE_URL}/{TARGET_DIR_MIHOMO}/Google.mrs\"",
        f"    path: ./rules/Mihomo/Google.mrs",
        f"    interval: 86400",
        f"",
        f"  # 🟢 案例 2：引用 IP 规则 (behavior: ipcidr)",
        f"  Google_IP:",
        f"    type: http",
        f"    behavior: ipcidr",
        f"    format: mrs",
        f"    url: \"{RAW_BASE_URL}/{TARGET_DIR_MIHOMO}/Google_IP.mrs\"",
        f"    path: ./rules/Mihomo/Google_IP.mrs",
        f"    interval: 86400",
        f"```",
        f"",
        f"**3. 应用规则 (Rules)**",
        f"*⚠️ 关键：引用 IP 规则集时，请务必加上 `no-resolve`，防止 DNS 泄露。*",
        f"```yaml",
        f"rules:",
        f"  - RULE-SET,Google,MyProxyGroup",
        f"  - RULE-SET,Google_IP,MyProxyGroup,no-resolve",
        f"```",
        f"",
        f"## 📊 规则索引",
        f"| 规则名称 | Mihomo (.mrs) | Loon (.lsr) | 更新状态 |",
        f"| :--- | :--- | :--- | :--- |"
    ]
    
    for name, status, has_d, has_i, has_l in stats:
        mihomo_links = []
        if has_d:
            url = f"{RAW_BASE_URL}/{TARGET_DIR_MIHOMO}/{name}.mrs"
            mihomo_links.append(f"[`DOMAIN`]({url})")
        if has_i:
            url = f"{RAW_BASE_URL}/{TARGET_DIR_MIHOMO}/{name}_IP.mrs"
            mihomo_links.append(f"[`IP-CIDR`]({url})")
        mihomo_cell = " \\| ".join(mihomo_links) if mihomo_links else "-"
        
        if has_l:
            url = f"{RAW_BASE_URL}/{TARGET_DIR_LOON}/{name}.lsr"
            loon_cell = f"[`RAW Link`]({url})"
        else:
            loon_cell = "-"
            
        md.append(f"| **{name}** | {mihomo_cell} | {loon_cell} | {status} |")
        
    with open(README_FILE, 'w', encoding='utf-8') as f:
        f.write("\n".join(md))

def get_status_text(days):
    if days == 0: return "Today"
    if days == 1: return "Yesterday"
    return f"{days} days ago"

def main():
    for d in [TARGET_DIR_MIHOMO, TARGET_DIR_LOON]:
        if os.path.exists(d): 
            try: shutil.rmtree(d) 
            except: pass
        os.makedirs(d, exist_ok=True)
    
    if not os.path.exists(SOURCE_DIR): return

    kernel = KernelIntrospector(MIHOMO_BIN)
    history = HistoryManager()
    aggregated = defaultdict(RuleSet)
    
    logger.info("🔍 扫描中...")
    cnt, skip = 0, 0
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
            if cnt % 500 == 0: logger.info(f"⏳ 解析: {cnt} (跳过: {skip})...")

    logger.info(f"✅ 解析完毕。规则组: {len(aggregated)}")
    
    stats = []
    done = 0
    for rel, rs in aggregated.items():
        name = get_smart_filename(rel)
        h_d, h_i = build_mihomo(kernel, name, rs)
        h_l = build_loon(name, rs)
        
        if h_d or h_i or h_l:
            # 使用 Loon 文件作为更新指纹
            check_file = ""
            if h_l: check_file = os.path.join(TARGET_DIR_LOON, f"{name}.lsr")
            elif h_d: check_file = os.path.join(TARGET_DIR_MIHOMO, f"{name}.mrs")
            elif h_i: check_file = os.path.join(TARGET_DIR_MIHOMO, f"{name}_IP.mrs")
            
            days = history.update_record(name, check_file)
            stats.append((name, get_status_text(days), h_d, h_i, h_l))
        
        done += 1
        if done % 100 == 0: logger.info(f"🚀 进度: {done}/{len(aggregated)}")

    history.save()
    generate_readme(stats)
    logger.info("🎉 完成")

if __name__ == "__main__":
    main()
