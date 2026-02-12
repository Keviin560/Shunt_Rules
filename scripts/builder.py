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
# ⚡️ v2.4 完美排版版: 修复 README 换行问题，优化文案视觉层级
GENERATOR_VERSION = "v2.4_PERFECT_LAYOUT" 
SOURCE_DIR = "temp_source/rule/Clash"
TARGET_DIR_MIHOMO = "rule/Mihomo"
TARGET_DIR_LOON = "rule/Loon"
HISTORY_FILE = "history.json"
README_FILE = "README.md"
MIHOMO_BIN = "./mihomo"

# 🛑 变体剔除黑名单
IGNORE_KEYWORDS = ["Classical", "Domain", "For_Clash", "No_Resolve", "Clash"]

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DigitalArchitect")

filename_registry = {}

# --- 关键词救援字典 ---
KEYWORD_RESCUE_MAP = {
    "googlevideo": ["googlevideo.com"],
    "youtube": ["youtube.com", "ytimg.com"],
    "google": ["google.com", "googleapis.com"],
    "github": ["github.com", "githubusercontent.com"],
    "twitter": ["twitter.com", "t.co", "twimg.com"],
    "telegram": ["telegram.org", "t.me"],
    "netflix": ["netflix.com", "nflxvideo.net"],
    "facebook": ["facebook.com", "fbcdn.net"],
    "instagram": ["instagram.com", "cdninstagram.com"],
    "openai": ["openai.com"],
    "chatgpt": ["chatgpt.com", "oaistatic.com", "oaiusercontent.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "xbox": ["xbox.com", "xboxlive.com"],
    "microsoft": ["microsoft.com", "azure.com"]
}

# --- 动态元数据获取 ---
def get_metadata():
    repo_full = os.getenv('GITHUB_REPOSITORY')
    if repo_full and "/" in repo_full:
        author = repo_full.split("/")[0]
        raw_base = f"https://raw.githubusercontent.com/{repo_full}/main"
        repo_url = f"https://github.com/{repo_full}"
    else:
        author = "Unknown"
        raw_base = "https://raw.githubusercontent.com/Unknown/Test/main"
        repo_url = "https://github.com/Unknown/Test"
        repo_full = "YourName/RepoName"
    return author, raw_base, repo_url, repo_full

AUTHOR_NAME, RAW_BASE_URL, REPO_URL, REPO_NAME_DISPLAY = get_metadata()

# --- 核心组件类 ---
class KernelIntrospector:
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
        self.domain_entries = set()
        self.ip_entries = defaultdict(bool)
    def add_domain(self, line):
        line = line.strip().strip("'").strip('"')
        if not line or line.startswith('#'): return
        rule_type = "DOMAIN-SUFFIX"
        value = line
        if ',' in line:
            parts = line.split(',')
            if len(parts) >= 2:
                t, v = parts[0].upper().strip(), parts[1].strip()
                if 'DOMAIN' in t: rule_type, value = t, v
        if len(value) > 2: self.domain_entries.add((rule_type, value))
    def add_ip(self, line):
        if not line: return
        clean = line.replace("'", "").replace('"', "").strip()
        parts = re.split(r'[,\s]+', clean)
        target = None
        no_res = False
        for p in parts:
            p = p.strip()
            if not p or 'IP-' in p.upper(): continue
            if p.lower() == 'no-resolve': 
                no_res = True
                continue
            try:
                ipaddress.ip_network(p, strict=False)
                target = p
            except ValueError: continue
        if target:
            if not self.ip_entries[target]: self.ip_entries[target] = no_res

class HistoryManager:
    def __init__(self):
        self.history = {}
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, 'r') as f: self.history = json.load(f)
            except: pass
        self.current_time = int(datetime.now().timestamp())
    def get_file_hash(self, filepath):
        if not filepath or not os.path.exists(filepath): return ""
        with open(filepath, 'rb') as f: return hashlib.md5(f.read()).hexdigest()
    def should_skip(self, name, source_path, expected_files):
        src_hash = self.get_file_hash(source_path)
        if not src_hash: return False, ""
        
        record = self.history.get(name, {})
        last_hash = record.get('src_hash', "")
        last_ver = record.get('gen_ver', "")
        
        # 强制重写：只要版本不对，立刻重编
        if src_hash != last_hash or last_ver != GENERATOR_VERSION:
            return False, src_hash
            
        for f in expected_files:
            if not os.path.exists(f) or os.path.getsize(f) == 0:
                return False, src_hash
                
        return True, src_hash

    def update_record(self, name, src_hash):
        self.history[name] = {
            'src_hash': src_hash,
            'updated_at': self.current_time,
            'gen_ver': GENERATOR_VERSION
        }
    def get_days_ago(self, name):
        record = self.history.get(name, {})
        last_ts = record.get('updated_at', self.current_time)
        diff = datetime.fromtimestamp(self.current_time) - datetime.fromtimestamp(last_ts)
        return diff.days
    def save(self):
        with open(HISTORY_FILE, 'w') as f: json.dump(self.history, f, indent=2)

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

def should_skip_file(fname):
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

def build_mihomo(kernel, name, ruleset):
    h_d, h_i = False, False
    
    if ruleset.domain_entries:
        final_domains = set()
        raw_candidates = set()

        for t, v in ruleset.domain_entries:
            if 'KEYWORD' in t.upper():
                for kw, domains in KEYWORD_RESCUE_MAP.items():
                    if kw in v.lower():
                        for d in domains:
                            raw_candidates.add(d)
                continue 

            if 'REGEX' in t.upper(): continue
            raw_candidates.add(v)
        
        for d in raw_candidates:
            if d.startswith('.'):
                clean_d = d[1:] 
                final_domains.add(clean_d)
                final_domains.add(d) 
            else:
                final_domains.add(d)
                final_domains.add(f".{d}")

        clean = sorted(list(final_domains))
        
        if clean and _compile_mihomo(kernel, name, clean, 'domain'): 
            h_d = True
            
    if ruleset.ip_entries:
        clean = sorted(ruleset.ip_entries.keys())
        if _compile_mihomo(kernel, f"{name}_IP", clean, 'ipcidr'): h_i = True
        
    return h_d, h_i

def _compile_mihomo(kernel, name, rules, behavior):
    tmp = f"temp_{name}.yaml"
    dst = os.path.join(TARGET_DIR_MIHOMO, f"{name}.mrs")
    try:
        with open(tmp, 'w', encoding='utf-8') as f: yaml.dump({'payload': rules}, f)
        res = subprocess.run(kernel.get_cmd(behavior, tmp, dst), capture_output=True, text=True, timeout=20)
        if res.returncode != 0 or os.path.getsize(dst) == 0:
            if os.path.exists(dst): os.remove(dst)
            return False
        return True
    except: return False
    finally:
        if os.path.exists(tmp): os.remove(tmp)

def build_loon(name, ruleset):
    count = len(ruleset.domain_entries) + len(ruleset.ip_entries)
    if count == 0: return False
    dst = os.path.join(TARGET_DIR_LOON, f"{name}.lsr")
    lines = []
    for ip, no_res in ruleset.ip_entries.items():
        lines.append(f"IP-CIDR,{ip}{',no-resolve' if no_res else ''}")
    for t, v in ruleset.domain_entries: lines.append(f"{t},{v}")
    lines.sort()
    lines.sort(key=lambda x: 0 if "no-resolve" in x else (1 if "DOMAIN" in x else 2))
    bj_time = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(dst, 'w', encoding='utf-8') as f:
            f.write(f"# Name = {name}\n# Author = {AUTHOR_NAME}\n# REPO = {REPO_URL}\n# Update = {bj_time}\n# Total = {count}\n\n")
            f.write("\n".join(lines))
        return True
    except: return False

def get_status_text(days):
    if days == 0: return "Today"
    if days == 1: return "Yesterday"
    return f"{days} days ago"

def detect_config_file():
    try:
        files = os.listdir('.')
    except:
        return "Mihomo_ShuntRules.yaml", False
    for f in files:
        if f.endswith(('.yaml', '.yml')) and "Mihomo" in f and "Shunt" in f:
            return f, True
    for f in files:
         if f.endswith(('.yaml', '.yml')) and ("Mihomo" in f or "Config" in f):
            return f, True
    return "Mihomo_ShuntRules.yaml", False

def generate_readme(stats):
    stats.sort(key=lambda x: x[0])
    total = len(stats)
    bj_time = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M')
    time_badge_str = bj_time.replace("-", "--").replace(" ", "_")
    
    config_name, found = detect_config_file()
    config_link = f"[{config_name}]({RAW_BASE_URL}/{config_name})"

    md = [
        f"# 🚀 Shunt Rules 规则集", 
        f"",
        f"![Total](https://img.shields.io/badge/规则总数-{total}-blue) "
        f"![Update](https://img.shields.io/badge/更新时间-{time_badge_str}-green)",
        f"",
        f"## ℹ️ 数据源说明",
        f"♻️本仓库规则数据同步自 [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) 项目，感谢各位维护规则的大佬们。",
        f"",
        f"## ⚠️ 使用前必读",
        f"* 🐱 **Mihomo**: .mrs 二进制格式。采用双重锚定策略，完美解决子域名漏网与视频流匹配。_IP.mrs 已移除 `no-resolve` 属性以防止内核崩溃。",
        f"* 🎈 **Loon**: .lsr 文本格式。支持混合负载并优化排序（`no-resolve IP` 优先），确保匹配效率与防泄露表现。",
        f"* 🎭 **DNS 泄露**: IP 规则在匹配前必须先解析域名，而解析过程会使用 DNS 配置中的 `nameserver` 字段指定的 DNS 服务器。这可能会暴露访问目标，无必要请避免使用 IP 规则，或添加 `no-resolve` 参数。",
        f"",
        f"## 📍 Mihomo 配置指引",
        # ✅ 修复点：使用引用块和空行来确保排版清晰、换行正确
        f"> ⚡ **最佳实践**: 用 `type: http` 远程引用规则集。",
        f"> 🔗 **覆写参考**: {config_link}",
        f"",
        f"💾 **配置示例** (以 Google 为例，请按需修改):",
        f"",
        f"1. 定义策略组 (Proxy Groups)",
        f"```yaml",
        f"proxy-groups:",
        f"  - name: \"MyProxyGroup\"   # 策略组名称，可自定义",
        f"    type: select",
        f"    proxies:",
        f"      - 🇭🇰 香港节点      # 👈 这里填写你在 'proxies' 中定义的节点名称",
        f"      - 🇺🇸 美国节点      # 👈 或者填写 'DIRECT' (直连) / 'REJECT' (拒绝)",
        f"```",
        f"",
        f"2. 配置规则集 (Rule Providers)",
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
        f"3. 应用规则 (Rules)",
        f"*⚠️ 关键：引用 IP 规则集时，建议加上 `no-resolve`，防止 DNS 泄露。*",
        f"```yaml",
        f"rules:",
        f"  - RULE-SET,Google,MyProxyGroup",
        f"  - RULE-SET,Google_IP,MyProxyGroup,no-resolve",
        f"```",
        f"",
        f"## 📊 规则索引",
        f"| 规则名称 | Mihomo (.mrs) | Loon (.lsr) | 更新状态 |",
        f"| :---: | :---: | :---: | :---: |"
    ]
    
    for name, status, has_d, has_i, has_l in stats:
        mihomo_links = []
        if has_d: mihomo_links.append(f"[`DOMAIN`]({RAW_BASE_URL}/{TARGET_DIR_MIHOMO}/{name}.mrs)")
        if has_i: mihomo_links.append(f"[`IP-CIDR`]({RAW_BASE_URL}/{TARGET_DIR_MIHOMO}/{name}_IP.mrs)")
        m_cell = " \\| ".join(mihomo_links) if mihomo_links else "-"
        l_cell = f"[`RAW Link`]({RAW_BASE_URL}/{TARGET_DIR_LOON}/{name}.lsr)" if has_l else "-"
        md.append(f"| {name} | {m_cell} | {l_cell} | {status} |")
        
    with open(README_FILE, 'w', encoding='utf-8') as f: f.write("\n".join(md))

def main():
    for d in [TARGET_DIR_MIHOMO, TARGET_DIR_LOON]:
        os.makedirs(d, exist_ok=True)
    if not os.path.exists(SOURCE_DIR): return
    kernel, history, aggregated = KernelIntrospector(MIHOMO_BIN), HistoryManager(), defaultdict(RuleSet)
    logger.info("🔍 扫描源文件...")
    
    rel_path_map = {} 
    cnt, skip = 0, 0
    for root, _, files in os.walk(SOURCE_DIR):
        rel = os.path.relpath(root, SOURCE_DIR)
        if rel == '.': continue
        rs = aggregated[rel]
        for f in files:
            if f.lower().endswith(('.yaml','.yml','.list','.txt')) and not should_skip_file(f):
                full_path = os.path.join(root, f)
                parse_file(full_path, rs)
                rel_path_map[rel] = full_path 
                cnt += 1
                
    logger.info(f"✅ 解析完成。规则组: {len(aggregated)}")
    
    stats = []
    valid_outputs = set()
    
    updated_count = 0
    skipped_count = 0
    
    for rel, rs in aggregated.items():
        name = get_smart_filename(rel)
        source_path = rel_path_map.get(rel)
        if not source_path: continue

        expect_d = bool(rs.domain_entries)
        expect_i = bool(rs.ip_entries)
        expect_l = expect_d or expect_i
        
        expected_files = []
        if expect_d: expected_files.append(os.path.join(TARGET_DIR_MIHOMO, f"{name}.mrs"))
        if expect_i: expected_files.append(os.path.join(TARGET_DIR_MIHOMO, f"{name}_IP.mrs"))
        if expect_l: expected_files.append(os.path.join(TARGET_DIR_LOON, f"{name}.lsr"))
        
        should_skip_build, src_hash = history.should_skip(name, source_path, expected_files)
        
        h_d, h_i, h_l = expect_d, expect_i, expect_l
        
        if should_skip_build:
            skipped_count += 1
            days = history.get_days_ago(name)
        else:
            updated_count += 1
            h_d, h_i = build_mihomo(kernel, name, rs)
            h_l = build_loon(name, rs)
            history.update_record(name, src_hash)
            days = 0
            
        if h_d: valid_outputs.add(os.path.join(TARGET_DIR_MIHOMO, f"{name}.mrs"))
        if h_i: valid_outputs.add(os.path.join(TARGET_DIR_MIHOMO, f"{name}_IP.mrs"))
        if h_l: valid_outputs.add(os.path.join(TARGET_DIR_LOON, f"{name}.lsr"))
        
        if h_d or h_i or h_l:
            stats.append((name, get_status_text(days), h_d, h_i, h_l))
            
    logger.info("🧹 执行清理...")
    removed_zombies = 0
    for d in [TARGET_DIR_MIHOMO, TARGET_DIR_LOON]:
        if not os.path.exists(d): continue
        for f in os.listdir(d):
            full_p = os.path.join(d, f)
            if full_p not in valid_outputs:
                os.remove(full_p)
                removed_zombies += 1
                
    history.save()
    generate_readme(stats)
    logger.info(f"🎉 完成: 更新 {updated_count}, 跳过 {skipped_count}, 清理 {removed_zombies}")

if __name__ == "__main__":
    main()
