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
GENERATOR_VERSION = "v3.2_README_UPGRADE" 
SOURCE_DIR = "temp_source/rule/Clash"
TARGET_DIR_MIHOMO = "rule/Mihomo"
TARGET_DIR_LOON = "rule/Loon"
# 🔥 历史记录的最终归宿
DATA_HISTORY_FILE = "data/history.json"
# 兼容根目录旧文件
ROOT_HISTORY_FILE = "history.json"

README_FILE = "README.md"
MIHOMO_BIN = "./mihomo"
IGNORE_KEYWORDS = ["Classical", "Domain", "For_Clash", "No_Resolve", "Clash"]

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DigitalArchitect")

filename_registry = {}
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
        if os.path.exists(DATA_HISTORY_FILE):
            try:
                with open(DATA_HISTORY_FILE, 'r') as f: 
                    self.history = json.load(f)
                logger.info(f"📂 Loaded history from {DATA_HISTORY_FILE}")
            except: pass
        elif os.path.exists(ROOT_HISTORY_FILE):
            try:
                with open(ROOT_HISTORY_FILE, 'r') as f: 
                    self.history = json.load(f)
                logger.info(f"📂 Loaded history from {ROOT_HISTORY_FILE} (Migration mode)")
            except: pass
        else:
            logger.info("📂 No history found, starting fresh.")
            
        self.current_time = int(datetime.now().timestamp())

    def get_file_hash(self, filepath):
        if not filepath or not os.path.exists(filepath): return ""
        with open(filepath, 'rb') as f: return hashlib.md5(f.read()).hexdigest()
        
    def should_skip(self, name, source_path, expected_files):
        src_hash = self.get_file_hash(source_path)
        if not src_hash: return False, ""
        record = self.history.get(name, {})
        last_hash = record.get('src_hash', "")
        if src_hash != last_hash: return False, src_hash
        for f in expected_files:
            if not os.path.exists(f) or os.path.getsize(f) == 0: return False, src_hash
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
        os.makedirs(os.path.dirname(DATA_HISTORY_FILE), exist_ok=True)
        with open(DATA_HISTORY_FILE, 'w') as f: 
            json.dump(self.history, f, indent=2)
        logger.info(f"💾 Saved history to {DATA_HISTORY_FILE}")
        if os.path.exists(ROOT_HISTORY_FILE):
            os.remove(ROOT_HISTORY_FILE)
            logger.info(f"🧹 Removed legacy {ROOT_HISTORY_FILE}")

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
                        for d in domains: raw_candidates.add(d)
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
        if clean and _compile_mihomo(kernel, name, clean, 'domain'): h_d = True
            
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
    try: files = os.listdir('.')
    except: return "Mihomo_ShuntRules.yaml", False
    for f in files:
        if f.endswith(('.yaml', '.yml')) and "Mihomo" in f and "Shunt" in f: return f, True
    for f in files:
         if f.endswith(('.yaml', '.yml')) and ("Mihomo" in f or "Config" in f): return f, True
    return "Mihomo_ShuntRules.yaml", False

def generate_readme(stats):
    stats.sort(key=lambda x: x[0])
    total = len(stats)
    bj_time = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime('%Y.%m.%d') 
    time_badge_val = bj_time
    
    # 动态获取 GitHub 仓库路径 (用于构建状态徽章)
    repo_path = os.getenv('GITHUB_REPOSITORY', 'YourName/Repo')

    # ✅ 徽章生成区 (V3.2 新版 - 两行布局)
    # 第一行：核心状态与硬指标 (Standard)
    badges_row1 = [
        f"![Build](https://img.shields.io/github/actions/workflow/status/{repo_path}/main.yml?label=Build&style=flat&color=brightgreen)",
        f"![Update](https://img.shields.io/badge/Update-{time_badge_val}-2ea44f?style=flat)",
        f"![Rules](https://img.shields.io/badge/Rules-{total}-blue?style=flat)"
    ]
    
    # 第二行：ASR 独家特性 (Features)
    badges_row2 = [
        f"![Anchor](https://img.shields.io/badge/-双重锚定-8e44ad?style=flat)",
        f"![Sort](https://img.shields.io/badge/-智能排序-009688?style=flat)",
        f"![Audit](https://img.shields.io/badge/-DNS%20审计-f44336?style=flat)",
        f"![Pure](https://img.shields.io/badge/-纯净标尺-007bff?style=flat)",
        f"![Ready](https://img.shields.io/badge/-开箱即用-ff69b4?style=flat)"
    ]

    badge_line = " ".join(badges_row1) + "\n\n" + " ".join(badges_row2)

    # 🔗 致谢链接
    link_ls = "https://github.com/Loyalsoldier/v2ray-rules-dat"
    link_bm = "https://github.com/blackmatrix7/ios_rule_script"
    link_mihomo = "https://github.com/MetaCubeX/mihomo"
    link_v2dat = "https://github.com/urlesistiana/v2dat"

    # 📝 全新文档结构 (V3.2)
    md = [
        f"<div align=\"center\">",
        f"",
        f"# 🤖 Auto Shunt Rules (ASR)", 
        f"",
        f"{badge_line}",
        f"",
        f"</div>",
        f"",
        f"## 📖 项目简述 (Overview)",
        f"ASR (Auto Shunt Rules) 是一套全自动化的 CI/CD 流水线。它每天定时从上游拉取最新数据，通过原子级转译和外科手术般的深度清洗，输出贴合内核运行逻辑的纯净规则。",
        f"* **Mihomo**: 享受 .mrs 二进制格式带来的极速加载与低内存占用。",
        f"* **Loon**: 获得针对其“混合负载”特性优化的排序逻辑。",
        f"",
        f"## 🧠 核心逻辑架构 (Core Logic)",
        f"本项目由双引擎驱动，分别处理通用规则与区域规则：",
        f"",
        f"### 引擎一：全量规则转译 (The Transmuter)",
        f"> **对象**：Blackmatrix7 全量规则库 (Google, YouTube, Telegram, OpenAI 等)",
        f"",
        f"根据目标客户端特性进行了逻辑重构：",
        f"* **Mihomo (.mrs) —— 双重锚定 (Double Anchoring)**",
        f"  采用双重生成策略把域名裂变为“精确匹配”与“泛域名匹配”两条指令（例如同时生成 `google.com` 和 `+.google.com`）。解决子域名匹配遗漏的问题，提升了流媒体与复杂应用服务的匹配精准度。",
        f"* **Loon (.lsr) —— 智能排序 (Smart Sorting)**",
        f"  针对 Loon 的 IP-CIDR 优先匹配机制，自动将带有 `no-resolve` 属性的 IP 规则强制置顶。确保内核在匹配时优先处理纯 IP 请求，减少不必要的 DNS 解析行为，从而有效降低 DNS 泄露风险。",
        f"",
        f"### 引擎二：区域深度净化 (The Purifier)",
        f"> **对象**：GeoIP/GeoSite CN 区域规则",
        f"",
        f"针对中国大陆地区（不含港澳台）的网站，实施“零信任”清洗：",
        f"* **IP 减法**：不盲信原版 CN IP 库。引入 Google, Cloudflare, AWS 等境外实体 IP 作为“黑名单”，从 CN 库中将其移除，实现真正的“提纯”。",
        f"* **域名验证**：引入生命周期管理。所有 CN 域名需经过 DNS 验活，连续 3 次（9天）解析失败的域名将被暂时移出规则库（进入180天冷冻期），防止规则体积无效膨胀。",
        f"* **前缀剥离**：自动剥离 `+.` 等泛域名通配符，还原为主域名进行物理验活，确保测试结果真实有效。",
        f"",
        f"## 📦 特性与格式说明 (Features & Formats)",
        f"### 1. 规则集 (Rule Sets)",
        f"源自 Blackmatrix7，同步上游数千个规则文件（如 Global, Google, YouTube, Netflix 等）。",
        f"* **Mihomo (.mrs)**：二进制编译格式，加载速度快，资源占用极低。",
        f"* **Loon (.lsr)**：纯文本格式，已针对 Loon 优化混合负载结构。",
        f"",
        f"### 2. 区域集 (Regional Sets)",
        f"源自 Loyalsoldier，经过 ASR 引擎深度清洗。",
        f"* **GeoSite_CN**",
        f"  * 核心逻辑：剔除死链、剔除伪直连（指纹识别）、剔除境外 CDN 域名。",
        f"* **GeoIP_CN**",
        f"  * 核心逻辑：剔除 Cloudflare/Google 等境外实体 IP，仅保留物理位置真实的纯 CN IP，Mihomo 建议配合 `no-resolve` 使用。",
        f"",
        f"## 🤝 致谢 (Credits)",
        f"感谢以下项目提供的数据与工具支持：",
        f"* 数据来源：[Loyalsoldier/v2ray-rules-dat]({link_ls}), [blackmatrix7/ios_rule_script]({link_bm})",
        f"* 构建工具：[MetaCubeX/mihomo]({link_mihomo}), [urlesistiana/v2dat]({link_v2dat})",
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
        
    # 添加免责声明
    md.append(f"")
    md.append(f"> **免责声明**：本项目生成的规则仅供技术研究与网络优化使用，请遵守当地法律法规。")

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
    sorted_rels = sorted(aggregated.keys(), key=lambda x: (x.count(os.sep), x))
    for rel in sorted_rels:
        rs = aggregated[rel]
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
