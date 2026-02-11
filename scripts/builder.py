import os
import yaml
import hashlib
import subprocess
import logging
import shutil
import re
import ipaddress
from collections import defaultdict

# --- 全局配置 ---
SOURCE_DIR = "temp_source/rule/Clash"
TARGET_DIR = "rule/Mihomo"
MIHOMO_BIN = "./mihomo"

# 🛑 变体剔除黑名单：只保留主规则，剔除冗余变体
IGNORE_KEYWORDS = [
    "Classical", 
    "Domain", 
    "For_Clash", 
    "No_Resolve", 
    "Clash"
]

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DigitalArchitect")

filename_registry = {}

class KernelIntrospector:
    def __init__(self, bin_path):
        self.bin_path = bin_path
        if not os.path.exists(bin_path):
            raise FileNotFoundError(f"内核文件不存在: {bin_path}")
        self.needs_format_arg = self._detect_capability()

    def _detect_capability(self):
        try:
            result = subprocess.run([self.bin_path, "convert-ruleset"], capture_output=True, text=True, timeout=5)
            # 探测 Usage 信息中是否包含 format 参数
            if "<format>" in (result.stderr + result.stdout) or " [format] " in (result.stderr + result.stdout):
                return True
            return False
        except: return False

    def get_cmd(self, behavior, temp_file, output_file):
        cmd = [self.bin_path, "convert-ruleset", behavior]
        if self.needs_format_arg: cmd.append("yaml")
        cmd.append(temp_file)
        cmd.append(output_file)
        return cmd

class RuleSet:
    def __init__(self):
        self.domains = set()
        self.ips = set() # 纯 IP 集合

    def add_domain(self, domain):
        if not domain: return
        d = domain.strip().strip("'").strip('"').strip()
        if d and not d.startswith('#') and len(d) > 3:
            self.domains.add(d)

    def add_ip(self, ip_line):
        if not ip_line: return
        # 移除引号
        clean_line = ip_line.replace("'", "").replace('"', "").strip()
        
        # 兼容 "IP-CIDR, 1.1.1.1" 和 "1.1.1.1,no-resolve"
        parts = re.split(r'[,\s]+', clean_line)
        
        for part in parts:
            part = part.strip()
            # 过滤掉非 IP 字符
            if not part or 'IP-' in part.upper() or 'NO-RESOLVE' in part.upper():
                continue
            
            try:
                # 物理校验：必须是合法 CIDR/IP
                # 这一步会过滤掉所有乱码、空值、非IP字符串
                ipaddress.ip_network(part, strict=False)
                self.ips.add(part)
            except ValueError:
                continue

def get_smart_filename(source_rel_path):
    parts = source_rel_path.split(os.sep)
    base_name = parts[-1]
    if base_name.lower().endswith(('.yaml', '.yml', '.list', '.txt')):
        base_name = os.path.splitext(base_name)[0]
    
    candidate = base_name
    stack = parts[:-1]
    while candidate in filename_registry:
        if filename_registry[candidate] == source_rel_path: return candidate
        if not stack:
            candidate = f"{candidate}_{hashlib.md5(source_rel_path.encode()).hexdigest()[:4]}"
            break
        parent = stack.pop()
        candidate = f"{parent}_{candidate}"
    filename_registry[candidate] = source_rel_path
    return candidate

def should_skip_file(filename):
    name_no_ext = os.path.splitext(filename)[0]
    for kw in IGNORE_KEYWORDS:
        if kw in name_no_ext: return True
    return False

def _process_entry(line, ruleset):
    if not line: return
    if isinstance(line, (list, tuple)):
        for item in line: _process_entry(item, ruleset)
        return
    
    line = str(line).strip()
    if not line or line.startswith('#'): return
    
    if line.startswith("['") or line.startswith('["'):
        line = line.replace('[', '').replace(']', '').replace("'", "").replace('"', "")
    
    upper = line.upper()
    # 粗略分流，具体交给 RuleSet 内部校验
    if 'DOMAIN' in upper or (not 'IP-' in upper and '.' in line and not line[0].isdigit()):
        if ',' in line:
            parts = line.split(',')
            if len(parts) > 1: ruleset.add_domain(parts[1])
        else: ruleset.add_domain(line)
    else:
        ruleset.add_ip(line)

def parse_file(filepath, ruleset):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            if filepath.endswith(('.yaml', '.yml')):
                try:
                    data = yaml.safe_load(f)
                    if data and 'payload' in data: _process_entry(data['payload'], ruleset)
                except: pass
            else:
                for line in f: _process_entry(line, ruleset)
    except: pass

def verify_artifact(filepath):
    # 简单校验：文件生成了且有内容
    if not os.path.exists(filepath): return False
    if os.path.getsize(filepath) == 0: return False
    return True

def convert_to_mrs(kernel, name, rules, behavior):
    if not rules: return
    # 最终清洗：确保列表元素为字符串
    clean_rules = [str(r).strip() for r in rules if r and str(r).strip()]
    if not clean_rules: return

    temp_yaml = f"temp_{name}.yaml"
    output_mrs = os.path.join(TARGET_DIR, f"{name}.mrs")
    os.makedirs(os.path.dirname(output_mrs), exist_ok=True)
    
    try:
        with open(temp_yaml, 'w', encoding='utf-8') as f:
            yaml.dump({'payload': clean_rules}, f)
        
        cmd = kernel.get_cmd(behavior, temp_yaml, output_mrs)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        
        if result.returncode != 0:
            if "unknown field" not in result.stderr:
                logger.error(f"❌ 转换失败 [{name}]: {result.stderr.strip()}")
            if os.path.exists(output_mrs): os.remove(output_mrs)
        else:
            if not verify_artifact(output_mrs):
                if os.path.exists(output_mrs): os.remove(output_mrs)
    except Exception as e:
        logger.error(f"💥 异常 [{name}]: {e}")
        if os.path.exists(output_mrs): os.remove(output_mrs)
    finally:
        if os.path.exists(temp_yaml): os.remove(temp_yaml)

def main():
    # 确保目录存在（无论是否已删除）
    if os.path.exists(TARGET_DIR):
        try: shutil.rmtree(TARGET_DIR)
        except: pass
    os.makedirs(TARGET_DIR, exist_ok=True)
    
    if not os.path.exists(SOURCE_DIR): return

    kernel = KernelIntrospector(MIHOMO_BIN)
    aggregated_rules = defaultdict(RuleSet)
    
    logger.info("🔍 启动...")
    count = 0
    skipped = 0
    for root, dirs, files in os.walk(SOURCE_DIR):
        rel_path = os.path.relpath(root, SOURCE_DIR)
        if rel_path == '.': continue
        current_set = aggregated_rules[rel_path]
        for file in files:
            if not file.lower().endswith(('.yaml', '.yml', '.list', '.txt')): continue
            if should_skip_file(file): 
                skipped += 1
                continue
            parse_file(os.path.join(root, file), current_set)
            count += 1
            if count % 200 == 0: logger.info(f"⏳ 解析: {count} (跳过: {skipped})...")

    logger.info(f"⚡ 解析完成，开始编译 {len(aggregated_rules)} 个规则组...")
    
    compiled = 0
    for rel_path, ruleset in aggregated_rules.items():
        safe_name = get_smart_filename(rel_path)
        
        if ruleset.domains:
            convert_to_mrs(kernel, safe_name, sorted(list(ruleset.domains)), 'domain')
            
        if ruleset.ips:
            # 这里的 sorted_ips 已经是纯 IP 列表，不带 no-resolve
            sorted_ips = sorted(list(ruleset.ips))
            convert_to_mrs(kernel, f"{safe_name}_IP", sorted_ips, 'ipcidr')
        
        compiled += 1
        if compiled % 50 == 0: logger.info(f"🚀 进度: {compiled}/{len(aggregated_rules)}")

    logger.info("🎉 完成")

if __name__ == "__main__":
    main()
