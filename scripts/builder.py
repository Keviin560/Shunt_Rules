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

IGNORE_KEYWORDS = ["Classical", "Domain", "For_Clash", "No_Resolve", "Clash"]

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DigitalArchitect")

filename_registry = {}

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
        self.domains = set()
        self.ips = set()

    def add_domain(self, d):
        if not d: return
        d = d.strip().strip("'").strip('"').strip()
        if d and not d.startswith('#') and len(d) > 3: self.domains.add(d)

    def add_ip(self, line):
        if not line: return
        line = line.replace("'", "").replace('"', "").strip()
        parts = re.split(r'[,\s]+', line)
        for p in parts:
            p = p.strip()
            if not p or 'IP-' in p.upper() or 'NO-RESOLVE' in p.upper(): continue
            try:
                ipaddress.ip_network(p, strict=False)
                self.ips.add(p)
            except ValueError: continue

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
        if ',' in line:
            parts = line.split(',')
            if len(parts)>1: ruleset.add_domain(parts[1])
        else: ruleset.add_domain(line)
    else: ruleset.add_ip(line)

def convert(kernel, name, rules, behavior):
    if not rules: return
    
    # 🔥 终极正则清洗：只允许合法字符，防止 Panic
    # IP 模式：只留数字、点、冒号、斜杠
    if behavior == 'ipcidr':
        final_rules = [r for r in rules if re.match(r'^[\d\.:/]+$', r)]
    else:
        final_rules = [r for r in rules if r.strip()]
        
    if not final_rules: return

    tmp = f"temp_{name}.yaml"
    dst = os.path.join(TARGET_DIR, f"{name}.mrs")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            yaml.dump({'payload': final_rules}, f)
        
        res = subprocess.run(kernel.get_cmd(behavior, tmp, dst), capture_output=True, text=True, timeout=20)
        
        if res.returncode != 0:
            if "unknown field" not in res.stderr:
                logger.error(f"❌ 转换失败 [{name}]: {res.stderr.strip()}")
            if os.path.exists(dst): os.remove(dst)
        elif os.path.exists(dst) and os.path.getsize(dst) == 0:
            os.remove(dst)
            
    except Exception as e:
        logger.error(f"💥 异常 [{name}]: {e}")
        if os.path.exists(dst): os.remove(dst)
    finally:
        if os.path.exists(tmp): os.remove(tmp)

def main():
    if os.path.exists(TARGET_DIR):
        try: shutil.rmtree(TARGET_DIR)
        except: pass
    os.makedirs(TARGET_DIR, exist_ok=True)
    
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
        if rs.domains: convert(kernel, name, sorted(list(rs.domains)), 'domain')
        if rs.ips: convert(kernel, f"{name}_IP", sorted(list(rs.ips)), 'ipcidr')
        
        done += 1
        if done % 50 == 0: logger.info(f"🚀 编译: {done}/{len(aggregated)}")

    logger.info("🎉 完成")

if __name__ == "__main__":
    main()
