import os
import yaml
import hashlib
import subprocess
import logging
import re
from collections import defaultdict

# --- 全局配置 ---
SOURCE_DIR = "temp_source/rule/Clash"
TARGET_DIR = "rule/Mihomo"
MIHOMO_BIN = "./mihomo"

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DigitalArchitect")

filename_registry = {}

class KernelIntrospector:
    """内核内省器：探测参数格式"""
    def __init__(self, bin_path):
        self.bin_path = bin_path
        if not os.path.exists(bin_path):
            raise FileNotFoundError(f"内核文件不存在: {bin_path}")
        self.needs_format_arg = self._detect_capability()

    def _detect_capability(self):
        try:
            result = subprocess.run([self.bin_path, "convert-ruleset"], capture_output=True, text=True, timeout=5)
            output = result.stderr + result.stdout
            if "<format>" in output or " [format] " in output:
                return True
            return False
        except:
            return False

    def get_cmd(self, behavior, temp_file, output_file):
        cmd = [self.bin_path, "convert-ruleset", behavior]
        if self.needs_format_arg:
            cmd.append("yaml")
        cmd.append(temp_file)
        cmd.append(output_file)
        return cmd

class RuleSet:
    def __init__(self):
        self.domains = set()
        self.ips = defaultdict(bool) 

    def add_domain(self, domain):
        if not domain: return
        # 🧪 无菌清洗：移除引号、空白、不可见字符
        d = domain.strip().strip("'").strip('"').strip()
        if d and not d.startswith('#'):
            self.domains.add(d)

    def add_ip(self, ip_line):
        if not ip_line: return
        # 🧪 无菌清洗：移除引号
        clean_line = ip_line.replace("'", "").replace('"', "").strip()
        parts = [p.strip() for p in clean_line.split(',')]
        if not parts: return
        
        ip = parts[0]
        if not self._is_valid_cidr(ip): return

        has_no_resolve = 'no-resolve' in parts
        if not self.ips[ip]: 
            self.ips[ip] = has_no_resolve

    def _is_valid_cidr(self, text):
        if not isinstance(text, str): return False
        if not text or not any(char.isdigit() for char in text): return False
        # 严格白名单
        allowed = set("0123456789./:abcdefABCDEF")
        return all(c in allowed for c in text)

def get_smart_filename(source_rel_path):
    parts = source_rel_path.split(os.sep)
    base_name = parts[-1]
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

def parse_file(filepath, ruleset):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            if filepath.endswith(('.yaml', '.yml')):
                try:
                    data = yaml.safe_load(f)
                    if data and 'payload' in data and isinstance(data['payload'], list):
                        for line in data['payload']: _process_entry(line, ruleset)
                except: pass
            else:
                for line in f: _process_entry(line, ruleset)
    except Exception as e:
        logger.error(f"❌ 读取错误 {filepath}: {e}")

def _process_entry(line, ruleset):
    """统一入口处理，递归解包"""
    if not line: return
    if isinstance(line, (list, tuple)):
        for item in line: _process_entry(item, ruleset)
        return
    
    line = str(line).strip()
    if not line or line.startswith('#'): return
    
    # 处理 ['IP-CIDR', '...'] 这种畸形字符串
    if line.startswith("['") or line.startswith('["'):
        line = line.replace('[', '').replace(']', '').replace("'", "").replace('"', "")
    
    parts = line.split(',') if ',' in line else line.split()
    parts = [p.strip() for p in parts if p.strip()]
    
    if not parts: return

    type_upper = parts[0].upper()
    if type_upper.startswith('DOMAIN'):
        if len(parts) >= 2: ruleset.add_domain(parts[1])
        elif len(parts) == 1 and '.' in parts[0]: ruleset.add_domain(parts[0])
    elif type_upper.startswith('IP-') or ruleset._is_valid_cidr(parts[0]):
        if type_upper.startswith('IP-') and len(parts) >= 2:
            ip = parts[1]
            extra = parts[2:]
        else:
            ip = parts[0]
            extra = parts[1:]
        
        full = ip
        if 'no-resolve' in extra or 'no-resolve' in line: full += ",no-resolve"
        ruleset.add_ip(full)

def verify_mrs(filepath, behavior):
    """
    🛡️ [质检仪] 校验生成的 MRS 文件是否合法
    """
    if not os.path.exists(filepath):
        return False
    
    # 1. 检查大小：MRS 有头部信息，如果是 0 字节或极小，说明生成失败
    size = os.path.getsize(filepath)
    if size < 20: # 经验值，MRS 头部至少有 Magic Bytes
        logger.error(f"🗑️ 校验失败: 文件过小 ({size} bytes) -> {filepath}")
        return False
        
    return True

def convert_to_mrs(kernel, name, rules, behavior):
    if not rules: return
    
    temp_yaml = f"temp_{name}.yaml"
    output_mrs = os.path.join(TARGET_DIR, f"{name}.mrs")
    os.makedirs(os.path.dirname(output_mrs), exist_ok=True)
    
    # 再次清洗：确保没有空字符串进入列表
    clean_rules = [r for r in rules if r and r.strip()]
    if not clean_rules: return

    try:
        with open(temp_yaml, 'w', encoding='utf-8') as f:
            yaml.dump({'payload': clean_rules}, f)
        
        cmd = kernel.get_cmd(behavior, temp_yaml, output_mrs)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        
        if result.returncode != 0:
            # 严重错误，删除可能产生的半成品
            if os.path.exists(output_mrs): os.remove(output_mrs)
            if "unknown field" not in result.stderr:
                logger.error(f"❌ 转换崩溃 [{name}]: {result.stderr.strip()}")
        else:
            # ✅ 转换后立即质检
            if not verify_mrs(output_mrs, behavior):
                if os.path.exists(output_mrs): os.remove(output_mrs)
            
    except Exception as e:
        logger.error(f"💥 异常 [{name}]: {e}")
        if os.path.exists(output_mrs): os.remove(output_mrs)
    finally:
        if os.path.exists(temp_yaml): os.remove(temp_yaml)

def main():
    if os.path.exists(TARGET_DIR): shutil.rmtree(TARGET_DIR) # 先清空旧的，确保全是新的
    os.makedirs(TARGET_DIR)
    
    kernel = KernelIntrospector(MIHOMO_BIN)
    aggregated_rules = defaultdict(RuleSet)
    
    logger.info("🔍 启动...")
    file_count = 0
    for root, dirs, files in os.walk(SOURCE_DIR):
        rel_path = os.path.relpath(root, SOURCE_DIR)
        if rel_path == '.': continue
        current_set = aggregated_rules[rel_path]
        for file in files:
            if file.lower().endswith(('.yaml', '.yml', '.list', '.txt')):
                parse_file(os.path.join(root, file), current_set)
                file_count += 1
                if file_count % 500 == 0: logger.info(f"⏳ 已解析 {file_count}...")

    logger.info(f"⚡ 开始编译 {len(aggregated_rules)} 个规则集...")
    
    compile_count = 0
    for rel_path, ruleset in aggregated_rules.items():
        safe_name = get_smart_filename(rel_path)
        
        if ruleset.domains:
            convert_to_mrs(kernel, safe_name, sorted(list(ruleset.domains)), 'domain')
            
        if ruleset.ips:
            sorted_ips = sorted(ruleset.ips.items(), key=lambda x: (not x[1], x[0]))
            # 关键修正：不要在这里手动加引号，让 clean_rules 处理
            payload = [f"{ip},no-resolve" if no_res else ip for ip, no_res in sorted_ips]
            convert_to_mrs(kernel, f"{safe_name}_IP", payload, 'ipcidr')
        
        compile_count += 1
        if compile_count % 100 == 0: logger.info(f"🚀 进度: {compile_count}/{len(aggregated_rules)}")

    logger.info("🎉 完成")

if __name__ == "__main__":
    main()
