import os
import yaml
import hashlib
import subprocess
import logging
import shutil
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
    """内核内省器：动态探测参数格式"""
    def __init__(self, bin_path):
        self.bin_path = bin_path
        if not os.path.exists(bin_path):
            raise FileNotFoundError(f"内核文件不存在: {bin_path}")
        self.needs_format_arg = self._detect_capability()

    def _detect_capability(self):
        try:
            result = subprocess.run(
                [self.bin_path, "convert-ruleset"], 
                capture_output=True, text=True, timeout=5
            )
            output = result.stderr + result.stdout
            if "<format>" in output or " [format] " in output:
                logger.info("🤖 [内核探测] 检测到新版签名：启用 format 参数")
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
        # 深度清洗：移除引号、不可见字符
        d = domain.strip().strip("'").strip('"').strip()
        if d and not d.startswith('#'):
            self.domains.add(d)

    def add_ip(self, ip_line):
        if not ip_line: return
        # 移除引号
        clean = ip_line.replace("'", "").replace('"', "").strip()
        
        # 移除 IP-CIDR, IP-CIDR6, IP-ASN 等前缀
        # 很多 Panic 是因为前缀没删干净，例如 "IP-CIDR,1.1.1.1" 传给内核
        if clean.upper().startswith('IP-'):
            parts = clean.split(',')
            if len(parts) > 1:
                clean = parts[1].strip() # 取出真正的 IP 部分
            else:
                return # 格式错误，丢弃

        # 分割 no-resolve (如果有)
        parts = [p.strip() for p in clean.split(',') if p.strip()]
        if not parts: return
        
        ip = parts[0]
        # 校验 CIDR 格式
        if not self._is_valid_cidr(ip): return

        has_no_resolve = 'no-resolve' in ip_line # 检查原始行最稳妥
        
        # 状态机更新
        if not self.ips[ip]: 
            self.ips[ip] = has_no_resolve

    def _is_valid_cidr(self, text):
        if not text or len(text) < 7: return False # 0.0.0.0 最短7位
        # 允许字符：数字、点、冒号、斜杠
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

def _process_entry(line, ruleset):
    if not line: return
    if isinstance(line, (list, tuple)):
        for item in line: _process_entry(item, ruleset)
        return
    
    line = str(line).strip()
    if not line or line.startswith('#'): return
    
    # 修复 ['...'] 畸形字符串
    if line.startswith("['") or line.startswith('["'):
        line = line.replace('[', '').replace(']', '').replace("'", "").replace('"', "")
    
    # 无论逗号还是空格，都视为分隔符
    parts = line.split(',') if ',' in line else line.split()
    parts = [p.strip() for p in parts if p.strip()]
    
    if not parts: return
    type_upper = parts[0].upper()
    
    if type_upper.startswith('DOMAIN'):
        if len(parts) >= 2: ruleset.add_domain(parts[1])
        elif len(parts) == 1 and '.' in parts[0]: ruleset.add_domain(parts[0])
    
    elif type_upper.startswith('IP-') or ruleset._is_valid_cidr(parts[0]):
        # 把整行扔给 add_ip，让它去处理前缀剥离
        ruleset.add_ip(line)

def parse_file(filepath, ruleset):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            if filepath.endswith(('.yaml', '.yml')):
                try:
                    data = yaml.safe_load(f)
                    if data and 'payload' in data:
                        _process_entry(data['payload'], ruleset)
                except: pass
            else:
                for line in f: _process_entry(line, ruleset)
    except: pass

def verify_artifact(filepath):
    """
    🛡️ [回旋镖校验仪]
    不依赖文件大小，而是让 Mihomo 尝试读取该文件。
    如果文件损坏或格式错误，内核会报错。
    """
    if not os.path.exists(filepath): return False
    
    # 只要文件存在且大于 0 字节，我们先假设它有内容
    # 真正的校验是逻辑校验。但在构建脚本中，我们至少保证它不是 0 字节。
    # 0 字节通常意味着 panic 导致的写入中断。
    if os.path.getsize(filepath) == 0:
        logger.error(f"🗑️ 拦截 0 字节僵尸文件: {os.path.basename(filepath)}")
        return False
        
    return True

def convert_to_mrs(kernel, name, rules, behavior):
    # ⚠️ [真空级清洗]：最后一道防线
    # 1. 转字符串 2. 去首尾空格 3. 过滤空串 4. 过滤 'None' 字符串
    clean_rules = []
    for r in rules:
        s = str(r).strip()
        if s and s.lower() != 'none':
            clean_rules.append(s)
            
    if not clean_rules: return # 如果洗完没剩东西，直接不生成
    
    temp_yaml = f"temp_{name}.yaml"
    output_mrs = os.path.join(TARGET_DIR, f"{name}.mrs")
    os.makedirs(os.path.dirname(output_mrs), exist_ok=True)
    
    try:
        # 写入临时文件
        with open(temp_yaml, 'w', encoding='utf-8') as f:
            # 纯 payload，不带任何其他 meta 信息，防止干扰
            yaml.dump({'payload': clean_rules}, f)
        
        cmd = kernel.get_cmd(behavior, temp_yaml, output_mrs)
        
        # 执行转换
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        
        if result.returncode != 0:
            # 只有当错误不是 unknown field 时才报错
            if "unknown field" not in result.stderr:
                logger.error(f"❌ 转换崩溃 [{name}]: {result.stderr.strip()}")
            # 崩溃时，必须删除可能残留的 0 字节文件
            if os.path.exists(output_mrs): os.remove(output_mrs)
        else:
            # ✅ 成功后的质检
            if not verify_artifact(output_mrs):
                if os.path.exists(output_mrs): os.remove(output_mrs)

    except Exception as e:
        logger.error(f"💥 异常 [{name}]: {e}")
        if os.path.exists(output_mrs): os.remove(output_mrs)
    finally:
        if os.path.exists(temp_yaml): os.remove(temp_yaml)

def main():
    # 1. 环境准备
    if os.path.exists(TARGET_DIR):
        try: shutil.rmtree(TARGET_DIR)
        except: pass
    os.makedirs(TARGET_DIR, exist_ok=True)
    
    if not os.path.exists(SOURCE_DIR):
        logger.error("源目录不存在")
        return

    # 2. 内核准备
    kernel = KernelIntrospector(MIHOMO_BIN)
    
    # 3. 聚合
    aggregated_rules = defaultdict(RuleSet)
    logger.info("🔍 启动扫描...")
    
    count = 0
    for root, dirs, files in os.walk(SOURCE_DIR):
        rel_path = os.path.relpath(root, SOURCE_DIR)
        if rel_path == '.': continue
        current_set = aggregated_rules[rel_path]
        for file in files:
            if file.lower().endswith(('.yaml', '.yml', '.list', '.txt')):
                parse_file(os.path.join(root, file), current_set)
                count += 1
                if count % 500 == 0: logger.info(f"⏳ 解析中: {count}...")

    logger.info(f"✅ 解析完毕，生成 {len(aggregated_rules)} 个规则集。")
    
    # 4. 编译
    compiled = 0
    for rel_path, ruleset in aggregated_rules.items():
        safe_name = get_smart_filename(rel_path)
        
        if ruleset.domains:
            convert_to_mrs(kernel, safe_name, sorted(list(ruleset.domains)), 'domain')
            
        if ruleset.ips:
            # 排序：no-resolve 优先
            sorted_ips = sorted(ruleset.ips.items(), key=lambda x: x[1], reverse=True)
            # 构建 payload
            payload = []
            for ip, no_res in sorted_ips:
                # 再次清洗 IP，防止带入 weird 字符
                clean_ip = ip.strip()
                if clean_ip:
                    entry = f"{clean_ip},no-resolve" if no_res else clean_ip
                    payload.append(entry)
            
            convert_to_mrs(kernel, f"{safe_name}_IP", payload, 'ipcidr')
        
        compiled += 1
        if compiled % 100 == 0: logger.info(f"🚀 编译进度: {compiled}/{len(aggregated_rules)}")

    logger.info("🎉 任务完成")

if __name__ == "__main__":
    main()
