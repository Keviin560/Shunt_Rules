import os
import yaml
import hashlib
import subprocess
import logging
from collections import defaultdict

# --- 配置区域 ---
# 源仓库下载位置
SOURCE_DIR = "temp_source/rule/Clash"
# 结果输出位置
TARGET_DIR = "rule/Mihomo"
# Mihomo 内核路径 (CI环境会自动下载到当前目录)
MIHOMO_BIN = "./mihomo"

# 日志配置
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 扁平化命名注册表 (防止文件名冲突)
filename_registry = {}

class RuleSet:
    def __init__(self):
        self.domains = set()
        # IP 存储结构: {'1.1.1.1/32': True} (True 表示 no-resolve)
        self.ips = defaultdict(bool) 

    def add_domain(self, domain):
        d = domain.strip()
        if d and not d.startswith('#'):
            self.domains.add(d)

    def add_ip(self, ip_line):
        # 识别并处理 IP 行
        parts = [p.strip() for p in ip_line.split(',')]
        if not parts: return
        
        ip = parts[0]
        # 只要源文件中包含 no-resolve，就标记为 True
        has_no_resolve = 'no-resolve' in parts
        
        # 逻辑或运算：如果已经标记为 no-resolve，则保持；否则更新
        if self.ips[ip]: 
            pass 
        else:
            self.ips[ip] = has_no_resolve

def get_smart_filename(source_rel_path):
    """
    智能计算文件名：将 rule/Clash/Game/Roblox 转换为 Game_Roblox.mrs
    如果 Roblox.mrs 未被占用，则直接使用 Roblox.mrs
    """
    parts = source_rel_path.split(os.sep)
    base_name = parts[-1]
    
    candidate = base_name
    stack = parts[:-1]
    
    # 冲突检测与回溯命名
    while candidate in filename_registry:
        if filename_registry[candidate] == source_rel_path:
            return candidate
        
        if not stack:
            # 极罕见情况：哈希后缀兜底
            candidate = f"{candidate}_{hashlib.md5(source_rel_path.encode()).hexdigest()[:4]}"
            break
            
        parent = stack.pop()
        candidate = f"{parent}_{candidate}"
    
    filename_registry[candidate] = source_rel_path
    return candidate

def parse_file(filepath, ruleset):
    """多态解析器：同时支持 YAML 和 List/Txt"""
    ext = filepath.split('.')[-1].lower()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            if ext in ['yaml', 'yml']:
                data = yaml.safe_load(f)
                if data and 'payload' in data:
                    for line in data['payload']:
                        process_line(str(line), ruleset)
            else:
                for line in f:
                    process_line(line, ruleset)
    except Exception as e:
        logger.warning(f"解析跳过 {filepath}: {e}")

def process_line(line, ruleset):
    """单行规则清洗与分流"""
    line = line.strip()
    if not line or line.startswith('#'): return

    # 清洗：去除可能存在的 'DOMAIN-SUFFIX,' 前缀，Mihomo domain 仅需域名
    if line.startswith('DOMAIN'):
        parts = line.split(',')
        if len(parts) >= 2:
            ruleset.add_domain(parts[1])
        elif ',' not in line: # 纯域名情况
            ruleset.add_domain(line)
            
    # 清洗：提取 IP
    elif line.startswith('IP-CIDR') or line.startswith('IP-ASN') or line.startswith('IP-'):
        parts = line.split(',')
        if len(parts) >= 2:
            clean_ip = parts[1]
            if 'no-resolve' in line:
                clean_ip += ",no-resolve"
            ruleset.add_ip(clean_ip)
    
    # 纯文本 IP 处理 (假设不带前缀)
    elif replace_cidr(line): 
         ruleset.add_ip(line)

def replace_cidr(text):
    # 简单的 IP 格式检查
    return '/' in text and text.replace('.', '').replace('/', '').isdigit()

def convert_to_mrs(name, rules, behavior):
    if not rules: return
    
    # 创建临时 YAML 喂给 Mihomo
    temp_yaml = f"temp_{name}.yaml"
    output_mrs = os.path.join(TARGET_DIR, f"{name}.mrs")
    
    with open(temp_yaml, 'w', encoding='utf-8') as f:
        yaml.dump({'payload': rules}, f)
        
    try:
        # 调用内核转换
        cmd = [MIHOMO_BIN, "convert-ruleset", behavior, temp_yaml, output_mrs]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        logger.info(f"✅ 生成: {name}.mrs ({behavior}) - {len(rules)}条")
    except subprocess.CalledProcessError as e:
        # 容错：不中断主流程，只记录错误
        logger.error(f"❌ 转换失败 {name}: {e.stderr.decode().strip()}")
    finally:
        if os.path.exists(temp_yaml):
            os.remove(temp_yaml)

def main():
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)

    # 1. 聚合阶段
    aggregated_rules = defaultdict(RuleSet)
    
    # 遍历 source_dir
    for root, dirs, files in os.walk(SOURCE_DIR):
        rel_path = os.path.relpath(root, SOURCE_DIR)
        if rel_path == '.': continue
        
        # 只要是同一个文件夹下的，都视为同一个规则集
        current_set = aggregated_rules[rel_path]
        
        for file in files:
            if file.lower().endswith(('.yaml', '.yml', '.list', '.txt')):
                parse_file(os.path.join(root, file), current_set)

    # 2. 转换阶段
    logger.info("⚡ 开始转换与编译...")
    
    for rel_path, ruleset in aggregated_rules.items():
        safe_name = get_smart_filename(rel_path)
        
        # 分流 1: 生成纯域名规则 (Tencent.mrs)
        if ruleset.domains:
            convert_to_mrs(safe_name, sorted(list(ruleset.domains)), 'domain')
            
        # 分流 2: 生成纯 IP 规则 (Tencent_IP.mrs)
        if ruleset.ips:
            # 核心排序逻辑：no-resolve (True) 排在前面 (False)
            # not True = False(0), not False = True(1). 0 < 1. 故 no-resolve 优先。
            sorted_ips = sorted(ruleset.ips.items(), key=lambda x: (not x[1], x[0]))
            
            payload = []
            for ip, no_res in sorted_ips:
                payload.append(f"{ip},no-resolve" if no_res else ip)
            
            convert_to_mrs(f"{safe_name}_IP", payload, 'ipcidr')

if __name__ == "__main__":
    main()
