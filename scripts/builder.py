import os
import yaml
import hashlib
import subprocess
import logging
import shutil
import re
import ipaddress  # 核心组件：用于物理校验 IP 格式
from collections import defaultdict

# --- 全局配置 ---
SOURCE_DIR = "temp_source/rule/Clash"
TARGET_DIR = "rule/Mihomo"
MIHOMO_BIN = "./mihomo"

# 🛑 变体剔除黑名单
# 包含这些关键词的文件将被直接忽略，只处理主文件 (如 Tencent.yaml)
# 这能将处理文件数从 2000+ 降低到 500+，且规则一条不少
IGNORE_KEYWORDS = [
    "Classical", 
    "Domain", 
    "For_Clash", 
    "No_Resolve", # 主文件通常包含 IP，且我们要剥离 no-resolve，所以此变体是冗余的
    "Clash"
]

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
                logger.info("🤖 [内核探测] 新版签名: 启用 yaml 参数")
                return True
            logger.info("🤖 [内核探测] 旧版签名: 禁用 yaml 参数")
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
        self.ips = set() # 纯 IP 集合，不再存储 no-resolve 状态

    def add_domain(self, domain):
        if not domain: return
        d = domain.strip().strip("'").strip('"').strip()
        # 简单过滤：过短的域名、注释
        if d and not d.startswith('#') and len(d) > 3:
            self.domains.add(d)

    def add_ip(self, ip_line):
        """
        [核心防御逻辑]
        使用 ipaddress 库进行校验。如果字符串不能被解析为 IP 网络，直接丢弃。
        这彻底解决了 "panic: empty rule" 问题。
        """
        if not ip_line: return
        
        # 1. 预清洗：去除引号
        clean_line = ip_line.replace("'", "").replace('"', "").strip()
        
        # 2. 分割：按逗号或空格分割
        # 例如: "IP-CIDR, 1.1.1.1/32, no-resolve" -> ["IP-CIDR", "1.1.1.1/32", "no-resolve"]
        parts = re.split(r'[,\s]+', clean_line)
        
        for part in parts:
            part = part.strip()
            if not part: continue
            
            # 3. 物理校验：尝试解析
            try:
                # 尝试解析为 IPv4 或 IPv6 网络对象
                # strict=False 允许主机位不为0的情况 (如 1.1.1.1/24)
                ip_net = ipaddress.ip_network(part, strict=False)
                
                # 4. 只有解析成功才存入。
                # 此时 part 绝对是一个合法的 IP 字符串，没有空格，没有 no-resolve
                self.ips.add(str(ip_net))
                
                # 找到一个有效的 IP 后通常不需要继续找同一行的其他部分（除非一行多个IP，罕见）
                # 这里我们假设一行只有一个有效 CIDR
            except ValueError:
                # 解析失败（说明是 IP-CIDR 标签、no-resolve 标记、或者乱码），直接忽略
                continue

def get_smart_filename(source_rel_path):
    parts = source_rel_path.split(os.sep)
    base_name = parts[-1]
    
    # 移除扩展名
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
    """变体剔除器：减少 80% 的无效扫描"""
    name_no_ext = os.path.splitext(filename)[0]
    for kw in IGNORE_KEYWORDS:
        if kw in name_no_ext:
            return True
    return False

def _process_entry(line, ruleset):
    if not line: return
    if isinstance(line, (list, tuple)):
        for item in line: _process_entry(item, ruleset)
        return
    
    line = str(line).strip()
    if not line or line.startswith('#'): return
    
    # 修复畸形列表字符串 "['DOMAIN', ...]"
    if line.startswith("['") or line.startswith('["'):
        line = line.replace('[', '').replace(']', '').replace("'", "").replace('"', "")

    # 简单特征路由
    upper = line.upper()
    # 如果包含 IP-CIDR, IP-ASN, 或者直接以数字开头 (可能是纯IP列表)
    if 'IP-' in upper or (line[0].isdigit() and ('/' in line or '.' in line or ':' in line)):
        ruleset.add_ip(line)
    # 否则默认为域名 (含 DOMAIN-, 或纯域名)
    else:
        # 清洗 DOMAIN, 前缀
        if ',' in line:
            parts = line.split(',')
            # 取最后一个可能是域名的部分
            if len(parts) > 1: ruleset.add_domain(parts[1])
        else:
            ruleset.add_domain(line)

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
    🛡️ 回旋镖校验：生成的文件如果不能被内核读取，就是垃圾。
    这里只检查文件是否存在且有内容。
    """
    if not os.path.exists(filepath): return False
    if os.path.getsize(filepath) == 0:
        logger.warning(f"🗑️ 删除空文件: {os.path.basename(filepath)}")
        return False
    return True

def convert_to_mrs(kernel, name, rules, behavior):
    if not rules: return
    
    # 最终列表，无需再次清洗，因为 add_ip/add_domain 已经保证了纯净
    payload_list = list(rules)
    
    temp_yaml = f"temp_{name}.yaml"
    output_mrs = os.path.join(TARGET_DIR, f"{name}.mrs")
    os.makedirs(os.path.dirname(output_mrs), exist_ok=True)
    
    try:
        with open(temp_yaml, 'w', encoding='utf-8') as f:
            yaml.dump({'payload': payload_list}, f)
        
        cmd = kernel.get_cmd(behavior, temp_yaml, output_mrs)
        
        # 转换
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        
        if result.returncode != 0:
            if "unknown field" not in result.stderr:
                logger.error(f"❌ 转换失败 [{name}]: {result.stderr.strip()}")
            if os.path.exists(output_mrs): os.remove(output_mrs)
        else:
            # 校验
            if not verify_artifact(output_mrs):
                if os.path.exists(output_mrs): os.remove(output_mrs)

    except Exception as e:
        logger.error(f"💥 异常 [{name}]: {e}")
        if os.path.exists(output_mrs): os.remove(output_mrs)
    finally:
        if os.path.exists(temp_yaml): os.remove(temp_yaml)

def main():
    if os.path.exists(TARGET_DIR):
        try: shutil.rmtree(TARGET_DIR)
        except: pass
    os.makedirs(TARGET_DIR, exist_ok=True)
    
    if not os.path.exists(SOURCE_DIR):
        logger.error("源目录不存在")
        return

    kernel = KernelIntrospector(MIHOMO_BIN)
    aggregated_rules = defaultdict(RuleSet)
    
    logger.info("🔍 启动智能去重扫描...")
    
    file_count = 0
    skipped_count = 0
    
    for root, dirs, files in os.walk(SOURCE_DIR):
        rel_path = os.path.relpath(root, SOURCE_DIR)
        if rel_path == '.': continue
        
        current_set = aggregated_rules[rel_path]
        for file in files:
            if not file.lower().endswith(('.yaml', '.yml', '.list', '.txt')): continue
            
            # [关键] 变体剔除
            if should_skip_file(file):
                skipped_count += 1
                continue
                
            parse_file(os.path.join(root, file), current_set)
            file_count += 1
            if file_count % 100 == 0: logger.info(f"⏳ 解析中: {file_count} (跳过冗余: {skipped_count})...")

    logger.info(f"✅ 解析完毕。有效文件: {file_count}, 忽略冗余: {skipped_count}, 生成规则组: {len(aggregated_rules)}")
    
    # 编译
    compiled = 0
    total = len(aggregated_rules)
    
    for rel_path, ruleset in aggregated_rules.items():
        safe_name = get_smart_filename(rel_path)
        
        # 1. 生成域名规则
        if ruleset.domains:
            convert_to_mrs(kernel, safe_name, sorted(list(ruleset.domains)), 'domain')
