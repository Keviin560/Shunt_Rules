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

# 🛑 变体剔除黑名单：文件名包含这些关键词的文件将被直接忽略
# 我们只保留主文件 (如 Tencent.yaml) 和无解析变体 (Tencent_No_Resolve.yaml)
IGNORE_KEYWORDS = [
    "Classical", 
    "Domain", 
    "For_Clash", 
    "Resolve", # 会误杀 No_Resolve，需特殊处理
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
    """内核内省器：确保指令参数正确"""
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
            if "<format>" in output or " [format] " in output or "format string" in output:
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
        # 预编译正则，提升 2000+ 文件处理速度
        self.ipv4_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$')
        self.ipv6_pattern = re.compile(r'^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}(?:/[0-9]{1,3})?$')

    def add_domain(self, domain):
        if not domain: return
        d = domain.strip().strip("'").strip('"').strip()
        if d and not d.startswith('#') and len(d) > 3: # 简单过滤过短垃圾
            self.domains.add(d)

    def add_ip(self, ip_line):
        if not ip_line: return
        clean_line = ip_line.replace("'", "").replace('"', "").strip()
        
        # 提取逻辑：兼容 "IP-CIDR,1.1.1.1,no-resolve" 和 "1.1.1.1"
        parts = [p.strip() for p in clean_line.split(',') if p.strip()]
        
        target_ip = ""
        has_no_resolve = False
        
        for part in parts:
            # 忽略类型标识
            if part.upper().startswith('IP-'): continue
            # 标记属性
            if part.lower() == 'no-resolve': 
                has_no_resolve = True
                continue
            # 找到 IP 候选者 (假设最长的那段是 IP，或者匹配正则)
            if self._is_valid_ip(part):
                target_ip = part

        if target_ip:
            # 状态机：保留 no-resolve
            if not self.ips[target_ip]:
                self.ips[target_ip] = has_no_resolve
            elif has_no_resolve:
                self.ips[target_ip] = True

    def _is_valid_ip(self, text):
        # 正则门卫：只放行真正的 IP，拒绝一切空值、空格、乱码
        return self.ipv4_pattern.match(text) or self.ipv6_pattern.match(text)

def get_smart_filename(source_rel_path):
    parts = source_rel_path.split(os.sep)
    base_name = parts[-1]
    
    # 变体文件命名优化：如果是 Tencent_No_Resolve，保持原名
    # 如果是 Game/Roblox/Roblox.yaml，扁平化为 Game_Roblox.mrs
    
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
    """
    [变体剔除器]
    减少冗余文件的核心逻辑
    """
    name_no_ext = os.path.splitext(filename)[0]
    
    # 特殊放行：No_Resolve 是重要的 DNS 变体
    if "No_Resolve" in name_no_ext:
        return False
        
    # 拒绝列表中的关键词
    for kw in IGNORE_KEYWORDS:
        if kw in name_no_ext:
            return True
    
    return False

def parse_file(filepath, ruleset):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            # YAML 模式
            if filepath.endswith(('.yaml', '.yml')):
                try:
                    data = yaml.safe_load(f)
                    if data and 'payload' in data and isinstance(data['payload'], list):
                        for line in data['payload']: 
                            process_entry(str(line), ruleset)
                except: pass
            # 文本模式
            else:
                for line in f: 
                    process_entry(line, ruleset)
    except Exception as e:
        pass

def process_entry(line, ruleset):
    """通用入口清洗"""
    line = line.strip()
    if not line or line.startswith('#'): return
    
    # 修复列表字符串
    if line.startswith("['"):
        line = line.replace('[', '').replace(']', '').replace("'", "")
    
    # 简单判定类型，具体解析交给 RuleSet 的正则
    upper = line.upper()
    if 'DOMAIN' in upper or (not 'IP-' in upper and '.' in line and not line[0].isdigit()):
        # 可能是域名
        parts = line.split(',')
        if len(parts) > 1: ruleset.add_domain(parts[1])
        else: ruleset.add_domain(line)
    else:
        # 可能是 IP
        ruleset.add_ip(line)

def convert_to_mrs(kernel, name, rules, behavior):
    if not rules: return
    
    # [真空清洗] 确保绝无空值
    clean_rules = [str(r).strip() for r in rules if r and str(r).strip()]
    if not clean_rules: 
        # logger.warning(f"⚠️ [跳过] 规则集为空或无效: {name}") 
        return

    temp_yaml = f"temp_{name}.yaml"
    output_mrs = os.path.join(TARGET_DIR, f"{name}.mrs")
    os.makedirs(os.path.dirname(output_mrs), exist_ok=True)
    
    try:
        with open(temp_yaml, 'w', encoding='utf-8') as f:
            yaml.dump({'payload': clean_rules}, f)
        
        cmd = kernel.get_cmd(behavior, temp_yaml, output_mrs)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            # 仅记录非致命错误外的错误
            if "unknown field" not in result.stderr:
                logger.error(f"❌ 转换崩溃 [{name}]: {result.stderr.strip()}")
            # 失败后必须清理垃圾
            if os.path.exists(output_mrs): os.remove(output_mrs)
        else:
            # 简单校验大小 > 0 即视为成功 (配合前面的正则清洗，这足够安全)
            if os.path.exists(output_mrs) and os.path.getsize(output_mrs) > 0:
                pass
            else:
                if os.path.exists(output_mrs): os.remove(output_mrs)

    except Exception:
        if os.path.exists(output_mrs): os.remove(output_mrs)
    finally:
        if os.path.exists(temp_yaml): os.remove(temp_yaml)

def main():
    if os.path.exists(TARGET_DIR):
        try: shutil.rmtree(TARGET_DIR)
        except: pass
    os.makedirs(TARGET_DIR, exist_ok=True)
    
    if not os.path.exists(SOURCE_DIR): return

    kernel = KernelIntrospector(MIHOMO_BIN)
    aggregated_rules = defaultdict(RuleSet)
    
    logger.info("🔍 启动智能扫描 (已启用变体剔除)...")
    
    file_count = 0
    skipped_count = 0
    
    for root, dirs, files in os.walk(SOURCE_DIR):
        rel_path = os.path.relpath(root, SOURCE_DIR)
        if rel_path == '.': continue
        
        current_set = aggregated_rules[rel_path]
        
        for file in files:
            # 1. 扩展名过滤
            if not file.lower().endswith(('.yaml', '.yml', '.list', '.txt')):
                continue
                
            # 2. [关键] 变体剔除逻辑
            if should_skip_file(file):
                skipped_count += 1
                continue
                
            parse_file(os.path.join(root, file), current_set)
            file_count += 1
            if file_count % 200 == 0:
                logger.info(f"⏳ 解析进度: {file_count} (已忽略冗余: {skipped_count})...")

    logger.info(f"✅ 解析完毕! 有效文件: {file_count}, 忽略冗余: {skipped_count}, 生成规则组: {len(aggregated_rules)}")
    logger.info("⚡ 开始编译...")
    
    compiled = 0
    for rel_path, ruleset in aggregated_rules.items():
        safe_name = get_smart_filename(rel_path)
        
        # 域名
        if ruleset.domains:
            convert_to_mrs(kernel, safe_name, sorted(list(ruleset.domains)), 'domain')
            
        # IP (排序确保 no-resolve 在前)
        if ruleset.ips:
            sorted_ips = sorted(ruleset.ips.items(), key=lambda x: x[1], reverse=True)
            payload = [f"{ip},no-resolve" if no_res else ip for ip, no_res in sorted_ips]
            convert_to_mrs(kernel, f"{safe_name}_IP", payload, 'ipcidr')
        
        compiled += 1
        if compiled % 50 == 0:
            logger.info(f"🚀 编译进度: {compiled}/{len(aggregated_rules)}")

    logger.info("🎉 任务完成")

if __name__ == "__main__":
    main()
