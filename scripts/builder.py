import os
import yaml
import hashlib
import subprocess
import logging
import shutil  # ✅ 已修复：添加缺失的依赖
import re
from collections import defaultdict

# --- 全局配置 ---
SOURCE_DIR = "temp_source/rule/Clash"
TARGET_DIR = "rule/Mihomo"
MIHOMO_BIN = "./mihomo"

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DigitalArchitect")

# 文件名注册表
filename_registry = {}

class KernelIntrospector:
    """
    [核心组件] 内核内省器
    不依赖硬编码，通过探测内核的帮助信息来决定参数格式
    """
    def __init__(self, bin_path):
        self.bin_path = bin_path
        if not os.path.exists(bin_path):
            raise FileNotFoundError(f"内核文件不存在: {bin_path}")
        self.needs_format_arg = self._detect_capability()

    def _detect_capability(self):
        try:
            # 故意发送无参指令获取 Usage
            result = subprocess.run(
                [self.bin_path, "convert-ruleset"], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            output = result.stderr + result.stdout
            
            # 智能特征匹配
            if "<format>" in output or " [format] " in output or "format string" in output:
                logger.info("🤖 [内核探测] 检测到新版签名：启用 format 参数")
                return True
            else:
                logger.info("🤖 [内核探测] 检测到经典签名：禁用 format 参数")
                return False
        except Exception as e:
            logger.warning(f"⚠️ 内核探测异常 (默认回退): {e}")
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
        # 🧪 深度清洗：去除引号、首尾空格
        d = domain.strip().strip("'").strip('"').strip()
        if d and not d.startswith('#'):
            self.domains.add(d)

    def add_ip(self, ip_line):
        if not ip_line: return
        # 🧪 深度清洗
        clean_line = ip_line.replace("'", "").replace('"', "").strip()
        
        # 分割并过滤空元素 (这是防止 Panic 的关键!)
        parts = [p.strip() for p in clean_line.split(',') if p.strip()]
        
        if not parts: return
        
        ip = parts[0]
        if not self._is_valid_cidr(ip): return

        has_no_resolve = 'no-resolve' in parts
        # 逻辑合并：只要有一次是 no-resolve，就标记为 True
        if not self.ips[ip]: 
            self.ips[ip] = has_no_resolve

    def _is_valid_cidr(self, text):
        """严格的 CIDR 格式校验门卫"""
        if not isinstance(text, str): return False
        if not text or not any(char.isdigit() for char in text): return False
        # 字符白名单
        allowed = set("0123456789./:abcdefABCDEF")
        return all(c in allowed for c in text) and ('/' in text or '.' in text or ':' in text)

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
    """递归解包与清洗入口"""
    if not line: return
    
    # 处理列表嵌套
    if isinstance(line, (list, tuple)):
        for item in line: _process_entry(item, ruleset)
        return
    
    line = str(line).strip()
    if not line or line.startswith('#'): return
    
    # 修复畸形的字符串列表 "['IP-CIDR', ...]"
    if line.startswith("['") or line.startswith('["'):
        line = line.replace('[', '').replace(']', '').replace("'", "").replace('"', "")
    
    # 智能分割：兼容逗号和空格
    parts = line.split(',') if ',' in line else line.split()
    # 再次过滤空元素
    parts = [p.strip() for p in parts if p.strip()]
    
    if not parts: return

    type_upper = parts[0].upper()
    
    # 分流逻辑
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
        
        # 重组用于 add_ip 的字符串
        full = ip
        # 检查剩余部分或原行是否包含 no-resolve
        if 'no-resolve' in extra or 'no-resolve' in line: 
            full += ",no-resolve"
        ruleset.add_ip(full)

def parse_file(filepath, ruleset):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            if filepath.endswith(('.yaml', '.yml')):
                try:
                    data = yaml.safe_load(f)
                    if data and 'payload' in data:
                        _process_entry(data['payload'], ruleset)
                except: pass # YAML 烂了就跳过，不纠结
            else:
                for line in f: _process_entry(line, ruleset)
    except Exception as e:
        logger.error(f"❌ 读取错误 {filepath}: {e}")

def verify_mrs(filepath):
    """🛡️ [质检仪] 检查产物是否有效"""
    if not os.path.exists(filepath): return False
    # MRS 文件头有固定开销，如果小于 20 字节肯定是坏的
    if os.path.getsize(filepath) < 20:
        logger.warning(f"🗑️ 拦截无效产物 (Size<20B): {os.path.basename(filepath)}")
        return False
    return True

def convert_to_mrs(kernel, name, rules, behavior):
    if not rules: return
    
    # 再次清洗：确保没有空字符串混入列表，这是 Panic 的最后一道防线
    clean_rules = [str(r).strip() for r in rules if r and str(r).strip()]
    if not clean_rules: return

    temp_yaml = f"temp_{name}.yaml"
    output_mrs = os.path.join(TARGET_DIR, f"{name}.mrs")
    os.makedirs(os.path.dirname(output_mrs), exist_ok=True)
    
    try:
        # 写入 YAML (纯数据，不带额外引号)
        with open(temp_yaml, 'w', encoding='utf-8') as f:
            yaml.dump({'payload': clean_rules}, f)
        
        cmd = kernel.get_cmd(behavior, temp_yaml, output_mrs)
        
        # 调用内核
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        
        if result.returncode != 0:
            # 失败处理：删除可能存在的半成品
            if os.path.exists(output_mrs): os.remove(output_mrs)
            # 忽略未知字段警告，只报真错
            if "unknown field" not in result.stderr:
                logger.error(f"❌ 转换失败 [{name}]: {result.stderr.strip()}")
        else:
            # 成功后质检
            if not verify_mrs(output_mrs):
                if os.path.exists(output_mrs): os.remove(output_mrs)

    except Exception as e:
        logger.error(f"💥 异常 [{name}]: {e}")
        if os.path.exists(output_mrs): os.remove(output_mrs)
    finally:
        if os.path.exists(temp_yaml): os.remove(temp_yaml)

def main():
    # 🛡️ 容错清理：先清理旧产物
    if os.path.exists(TARGET_DIR):
        try:
            shutil.rmtree(TARGET_DIR)
        except Exception as e:
            logger.warning(f"清理目录失败 (非致命): {e}")
    
    os.makedirs(TARGET_DIR, exist_ok=True)
    
    if not os.path.exists(SOURCE_DIR):
        logger.error("源目录不存在，请检查 Git Clone")
        return

    # 1. 启动内核探测
    kernel = KernelIntrospector(MIHOMO_BIN)
    
    # 2. 聚合阶段
    aggregated_rules = defaultdict(RuleSet)
    logger.info("🔍 启动深度扫描...")
    
    file_count = 0
    for root, dirs, files in os.walk(SOURCE_DIR):
        rel_path = os.path.relpath(root, SOURCE_DIR)
        if rel_path == '.': continue
        
        current_set = aggregated_rules[rel_path]
        for file in files:
            if file.lower().endswith(('.yaml', '.yml', '.list', '.txt')):
                parse_file(os.path.join(root, file), current_set)
                file_count += 1
                if file_count % 500 == 0:
                    logger.info(f"⏳ 已解析 {file_count} 个文件...")

    logger.info(f"✅ 解析完毕，准备编译 {len(aggregated_rules)} 个规则集...")
    
    # 3. 编译阶段
    compile_count = 0
    for rel_path, ruleset in aggregated_rules.items():
        safe_name = get_smart_filename(rel_path)
        
        # 域名编译
        if ruleset.domains:
            convert_to_mrs(kernel, safe_name, sorted(list(ruleset.domains)), 'domain')
            
        # IP 编译 (no-resolve 优先)
        if ruleset.ips:
            # Sort Key: False(0) < True(1). We want True first, so reverse=True
            sorted_ips = sorted(ruleset.ips.items(), key=lambda x: x[1], reverse=True)
            # 构建无引号的纯字符串列表
            payload = [f"{ip},no-resolve" if no_res else ip for ip, no_res in sorted_ips]
            convert_to_mrs(kernel, f"{safe_name}_IP", payload, 'ipcidr')
            
        compile_count += 1
        if compile_count % 100 == 0:
            logger.info(f"🚀 编译进度: {compile_count}/{len(aggregated_rules)}")

    logger.info("🎉 全流程执行完毕")

if __name__ == "__main__":
    main()
