import os
import yaml
import hashlib
import subprocess
import logging
import shutil
import re
from collections import defaultdict

# --- 全局配置区域 ---
# 上游下载的临时目录
SOURCE_DIR = "temp_source/rule/Clash"
# 最终产物输出目录
TARGET_DIR = "rule/Mihomo"
# 内核路径
MIHOMO_BIN = "./mihomo"

# 配置日志格式：带时间戳和日志级别，方便排错
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DigitalArchitect")

# 全局注册表：用于解决文件名扁平化冲突
filename_registry = {}

class KernelIntrospector:
    """
    [数字架构师核心组件]
    内核内省器：负责在运行时探测二进制文件的能力边界。
    它不依赖硬编码，而是通过交互式探测来决定调用策略。
    """
    def __init__(self, bin_path):
        self.bin_path = bin_path
        if not os.path.exists(bin_path):
            raise FileNotFoundError(f"内核文件不存在: {bin_path}")
        
        logger.info("🕵️ 正在初始化内核内省器...")
        self.needs_format_arg = self._detect_capability()

    def _detect_capability(self):
        """
        探测逻辑：故意发送不带参数的指令，诱导内核打印 Usage 帮助信息，
        然后通过正则分析帮助信息中是否包含特定的参数关键词。
        """
        try:
            # 调用 ./mihomo convert-ruleset (不带参)
            result = subprocess.run(
                [self.bin_path, "convert-ruleset"], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            # 合并 stdout 和 stderr，因为有些程序报错在不同流
            output = result.stderr + result.stdout
            
            # 智能分析：
            # 新版特征: Usage: ... <behavior> <format> ...
            # 旧版特征: Usage: ... <behavior> ...
            
            if "<format>" in output or " [format] " in output or "format string" in output:
                logger.info("🤖 [探测结果] 检测到新版内核签名：需要显式传递 format 参数")
                return True
            else:
                logger.info("🤖 [探测结果] 检测到经典内核签名：无需 format 参数")
                return False
        except Exception as e:
            logger.warning(f"⚠️ 内核探测发生异常 (默认回退到经典模式): {e}")
            return False

    def get_cmd(self, behavior, temp_file, output_file):
        """
        工厂方法：根据探测结果，生产出绝对正确的命令行列表
        """
        cmd = [self.bin_path, "convert-ruleset", behavior]
        
        # 动态适配：如果内核需要 format，我们就给它 yaml
        if self.needs_format_arg:
            cmd.append("yaml") 
            
        cmd.append(temp_file)
        cmd.append(output_file)
        return cmd

class RuleSet:
    """
    规则集合实体：负责在内存中清洗、去重和逻辑合并
    """
    def __init__(self):
        self.domains = set()
        # IP 存储设计: Key=IP/CIDR, Value=Boolean(是否 no-resolve)
        # 使用 defaultdict 默认 False (默认解析)
        self.ips = defaultdict(bool) 

    def add_domain(self, domain):
        if not domain: return
        # 深度清洗：移除首尾空白、单引号、双引号
        d = domain.strip().strip("'").strip('"')
        if d and not d.startswith('#'):
            self.domains.add(d)

    def add_ip(self, ip_line):
        if not ip_line: return
        # 深度清洗
        clean_line = ip_line.replace("'", "").replace('"', "").strip()
        parts = [p.strip() for p in clean_line.split(',')]
        
        if not parts: return
        
        ip = parts[0]
        # 安全校验：防止把非 IP 的垃圾数据放进来
        if not self._is_valid_cidr(ip):
            return

        # 逻辑判断：只要当前行包含 no-resolve，则标记为 True
        has_no_resolve = 'no-resolve' in parts
        
        # 状态机更新：逻辑 OR 运算
        # 如果历史记录已经是 no-resolve (True)，则保持 True
        # 如果历史是 False，当前是 True，则更新为 True
        if not self.ips[ip]: 
            self.ips[ip] = has_no_resolve

    def _is_valid_cidr(self, text):
        """鲁棒的 IP 格式校验"""
        if not isinstance(text, str): return False
        # 必须包含数字
        if not any(char.isdigit() for char in text): return False
        # 允许字符集白名单
        allowed = set("0123456789./:abcdefABCDEF")
        return all(c in allowed for c in text) and ('/' in text or '.' in text or ':' in text)

def get_smart_filename(source_rel_path):
    """
    智能命名系统：解决扁平化冲突
    将 rule/Clash/Game/Roblox 转换为 Game_Roblox.mrs
    """
    parts = source_rel_path.split(os.sep)
    base_name = parts[-1]
    
    candidate = base_name
    stack = parts[:-1]
    
    # 冲突检测循环
    while candidate in filename_registry:
        # 如果路径完全一致，说明是同一个源（这不应发生，但为了健壮性）
        if filename_registry[candidate] == source_rel_path:
            return candidate
        
        if not stack:
            # 栈空了还有冲突，追加哈希兜底
            candidate = f"{candidate}_{hashlib.md5(source_rel_path.encode()).hexdigest()[:4]}"
            break
            
        # 回溯父目录，拼接前缀
        parent = stack.pop()
        candidate = f"{parent}_{candidate}"
    
    # 注册新名字
    filename_registry[candidate] = source_rel_path
    return candidate

def process_line(line, ruleset):
    """
    单行处理器：处理 YAML 列表项的多种变体（String, List, Dirty String）
    """
    try:
        if line is None: return
        
        # 1. 递归解包：如果 payload 里嵌套了列表
        if isinstance(line, (list, tuple)):
            for item in line: process_line(item, ruleset)
            return

        # 2. 字符串标准化
        line = str(line).strip()
        if not line or line.startswith('#'): return

        # 3. 脏数据清洗：处理被错误转为字符串的列表 "['IP-CIDR', '...']"
        if line.startswith("['") or line.startswith('["'):
            cleaned = line.replace('[', '').replace(']', '').replace("'", "").replace('"', "")
            process_line(cleaned, ruleset)
            return

        # 4. 分割逻辑
        if ',' not in line and ' ' in line: 
            parts = line.split() # 兼容空格分隔
        else: 
            parts = line.split(',')
            
        parts = [p.strip() for p in parts]
        type_upper = parts[0].upper()

        # 5. 策略分流
        if type_upper.startswith('DOMAIN'):
            if len(parts) >= 2: 
                ruleset.add_domain(parts[1])
            elif len(parts) == 1 and '.' in parts[0]: 
                # 纯域名情况
                ruleset.add_domain(parts[0])

        elif type_upper.startswith('IP-') or ruleset._is_valid_cidr(parts[0]):
            if type_upper.startswith('IP-') and len(parts) >= 2:
                ip_val = parts[1]
                extra = parts[2:]
            elif ruleset._is_valid_cidr(parts[0]):
                ip_val = parts[0]
                extra = parts[1:]
            else: return

            # 重组用于 add_ip 的数据
            full_ip_line = ip_val
            if 'no-resolve' in extra or 'no-resolve' in line:
                full_ip_line += ",no-resolve"
            
            ruleset.add_ip(full_ip_line)

    except Exception:
        # 单行错误忽略，不中断流
        pass

def parse_file(filepath, ruleset):
    """文件解析器：支持 YAML 和 TXT/LIST"""
    try:
        ext = filepath.split('.')[-1].lower()
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            if ext in ['yaml', 'yml']:
                try:
                    data = yaml.safe_load(f)
                    if data and isinstance(data, dict) and 'payload' in data:
                        payload = data['payload']
                        if isinstance(payload, list):
                            for line in payload: process_line(line, ruleset)
                except yaml.YAMLError: 
                    pass # YAML 格式错误，跳过
            else:
                # 文本模式
                for line in f: process_line(line, ruleset)
    except Exception as e:
        logger.error(f"❌ 文件读取致命错误 {filepath}: {e}")

def convert_to_mrs(kernel, name, rules, behavior):
    """
    编译控制器：生成临时文件并调用内核
    """
    if not rules: return
    
    temp_yaml = f"temp_{name}.yaml"
    output_mrs = os.path.join(TARGET_DIR, f"{name}.mrs")
    
    # 确保父目录存在
    os.makedirs(os.path.dirname(output_mrs), exist_ok=True)
    
    try:
        # 1. 生成符合 Mihomo 标准的 YAML
        with open(temp_yaml, 'w', encoding='utf-8') as f:
            yaml.dump({'payload': rules}, f)
        
        # 2. 获取自适应命令
        cmd = kernel.get_cmd(behavior, temp_yaml, output_mrs)
        
        # 3. 执行编译
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        
        if result.returncode != 0:
            # 过滤非致命的 unknown field 警告，只报真错
            if "unknown field" not in result.stderr:
                logger.error(f"❌ 转换失败 [{name}]: {result.stderr.strip()}")
            
    except subprocess.TimeoutExpired:
        logger.error(f"⏳ 编译超时 [{name}]")
    except Exception as e:
        logger.error(f"💥 编译异常 [{name}]: {e}")
    finally:
        # 清理临时文件
        if os.path.exists(temp_yaml):
            try: os.remove(temp_yaml)
            except: pass

def main():
    # 初始化环境
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)
        
    if not os.path.exists(SOURCE_DIR):
        logger.error(f"❌ 源目录不存在: {SOURCE_DIR}，请检查 git clone 是否成功")
        return

    # 1. 启动内核内省
    kernel = KernelIntrospector(MIHOMO_BIN)

    # 2. 聚合阶段 (Aggregation Phase)
    aggregated_rules = defaultdict(RuleSet)
    logger.info("🔍 开始全量扫描与聚合...")
    
    file_count = 0
    for root, dirs, files in os.walk(SOURCE_DIR):
        rel_path = os.path.relpath(root, SOURCE_DIR)
        if rel_path == '.': continue
        
        # 聚合键：以文件夹路径为单位（例如 Game/Roblox）
        current_set = aggregated_rules[rel_path]
        
        for file in files:
            if file.lower().endswith(('.yaml', '.yml', '.list', '.txt')):
                parse_file(os.path.join(root, file), current_set)
                file_count += 1
                
                # 💓 心跳日志：每 500 个文件报一次平安
                if file_count % 500 == 0:
                    logger.info(f"💓 [心跳] 已解析 {file_count} 个源文件...")

    logger.info(f"✅ 解析完成，共 {file_count} 个文件。生成 {len(aggregated_rules)} 个规则组。")
    logger.info("⚡ 开始编译二进制规则集 (.mrs)...")
    
    # 3. 转换阶段 (Conversion Phase)
    compile_count = 0
    total_sets = len(aggregated_rules)
    
    for rel_path, ruleset in aggregated_rules.items():
        # 获取智能扁平化文件名
        safe_name = get_smart_filename(rel_path)
        
        # --- 分流处理：域名 ---
        if ruleset.domains:
            # 排序保证确定性
            convert_to_mrs(kernel, safe_name, sorted(list(ruleset.domains)), 'domain')
            
        # --- 分流处理：IP ---
        if ruleset.ips:
            # 排序逻辑：no-resolve (True) 优先排在前面
            # Python sort True > False? No, False=0, True=1.
            # 我们需要 True 在前，所以 key 取反: (not True) -> 0, (not False) -> 1
            sorted_ips = sorted(ruleset.ips.items(), key=lambda x: (not x[1], x[0]))
            
            payload = []
            for ip, no_res in sorted_ips:
                entry = f"'{ip}',no-resolve" if no_res else f"'{ip}'"
                # 这里移除引号再传入 payload，因为 yaml.dump 会自己处理
                clean_entry = f"{ip},no-resolve" if no_res else ip
                payload.append(clean_entry)
                
            convert_to_mrs(kernel, f"{safe_name}_IP", payload, 'ipcidr')
        
        compile_count += 1
        if compile_count % 100 == 0:
             logger.info(f"🚀 [进度] 已编译 {compile_count}/{total_sets} 个规则集")

    logger.info("🎉 所有任务执行完毕！数字架构师祝您运行愉快。")

if __name__ == "__main__":
    main()
