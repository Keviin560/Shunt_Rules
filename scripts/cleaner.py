import asyncio, aiohttp, os

RAW_DIR = "raw_data"
DATA_DIR = "data"
INJECT_ROOT = "temp_source/rule/Clash"

def load_blackhole(filename):
    s = set()
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                val = line.strip().split(' @')[0].split(':')[-1].lower()
                if val: s.add(val)
    return s

def process_vip_channel(input_file, output_dir, rule_name, ads_bh):
    """
    🚨 核心逻辑：AI、游戏、Global_CN 专用
    只过滤广告，保留所有规则，确保不误杀海外/大厂域名。
    """
    if not os.path.exists(input_file): return
    valid_rules = set()
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            raw = line.strip().split(' @')[0]
            if not raw or raw.startswith('#'): continue
            
            domain = raw.split(':')[-1].lower()
            if domain in ads_bh: continue # 仅拦截广告
            
            # 统一输出格式为 DOMAIN-SUFFIX 或 DOMAIN
            if raw.startswith("full:"):
                valid_rules.add(f"DOMAIN,{raw[5:]}")
            else:
                d = raw[7:] if raw.startswith("domain:") else domain
                valid_rules.add(f"DOMAIN-SUFFIX,{d}")

    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "list.txt"), 'w', encoding='utf-8') as f:
        f.write(f"# NAME: {rule_name}\n# Total: {len(valid_rules)}\n")
        f.write("\n".join(sorted(list(valid_rules))))
    print(f"✅ {rule_name} 修复完成，共 {len(valid_rules)} 条规则。")

async def clean_domestic_track(ads_bh, foreign_bh):
    """
    🚨 核心逻辑：GeoSite_CN 专用
    必须经过双重过滤：广告黑洞 + 海外隔离库。
    """
    input_path = os.path.join(RAW_DIR, "geosite_cn.txt")
    if not os.path.exists(input_path): return
    
    clean_rules = set()
    with open(input_path, 'r', encoding='utf-8') as f:
        for line in f:
            val = line.strip().split(' @')[0].split(':')[-1].lower()
            if not val or val in ads_bh or val in foreign_bh: continue
            clean_rules.add(f"DOMAIN-SUFFIX,{val}")

    output_dir = os.path.join(INJECT_ROOT, "GeoSite_CN")
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "list.txt"), 'w', encoding='utf-8') as f:
        f.write(f"# NAME: GeoSite_CN\n# Total: {len(clean_rules)}\n")
        f.write("\n".join(sorted(list(clean_rules))))
    print(f"✅ GeoSite_CN 清洗完成，共 {len(clean_rules)} 条。")

async def main():
    # 1. 加载黑洞库
    ads_bh = load_blackhole("blackhole_ads.txt")
    foreign_bh = load_blackhole("blackhole_foreign.txt")
    
    # 2. 修复 AI、游戏、Global_CN (只过广告黑洞)
    # AI 规则
    process_vip_channel(os.path.join(RAW_DIR, "ai_rules.txt"), os.path.join(INJECT_ROOT, "AI_Rules"), "AI_Rules", ads_bh)
    # 海外游戏 (Game_Proxy)
    process_vip_channel(os.path.join(RAW_DIR, "geosite_category-games-!cn.txt"), os.path.join(INJECT_ROOT, "Game_Proxy"), "Game_Proxy", ads_bh)
    # 国内游戏 (Game_CN)
    process_vip_channel(os.path.join(RAW_DIR, "geosite_category-games-cn.txt"), os.path.join(INJECT_ROOT, "Game_CN"), "Game_CN", ads_bh)
    # 🚨 Global_CN (带 @cn 的规则)
    process_vip_channel(os.path.join(DATA_DIR, "global_cn_raw.txt"), os.path.join(INJECT_ROOT, "Global_CN"), "Global_CN", ads_bh)
    
    # 3. 深度清洗国内主干道 (过双重黑洞)
    await clean_domestic_track(ads_bh, foreign_bh)

if __name__ == "__main__":
    asyncio.run(main())
