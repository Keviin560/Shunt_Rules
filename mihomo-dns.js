/**
 * 作者：Keviin560
 * 更新日期：2026-03-01
 * 
 * * * -------------------------------------------------------
 * 【 ⚙️ 核心架构说明 】
 * --> 全局接管 GUI 设置：覆盖客户端基础设置 (端口/模式/TUN)，实现底层参数统一
 * --> 物理防漏：开启 TUN strict-route，并物理斩断引擎的 fallback DNS，彻底绞杀 ISP (如中国移动/阿里云) 的并发侧漏
 * --> 动态指纹防封：为 TLS 协议 (VMess/VLESS/Trojan/AnyTLS 协议) 动态挂载 random 高熵指纹，实现 DPI 隐身
 * --> 五大洲节点自动筛选分组：Unicode 国旗解码；内置 240+ 国家与城市字典
 *
 * * 【 ⚠️ 必读设置 】
 * --> 关闭浏览器安全 DNS：Chrome 设置 -> 隐私与安全 -> 关闭 "使用安全 DNS"。防止浏览器绕过客户端自己去解析 DNS，导致分流失败
 * --> Windows 用户：关闭 "智能多宿主名称解析" (组策略或注册表修改)，防止 DNS 请求泄露
 * --> IPv6 相关设置（两者选其一）
 *       - 用不上 IPv6 建议关闭：在客户端的 [内核设置] 和 [ DNS ] 里关闭 IPv6 ；同时在系统的物理网卡（一般是 WLAN 或 以太网）里关闭 IPv6 ，即关闭 Internet 协议版本 6 (TCP/IPv6)
 *       - 需要用 IPv6 ：打开客户端的 [内核设置] 和 [ DNS ] 的 IPv6 功能，IPv6 虚假 IP 池填写 [fc00::/18]，同时在物理网卡里的 [Internet 协议版本 6 (TCP/IPv6)] 里选择 [使用下面的 DNS 服务器地址]，然后在 [首选 DNS 服务器] 框内填入 [::1] （ IPv6 的本地回环地址，相当于 IPv4 的 127.0.0.1）
 * 
 * * 【 🛠️ 修改与维护指南 】
 * --> 若机场新增冷门国家/城市未被识别：请在第 1 部分的 `continentKeywords` 对应的数组里添加中文名。
 * --> 若想新增独立地区策略组（如新增“英国节点”）：
 *       - 在 `regionKeywords` 中添加 `UK: ['英国', '伦敦']`。
 *       - 在 `sorted` 容器中添加 `UK: []`。
 *       - 在 `config['proxy-groups']` 中添加 `UK` 的策略组挂载。
 * -------------------------------------------------------
 */


function main(config) {
    // =======================================================
    // 0. 基础设置全量接管
    // =======================================================
    // [防御机制] 确保传入的 proxies 是合法数组，防止引擎崩溃
    if (!config.proxies || !Array.isArray(config.proxies)) {
        config.proxies = [];
    }
    
    // [历史包袱清理] 彻底抹除旧版全局指纹
    delete config['global-client-fingerprint'];

    // 【接管 I：基础网络框架】
    // 脚本启动即锁定以下最优运行参数
    config.mode = 'rule';                    // 分流模式
    config['mixed-port'] = 7890;             // 统一混合代理端口
    config['allow-lan'] = true;              // 允许局域网设备接入代理
    config['log-level'] = 'info';            // 日志级别
    config.ipv6 = false;                     // 关闭 IPv6  (若需开启请改为 true，并阅读头部注意事项)
    config['find-process-mode'] = 'strict';  // 严格进程匹配，配合规则集使用
    config['unified-delay'] = true;          // 去除 TCP 握手，计算真实的物理 RTT 延迟

    // 接管流量嗅探
    // 防止在 GUI 面板关闭嗅探功能，强制捕获真实域名，对抗域名前置/伪装逃逸
    config.sniffer = {
        enable: true,
        'force-domain': ['+'],               // 对所有流量进行 SNI 嗅探
        sniff: {
            HTTP: { ports: [80, 8080], 'override-destination': true },
            TLS: { ports: [443, 8443] },
            QUIC: { ports: [443, 8443] }     // 接管 QUIC 流量的真实域名
        },
        'skip-domain': [                   // 跳过域名嗅探
            'Mijia Cloud',                   // 米家智能家居，防止局域网设备掉线
            '*.apple.com',                   // 苹果核心服务，防止 APNs 推送断连
            '*.icloud.com'
        ]
    };

    // 【接管 II：TUN 虚拟网卡与严格路由】
    if (!config.tun) config.tun = {};
    config.tun.enable = true;                // 强制开启虚拟网卡
    config.tun.stack = 'system';             // 网络栈模型
    config.tun['auto-route'] = true;         // 自动路由全局流量进入 TUN
    config.tun['auto-detect-interface'] = true; // 自动识别出口网卡
    config.tun['dns-hijack'] = ['any:53'];   // 劫持本机所有 53 端口的 DNS 请求
    // ⚠️ 锁死物理网卡并发，所有的流量/DNS必须先经过 Mihomo 的 TUN 虚拟网卡
    config.tun['strict-route'] = true;       

    
    // =======================================================
    // 1. Unicode 解码器 & 全球微型数据库
    // =======================================================
    
    // 国旗 Emoji 降维提取器
    const extractISOFromEmoji = (str) => {
        const regex = /[\uD83C][\uDDE6-\uDDFF][\uD83C][\uDDE6-\uDDFF]/;
        const match = str.match(regex);
        if (match) {
            const char1 = String.fromCharCode(match[0].charCodeAt(1) - 0xDDE6 + 65);
            const char2 = String.fromCharCode(match[0].charCodeAt(3) - 0xDDE6 + 65);
            return char1 + char2;
        }
        return null;
    };

    // 【微型库 A：ISO 绝对防碰撞路由表】
    // 将 Emoji 算出的 ISO 标准码，精准归类到五大洲 (排除独立路权地区)
    const isoToContinentMap = {
        'IN':'Asia', 'AE':'Asia', 'TR':'Asia', 'TH':'Asia', 'ID':'Asia', 'MY':'Asia', 'PH':'Asia', 'VN':'Asia', 'PK':'Asia', 'IL':'Asia', 'KZ':'Asia', 'KH':'Asia', 'NP':'Asia', 'SA':'Asia', 'IR':'Asia', 'IQ':'Asia', 'SY':'Asia', 'LB':'Asia', 'JO':'Asia', 'OM':'Asia', 'YE':'Asia', 'QA':'Asia', 'BH':'Asia', 'KW':'Asia', 'BD':'Asia', 'LK':'Asia', 'MV':'Asia', 'MM':'Asia', 'LA':'Asia', 'BN':'Asia', 'TL':'Asia', 'MN':'Asia', 'UZ':'Asia', 'TM':'Asia', 'KG':'Asia', 'TJ':'Asia', 'AF':'Asia', 'BT':'Asia', 'CY':'Asia', 'GE':'Asia', 'AM':'Asia', 'AZ':'Asia',
        'GB':'Europe', 'FR':'Europe', 'DE':'Europe', 'NL':'Europe', 'RU':'Europe', 'IT':'Europe', 'CH':'Europe', 'SE':'Europe', 'ES':'Europe', 'PT':'Europe', 'PL':'Europe', 'IE':'Europe', 'AT':'Europe', 'FI':'Europe', 'DK':'Europe', 'IS':'Europe', 'NO':'Europe', 'UA':'Europe', 'BE':'Europe', 'LU':'Europe', 'MC':'Europe', 'AD':'Europe', 'LI':'Europe', 'SM':'Europe', 'VA':'Europe', 'MT':'Europe', 'GR':'Europe', 'BG':'Europe', 'RO':'Europe', 'HU':'Europe', 'CZ':'Europe', 'SK':'Europe', 'SI':'Europe', 'HR':'Europe', 'BA':'Europe', 'ME':'Europe', 'RS':'Europe', 'MK':'Europe', 'AL':'Europe', 'EE':'Europe', 'LV':'Europe', 'LT':'Europe', 'BY':'Europe', 'MD':'Europe',
        'CA':'Americas', 'BR':'Americas', 'AR':'Americas', 'MX':'Americas', 'CL':'Americas', 'CO':'Americas', 'PE':'Americas', 'VE':'Americas', 'EC':'Americas', 'BO':'Americas', 'PY':'Americas', 'UY':'Americas', 'GY':'Americas', 'SR':'Americas', 'GF':'Americas', 'BZ':'Americas', 'GT':'Americas', 'HN':'Americas', 'SV':'Americas', 'NI':'Americas', 'CR':'Americas', 'PA':'Americas', 'CU':'Americas', 'HT':'Americas', 'DO':'Americas', 'JM':'Americas', 'TT':'Americas', 'BB':'Americas', 'BS':'Americas',
        'AU':'Oceania', 'NZ':'Oceania', 'PG':'Oceania', 'SB':'Oceania', 'VU':'Oceania', 'FJ':'Oceania', 'PW':'Oceania', 'FM':'Oceania', 'MH':'Oceania', 'KI':'Oceania', 'NR':'Oceania', 'TV':'Oceania', 'WS':'Oceania', 'TO':'Oceania', 'NU':'Oceania', 'CK':'Oceania',
        'ZA':'Africa', 'EG':'Africa', 'NG':'Africa', 'MA':'Africa', 'DZ':'Africa', 'TN':'Africa', 'LY':'Africa', 'SD':'Africa', 'ET':'Africa', 'KE':'Africa', 'TZ':'Africa', 'UG':'Africa', 'AO':'Africa', 'MZ':'Africa', 'MG':'Africa', 'CM':'Africa', 'CI':'Africa', 'GH':'Africa', 'SN':'Africa', 'ML':'Africa', 'BF':'Africa', 'NE':'Africa', 'TD':'Africa', 'MR':'Africa', 'GN':'Africa', 'SL':'Africa', 'LR':'Africa', 'TG':'Africa', 'BJ':'Africa', 'CF':'Africa', 'CG':'Africa', 'CD':'Africa', 'GA':'Africa', 'GQ':'Africa', 'ST':'Africa', 'RW':'Africa', 'BI':'Africa', 'SO':'Africa', 'DJ':'Africa', 'ER':'Africa', 'ZM':'Africa', 'ZW':'Africa', 'MW':'Africa', 'BW':'Africa', 'NA':'Africa', 'LS':'Africa', 'SZ':'Africa', 'KM':'Africa', 'MU':'Africa', 'SC':'Africa', 'CV':'Africa'
    };

    // 【微型库 B：最高特权路由表】
    // 识别这些节点并放入专门的组
    const regionKeywords = {
        HK: ['香港', 'HK', 'Hong Kong', '深港', '广港'],
        MO: ['澳门', 'Macau', 'MO', 'Macao'],
        TW: ['台湾', 'Taiwan', 'TW', 'Taipei', '台北', '新北', '中华民国'],
        JP: ['日本', 'Japan', 'JP', '东京', '大阪', '埼玉', '川日', '沪日'],
        KR: ['韩国', 'Korea', 'KR', '首尔', '春川', '南韩'],
        SG: ['新加坡', 'Singapore', 'SG', '狮城', '深新'],
        US: ['美国', 'US', 'America', 'United States', '波特兰', '达拉斯', '俄勒冈', '凤凰城', '费利蒙', '硅谷', '洛杉矶', '圣何塞', '圣克拉拉', '西雅图', '芝加哥', '拉斯维加斯']
    };

    // 【微型库 C：大洲降维兜底】
    const continentKeywords = {
        Asia: ['印度', '阿联酋', '迪拜', '土耳其', '泰国', '印尼', '马来西亚', '菲律宾', '越南', '巴基斯坦', '以色列', '哈萨克斯坦', '柬埔寨', '尼泊尔', '沙特', '孟加拉', '斯里兰卡', '曼谷', '雅加达', '吉隆坡', '马尼拉', '金边', '万象', '孟买', '新德里', '伊斯兰堡', '卡拉奇', '迪拜', '阿布扎比', '伊斯坦布尔', '安卡拉', '特拉维夫', '耶路撒冷', '德黑兰', '卡塔尔', '科威特', '伊朗', '伊拉克', '叙利亚', '黎巴嫩', '约旦', '阿曼', '也门', '巴林', '马尔代夫', '缅甸', '老挝', '文莱', '蒙古', '乌兹别克斯坦', '土库曼斯坦', '吉尔吉斯斯坦', '塔吉克斯坦', '阿富汗', '不丹', '塞浦路斯', '格鲁吉亚', '亚美尼亚', '阿塞拜疆'],
        Europe: ['英国', '法国', '德国', '荷兰', '俄罗斯', '意大利', '瑞士', '瑞典', '西班牙', '葡萄牙', '波兰', '爱尔兰', '奥地利', '芬兰', '丹麦', '冰岛', '挪威', '乌克兰', '比利时', '伦敦', '巴黎', '法兰克福', '阿姆斯特丹', '莫斯科', '罗马', '米兰', '日内瓦', '苏黎世', '斯德哥尔摩', '马德里', '里斯本', '华沙', '都柏林', '维也纳', '哥本哈根', '卢森堡', '摩纳哥', '安道尔', '列支敦士登', '圣马力诺', '梵蒂冈', '马耳他', '希腊', '保加利亚', '罗马尼亚', '匈牙利', '捷克', '斯洛伐克', '斯洛文尼亚', '克罗地亚', '波黑', '黑山', '塞尔维亚', '北马其顿', '阿尔巴尼亚', '爱沙尼亚', '拉脱维亚', '立陶宛', '白俄罗斯', '摩尔多瓦'],
        Americas: ['加拿大', '巴西', '阿根廷', '墨西哥', '智解', '哥伦比亚', '秘鲁', '委内瑞拉', '厄瓜多尔', '古巴', '巴拿马', '多伦多', '温哥华', '蒙特利尔', '卡尔加里', '渥太华', '圣保罗', '里约热内卢', '布宜诺斯艾利斯', '墨西哥城', '圣地亚哥', '利马', '玻利维亚', '巴拉圭', '乌拉圭', '圭亚那', '苏里南', '法属圭亚那', '伯利兹', '危地马拉', '洪都拉斯', '萨尔瓦多', '尼加拉瓜', '哥斯达黎加', '海地', '多米尼加', '牙买加', '特立尼达', '巴巴多斯', '巴哈马'],
        Oceania: ['澳大利亚', '澳洲', '新西兰', '悉尼', '墨尔本', '布里斯班', '珀斯', '阿德莱德', '奥克兰', '惠灵顿', '基督城', '巴布亚新几内亚', '所罗门群岛', '瓦努阿图', '斐济', '帕劳', '密克罗尼西亚', '马绍尔群岛', '基里巴斯', '瑙鲁', '图瓦卢', '萨摩亚', '汤加', '纽埃', '库克群岛'],
        Africa: ['南非', '埃及', '尼日利亚', '摩洛哥', '阿尔及利亚', '肯尼亚', '毛里求斯', '约翰内斯堡', '开普敦', '开罗', '拉各斯', '卡萨布兰卡', '内罗毕', '突尼斯', '利比亚', '苏丹', '埃塞俄比亚', '坦桑尼亚', '乌干达', '安哥拉', '莫桑比克', '马达加斯加', '喀麦隆', '科特迪瓦', '加纳', '塞内加尔', '马里', '布基纳法索', '尼日尔', '乍得', '毛里塔尼亚', '几内亚', '塞拉利昂', '利比里亚', '多哥', '贝宁', '中非', '刚果', '加蓬', '赤道几内亚', '圣多美', '卢旺达', '布隆迪', '索马里', '吉布提', '厄立特里亚', '赞比亚', '津巴布韦', '马拉维', '博茨瓦纳', '纳米比亚', '莱索托', '斯威士兰', '科摩罗', '塞舌尔', '佛得角']
    };

    
    // =======================================================
    // 2. 运行时分拣管道
    // =======================================================
    // 初始化存放分拣后节点名称的空容器
    const sorted = {
        All: [], HK: [], MO: [], TW: [], JP: [], KR: [], SG: [], US: [],
        Asia: [], Europe: [], Americas: [], Oceania: [], Africa: []
    };

    // 需注入指纹的底层强加密协议
    const tlsProtocols = ['vmess', 'vless', 'trojan', 'tuic', 'hysteria2'];
    // 垃圾信息节点特征词，净化机场列表
    const ignoreKeywords = ['剩余', '到期', '过期', '官网', '流量', '联系', '套餐', '重置', '更新', '群', '邀请', '返回', '网址', '贩卖', '倒卖', 'Expire', 'Traffic'];

    config.proxies.forEach(proxy => {
        const pName = proxy.name;

        // 【净化】：过滤垃圾节点
        if (ignoreKeywords.some(kw => pName.toUpperCase().includes(kw.toUpperCase()))) return;

        // 【伪装】：注入动态高熵指纹，对抗防火长城的主动探测
        if (proxy.type && tlsProtocols.includes(proxy.type)) {
            proxy['client-fingerprint'] = 'random';
        }

        sorted.All.push(pName); // 保底装入全量节点池

        let matched = false;

        // 尝试解析 Emoji 国旗
        const isoCode = extractISOFromEmoji(pName);
        if (isoCode) {
            if (['HK', 'MO', 'TW', 'JP', 'KR', 'SG', 'US'].includes(isoCode)) {
                sorted[isoCode].push(pName);
                matched = true;
            } else if (isoToContinentMap[isoCode]) {
                sorted[isoToContinentMap[isoCode]].push(pName);
                matched = true;
            }
        }

        // 特权中文词库扫描
        if (!matched) {
            for (const [reg, kws] of Object.entries(regionKeywords)) {
                // some() 找到立即返回 true
                if (kws.some(kw => pName.toUpperCase().includes(kw.toUpperCase()))) {
                    sorted[reg].push(pName);
                    matched = true;
                    break;
                }
            }
        }

        // 【拦截网 III】：五大洲词库兜底
        if (!matched) {
            for (const [cont, kws] of Object.entries(continentKeywords)) {
                if (kws.some(kw => pName.toUpperCase().includes(kw.toUpperCase()))) {
                    sorted[cont].push(pName);
                    break;
                }
            }
        }
    });

    // 防止某个分类节点数为 0 导致内核加载策略组时崩溃
    const safe = (arr) => arr.length > 0 ? arr : ['节点选择'];

    
    // =======================================================
    // 3. DNS 劫持与 Fake-IP 底层净化
    // =======================================================
    if (!config.dns) config.dns = {};
    
    // ⚠️ 移除 GUI 兜底参数，切断阿里/腾讯 DNS 的并发侧漏源
    delete config.dns.fallback;
    delete config.dns['fallback-filter'];
    delete config.dns['default-nameserver'];

    // 恢复仅用于解析节点域名的自举 DNS
    config.dns['default-nameserver'] = [
        '223.5.5.5',        // 阿里云 DNS
        '119.29.29.29'      // 腾讯云 DNS
    ]; // 👈 在这里修复了缺失的闭合中括号和分号

    config.dns = {
        ...config.dns, // 无损继承原有的基础配置
        enable: true,
        listen: '0.0.0.0:1053',
        ipv6: false, // 保持与外部基础设置同步
        'enhanced-mode': 'fake-ip',         // 秒回假 IP 机制
        'fake-ip-range': '198.18.0.1/16',   // 假 IP 响应池
        // 'fake-ip-range6': 'fc00::/18',      // ⚠️ 假 IPv6 响应池，若开启 IPv6 请取消注释
        'prefer-h3': true,                  // 优先使用 HTTP/3 (QUIC) 查询 DNS，降延迟
        

        // Fake-IP 过滤，解决 P2P 和局域网故障
        'fake-ip-filter': [
            'rule-set:Lan',                 // 联动 Lan 规则集，确保局域网设备互访正常
            'stun.*',                       // 豁免 WebRTC/STUN 穿透服务器
            '*.stun.*',
            '*.+.msftncsi.com',
            '*.+.msftconnecttest.com',
            '*.+.market.xiaomi.com',
            '*.local',                      // 豁免 mDNS 局域网多播
            '*.ptlogin2.qq.com',            // 解决国内快捷登录在 Fake-IP 下失效的顽疾
            '+.pool.ntp.org'                // 豁免时间同步服务器，防止系统时钟失真导致证书验证失败
        ],

        // 兜底与国外大厂域名解析通道 (DoH)
        nameserver: [
            'https://1.1.1.1/dns-query#节点选择',
            'https://8.8.8.8/dns-query#节点选择'
        ],
        
        // Split-Horizon (水平分割) 策略路由：国内查直连，国外查 DoH
        'nameserver-policy': {
            'rule-set:Lan': ['system'],
            'rule-set:GeoSite_CN': ['223.5.5.5', '119.29.29.29', '180.184.1.1'],
            'rule-set:Google': ['https://1.1.1.1/dns-query#节点选择', 'https://8.8.8.8/dns-query#节点选择'],
            'rule-set:YouTube': ['https://1.1.1.1/dns-query#节点选择', 'https://8.8.8.8/dns-query#节点选择'],
            'rule-set:Netflix': ['https://1.1.1.1/dns-query#节点选择', 'https://8.8.8.8/dns-query#节点选择']
        }
    };

    
    // =======================================================
    // 4. 策略组架构重铸
    // =======================================================
    // 采用静态数组直接挂载 (safe() 传入防止空数组崩溃)
    config['proxy-groups'] = [
        // ---------- 1. 全局枢纽 ----------
        { name: '节点选择', type: 'select', proxies: safe(sorted.All), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Locator.png' },
        
        // ---------- 2. 业务应用与流媒体生态 ----------
        { name: 'AI Rules', type: 'select', proxies: ['美国节点', '日本节点', '新加坡节点', '节点选择'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Chatbot.png' },
        { name: 'YouTube', type: 'select', proxies: ['节点选择', '香港节点', '美国节点', '新加坡节点'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/YouTube.png' },
        { name: 'Google', type: 'select', proxies: ['美国节点', '香港节点', '新加坡节点', '节点选择'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Google.png' },
        { name: 'Telegram', type: 'select', proxies: ['节点选择', '香港节点', '美国节点', '新加坡节点'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Telegram.png' },
        { name: 'Spotify', type: 'select', proxies: ['DIRECT', '香港节点', '美国节点', '新加坡节点'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Spotify.png' },
        { name: 'TikTok', type: 'select', proxies: ['美国节点', '台湾节点', '日本节点', '新加坡节点'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/TikTok.png' },
        { name: 'Netflix', type: 'select', proxies: ['新加坡节点', '香港节点', '美国节点'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Netflix.png' },
        { name: 'Apple账户', type: 'select', proxies: ['DIRECT', '美国节点', '香港节点'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/iCloud.png' },
        
        // ---------- 3. 核心安全防护功能 ----------
        { name: '广告拦截', type: 'select', proxies: ['REJECT', 'DIRECT'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Ad Blocker.png' },
        { name: '隐私保护', type: 'select', proxies: ['REJECT', 'DIRECT'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Privacy.png' },
        { name: '反劫持', type: 'select', proxies: ['REJECT', 'DIRECT'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Hijacking.png' },
        { name: '兜底策略', type: 'select', proxies: ['节点选择', '香港节点', '新加坡节点', '美国节点', '亚洲节点', '欧洲节点', '美洲节点', '大洋洲节点', '非洲节点'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Rules.png' },

        // ---------- 4. 地区分流矩阵 (7 大最高特权 + 5 大降维兜底) ----------
        { name: '香港节点', type: 'select', proxies: safe(sorted.HK), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/HK.png' },
        { name: '澳门节点', type: 'select', proxies: safe(sorted.MO), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/MAC.png' },
        { name: '台湾节点', type: 'select', proxies: safe(sorted.TW), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/CHN.png' },
        { name: '美国节点', type: 'select', proxies: safe(sorted.US), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/USA.png' },
        { name: '日本节点', type: 'select', proxies: safe(sorted.JP), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/JP.png' },
        { name: '韩国节点', type: 'select', proxies: safe(sorted.KR), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/KOR.png' },
        { name: '新加坡节点', type: 'select', proxies: safe(sorted.SG), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/SG.png' },
        { name: '亚洲节点', type: 'select', proxies: safe(sorted.Asia), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Asia.png' },
        { name: '欧洲节点', type: 'select', proxies: safe(sorted.Europe), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Europe.png' },
        { name: '美洲节点', type: 'select', proxies: safe(sorted.Americas), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Americas.png' },
        { name: '大洋洲节点', type: 'select', proxies: safe(sorted.Oceania), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Oceania.png' },
        { name: '非洲节点', type: 'select', proxies: safe(sorted.Africa), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Africa.png' }
    ];

    
    // =======================================================
    // 5. 规则集
    // =======================================================
    // [锚点] JS 对象的复用
    const RuleDomain = { type: 'http', format: 'mrs', behavior: 'domain', interval: 86400, proxy: '节点选择' };
    const RuleIP     = { type: 'http', format: 'mrs', behavior: 'ipcidr', interval: 86400, proxy: '节点选择' };
    const RuleText   = { type: 'http', format: 'text', behavior: 'domain', interval: 86400, proxy: '节点选择' };

    config['rule-providers'] = {
        AdRules:        { ...RuleDomain, url: 'https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules-mihomo.mrs', path: './rules/AdRules.mrs' },
        Privacy:        { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Privacy.mrs', path: './rules/Privacy.mrs' },
        WinSpy:         { ...RuleText,   url: 'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/win-spy.txt', path: './rules/WinSpy.txt' },
        Hijacking:      { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Hijacking.mrs', path: './rules/Hijacking.mrs' },
        Hijacking_IP:   { ...RuleIP,     url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Hijacking_IP.mrs', path: './rules/Hijacking_IP.mrs' },
        Lan:            { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Lan.mrs', path: './rules/Lan.mrs' },
        Lan_IP:         { ...RuleIP,     url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Lan_IP.mrs', path: './rules/Lan_IP.mrs' },
        GameDownloadCN: { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/GameDownloadCN.mrs', path: './rules/GameDownloadCN.mrs' },
        GeoSite_CN:     { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/China.mrs', path: './rules/China.mrs' },
        GeoIP_CN:       { ...RuleIP,     url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/ChinaIPs_IP.mrs', path: './rules/ChinaIPs_IP.mrs' },
        OpenAI:         { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/OpenAI.mrs', path: './rules/OpenAI.mrs' },
        Gemini:         { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Gemini.mrs', path: './rules/Gemini.mrs' },
        Claude:         { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Claude.mrs', path: './rules/Claude.mrs' },
        Copilot:        { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Copilot.mrs', path: './rules/Copilot.mrs' },
        YouTube:        { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/YouTube.mrs', path: './rules/YouTube.mrs' },
        YouTube_IP:     { ...RuleIP,     url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/YouTube_IP.mrs', path: './rules/YouTube_IP.mrs' },
        Netflix:        { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Netflix.mrs', path: './rules/Netflix.mrs' },
        Netflix_IP:     { ...RuleIP,     url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Netflix_IP.mrs', path: './rules/Netflix_IP.mrs' },
        TikTok:         { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/TikTok.mrs', path: './rules/TikTok.mrs' },
        Spotify:        { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Spotify.mrs', path: './rules/Spotify.mrs' },
        Telegram:       { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Telegram.mrs', path: './rules/Telegram.mrs' },
        Telegram_IP:    { ...RuleIP,     url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Telegram_IP.mrs', path: './rules/Telegram_IP.mrs' },
        Google:         { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Google.mrs', path: './rules/Google.mrs' },
        Google_IP:      { ...RuleIP,     url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Google_IP.mrs', path: './rules/Google_IP.mrs' },
        AppleID:        { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/AppleID.mrs', path: './rules/AppleID.mrs' },
        Apple:          { ...RuleDomain, url: 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/Apple.mrs', path: './rules/Apple.mrs' }
    };

    config.rules = [
        // 1. 净化与阻断层
        'AND,((NETWORK,UDP),(DST-PORT,443)),REJECT', // 阻断 QUIC 降级为 TCP
        'RULE-SET,AdRules,广告拦截',
        'RULE-SET,Privacy,隐私保护',
        'RULE-SET,WinSpy,隐私保护',
        'RULE-SET,Hijacking,反劫持',
        'RULE-SET,Hijacking_IP,反劫持,no-resolve',   // 不发起无谓的 DNS 解析
        
        // 2. 直连穿透层
        'RULE-SET,Lan,DIRECT',
        'RULE-SET,Lan_IP,DIRECT,no-resolve',
        'RULE-SET,GameDownloadCN,DIRECT',
        'DST-PORT,123,DIRECT',                      // Windows NTP 时间同步
        
        // 3. 高频代理应用命中层
        'RULE-SET,OpenAI,AI Rules',
        'RULE-SET,Gemini,AI Rules',
        'RULE-SET,Claude,AI Rules',
        'RULE-SET,Copilot,AI Rules',
        'RULE-SET,YouTube,YouTube',
        'RULE-SET,Netflix,Netflix',
        'RULE-SET,TikTok,TikTok',
        'RULE-SET,Spotify,Spotify',
        'RULE-SET,Telegram,Telegram',
        
        // 4. 生态服务命中层
        'RULE-SET,Google,Google',
        'RULE-SET,AppleID,Apple账户',
        'RULE-SET,Apple,Apple账户',
        
        // 5. 国内主兜底 (域名先行)
        'RULE-SET,GeoSite_CN,DIRECT',
        
        // 6. 异常 IP 补漏层 (防止域名匹配失败时的 IP 兜底)
        'RULE-SET,Telegram_IP,Telegram,no-resolve',
        'RULE-SET,Google_IP,Google,no-resolve',
        'RULE-SET,YouTube_IP,YouTube,no-resolve',
        'RULE-SET,Netflix_IP,Netflix,no-resolve',
        'RULE-SET,GeoIP_CN,DIRECT,no-resolve',      // 国内 IP 最终过滤池
        
        // 7. 全局最终兜底
        'MATCH,兜底策略'
    ];

    return config; // 返回重铸完毕的配置树，正式交由 Mihomo 内核接管
}
