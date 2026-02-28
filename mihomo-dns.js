/**
 * 作者：Keviin560
 * 更新日期：2026-03-01  02:53
 * 
 * * -------------------------------------------------------
 * 【 ⚙️ 核心架构说明 】
 * 1. 动态 utls 指纹 (仅适用于 VMess/VLESS/Trojan/AnyTLS 协议) ：为所有底层 TLS 协议挂载 random 高熵指纹
 * 2. 大洲节点自动筛选分组：
 * - 方式一：把国旗 Emoji 在底层二进制层面直接解算为 ISO 3166-1 二位标准码
 * - 方式二：内置维基百科 240+ 国家及常见城市字典，按出现频率降序排列
 * 3. 分流逻辑：Split-Horizon DNS (水平分割 DNS) + "Fake-IP" 模式
 * - 国内流量：由 nameserver-policy 引导至字节/阿里/腾讯 DNS -> 解析真实 IP -> 直连
 * - 国外流量：走 Fake-IP 模式 -> 立即返回假 IP -> 流量封装发送至机场节点 -> 远端解析
 * - 联动机制：DNS 策略 (nameserver-policy) 与分流规则 (rule-providers) 绑定
 * 
 * 【 ⚠️ 必读设置 】
 * 1. 开启 TUN 模式：
 * 在 Mihomo/Clash 界面必须开启 "TUN Mode" (服务模式/虚拟网卡)，否则 Fake-IP 无法接管所有流量；开启 虚拟网卡 (TUN 模式)后，会默认启用 DNS 劫持 any:53
 * 开启域名嗅探中的 [ 覆盖连接地址 ] 和 [ QUIC 端口嗅探 (443) ]
 * 2. 关闭浏览器安全 DNS：
 * Chrome/Edge 设置 -> 隐私与安全 -> 关闭 "使用安全 DNS"。防止浏览器绕过客户端自己去解析 DNS，导致分流失败
 * 3. Windows 用户建议：
 * 建议关闭 "智能多宿主名称解析" (组策略或注册表修改)，防止 DNS 请求泄露；同时也可考虑把“并行 DNS 性能优化”干掉
 * 4. IPv6 相关设置（两者选其一）
 * 用不上 IPv6 建议关闭：在客户端的 [内核设置] 和 [ DNS ] 里关闭 IPv6 ；同时在系统的物理网卡（一般是 WLAN 或 以太网）里关闭 IPv6 ，即关闭 Internet 协议版本 6 (TCP/IPv6)
 * 需要用 IPv6 ：打开客户端的 [内核设置] 和 [ DNS ] 的 IPv6 功能，IPv6 虚假 IP 池填写 [fc00::/18]，同时在物理网卡里的 [Internet 协议版本 6 (TCP/IPv6)] 里选择 [使用下面的 DNS 服务器地址]，然后在 [首选 DNS 服务器] 框内填入 [::1] （ IPv6 的本地回环地址，相当于 IPv4 的 127.0.0.1）
 * 
 * 【 🛠️ 客户端设置 】
 * 1. 基础设置
 * mode: rule    # 规则分流模式
 * mixed-port: 7890    # 混合端口
 * 👇下面为“进程匹配”，一般客户端上有这项设置，需自查在用的主订阅规则集是否要开启。在客户端左侧边栏的 [规则] 搜索 [PROCESS-NAME]，如果搜索出了一堆规则，则可在 内核设置 把查找进程设置为开启（或直接取消该注释强行接管）；如果搜索结果为空，说明你的规则是基于域名和 IP，查找进程可设为自动或关闭
 * find-process-mode: strict
 * unified-delay: true    # 使用 RTT 延迟测试，测速时去除 TCP 握手时间，只计算传输层的物理延迟
 * 2. DNS 设置
 * Fake-IP 模式（域名映射模式 -> 虚假 IP  -> 回应范围 198.18.0.1/16），本地 DNS 不进行真实解析解析：客户端发起请求 -> 秒回假 IP (198.18.x.x) -> 建立连接 -> 匹配规则分流
 * enhanced-mode: fake-ip
 * IPv4 的虚假 IP 池
 * fake-ip-range: 198.18.0.1/16
 * 👇 如果需要保留 IPv6 ，就填写 Fake-IPv6 的专属网段，需打开 IPv6 开关
 * fake-ip-range6: fc00::/18
 * -------------------------------------------------------
 */



function main(config) {
    // =======================================================
    // 0. 架构初始化与防御性拦截
    // =======================================================
    if (!config.proxies || !Array.isArray(config.proxies)) {
        config.proxies = [];
    }
    // 防止内核引擎抛出 Fatal Error 阻断启动，如果客户端没有全局指纹字段，可以删除
    delete config['global-client-fingerprint'];



    // =======================================================
    // 1. 核心算力：Unicode 解码器 & 全球微型数据库
    // =======================================================
    
    // 【算法引擎】Unicode 国旗降维解码
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

    // 【数据库 I】全球 ISO 3166-1 绝对路由映射表
    const isoToContinentMap = {
        // 亚洲 (排除 JP, KR, SG, TW, HK, MO 独立最高路权)
        'IN':'Asia', 'AE':'Asia', 'TR':'Asia', 'TH':'Asia', 'ID':'Asia', 'MY':'Asia', 'PH':'Asia', 'VN':'Asia', 'PK':'Asia', 'IL':'Asia', 'KZ':'Asia', 'KH':'Asia', 'NP':'Asia', 'SA':'Asia', 'IR':'Asia', 'IQ':'Asia', 'SY':'Asia', 'LB':'Asia', 'JO':'Asia', 'OM':'Asia', 'YE':'Asia', 'QA':'Asia', 'BH':'Asia', 'KW':'Asia', 'BD':'Asia', 'LK':'Asia', 'MV':'Asia', 'MM':'Asia', 'LA':'Asia', 'BN':'Asia', 'TL':'Asia', 'MN':'Asia', 'UZ':'Asia', 'TM':'Asia', 'KG':'Asia', 'TJ':'Asia', 'AF':'Asia', 'BT':'Asia', 'CY':'Asia', 'GE':'Asia', 'AM':'Asia', 'AZ':'Asia',
        // 欧洲
        'GB':'Europe', 'FR':'Europe', 'DE':'Europe', 'NL':'Europe', 'RU':'Europe', 'IT':'Europe', 'CH':'Europe', 'SE':'Europe', 'ES':'Europe', 'PT':'Europe', 'PL':'Europe', 'IE':'Europe', 'AT':'Europe', 'FI':'Europe', 'DK':'Europe', 'IS':'Europe', 'NO':'Europe', 'UA':'Europe', 'BE':'Europe', 'LU':'Europe', 'MC':'Europe', 'AD':'Europe', 'LI':'Europe', 'SM':'Europe', 'VA':'Europe', 'MT':'Europe', 'GR':'Europe', 'BG':'Europe', 'RO':'Europe', 'HU':'Europe', 'CZ':'Europe', 'SK':'Europe', 'SI':'Europe', 'HR':'Europe', 'BA':'Europe', 'ME':'Europe', 'RS':'Europe', 'MK':'Europe', 'AL':'Europe', 'EE':'Europe', 'LV':'Europe', 'LT':'Europe', 'BY':'Europe', 'MD':'Europe',
        // 美洲 (排除 US 独立最高路权)
        'CA':'Americas', 'BR':'Americas', 'AR':'Americas', 'MX':'Americas', 'CL':'Americas', 'CO':'Americas', 'PE':'Americas', 'VE':'Americas', 'EC':'Americas', 'BO':'Americas', 'PY':'Americas', 'UY':'Americas', 'GY':'Americas', 'SR':'Americas', 'GF':'Americas', 'BZ':'Americas', 'GT':'Americas', 'HN':'Americas', 'SV':'Americas', 'NI':'Americas', 'CR':'Americas', 'PA':'Americas', 'CU':'Americas', 'HT':'Americas', 'DO':'Americas', 'JM':'Americas', 'TT':'Americas', 'BB':'Americas', 'BS':'Americas',
        // 大洋洲
        'AU':'Oceania', 'NZ':'Oceania', 'PG':'Oceania', 'SB':'Oceania', 'VU':'Oceania', 'FJ':'Oceania', 'PW':'Oceania', 'FM':'Oceania', 'MH':'Oceania', 'KI':'Oceania', 'NR':'Oceania', 'TV':'Oceania', 'WS':'Oceania', 'TO':'Oceania', 'NU':'Oceania', 'CK':'Oceania',
        // 非洲
        'ZA':'Africa', 'EG':'Africa', 'NG':'Africa', 'MA':'Africa', 'DZ':'Africa', 'TN':'Africa', 'LY':'Africa', 'SD':'Africa', 'ET':'Africa', 'KE':'Africa', 'TZ':'Africa', 'UG':'Africa', 'AO':'Africa', 'MZ':'Africa', 'MG':'Africa', 'CM':'Africa', 'CI':'Africa', 'GH':'Africa', 'SN':'Africa', 'ML':'Africa', 'BF':'Africa', 'NE':'Africa', 'TD':'Africa', 'MR':'Africa', 'GN':'Africa', 'SL':'Africa', 'LR':'Africa', 'TG':'Africa', 'BJ':'Africa', 'CF':'Africa', 'CG':'Africa', 'CD':'Africa', 'GA':'Africa', 'GQ':'Africa', 'ST':'Africa', 'RW':'Africa', 'BI':'Africa', 'SO':'Africa', 'DJ':'Africa', 'ER':'Africa', 'ZM':'Africa', 'ZW':'Africa', 'MW':'Africa', 'BW':'Africa', 'NA':'Africa', 'LS':'Africa', 'SZ':'Africa', 'KM':'Africa', 'MU':'Africa', 'SC':'Africa', 'CV':'Africa'
    };

    // 【数据库 II】常用的国际或地区独立路权
    const regionKeywords = {
        HK: ['香港', 'HK', 'Hong Kong', '深港', '广港'],
        MO: ['澳门', 'Macau', 'MO', 'Macao'],
        TW: ['台湾', 'Taiwan', 'TW', 'Taipei', '台北', '新北', '中华民国'],
        JP: ['日本', 'Japan', 'JP', '东京', '大阪', '埼玉', '川日', '沪日'],
        KR: ['韩国', 'Korea', 'KR', '首尔', '春川', '南韩'],
        SG: ['新加坡', 'Singapore', 'SG', '狮城', '深新'],
        US: ['美国', 'US', 'America', 'United States', '波特兰', '达拉斯', '俄勒冈', '凤凰城', '费利蒙', '硅谷', '洛杉矶', '圣何塞', '圣克拉拉', '西雅图', '芝加哥', '拉斯维加斯']
    };

    // 【数据库 III】维基百科全量词典 + 高频城市附着
    const continentKeywords = {
        Asia: [
            // 核心高频
            '印度', '阿联酋', '迪拜', '土耳其', '泰国', '印尼', '马来西亚', '菲律宾', '越南', '巴基斯坦', '以色列', '哈萨克斯坦', '柬埔寨', '尼泊尔', '沙特', '孟加拉', '斯里兰卡',
            // 高频城市
            '曼谷', '雅加达', '吉隆坡', '马尼拉', '金边', '万象', '孟买', '新德里', '伊斯兰堡', '卡拉奇', '迪拜', '阿布扎比', '伊斯坦布尔', '安卡拉', '特拉维夫', '耶路撒冷', '德黑兰', 
            // 维基全量冷门国家
            '卡塔尔', '科威特', '伊朗', '伊拉克', '叙利亚', '黎巴嫩', '约旦', '阿曼', '也门', '巴林', '马尔代夫', '缅甸', '老挝', '文莱', '蒙古', '乌兹别克斯坦', '土库曼斯坦', '吉尔吉斯斯坦', '塔吉克斯坦', '阿富汗', '不丹', '塞浦路斯', '格鲁吉亚', '亚美尼亚', '阿塞拜疆'
        ],
        Europe: [
            // 核心高频
            '英国', '法国', '德国', '荷兰', '俄罗斯', '意大利', '瑞士', '瑞典', '西班牙', '葡萄牙', '波兰', '爱尔兰', '奥地利', '芬兰', '丹麦', '冰岛', '挪威', '乌克兰', '比利时',
            // 高频城市
            '伦敦', '巴黎', '法兰克福', '阿姆斯特丹', '莫斯科', '罗马', '米兰', '日内瓦', '苏黎世', '斯德哥尔摩', '马德里', '里斯本', '华沙', '都柏林', '维也纳', '哥本哈根', 
            // 维基全量冷门国家
            '卢森堡', '摩纳哥', '安道尔', '列支敦士登', '圣马力诺', '梵蒂冈', '马耳他', '希腊', '保加利亚', '罗马尼亚', '匈牙利', '捷克', '斯洛伐克', '斯洛文尼亚', '克罗地亚', '波黑', '黑山', '塞尔维亚', '北马其顿', '阿尔巴尼亚', '爱沙尼亚', '拉脱维亚', '立陶宛', '白俄罗斯', '摩尔多瓦'
        ],
        Americas: [
            // 核心高频
            '加拿大', '巴西', '阿根廷', '墨西哥', '智利', '哥伦比亚', '秘鲁', '委内瑞拉', '厄瓜多尔', '古巴', '巴拿马',
            // 高频城市
            '多伦多', '温哥华', '蒙特利尔', '卡尔加里', '渥太华', '圣保罗', '里约热内卢', '布宜诺斯艾利斯', '墨西哥城', '圣地亚哥', '利马',
            // 维基全量冷门国家
            '玻利维亚', '巴拉圭', '乌拉圭', '圭亚那', '苏里南', '法属圭亚那', '伯利兹', '危地马拉', '洪都拉斯', '萨尔瓦多', '尼加拉瓜', '哥斯达黎加', '海地', '多米尼加', '牙买加', '特立尼达', '巴巴多斯', '巴哈马'
        ],
        Oceania: [
            // 核心高频与城市
            '澳大利亚', '澳洲', '新西兰', '悉尼', '墨尔本', '布里斯班', '珀斯', '阿德莱德', '奥克兰', '惠灵顿', '基督城',
            // 维基全量冷门国家
            '巴布亚新几内亚', '所罗门群岛', '瓦努阿图', '斐济', '帕劳', '密克罗尼西亚', '马绍尔群岛', '基里巴斯', '瑙鲁', '图瓦卢', '萨摩亚', '汤加', '纽埃', '库克群岛'
        ],
        Africa: [
            // 核心高频与城市
            '南非', '埃及', '尼日利亚', '摩洛哥', '阿尔及利亚', '肯尼亚', '毛里求斯', '约翰内斯堡', '开普敦', '开罗', '拉各斯', '卡萨布兰卡', '内罗毕',
            // 维基全量冷门国家
            '突尼斯', '利比亚', '苏丹', '埃塞俄比亚', '坦桑尼亚', '乌干达', '安哥拉', '莫桑比克', '马达加斯加', '喀麦隆', '科特迪瓦', '加纳', '塞内加尔', '马里', '布基纳法索', '尼日尔', '乍得', '毛里塔尼亚', '几内亚', '塞拉利昂', '利比里亚', '多哥', '贝宁', '中非', '刚果', '加蓬', '赤道几内亚', '圣多美', '卢旺达', '布隆迪', '索马里', '吉布提', '厄立特里亚', '赞比亚', '津巴布韦', '马拉维', '博茨瓦纳', '纳米比亚', '莱索托', '斯威士兰', '科摩罗', '塞舌尔', '佛得角'
        ]
    };



    // =======================================================
    // 2. 数据流转管道 (Stream Pipeline)
    // =======================================================
    const sorted = {
        All: [], HK: [], MO: [], TW: [], JP: [], KR: [], SG: [], US: [],
        Asia: [], Europe: [], Americas: [], Oceania: [], Africa: []
    };

    const tlsProtocols = ['vmess', 'vless', 'trojan', 'tuic', 'hysteria2'];
    const ignoreKeywords = ['剩余', '到期', '过期', '官网', '流量', '联系', '套餐', '重置', '更新', '群', '邀请', '返回', '网址', '贩卖', '倒卖', 'Expire', 'Traffic'];

    config.proxies.forEach(proxy => {
        const pName = proxy.name;

        // 过滤垃圾探针节点
        if (ignoreKeywords.some(kw => pName.toUpperCase().includes(kw.toUpperCase()))) return;

        // 注入动态高熵指纹，实现 DPI 隐身
        if (proxy.type && tlsProtocols.includes(proxy.type)) {
            proxy['client-fingerprint'] = 'random';
        }

        sorted.All.push(pName); // 纳入全量池

        let matched = false;

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

        if (!matched) {
            for (const [reg, kws] of Object.entries(regionKeywords)) {
                if (kws.some(kw => pName.toUpperCase().includes(kw.toUpperCase()))) {
                    sorted[reg].push(pName);
                    matched = true;
                    break;
                }
            }
        }

        if (!matched) {
            for (const [cont, kws] of Object.entries(continentKeywords)) {
                if (kws.some(kw => pName.toUpperCase().includes(kw.toUpperCase()))) {
                    sorted[cont].push(pName);
                    break;
                }
            }
        }
    });

    // 内存安全熔断器：若某类别彻底无节点，自动塞入保底指针防止内核树崩塌
    const safe = (arr) => arr.length > 0 ? arr : ['节点选择'];



// =======================================================
    // 3. DNS 劫持与引擎纯净化 (防泄露核心)
    // =======================================================
    delete config.dns.fallback;
    delete config.dns['fallback-filter'];
    delete config.dns['default-nameserver'];

    config.dns = {
        ...config.dns, // 继承剩余安全配置
        'prefer-h3': true,
        nameserver: [
            'https://1.1.1.1/dns-query#节点选择',
            'https://8.8.8.8/dns-query#节点选择'
        ],
        'nameserver-policy': {
            'rule-set:Lan': ['system'],
            'rule-set:GeoSite_CN': ['223.5.5.5', '119.29.29.29', '180.184.1.1'],
            'rule-set:Google': ['https://1.1.1.1/dns-query#节点选择', 'https://8.8.8.8/dns-query#节点选择'],
            'rule-set:YouTube': ['https://1.1.1.1/dns-query#节点选择', 'https://8.8.8.8/dns-query#节点选择'],
            'rule-set:Netflix': ['https://1.1.1.1/dns-query#节点选择', 'https://8.8.8.8/dns-query#节点选择']
        }
    };

    if (!config.tun) config.tun = {};
    config.tun['strict-route'] = true;


    // =======================================================
    // 4. 策略组架构重铸 (Proxy Groups)
    // =======================================================
    config['proxy-groups'] = [
        { name: '节点选择', type: 'select', proxies: safe(sorted.All), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Locator.png' },
        
        { name: 'AI Rules', type: 'select', proxies: ['美国节点', '日本节点', '新加坡节点', '节点选择'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Chatbot.png' },
        { name: 'YouTube', type: 'select', proxies: ['节点选择', '香港节点', '美国节点', '新加坡节点'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/YouTube.png' },
        { name: 'Google', type: 'select', proxies: ['美国节点', '香港节点', '新加坡节点', '节点选择'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Google.png' },
        { name: 'Telegram', type: 'select', proxies: ['节点选择', '香港节点', '美国节点', '新加坡节点'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Telegram.png' },
        { name: 'Spotify', type: 'select', proxies: ['DIRECT', '香港节点', '美国节点', '新加坡节点'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Spotify.png' },
        { name: 'TikTok', type: 'select', proxies: ['美国节点', '台湾节点', '日本节点', '新加坡节点'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/TikTok.png' },
        { name: 'Netflix', type: 'select', proxies: ['新加坡节点', '香港节点', '美国节点'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Netflix.png' },
        { name: 'Apple账户', type: 'select', proxies: ['DIRECT', '美国节点', '香港节点'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/iCloud.png' },
        
        { name: '广告拦截', type: 'select', proxies: ['REJECT', 'DIRECT'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Ad Blocker.png' },
        { name: '隐私保护', type: 'select', proxies: ['REJECT', 'DIRECT'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Privacy.png' },
        { name: '反劫持', type: 'select', proxies: ['REJECT', 'DIRECT'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Hijacking.png' },
        { name: '兜底策略', type: 'select', proxies: ['节点选择', '香港节点', '新加坡节点', '美国节点', '亚洲节点', '欧洲节点', '美洲节点', '大洋洲节点', '非洲节点'], icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Rules.png' },

        { name: '香港节点', type: 'select', proxies: safe(sorted.HK), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/HK.png' },
        { name: '澳门节点', type: 'select', proxies: safe(sorted.MO), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/MAC.png' },
        { name: '台湾节点', type: 'select', proxies: safe(sorted.TW), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/CHN.png' },
        { name: '美国节点', type: 'select', proxies: safe(sorted.US), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/USA.png' },
        { name: '日本节点', type: 'select', proxies: safe(sorted.JP), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/JP.png' },
        { name: '韩国节点', type: 'select', proxies: safe(sorted.KR), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/KOR.png' },
        { name: '新加坡节点', type: 'select', proxies: safe(sorted.SG), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/SG.png' },
        
        // 5 大全量兜底聚合洲 (自动接纳维基百科全库中的冷门国家)
        { name: '亚洲节点', type: 'select', proxies: safe(sorted.Asia), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Asia.png' },
        { name: '欧洲节点', type: 'select', proxies: safe(sorted.Europe), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Europe.png' },
        { name: '美洲节点', type: 'select', proxies: safe(sorted.Americas), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Americas.png' },
        { name: '大洋洲节点', type: 'select', proxies: safe(sorted.Oceania), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Oceania.png' },
        { name: '非洲节点', type: 'select', proxies: safe(sorted.Africa), icon: 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/Africa.png' }
    ];



    // =======================================================
    // 5. 规则集
    // =======================================================
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

    // 分流终端
    config.rules = [
        'AND,((NETWORK,UDP),(DST-PORT,443)),REJECT',
        'RULE-SET,AdRules,广告拦截',
        'RULE-SET,Privacy,隐私保护',
        'RULE-SET,WinSpy,隐私保护',
        'RULE-SET,Hijacking,反劫持',
        'RULE-SET,Hijacking_IP,反劫持,no-resolve',
        'RULE-SET,Lan,DIRECT',
        'RULE-SET,Lan_IP,DIRECT,no-resolve',
        'RULE-SET,GameDownloadCN,DIRECT',
        'DST-PORT,123,DIRECT',
        'RULE-SET,OpenAI,AI Rules',
        'RULE-SET,Gemini,AI Rules',
        'RULE-SET,Claude,AI Rules',
        'RULE-SET,Copilot,AI Rules',
        'RULE-SET,YouTube,YouTube',
        'RULE-SET,Netflix,Netflix',
        'RULE-SET,TikTok,TikTok',
        'RULE-SET,Spotify,Spotify',
        'RULE-SET,Telegram,Telegram',
        'RULE-SET,Google,Google',
        'RULE-SET,AppleID,Apple账户',
        'RULE-SET,Apple,Apple账户',
        'RULE-SET,GeoSite_CN,DIRECT',
        'RULE-SET,Telegram_IP,Telegram,no-resolve',
        'RULE-SET,Google_IP,Google,no-resolve',
        'RULE-SET,YouTube_IP,YouTube,no-resolve',
        'RULE-SET,Netflix_IP,Netflix,no-resolve',
        'RULE-SET,GeoIP_CN,DIRECT,no-resolve',
        'MATCH,兜底策略'
    ];

    return config;
}
