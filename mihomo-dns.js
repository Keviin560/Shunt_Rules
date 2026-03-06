/**
 * 作者：Keviin560
 * 更新日期：2026-03-07
 * 
 * -------------------------------------------------------------------------------------------------------------------------
 * 【 ⚙️ 核心架构说明 】
 * ->  全局接管 GUI 设置：覆盖客户端的设置 (如端口/嗅探/TUN)，实现底层参数统一
 * ->  动态指纹防封：为 TLS 协议 (VMess/VLESS/Trojan/AnyTLS 协议) 动态挂载 random 高熵指纹
 * ->  五大洲节点自动筛选：Unicode 国旗解码；内置 240+ 国家与城市中英双语及高频三字码字典
 * ->  自动隐藏无节点分组 ：没有节点的分组会自动隐藏分组，并自动修复依赖
 * ->  智能规则：自动识别名字带 "_IP" 的规则，自动按 IP 拦截处理；带 ".txt" 的规则，自动按文本处理
 * ->  PASS 策略智能分流：针对 Apple 和 Microsoft 流量引入 PASS 策略，实现动态判定分流
 * 
 * -------------------------------------------------------------------------------------------------------------------------
 * 【 ⚠️ 小白用户必读设置 】
 * ->  全局仓库锚点：可以自行更改所需的全局规则仓库和 icon 仓库
 * ->  浏览器防漏： Chrome/Edge 设置 -> 隐私与安全 -> 关闭 "使用安全 DNS"。防止浏览器绕过客户端自己去解析 DNS，导致分流失败
 * ->   IPv6 相关设置（二选一）：
 *   - 【不用 IPv6，默认】 ：在 [基础设置与全量接管] 和 [DNS 劫持与底层防漏] 里把 [IPv6] 改为 false ；同时在系统的物理网卡（一般是 WLAN 或 以太网）里关闭 IPv6 ，即关闭 Internet 协议版本 6 (TCP/IPv6)
 *   - 【用 IPv6】 ：在 [基础设置与全量接管] 和 [DNS 劫持与底层防漏] 里把 [IPv6] 改为 ture ，把 IPv6 虚假 IP 池填写 [fc00::/18]；并在电脑物理网卡里选 [使用下面的 DNS 服务器地址]，填入 [::1]
 * 
 * -------------------------------------------------------------------------------------------------------------------------
 * 【 🛠️ 修改与维护】
 * ->  如果冷门国家节点未被识别：请在第 1 部分的 `continentRegexes` (五大洲兜底扫描) 里，加入对应的中文或英文，比如在欧洲里面加上 `|冰岛`。
 * ->  想新增独立国家/地区分组（例如新增“英国节点”）：
 *   - 找分组：在 `regionRegexes` (独立分组节点扫描) 中加一行：`['UK', /英国|伦敦|UK/i],`
 *   - 加空盒：在 `sorted` 准备盒子里加一个空数组：`UK: [],`
 *   - 上名单：在 `regionsConfig` (候选名单) 里加一行：`{ tag: 'UK', name: '英国节点', icon: iconBase + 'UK.png' },`
 *
 * -------------------------------------------------------------------------------------------------------------------------
 */


function main(config) {
    // 【系统自检】：确保软件传进来的节点列表是正常的，防止一启动就崩溃
    if (!config.proxies || !Array.isArray(config.proxies)) config.proxies = [];
    
    // 删掉旧版的全局指纹配置，避免冲突
    delete config['global-client-fingerprint'];

    // =======================================================
    // 🛠️ 全局仓库锚点区 (修改这里，全局生效)
    // 要换规则集或 icon 图标，修改下面这两行
    // =======================================================
    const iconBase = 'https://raw.githubusercontent.com/Keviin560/resources/main/icon/';
    const ruleBase = 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/';

    
    // =======================================================
    // 0. 基础设置与全量接管
    // =======================================================
    Object.assign(config, {
        mode: 'rule',                  // 强制使用规则分流模式
        'mixed-port': 7890,            // 统一混合代理端口为 7890
        'allow-lan': true,             // 允许局域网里的其他设备（如手机、电视）连上这个代理
        'log-level': 'info',           // 日志记录级别
        ipv6: false,                   // ⚠️ 默认关闭 IPv6 (若需开启请改为 true ，并认真阅读头部说明)
        'find-process-mode': 'strict', // 严格匹配电脑里的软件进程，分流更准
        'unified-delay': true,         // 显示节点真实的物理延迟，去掉虚高的握手时间
        'keep-alive-interval': 15      // 探针保活核心：全局 TCP 底层保活，每 15 秒发送心跳包，防 NAT 僵死
    });

    // 【流量嗅探器】    
    // 强制捕获真实的网站域名，解决 DNS 污染
    config.sniffer = {
        enable: true,
        'override-destination': true,  // 强制用嗅探到的真实域名覆盖虚假 IP
        'force-domain': ['+'],         // 对所有流量进行嗅探
        sniff: {
            HTTP: { 
                ports: [80, 8080], 
                'override-destination': true 
            },
            TLS: { 
                ports: [443, 8443] 
            },
            QUIC: { 
                ports: [443, 8443]
            } 
        },
        'skip-domain': [               // 以下域名不嗅探，防止国内智能家居或苹果推送断线
            'Mijia Cloud', 
            '*.apple.com', 
            '*.icloud.com'
        ]
    };

    // 【虚拟网卡 TUN 设置】
    config.tun = Object.assign(config.tun || {}, {
        enable: true,                  // 强制开启 TUN 虚拟网卡
        stack: 'system',               // 采用系统级网络栈
        'auto-route': true,            // 自动把全局流量吸入 TUN
        'auto-detect-interface': true, // 自动找出口网卡
        'dns-hijack': ['any:53'],      // 劫持本机所有乱跑的 DNS 域名解析请求
        'strict-route': true           // ⚠️ 物理防漏核心：锁死物理网卡并发，彻底切断国内运营商的监控
    });

    // 【防断网保护伞】
    // 用 try...catch 包裹核心逻辑。防止遇到奇葩节点名报错
    try {
        // =======================================================
        // 1. 分类扫描与微型国家字典
        // =======================================================
        
        // 【国旗提取器】：识别节点名里的 Emoji 国旗
        const emojiRegex = /[\uD83C][\uDDE6-\uDDFF][\uD83C][\uDDE6-\uDDFF]/;
        const extractISO = (str) => {
            const match = str.match(emojiRegex);
            return match ? String.fromCharCode(match[0].charCodeAt(1) - 0xDDE6 + 65) + 
                           String.fromCharCode(match[0].charCodeAt(3) - 0xDDE6 + 65) : null;
        };

        // 【国家转大洲】
        const isoToContinentMap = new Map([
            ['IN','Asia'], ['AE','Asia'], ['TR','Asia'], ['TH','Asia'], ['ID','Asia'], ['MY','Asia'], ['PH','Asia'], ['VN','Asia'], ['PK','Asia'], ['IL','Asia'], ['KZ','Asia'], ['KH','Asia'], ['NP','Asia'], ['SA','Asia'], ['IR','Asia'], ['IQ','Asia'], ['SY','Asia'], ['LB','Asia'], ['JO','Asia'], ['OM','Asia'], ['YE','Asia'], ['QA','Asia'], ['BH','Asia'], ['KW','Asia'], ['BD','Asia'], ['LK','Asia'], ['MV','Asia'], ['MM','Asia'], ['LA','Asia'], ['BN','Asia'], ['TL','Asia'], ['MN','Asia'], ['UZ','Asia'], ['TM','Asia'], ['KG','Asia'], ['TJ','Asia'], ['AF','Asia'], ['BT','Asia'], ['CY','Asia'], ['GE','Asia'], ['AM','Asia'], ['AZ','Asia'],
            ['GB','Europe'], ['FR','Europe'], ['DE','Europe'], ['NL','Europe'], ['RU','Europe'], ['IT','Europe'], ['CH','Europe'], ['SE','Europe'], ['ES','Europe'], ['PT','Europe'], ['PL','Europe'], ['IE','Europe'], ['AT','Europe'], ['FI','Europe'], ['DK','Europe'], ['IS','Europe'], ['NO','Europe'], ['UA','Europe'], ['BE','Europe'], ['LU','Europe'], ['MC','Europe'], ['AD','Europe'], ['LI','Europe'], ['SM','Europe'], ['VA','Europe'], ['MT','Europe'], ['GR','Europe'], ['BG','Europe'], ['RO','Europe'], ['HU','Europe'], ['CZ','Europe'], ['SK','Europe'], ['SI','Europe'], ['HR','Europe'], ['BA','Europe'], ['ME','Europe'], ['RS','Europe'], ['MK','Europe'], ['AL','Europe'], ['EE','Europe'], ['LV','Europe'], ['LT','Europe'], ['BY','Europe'], ['MD','Europe'],
            ['CA','Americas'], ['BR','Americas'], ['AR','Americas'], ['MX','Americas'], ['CL','Americas'], ['CO','Americas'], ['PE','Americas'], ['VE','Americas'], ['EC','Americas'], ['BO','Americas'], ['PY','Americas'], ['UY','Americas'], ['GY','Americas'], ['SR','Americas'], ['GF','Americas'], ['BZ','Americas'], ['GT','Americas'], ['HN','Americas'], ['SV','Americas'], ['NI','Americas'], ['CR','Americas'], ['PA','Americas'], ['CU','Americas'], ['HT','Americas'], ['DO','Americas'], ['JM','Americas'], ['TT','Americas'], ['BB','Americas'], ['BS','Americas'],
            ['AU','Oceania'], ['NZ','Oceania'], ['PG','Oceania'], ['SB','Oceania'], ['VU','Oceania'], ['FJ','Oceania'], ['PW','Oceania'], ['FM','Oceania'], ['MH','Oceania'], ['KI','Oceania'], ['NR','Oceania'], ['TV','Oceania'], ['WS','Oceania'], ['TO','Oceania'], ['NU','Oceania'], ['CK','Oceania'],
            ['ZA','Africa'], ['EG','Africa'], ['NG','Africa'], ['MA','Africa'], ['DZ','Africa'], ['TN','Africa'], ['LY','Africa'], ['SD','Africa'], ['ET','Africa'], ['KE','Africa'], ['TZ','Africa'], ['UG','Africa'], ['AO','Africa'], ['MZ','Africa'], ['MG','Africa'], ['CM','Africa'], ['CI','Africa'], ['GH','Africa'], ['SN','Africa'], ['ML','Africa'], ['BF','Africa'], ['NE','Africa'], ['TD','Africa'], ['MR','Africa'], ['GN','Africa'], ['SL','Africa'], ['LR','Africa'], ['TG','Africa'], ['BJ','Africa'], ['CF','Africa'], ['CG','Africa'], ['CD','Africa'], ['GA','Africa'], ['GQ','Africa'], ['ST','Africa'], ['RW','Africa'], ['BI','Africa'], ['SO','Africa'], ['DJ','Africa'], ['ER','Africa'], ['ZM','Africa'], ['ZW','Africa'], ['MW','Africa'], ['BW','Africa'], ['NA','Africa'], ['LS','Africa'], ['SZ','Africa'], ['KM','Africa'], ['MU','Africa'], ['SC','Africa'], ['CV','Africa']
        ]);

        // 【独立分组名单】：这些国家（港澳台日韩新美）的节点单独成立一个策略组
        const specialISOs = new Set(['HK', 'MO', 'TW', 'JP', 'KR', 'SG', 'US']);
        
        // 【高级隐身名单】：以下协议加上高随机度的防封锁指纹
        const tlsProtocols = new Set(['vmess', 'vless', 'trojan', 'tuic', 'hysteria2']);

        // 【净化】：过滤掉“剩余流量”、“到期”等信息
        const ignoreRegex = /剩余|到期|过期|官网|流量|联系|套餐|重置|更新|交流群|TG群|QQ群|电报群|群组|邀请|返回|网址|贩卖|倒卖|Expire|Traffic/i;
        
        // 【独立分组扫描】：包含中英文和三字码，一旦匹配上，立刻放到对应的盒子里
        const regionRegexes = [
            ['HK', /香港|HK|Hong Kong|深港|广港/i], 
            ['MO', /澳门|Macau|MO|Macao/i],
            ['TW', /台湾|Taiwan|TW|Taipei|台北|新北|中华民国/i], 
            ['JP', /日本|Japan|JP|东京|大阪|埼玉|川日|沪日/i],
            ['KR', /韩国|Korea|KR|首尔|春川|南韩/i], 
            ['SG', /新加坡|Singapore|SG|狮城|深新/i],
            ['US', /美国|US|America|United States|波特兰|达拉斯|俄勒冈|凤凰城|费利蒙|硅谷|洛杉矶|圣何塞|圣克拉拉|西雅图|芝加哥|拉斯维加斯/i]
        ];

        // 【五大洲兜底扫描】：冷门国家丢进对应大洲
        const continentRegexes = [
            ['Asia', /印度|阿联酋|迪拜|土耳其|泰国|印尼|马来西亚|菲律宾|越南|巴基斯坦|以色列|哈萨克斯坦|柬埔寨|尼泊尔|沙特|孟加拉|斯里兰卡|曼谷|雅加达|吉隆坡|马尼拉|金边|万象|孟买|新德里|伊斯兰堡|卡拉奇|阿布扎比|伊斯坦布尔|安卡拉|特拉维夫|耶路撒冷|德黑兰|卡塔尔|科威特|伊朗|伊拉克|叙利亚|黎巴嫩|约旦|阿曼|也门|巴林|马尔代夫|缅甸|老挝|文莱|蒙古|乌兹别克斯坦|土库曼斯坦|吉尔吉斯斯坦|塔吉克斯坦|阿富汗|不丹|塞浦路斯|格鲁吉亚|亚美尼亚|阿塞拜疆|Pakistan|PAK|India|IND|Malaysia|MYS|Indonesia|IDN|Thailand|THA|Vietnam|VNM|Cambodia|KHM|Philippines|PHL|Turkey|TUR|Kazakhstan|KAZ|Dubai|UAE|Israel|ISR|Saudi Arabia|SAU|Bangladesh|BGD/i],
            ['Europe', /英国|法国|德国|荷兰|俄罗斯|意大利|瑞士|瑞典|西班牙|葡萄牙|波兰|爱尔兰|奥地利|芬兰|丹麦|冰岛|挪威|乌克兰|比利时|伦敦|巴黎|法兰克福|阿姆斯特丹|莫斯科|罗马|米兰|日内瓦|苏黎世|斯德哥尔摩|马德里|里斯本|华沙|都柏林|维也纳|哥本哈根|卢森堡|摩纳哥|安道尔|列支敦士登|圣马力诺|梵蒂冈|马耳他|希腊|保加利亚|罗马尼亚|匈牙利|捷克|斯洛伐克|斯洛文尼亚|克罗地亚|波黑|黑山|塞尔维亚|北马其顿|阿尔巴尼亚|爱沙尼亚|拉脱维亚|立陶宛|白俄罗斯|摩尔多瓦|UK|United Kingdom|France|FRA|Germany|DEU|Netherlands|NLD|Russia|RUS|Italy|ITA|Switzerland|CHE|Sweden|SWE|Spain|ESP|Poland|POL|Ireland|IRL|Austria|AUT|Denmark|DNK|Norway|NOR|Iceland|ISL|Ukraine|UKR|Czech|CZE|Hungary|HUN|Romania|ROU|Bulgaria|BGR|Greece|GRC/i],
            ['Americas', /加拿大|巴西|阿根廷|墨西哥|智利|哥伦比亚|秘鲁|委内瑞拉|厄瓜多尔|古巴|巴拿马|多伦多|温哥华|蒙特利尔|卡尔加里|渥太华|圣保罗|里约热内卢|布宜诺斯艾利斯|墨西哥城|圣地亚哥|利马|玻利维亚|巴拉圭|乌拉圭|圭亚那|苏里南|法属圭亚那|伯利兹|危地马拉|洪都拉斯|萨尔瓦多|尼加拉瓜|哥斯达黎加|海地|多米尼加|牙买加|特立尼达|巴巴多斯|巴哈马|Canada|CAN|Toronto|YTO|YYZ|Vancouver|YVR|Montreal|YMQ|Mexico|MEX|Brazil|BRA|Argentina|ARG|Chile|CHL|Colombia|COL|Peru|PER/i],
            ['Oceania', /澳大利亚|澳洲|新西兰|悉尼|墨尔本|布里斯班|珀斯|阿德莱德|奥克兰|惠灵顿|基督城|巴布亚新几内亚|所罗门群岛|瓦努阿图|斐济|帕劳|密克罗尼西亚|马绍尔群岛|基里巴斯|瑙鲁|图瓦卢|萨摩亚|汤加|纽埃|库克群岛|Australia|AUS|New Zealand|NZL|Fiji|FJI|Sydney|Melbourne|Auckland/i],
            ['Africa', /南非|埃及|尼日利亚|摩洛哥|阿尔及利亚|肯尼亚|毛里求斯|约翰内斯堡|开普敦|开罗|拉各斯|卡萨布兰卡|内罗毕|突尼斯|利比亚|苏丹|埃塞俄比亚|坦桑尼亚|乌干达|安哥拉|莫桑比克|马达加斯加|喀麦隆|科特迪瓦|加纳|塞内加尔|马里|布基纳法索|尼日尔|乍得|毛里塔尼亚|几内亚|塞拉利昂|利比里亚|多哥|贝宁|中非|刚果|加蓬|赤道几内亚|圣多美|卢旺达|布隆迪|索马里|吉布提|厄立特里亚|赞比亚|津巴布韦|马拉维|博茨瓦纳|纳米比亚|莱索托|斯威士兰|科摩罗|塞舌尔|佛得角|South Africa|ZAF|Egypt|EGY|Nigeria|NGA|Morocco|MAR|Kenya|KEN/i]
        ];

        // =======================================================
        // 2. 把所有节点分别装进对应的“盒子”里
        // =======================================================
        
        // 空盒子区
        const sorted = {
            All: [], HK: [], MO: [], TW: [], JP: [], KR: [], SG: [], US: [],
            Asia: [], Europe: [], Americas: [], Oceania: [], Africa: []
        };

        for (const proxy of config.proxies) {
            const pName = proxy.name;
            
            // 无视没有名字的节点或广告信息
            if (!pName || ignoreRegex.test(pName)) continue; 

            // 【隐身模式】：给高级节点挂上动态指纹
            if (proxy.type && tlsProtocols.has(proxy.type)) {
                proxy['client-fingerprint'] = 'random'; 
            }

            // 先全部装进 "All (全量池)" 
            sorted.All.push(pName);
            let matched = false;

            // 第一步：识别 Emoji 国旗
            const isoCode = extractISO(pName);
            if (isoCode) {
                if (specialISOs.has(isoCode)) {
                    sorted[isoCode].push(pName); 
                    continue; 
                } 
                const continent = isoToContinentMap.get(isoCode);
                if (continent) {
                    sorted[continent].push(pName); 
                    continue; 
                }
            }

            // 第二步：识别关键字
            for (const [reg, regex] of regionRegexes) {
                if (regex.test(pName)) {
                    sorted[reg].push(pName); 
                    matched = true; 
                    break;
                }
            }
            if (matched) continue;

            // 第三步：五大洲兜底
            for (const [cont, regex] of continentRegexes) {
                if (regex.test(pName)) {
                    sorted[cont].push(pName); 
                    break;
                }
            }
        }

        // =======================================================
        // 3. DNS 劫持与底层防漏
        // =======================================================
        config.dns = config.dns || {};
        
        // ⚠️ 接管 GUI 里的 DNS 设置，切断侧漏
        delete config.dns.fallback; 
        delete config.dns['fallback-filter']; 
        delete config.dns['default-nameserver'];

        Object.assign(config.dns, {
            'default-nameserver': [
                '223.5.5.5', 
                '119.29.29.29'
            ],
            enable: true, 
            listen: '0.0.0.0:1053', 
            ipv6: false,      // ⚠️ 保持与外部基础设置同步
            'enhanced-mode': 'fake-ip',       // 秒回假 IP 机制
            'fake-ip-range': '198.18.0.1/16',       // 假 IP 响应池
           // 'fake-ip-range6': 'fc00::/18',      // ⚠️ 假 IPv6 响应池，若开启 IPv6 请取消注释
            'prefer-h3': true,      // 优先使用 HTTP/3 (QUIC) 查询 DNS，降延迟
            
            // 💡 Fake-IP 过滤器：强制让这些域名返回真实 IP
            'fake-ip-filter': [ 
                'rule-set:Lan',                 // 联动 Lan 规则集，确保局域网设备互访正常
                'stun.*',                       // 豁免 WebRTC/STUN 穿透服务器
                '*.stun.*',
                '*.+.msftncsi.com',             // 微软 NCSI 网络状态指示器，获取真实 IP
                '*.+.msftconnecttest.com',      // 微软连接测试，获取真实 IP
                '*.+.market.xiaomi.com',
                '*.local',                      // 豁免 mDNS 局域网多播
                '*.ptlogin2.qq.com',            // 解决国内快捷登录在 Fake-IP 下失效的顽疾
                '+.pool.ntp.org'                // 时间同步，防止系统时钟失真导致证书验证失败                
            ],
            
            // 国外的兜底安全 DNS 通道
            nameserver: [ 
                'https://1.1.1.1/dns-query#节点选择', 
                'https://8.8.8.8/dns-query#节点选择' 
            ],
            
            // 智能 DNS 分流：国内查直连，国外查 DoH
            'nameserver-policy': {
                'rule-set:Lan': ['system'],
                'rule-set:GeoSite_CN': [
                    '223.5.5.5', 
                    '119.29.29.29', 
                    '180.184.1.1'
                ],
                'rule-set:Google': [
                    'https://1.1.1.1/dns-query#节点选择', 
                    'https://8.8.8.8/dns-query#节点选择'
                ],
                'rule-set:YouTube': [
                    'https://1.1.1.1/dns-query#节点选择', 
                    'https://8.8.8.8/dns-query#节点选择'
                ],
                'rule-set:Netflix': [
                    'https://1.1.1.1/dns-query#节点选择', 
                    'https://8.8.8.8/dns-query#节点选择'
                ]
            }
        });

        // =======================================================
        // 4. 动态分组与探针注入
        // =======================================================
        
        // 📋【存活白名单】：把基础选项加入白名单，防止被当成空节点清理掉
        const activeGroups = new Set(['节点选择', 'DIRECT', 'REJECT', 'PASS']);
        const dynamicGroupsList = [];

        // 🗺️ 这是一个“候选名单”。不管机场有没有，先全部列出来。图标自动通过锚点拼接
        const regionsConfig = [
            { tag: 'HK', name: '香港节点', icon: iconBase + 'HK.png' },
            { tag: 'MO', name: '澳门节点', icon: iconBase + 'MAC.png' },
            { tag: 'TW', name: '台湾节点', icon: iconBase + 'CHN.png' },
            { tag: 'US', name: '美国节点', icon: iconBase + 'USA.png' },
            { tag: 'JP', name: '日本节点', icon: iconBase + 'JP.png' },
            { tag: 'KR', name: '韩国节点', icon: iconBase + 'KOR.png' },
            { tag: 'SG', name: '新加坡节点', icon: iconBase + 'SG.png' },
            { tag: 'Asia', name: '亚洲节点', icon: iconBase + 'Asia.png' },
            { tag: 'Europe', name: '欧洲节点', icon: iconBase + 'Europe.png' },
            { tag: 'Americas', name: '美洲节点', icon: iconBase + 'Americas.png' },
            { tag: 'Oceania', name: '大洋洲节点', icon: iconBase + 'Oceania.png' },
            { tag: 'Africa', name: '非洲节点', icon: iconBase + 'Africa.png' }
        ];

        // 🪄 【自动隐藏空节点分组 + 探针保活注入】
        for (const r of regionsConfig) {
            if (sorted[r.tag].length > 0) {
                dynamicGroupsList.push({ 
                    name: r.name, 
                    type: 'select', 
                    proxies: sorted[r.tag], 
                    icon: r.icon,
                    url: 'https://www.gstatic.com/generate_204', // 注入保活探针网址
                    interval: 300,                               // 每 5 分钟在后台悄悄发一次请求，一天几百 KB
                    timeout: 3000
                });
                activeGroups.add(r.name); // 把它加入“存活白名单”
            }
        }

        // 📱 这里是你面板上看到的功能应用分组，图标同样全自动拼接
        const appGroups = [
            { name: 'AI Rules', type: 'select', proxies: ['美国节点', '日本节点', '新加坡节点', '节点选择'], icon: iconBase + 'Chatbot.png' },
            { name: 'YouTube', type: 'select', proxies: ['节点选择', '香港节点', '美国节点', '新加坡节点'], icon: iconBase + 'YouTube.png' },
            { name: 'Google', type: 'select', proxies: ['美国节点', '香港节点', '新加坡节点', '节点选择'], icon: iconBase + 'Google.png' },
            { name: 'Telegram', type: 'select', proxies: ['节点选择', '香港节点', '美国节点', '新加坡节点'], icon: iconBase + 'Telegram.png' },
            { name: 'Spotify', type: 'select', proxies: ['DIRECT', '香港节点', '美国节点', '新加坡节点'], icon: iconBase + 'Spotify.png' },
            { name: 'TikTok', type: 'select', proxies: ['美国节点', '台湾节点', '日本节点', '新加坡节点'], icon: iconBase + 'TikTok.png' },
            { name: 'Netflix', type: 'select', proxies: ['新加坡节点', '香港节点', '美国节点'], icon: iconBase + 'Netflix.png' },
            { name: '广告拦截', type: 'select', proxies: ['REJECT', 'DIRECT'], icon: iconBase + 'Ad Blocker.png' },
            { name: '隐私保护', type: 'select', proxies: ['REJECT', 'DIRECT'], icon: iconBase + 'Privacy.png' },
            { name: '反劫持', type: 'select', proxies: ['REJECT', 'DIRECT'], icon: iconBase + 'Hijacking.png' },
            { name: '兜底策略', type: 'select', proxies: ['节点选择', '香港节点', '新加坡节点', '美国节点', '亚洲节点', '欧洲节点', '美洲节点', '大洋洲节点', '非洲节点'], icon: iconBase + 'Rules.png' }
        ];

        // 🪄 【依赖 + 探针保活注入】
        for (const g of appGroups) {
            // 自动扫描剔除不存在的国家节点，防止内核崩溃
            g.proxies = g.proxies.filter(p => activeGroups.has(p));
            if (g.proxies.length === 0) g.proxies = ['节点选择'];
            
            // 注入探针机制：确保各种流媒体选项卡也能防断流
            g.url = 'https://www.gstatic.com/generate_204';
            g.interval = 300;
            g.timeout = 3000;
        }

        // 拼装最终显示的策略组
        const baseGroups = [
            { 
                name: '节点选择', 
                type: 'select', 
                proxies: sorted.All.length > 0 ? sorted.All : ['DIRECT'], 
                icon: iconBase + 'Locator.png',
                url: 'https://www.gstatic.com/generate_204', // 兜底防断流探针
                interval: 300,
                timeout: 3000
            }
        ];
        config['proxy-groups'] = [...baseGroups, ...appGroups, ...dynamicGroupsList];


        // =======================================================
        // 5. 规则区
        // =======================================================
        
        // ⚡ 【全自动判定】：
        // 1. 如果填了 customUrl (别人的规则)，就用别人的；没填则自动用顶部锚点拼接
        // 2. 只要名字里带 "_IP" 自动按 IP 拦截（引用了别人的规则，可以视情况添加 “|| name.includes('IP')”，这里表示包含 "IP" ）
        const buildRule = (name, customUrl = null) => {
            const isIP = name.endsWith('_IP'); 
            const finalUrl = customUrl || `${ruleBase}${name}.mrs`; // 统一使用 mrs 后缀拼接
            const isText = finalUrl.endsWith('.txt'); // 自动判断是不是文本格式

            return {
                type: 'http',
                format: isText ? 'text' : 'mrs',                   // 自动分配格式
                behavior: isIP ? 'ipcidr' : 'domain',              // 自动分配拦截行为
                interval: 86400 + Math.floor(Math.random() * 600), // ⚡ 随机加 0~10 分钟防拥堵
                proxy: '节点选择',
                url: finalUrl,
                path: `./rules/${name}.${isText ? 'txt' : 'mrs'}`  // 本地文件也自动归类
            };
        };

        // 👇 配置区
        config['rule-providers'] = {
            // 外部特殊规则（手动填网址）
            AdRules:        buildRule('AdRules', 'https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules-mihomo.mrs'),
            WinSpy:         buildRule('WinSpy',  'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/win-spy.txt'),
            
            // 全局的规则仓库（填写 锚定规则仓库 中的规则名，系统会自动完成）
            Privacy:        buildRule('Privacy'),
            Hijacking:      buildRule('Hijacking'),
            Hijacking_IP:   buildRule('Hijacking_IP'), 
            Lan:            buildRule('Lan'),
            Lan_IP:         buildRule('Lan_IP'),
            GameDownloadCN: buildRule('GameDownloadCN'),
            GeoSite_CN:     buildRule('GeoSite_CN'), 
            GeoIP_CN_IP:       buildRule('GeoIP_CN_IP'), 
            OpenAI:         buildRule('OpenAI'),
            Gemini:         buildRule('Gemini'),
            Claude:         buildRule('Claude'),
            Copilot:        buildRule('Copilot'),
            YouTube:        buildRule('YouTube'),
            YouTube_IP:     buildRule('YouTube_IP'),
            Netflix:        buildRule('Netflix'),
            Netflix_IP:     buildRule('Netflix_IP'),
            TikTok:         buildRule('TikTok'),
            Spotify:        buildRule('Spotify'),
            Telegram:       buildRule('Telegram'),
            Telegram_IP:    buildRule('Telegram_IP'),
            Google:         buildRule('Google'),
            Google_IP:      buildRule('Google_IP'),
            AppleID:        buildRule('AppleID'),
            Apple:          buildRule('Apple'),
            Microsoft:      buildRule('Microsoft')
        };

        // =======================================================
        // 6. 规则集
        // =======================================================
        config.rules = [
            // ===============================================
            // 🛡️ 第一层：净化与拦截
            // ===============================================
            'AND,((NETWORK,UDP),(DST-PORT,443)),REJECT', 
            'RULE-SET,AdRules,广告拦截',
            // 屏蔽隐私收集/遥测收集/行为埋点/性能监控/网页性标/诊断数据上传
            'DOMAIN-REGEX,^(crash|metrics|track|report|api|stat|collect|telemetry|apm|sdk|event|events|trace|beacon|analytics|probe|upload|diag)\\.log\\.,REJECT',
            'RULE-SET,Privacy,隐私保护',
            'RULE-SET,WinSpy,隐私保护',
            'RULE-SET,Hijacking,反劫持',
            'RULE-SET,Hijacking_IP,反劫持,no-resolve',   
          
            // ===============================================
            // 🏠 第二层：局域网与基础直连
            // ===============================================
            'RULE-SET,Lan,DIRECT',
            'RULE-SET,Lan_IP,DIRECT,no-resolve',
            'RULE-SET,GameDownloadCN,DIRECT',
            'DST-PORT,123,DIRECT',                      

            // ===============================================
            // 🚫 第三层：P2P/BT 流量
            // ===============================================
            // 1.  P2P 默认端口
            'DST-PORT,6881-6889,DIRECT', 
            'DST-PORT,51413,DIRECT', // Transmission 默认端口
            // 2.  BT 追踪器与特殊特征域名
            'DOMAIN-KEYWORD,tracker,DIRECT',
            'DOMAIN-KEYWORD,torrent,DIRECT',
            'DOMAIN-KEYWORD,announce,DIRECT',
             // 3. 匹配主流下载器进程直连
            'PROCESS-NAME,aria2c.exe,DIRECT',
            'PROCESS-NAME,BitComet.exe,DIRECT',
            'PROCESS-NAME,qbittorrent.exe,DIRECT',
            'PROCESS-NAME,transmission-daemon.exe,DIRECT',
            'PROCESS-NAME,transmission-qt.exe,DIRECT',
            'PROCESS-NAME,Thunder.exe,DIRECT',           // 迅雷主程序
            'PROCESS-NAME,DownloadSDKServer.exe,DIRECT', // 迅雷底层下载核心进程
            'PROCESS-NAME,uTorrent.exe,DIRECT',
            'PROCESS-NAME,WebTorrent.exe,DIRECT',
            
            // ===============================================
            // 🚀 第四层：各大应用智能分流
            // ===============================================
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
            
            // ===============================================
            // 🍏 第五层：特殊通行证
            // ===============================================
            'RULE-SET,AppleID,PASS',
            'RULE-SET,Apple,PASS',
            'RULE-SET,Microsoft,PASS',
            
            // ===============================================
            // 🇨🇳 第六层：国内直连兜底
            // ===============================================
            'RULE-SET,GeoSite_CN,DIRECT', 
            
            // ===============================================
            // 🕳️ 第七层：IP 补漏层
            // ===============================================
            'RULE-SET,Telegram_IP,Telegram,no-resolve',
            'RULE-SET,Google_IP,Google,no-resolve',
            'RULE-SET,YouTube_IP,YouTube,no-resolve',
            'RULE-SET,Netflix_IP,Netflix,no-resolve',
            'RULE-SET,GeoIP_CN_IP,DIRECT,no-resolve', 
            
            // ===============================================
            // 🌍 兜底：所有未匹配规则的外国流量
            // ===============================================
            'MATCH,兜底策略'
        ];

    } catch (error) {
        // 【系统自救机制触发】
        console.log("[架构师防御机制]: 预处理脚本执行遭遇异常", error);
    }

    // 完整配置给 Mihomo 核心运行
    return config; 
}
