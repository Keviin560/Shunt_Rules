/**
 * 作者：Keviin560
 * 版本：v1.5
 * 更新日期：2026-06-17
 *
 * -------------------------------------------------------------------------------------------------------------------------
 * 【 v1.5 更新日志 】
 * 1. 修复：修复了一个致命崩溃漏洞
 * 2. 隐私增强：新增全局拦截外部明文 DNS 查询 (UDP 53 端口)，强制所有 App 走内核加密 DNS
 * 3. 防跟踪增强：新增对 telemetry、app-measurement、appsflyer、bugly、umeng 等流氓设备指纹探针的全局封杀
 * 4. 备用策略：新增 WebRTC 真实 IP 泄漏防护规则（默认注释屏蔽，供对隐私要求极高的可按需开启）
 *
 * -------------------------------------------------------------------------------------------------------------------------
 * 【 ⚙️ 核心架构说明 】
 * ->  动态指纹防封：为 TLS 协议 (VMess/VLESS/Trojan/AnyTLS 协议) 动态挂载 random 高熵指纹
 * ->  五大洲节点自动筛选：Unicode 国旗解码；内置国家与城市三字码字典
 * ->  自动隐藏无节点分组 ：没有节点的组会自动隐藏，并自动修复依赖
 * ->  智能规则：自动识别名字带 "_IP" 的规则，自动按 IP 拦截处理；带 ".txt" 的规则，自动按文本处理
 * 
 * -------------------------------------------------------------------------------------------------------------------------
 * 【 ⚠️ 必读设置与防卡顿优化 】
 * ->  全局仓库锚点：可以自行更改所需的规则或 icon 仓库
 * ->  浏览器防漏： Chrome/Edge 设置 -> 隐私与安全 -> 关闭 "使用安全 DNS"，防止浏览器绕过客户端自己去解析 DNS
 * ->  Windows 用户：关闭 "智能多宿主名称解析" (组策略或注册表修改)，TUN 模式下防止把 DNS 请求同步给物理网卡
 * ->   IPv6 相关设置（二选一）： 
 * - 【不用 IPv6，默认】 👇
 * ---- 客户端内：内核设置和 DNS 设置里关闭 IPv6 
 * ---- 系统物理网卡：控制面板 -> 网络连接 -> 右键物理网卡(以太网/WLAN) -> 属性 -> 坚决取消勾选「Internet 协议版本 6 (TCP/IPv6)」；Mac则在 [网络 → (选择 Wi-Fi 或以太网) → 详细信息 → TCP/IP，将'配置 IPv6' 设置为 仅本地链路 或 关闭 ]
 * ---- 系统虚拟网卡：同上，右键 `mihomo` 虚拟网卡 -> 属性 -> 坚决取消勾选「Internet 协议版本 6 (TCP/IPv6)」
 * ---- 清理系统缓存：按 Win+R 输入 cmd，执行 `ipconfig /flushdns` 并回车
 * - 【用 IPv6】 ：在客户端开启 IPv6，把 IPv6 虚假 IP 池填写 [fc00::/18]；并在电脑物理网卡里选 [使用下面的 DNS 服务器地址]，填入 [::1]
 * - 【可考虑】：浏览器层面物理阉割 QUIC：在 Chrome 或 Edge 浏览器地址栏输入：chrome://flags (Edge 输入 edge://flags) → 搜索：QUIC → 找到 Experimental QUIC protocol，把后面的 Default 改成 Disabled → 重启浏览器
 * 
 * -------------------------------------------------------------------------------------------------------------------------
 * 【 🛠️ 修改与维护】
 * ->  如果冷门国家节点未被识别：请在第 1 部分的 `continentRegexes` (五大洲兜底扫描) 里，加入对应的中文或英文，比如在欧洲里面加上 `|冰岛`。
 * ->  想新增独立国家/地区分组（例如新增“英国节点”）：
 * - 找分组：在 `regionRegexes` (独立分组节点扫描) 中加一行：`['UK', /英国|伦敦|UK/i],`
 * - 加空盒：在 `sorted` 准备盒子里加一个空数组：`UK: [],`
 * - 上名单：在 `regionsConfig` (候选名单) 里加一行：`{ tag: 'UK', name: '英国节点', icon: iconBase + 'UK.png' },`
 *
 * -------------------------------------------------------------------------------------------------------------------------
 * 【 📝 GUI 界面设置备忘录 (基础参数由客户端接管) 】
 * ->  [基础设置]：
 * - 混合端口：7890
 * - 局域网连接：开启 (按需开启)
 * - IPv6：关闭
 * ->  [虚拟网卡 (TUN) 设置]：
 * - 状态：开启
 * - 堆栈：system
 * - 开启：严格路由、自动设置路由规则、自动选择流量出口
 * - DNS 劫持：any:53
 * ->  [内核设置]：
 * - 开启：查找进程、存储选择节点、存储 FakelP 、使用 RTT 延迟测试（统一延迟测试）、 TCP 并发
 * ->  [域名嗅探设置]：
 * - HTTP 端口嗅探：80, 8080
 * - TLS 端口嗅探：443, 8443
 * - QUIC 端口嗅探：443, 8443
 * - 跳过域名嗅探：Mijia Cloud, *.apple.com, *.icloud.com
 * - 开启：覆盖连接地址、对真实 IP 映射嗅探、对未映射 IP 地址嗅探
 * ->  [DNS 设置]：
 * - IPv6：关闭
 * - 基础服务器：223.5.5.5 | 119.29.29.29
 * - 默认解析服务器：https://1.1.1.1/dns-query#节点选择 | https://8.8.8.8/dns-query#节点选择
 * - 直连解析服务器：223.5.5.5 | 119.29.29.29 | 180.184.1.1
 * - 代理节点解析服务器：https://dns.alidns.com/dns-query | https://doh.pub/dns-query
 * - 域名解析策略：
 * 左侧 rule-set:Lan，右侧 system
 * 左侧 rule-set:Google (含 YouTube, Netflix 等防漏规则集)，右侧 https://1.1.1.1/dns-query#节点选择
 * - Fake-IP 过滤: rule-set:Lan, *.stun.*, +.msftncsi.com, +.msftconnecttest.com, +.market.xiaomi.com, *.local, *.ptlogin2.qq.com, +.pool.ntp.org
 * - 连接遵守规则：关闭
 * 
 * -------------------------------------------------------------------------------------------------------------------------
 */


function main(config) {
    // 【自检】：防止启动时崩溃
    if (!config.proxies || !Array.isArray(config.proxies)) config.proxies = [];
    
    // 去除全局指纹配置，避免冲突
    delete config['global-client-fingerprint'];

    // =======================================================
    // 🛠️ 全局仓库锚点区 (全局生效)
    // 需自定义规则集或 icon 图标仓库，修改下面地址即可
    // =======================================================
    const iconBase = 'https://raw.githubusercontent.com/Keviin560/icon/main/src/';
    const ruleBase = 'https://raw.githubusercontent.com/Keviin560/Shunt_Rules/main/rule/Mihomo/';

    
    // =======================================================
    // 0. 底层优化与排错
    // =======================================================
    Object.assign(config, {
        'keep-alive-interval': 60      // 探针保活核心：全局 TCP 底层保活，每 60 秒发送心跳包，防 NAT 僵死
    });

    config.dns = config.dns || {};
    config.dns['prefer-h3'] = false;   // 关闭 H3，防止国内运营商丢弃 UDP 导致网页首屏打开卡顿 3~5 秒


    // 【防断网】
    // 防止遇到奇葩节点名报错
    try {
        // =======================================================
        // 1. 国家与大洲识别
        // =======================================================
        
        // 【国旗解码】：识别节点名里的 Emoji 国旗
        const emojiRegex = /[\uD83C][\uDDE6-\uDDFF][\uD83C][\uDDE6-\uDDFF]/;
        const extractISO = (str) => {
            const match = str.match(emojiRegex);
            return match ? String.fromCharCode(match[0].charCodeAt(1) - 0xDDE6 + 65) + 
                           String.fromCharCode(match[0].charCodeAt(3) - 0xDDE6 + 65) : null;
        };

        // 【五大洲】
        const isoToContinentMap = new Map([
            ['IN','Asia'], ['AE','Asia'], ['TR','Asia'], ['TH','Asia'], ['ID','Asia'], ['MY','Asia'], ['PH','Asia'], ['VN','Asia'], ['PK','Asia'], ['IL','Asia'], ['KZ','Asia'], ['KH','Asia'], ['NP','Asia'], ['SA','Asia'], ['IR','Asia'], ['IQ','Asia'], ['SY','Asia'], ['LB','Asia'], ['JO','Asia'], ['OM','Asia'], ['YE','Asia'], ['QA','Asia'], ['BH','Asia'], ['KW','Asia'], ['BD','Asia'], ['LK','Asia'], ['MV','Asia'], ['MM','Asia'], ['LA','Asia'], ['BN','Asia'], ['TL','Asia'], ['MN','Asia'], ['UZ','Asia'], ['TM','Asia'], ['KG','Asia'], ['TJ','Asia'], ['AF','Asia'], ['BT','Asia'], ['CY','Asia'], ['GE','Asia'], ['AM','Asia'], ['AZ','Asia'],
            ['GB','Europe'], ['FR','Europe'], ['DE','Europe'], ['NL','Europe'], ['RU','Europe'], ['IT','Europe'], ['CH','Europe'], ['SE','Europe'], ['ES','Europe'], ['PT','Europe'], ['PL','Europe'], ['IE','Europe'], ['AT','Europe'], ['FI','Europe'], ['DK','Europe'], ['IS','Europe'], ['NO','Europe'], ['UA','Europe'], ['BE','Europe'], ['LU','Europe'], ['MC','Europe'], ['AD','Europe'], ['LI','Europe'], ['SM','Europe'], ['VA','Europe'], ['MT','Europe'], ['GR','Europe'], ['BG','Europe'], ['RO','Europe'], ['HU','Europe'], ['CZ','Europe'], ['SK','Europe'], ['SI','Europe'], ['HR','Europe'], ['BA','Europe'], ['ME','Europe'], ['RS','Europe'], ['MK','Europe'], ['AL','Europe'], ['EE','Europe'], ['LV','Europe'], ['LT','Europe'], ['BY','Europe'], ['MD','Europe'],
            ['CA','Americas'], ['BR','Americas'], ['AR','Americas'], ['MX','Americas'], ['CL','Americas'], ['CO','Americas'], ['PE','Americas'], ['VE','Americas'], ['EC','Americas'], ['BO','Americas'], ['PY','Americas'], ['UY','Americas'], ['GY','Americas'], ['SR','Americas'], ['GF','Americas'], ['BZ','Americas'], ['GT','Americas'], ['HN','Americas'], ['SV','Americas'], ['NI','Americas'], ['CR','Americas'], ['PA','Americas'], ['CU','Americas'], ['HT','Americas'], ['DO','Americas'], ['JM','Americas'], ['TT','Americas'], ['BB','Americas'], ['BS','Americas'],
            ['AU','Oceania'], ['NZ','Oceania'], ['PG','Oceania'], ['SB','Oceania'], ['VU','Oceania'], ['FJ','Oceania'], ['PW','Oceania'], ['FM','Oceania'], ['MH','Oceania'], ['KI','Oceania'], ['NR','Oceania'], ['TV','Oceania'], ['WS','Oceania'], ['TO','Oceania'], ['NU','Oceania'], ['CK','Oceania'],
            ['ZA','Africa'], ['EG','Africa'], ['NG','Africa'], ['MA','Africa'], ['DZ','Africa'], ['TN','Africa'], ['LY','Africa'], ['SD','Africa'], ['ET','Africa'], ['KE','Africa'], ['TZ','Africa'], ['UG','Africa'], ['AO','Africa'], ['MZ','Africa'], ['MG','Africa'], ['CM','Africa'], ['CI','Africa'], ['GH','Africa'], ['SN','Africa'], ['ML','Africa'], ['BF','Africa'], ['NE','Africa'], ['TD','Africa'], ['MR','Africa'], ['GN','Africa'], ['SL','Africa'], ['LR','Africa'], ['TG','Africa'], ['BJ','Africa'], ['CF','Africa'], ['CG','Africa'], ['CD','Africa'], ['GA','Africa'], ['GQ','Africa'], ['ST','Africa'], ['RW','Africa'], ['BI','Africa'], ['SO','Africa'], ['DJ','Africa'], ['ER','Africa'], ['ZM','Africa'], ['ZW','Africa'], ['MW','Africa'], ['BW','Africa'], ['NA','Africa'], ['LS','Africa'], ['SZ','Africa'], ['KM','Africa'], ['MU','Africa'], ['SC','Africa'], ['CV','Africa']
        ]);

        // 【独立分组】：港澳台日韩新美
        const specialISOs = new Set(['HK', 'MO', 'TW', 'JP', 'KR', 'SG', 'US']);
        
        // 【动态指纹】：以下协议加上随机防封锁指纹
        const tlsProtocols = new Set(['vmess', 'vless', 'trojan', 'tuic', 'hysteria2']);

        // 【净化】：过滤掉“剩余流量”、“到期”等信息
        const ignoreRegex = /剩余|到期|过期|官网|流量|联系|套餐|重置|更新|交流群|TG群|QQ群|电报群|群组|邀请|返回|网址|贩卖|倒卖|Expire|Traffic/i;
        
        // 【独立分组扫描】
        const regionRegexes = [
            ['HK', /香港|HK|Hong Kong|深港|广港/i], 
            ['MO', /澳门|Macau|MO|Macao/i],
            ['TW', /台湾|Taiwan|TW|Taipei|台北|新北|中华民国/i], 
            ['JP', /日本|Japan|JP|东京|大阪|埼玉|川日|沪日/i],
            ['KR', /韩国|Korea|KR|首尔|春川|南韩/i], 
            ['SG', /新加坡|Singapore|SG|狮城|深新/i],
            ['US', /美国|US|America|United States|波特兰|达拉斯|俄勒冈|凤凰城|费利蒙|硅谷|洛杉矶|圣何塞|圣克拉拉|西雅图|芝加哥|拉斯维加斯/i]
        ];

        // 【五大洲扫描】：冷门国家丢进对应大洲
        const continentRegexes = [
            ['Asia', /印度|阿联酋|迪拜|土耳其|泰国|印尼|马来西亚|菲律宾|越南|巴基斯坦|以色列|哈萨克斯坦|柬埔寨|尼泊尔|沙特|孟加拉|斯里兰卡|曼谷|雅加达|吉隆坡|马尼拉|金边|万象|孟买|新德里|伊斯兰堡|卡拉奇|阿布扎比|伊斯坦布尔|安卡拉|特拉维夫|耶路撒冷|德黑兰|卡塔尔|科威特|伊朗|伊拉克|叙利亚|黎巴嫩|约旦|阿曼|也门|巴林|马尔代夫|缅甸|老挝|文莱|蒙古|乌兹别克斯坦|土库曼斯坦|吉尔吉斯斯坦|塔吉克斯坦|阿富汗|不丹|塞浦路斯|格鲁吉亚|亚美尼亚|阿塞拜疆|Pakistan|PAK|India|IND|Malaysia|MYS|Indonesia|IDN|Thailand|THA|Vietnam|VNM|Cambodia|KHM|Philippines|PHL|Turkey|TUR|Kazakhstan|KAZ|Dubai|UAE|Israel|ISR|Saudi Arabia|SAU|Bangladesh|BGD/i],
            ['Europe', /英国|法国|德国|荷兰|俄罗斯|意大利|瑞士|瑞典|西班牙|葡萄牙|波兰|爱尔兰|奥地利|芬兰|丹麦|冰岛|挪威|乌克兰|比利时|伦敦|巴黎|法兰克福|阿姆斯特丹|莫斯科|罗马|米兰|日内瓦|苏黎世|斯德哥尔摩|马德里|里斯本|华沙|都柏林|维也纳|哥本哈根|卢森堡|摩纳哥|安道尔|列支敦士登|圣马力诺|梵蒂冈|马耳他|希腊|保加利亚|罗马尼亚|匈牙利|捷克|斯洛伐克|斯洛文尼亚|克罗地亚|波黑|黑山|塞尔维亚|北马其顿|阿尔巴尼亚|爱沙尼亚|拉脱维亚|立陶宛|白俄罗斯|摩尔多瓦|UK|United Kingdom|France|FRA|Germany|DEU|Netherlands|NLD|Russia|RUS|Italy|ITA|Switzerland|CHE|Sweden|SWE|Spain|ESP|Poland|POL|Ireland|IRL|Austria|AUT|Denmark|DNK|Norway|NOR|Iceland|ISL|Ukraine|UKR|Czech|CZE|Hungary|HUN|Romania|ROU|Bulgaria|BGR|Greece|GRC/i],
            ['Americas', /加拿大|巴西|阿根廷|墨西哥|智利|哥伦比亚|秘鲁|委内瑞拉|厄瓜多尔|古巴|巴拿马|多伦多|温哥华|蒙特利尔|卡尔加里|渥太华|圣保罗|里约热内卢|布宜诺斯艾利斯|墨西哥城|圣地亚哥|利马|玻利维亚|巴拉圭|乌拉圭|圭亚那|苏里南|法属圭亚那|伯利兹|危地马拉|洪都拉斯|萨尔瓦多|尼加拉瓜|哥斯达രുവ|海地|多米尼加|牙买加|特立尼达|巴巴多斯|巴哈马|Canada|CAN|Toronto|YTO|YYZ|Vancouver|YVR|Montreal|YMQ|Mexico|MEX|Brazil|BRA|Argentina|ARG|Chile|CHL|Colombia|COL|Peru|PER/i],
            ['Oceania', /澳大利亚|澳洲|新西兰|悉尼|墨尔本|布里斯班|珀斯|阿德莱德|奥克兰|惠灵顿|基督城|巴布亚新几内亚|所罗门群岛|瓦努阿图|斐济|帕劳|密克罗尼西亚|马绍尔群岛|基里巴斯|瑙鲁|图瓦卢|萨摩亚|汤加|纽埃|库克群岛|Australia|AUS|New Zealand|NZL|Fiji|FJI|Sydney|Melbourne|Auckland/i],
            ['Africa', /南非|埃及|尼日利亚|摩洛哥|阿尔及利亚|肯尼亚|毛里求斯|约翰内斯堡|开普敦|开罗|拉各斯|卡萨布兰卡|内罗毕|突尼斯|利比亚|苏丹|埃塞俄比亚|坦桑尼亚|乌干达|安哥拉|莫桑比克|马达加斯加|喀麦隆|科特迪瓦|加纳|塞内加尔|马里|布基纳法索|尼日尔|乍得|毛里塔尼亚|几内亚|塞拉利昂|利比里亚|多哥|贝宁|中非|刚果|加蓬|赤道几内亚|圣多美|卢旺达|布隆迪|索马里|吉布提|厄立特里亚|赞比亚|津巴布韦|马拉维|博茨瓦纳|纳米比亚|莱索托|斯威士兰|科摩罗|塞舌尔|佛得角|South Africa|ZAF|Egypt|EGY|Nigeria|NGA|Morocco|MAR|Kenya|KEN/i]
        ];

        // =======================================================
        // 2. 把节点放进对应的盒子区
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

            // 【隐身模式】：挂上动态指纹
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
        // 3. 动态分组与探针注入
        // =======================================================
        
        // 📋【存活白名单】：把基础选项加入白名单，防止被当成空节点清理掉
        const activeGroups = new Set(['节点选择', 'DIRECT', 'REJECT', 'PASS']);
        const dynamicGroupsList = [];

        // 🗺️ 【候选名单】：图标会自动通过锚点拼接
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
                    interval: 300,                               // 每 5 分钟在后台悄悄发一次请求
                    timeout: 3000
                });
                activeGroups.add(r.name); // 把它加入“存活白名单”
            }
        }

        // 📱 客户端面板上的分组，图标会自动拼接
        const appGroups = [
            { name: 'AI Rules', type: 'select', proxies: ['美国节点', '日本节点', '新加坡节点', '节点选择'], icon: iconBase + 'ChatGPT.png' },
            { name: 'YouTube', type: 'select', proxies: ['美国节点', '香港节点', '新加坡节点', '节点选择'], icon: iconBase + 'YouTube.png' },
            { name: 'Google', type: 'select', proxies: ['美国节点', '香港节点', '新加坡节点', '节点选择'], icon: iconBase + 'Google.png' },
            { name: 'Telegram', type: 'select', proxies: ['香港节点', '美国节点', '新加坡节点', '节点选择'], icon: iconBase + 'Telegram.png' },
            { name: 'Apple', type: 'select', proxies: ['美国节点', '香港节点', '日本节点', '亚洲节点', '欧洲节点', '美洲节点', '非洲节点', 'DIRECT'], icon: iconBase + 'Apple.png' },
            { name: 'Spotify', type: 'select', proxies: ['DIRECT', '香港节点', '美国节点', '新加坡节点'], icon: iconBase + 'Spotify.png' },
            { name: 'TikTok', type: 'select', proxies: ['美国节点', '台湾节点', '日本节点', '新加坡节点'], icon: iconBase + 'TikTok.png' },
            { name: 'Netflix', type: 'select', proxies: ['新加坡节点', '香港节点', '美国节点'], icon: iconBase + 'Netflix.png' },
            { name: '海外游戏', type: 'select', proxies: ['香港节点', '美国节点', '新加坡节点', '日本节点', '亚洲节点', '欧洲节点', '美洲节点', '大洋洲节点', '非洲节点', 'DIRECT'], icon: iconBase + 'Game Controller.png' },
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
            
            // 注入探针机制
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
        // 4. 规则区
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
            // 外部特殊规则（需手动填 RAW URL）
            AdRules:        buildRule('AdRules', 'https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules-mihomo.mrs'),
            WinSpy:         buildRule('WinSpy',  'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/win-spy.txt'),
            
            // 全局的规则仓库（填写规则名即可）
            Privacy:        buildRule('Privacy'),
            Hijacking:      buildRule('Hijacking'),
            Hijacking_IP:   buildRule('Hijacking_IP'), 
            Lan:            buildRule('Lan'),
            Lan_IP:         buildRule('Lan_IP'),
            Game_CN:     buildRule('Game_CN'),
            GameDownloadCN: buildRule('GameDownloadCN'),
            WeChat:         buildRule('WeChat'),
            Global_CN:         buildRule('Global_CN'), 
            GeoSite_CN:     buildRule('GeoSite_CN'), 
            GeoIP_CN_IP:       buildRule('GeoIP_CN_IP'), 
            AI_Rules:         buildRule('AI_Rules'),
            Game_Proxy:       buildRule('Game_Proxy'),
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
            iCloud:        buildRule('iCloud'),
            AppleID:        buildRule('AppleID'),
            Apple:          buildRule('Apple'),
        };

        // =======================================================
        // 5. 规则集
        // =======================================================
        config.rules = [
            // ===============================================
            // 🛡️ 净化与拦截 (高阶隐私防护版)
            // ===============================================
            'AND,((NETWORK,UDP),(DST-PORT,443)),REJECT'， // 阻断 QUIC，防止 App 绕过代理
            'AND,((NETWORK,UDP),(DST-PORT,53)),REJECT',  // 阻断外部明文 DNS，强制所有 App 走 Mihomo 加密 DNS，防运营商嗅探
            'RULE-SET,AdRules,广告拦截',
            
            // 🚨 WebRTC 防漏 (按需开启)：防止网页通过 STUN 协议获取你的真实物理 IP (注：开启后可能会影响微信视频/TG语音通话)
            // 'DOMAIN-KEYWORD,stun,REJECT', 

            // 屏蔽隐私收集/遥测收集/行为埋点/性能监控/网页性标/诊断数据上传
            'DOMAIN-REGEX,^(crash|metrics|track|report|api|stat|collect|telemetry|apm|sdk|event|events|trace|beacon|analytics|probe|upload|diag)\\.log\\.,REJECT',
            'DOMAIN-KEYWORD,telemetry,REJECT',           // 全局拦截遥测探针
            'DOMAIN-KEYWORD,app-measurement,REJECT',     // 拦截谷歌高强度用户测量
            'DOMAIN-KEYWORD,appsflyer,REJECT',           // 拦截流氓归因分析 SDK
            'DOMAIN-KEYWORD,bugly,REJECT',               // 拦截腾讯 Bugly 探针
            'DOMAIN-KEYWORD,umeng,REJECT',               // 拦截友盟大数据设备指纹收集
            
            'RULE-SET,Privacy,隐私保护',
            'RULE-SET,WinSpy,隐私保护',
            'RULE-SET,Hijacking,反劫持',
            'RULE-SET,Hijacking_IP,反劫持,no-resolve',   
          
            // ===============================================
            // 🏠 局域网与基础直连
            // ===============================================
            'RULE-SET,WeChat,DIRECT',
            'RULE-SET,Lan,DIRECT',
            'RULE-SET,Lan_IP,DIRECT,no-resolve',
            'RULE-SET,GameDownloadCN,DIRECT',
            'DST-PORT,123,DIRECT',                      

            // ===============================================
            // 🚫 P2P/BT 流量
            // ===============================================
            // 1.  P2P 默认端口
            'DST-PORT,6881-6889,DIRECT', 
            'DST-PORT,51413,DIRECT', // Transmission 默认端口
            // 2.  BT 追踪器与特殊特征域名
            'DOMAIN-KEYWORD,tracker,DIRECT',
            'DOMAIN-KEYWORD,torrent,DIRECT',
            'DOMAIN-KEYWORD,announce,DIRECT',
             // 3. 主流下载器进程直连
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
            // 🚀 海外平台分流
            // ===============================================
            'RULE-SET,AI_Rules,AI Rules',
            'RULE-SET,YouTube,YouTube',
            'RULE-SET,Netflix,Netflix'，
            'RULE-SET,TikTok,TikTok',
            'RULE-SET,Spotify,Spotify',
            'RULE-SET,Telegram,Telegram',
            'RULE-SET,Google,Google',
            'RULE-SET,iCloud,Apple',
            'RULE-SET,AppleID,Apple',
            'RULE-SET,Apple,Apple',
            'RULE-SET,Game_Proxy,海外游戏',
            
            // ===============================================
            // 🍏 国内直连
            // ===============================================
            'RULE-SET,Global_CN,DIRECT',
            'RULE-SET,Game_CN,DIRECT',             
            'RULE-SET,GeoSite_CN,DIRECT', 

            // ===============================================
            // 🕳️ IP 补漏
            // ===============================================
            'RULE-SET,Telegram_IP,Telegram,no-resolve',
            'RULE-SET,Google_IP,Google,no-resolve',
            'RULE-SET,YouTube_IP,YouTube,no-resolve',
            'RULE-SET,Netflix_IP,Netflix,no-resolve',
            'RULE-SET,GeoIP_CN_IP,DIRECT,no-resolve', 
            
            // ===============================================
            // 🌍 兜底层
            // ===============================================
            'MATCH,兜底策略'
        ];

    } catch (error) {
        console.log("[防御机制]: 预处理脚本执行遭遇异常", error);
    }

    return config; 
}
