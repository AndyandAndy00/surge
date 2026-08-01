// --- 静态配置区域 ---

/**
 * 分流策略组启用配置,若不需要某个策略组,请设为 false
 */
const ruleOptionsEnable = {
  AI: true,
  Media: true,
  FCM: false,
  Google: true,
  Microsoft: true,
  Apple: false,
  Telegram: true,
  Steam: false,
  TikTok: false,
  Twitter: false,
  Emby: false,
  PikPak: false,
  Spotify: false,
  AdBlock: true,
};

// 节点过滤正则（内核原生 exclude-filter 使用，已转换为字符串格式）
const excludeFilterStr = '返利|循环|广州|官网|客服|网站|网址|获取|订阅|流量|到期|机场|下次|版本|官址|备用|过期|已用|联系|邮箱|工单|贩卖|通知|倒卖|防止|国内|地址|频道|无法|说明|使用|提示|访问|支持|教程|关注|更新|作者|加入|超时|收藏|福利|邀请|好友|失联|选择|剩余|公益|发布|DIZTNA|通路|登录|禁止|定时|渠道|牢记|永久|余额|阁下|本站|刷新|导航|建议|重置|以下|⚠️|@|expire|http|com|traffic';

// 预定义基础规则
const rules = [
  // 禁用国外 QUIC 流量
  'AND,((NETWORK,UDP),(DST-PORT,443),(NOT,((OR,((RULE-SET,cn_additional),(RULE-SET,cn_ip,no-resolve)))))),REJECT',
  // 私有网络直连
  'RULE-SET,private,直连',
  'RULE-SET,private_ip,直连,no-resolve',
  // 国内直连
  'RULE-SET,games_cn,直连',
  'RULE-SET,epicgames,直连',
  'RULE-SET,nvidia_cn,直连',
  'RULE-SET,apple_cn,直连',
  'RULE-SET,microsoft_cn,直连',
  'DOMAIN-SUFFIX,bing.com,直连',
  'DOMAIN-SUFFIX,bing.net,直连',
  'DOMAIN-SUFFIX,bingapis.com,直连',
  'DOMAIN-SUFFIX,msn.com,直连',
  'DOMAIN,fsend.cn,直连',
  'DOMAIN,international-gfe.download.nvidia.com,直连',
];

// 地区策略组定义 
const regionDefinitions = [
  {
    name: '香港',
    regex: '🇭🇰|港|HK|[Hh]ong\\s*[Kk]ong',
    icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Hong_Kong.png',
  },
  {
    name: '日本',
    regex: '🇯🇵|日本|JP|[Jj]apan',
    icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Japan.png',
  },
  {
    name: '美国',
    regex: '🇺🇸|美|US|[Aa]merica|[Uu]nited\\s*[Ss]tates',
    icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/United_States.png',
  },
  {
    name: '新加坡',
    regex: '🇸🇬|新加坡|狮城|SG|[Ss]ingapore',
    icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Singapore.png',
  },
  {
    name: '台湾省',
    regex: '🇹🇼|台湾|TW|[Tt]aiwan',
    icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Taiwan.png',
  }
];

// Rule Providers 通用配置
const ruleProviderCommonDomain = {
  type: 'http',
  format: 'mrs',
  interval: 86400,
  behavior: 'domain',
};
const ruleProviderCommonIpcidr = {
  type: 'http',
  format: 'mrs',
  interval: 86400,
  behavior: 'ipcidr',
};

// 基础 Rule Providers
const baseRuleProviders = {
  private: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/private.mrs', path: './ruleset/private.mrs' },
  private_ip: { ...ruleProviderCommonIpcidr, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/private.mrs', path: './ruleset/private_ip.mrs' },
  games_cn: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-games@cn.mrs', path: './ruleset/category-games@cn.mrs' },
  epicgames: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/epicgames.mrs', path: './ruleset/epicgames.mrs' },
  nvidia_cn: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/nvidia@cn.mrs', path: './ruleset/nvidia@cn.mrs' },
  apple_cn: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/apple@cn.mrs', path: './ruleset/apple@cn.mrs' },
  microsoft_cn: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/microsoft@cn.mrs', path: './ruleset/microsoft@cn.mrs' },
  cn_additional: { ...ruleProviderCommonDomain, url: 'https://static-file-global.353355.xyz/rules/cn-additional-list.mrs', path: './ruleset/cn-additional-list.mrs' },
  cn_ip: { ...ruleProviderCommonIpcidr, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/cn.mrs', path: './ruleset/cn_ip.mrs' },
  github: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/github.mrs', path: './ruleset/github.mrs' },
  gfw: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/gfw.mrs', path: './ruleset/gfw.mrs' },
  cn: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/wwqgtxx/clash-rules@release/direct.mrs', path: './ruleset/cn.mrs' },
};

// 策略组公共配置
const groupBaseOption = {
  interval: 600,
  timeout: 3000,
  url: 'https://g.cn/generate_204',
  lazy: true,
  'max-failed-times': 3,
  'empty-fallback': 'REJECT',
};

const selectBaseOption = { ...groupBaseOption, type: 'select', hidden: false };
const urlTestBaseOption = { ...groupBaseOption, type: 'url-test', tolerance: 50, 'exclude-type': 'DIRECT', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Auto.png', hidden: true };
const loadBalanceBaseOption = { ...groupBaseOption, type: 'load-balance', strategy: 'sticky-sessions', 'exclude-type': 'DIRECT', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Round_Robin.png', hidden: true };
const fallbackBaseOption = { ...groupBaseOption, type: 'fallback', 'exclude-type': 'DIRECT', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Available_1.png', hidden: true };

// 分流策略组配置
const serviceConfigs = [
  { name: 'AI', defaultSelected: '美国', providers: { ai: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-ai-!cn.mrs', path: './ruleset/ai.mrs' } }, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/ChatGPT.png', rules: ['RULE-SET,ai,AI'] },
  { name: 'Media', defaultSelected: '日本', providers: { youtube: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/youtube.mrs', path: './ruleset/youtube.mrs' }, netflix: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/netflix.mrs', path: './ruleset/netflix.mrs' } }, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/ForeignMedia.png', rules: ['RULE-SET,youtube,Media', 'RULE-SET,netflix,Media'] },
  { name: 'Google', providers: { google: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/google.mrs', path: './ruleset/google.mrs' } }, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Google_Search.png', rules: ['RULE-SET,google,Google'] },
  { name: 'Microsoft', direct: true, providers: { microsoft: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/microsoft.mrs', path: './ruleset/microsoft.mrs' } }, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Microsoft.png', rules: ['RULE-SET,microsoft,Microsoft'] },
  { name: 'Apple', direct: true, providers: { apple: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/apple.mrs', path: './ruleset/apple.mrs' } }, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Apple.png', rules: ['RULE-SET,apple,Apple'] },
  { name: 'Telegram', providers: { telegram: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/telegram.mrs', path: './ruleset/telegram.mrs' } }, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Telegram.png', rules: ['RULE-SET,telegram,Telegram'] },
  { name: 'AdBlock', reject: true, providers: { adblockmihomolite: { ...ruleProviderCommonDomain, url: 'https://fastly.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/adblockmihomolite.mrs', path: './ruleset/adblockmihomolite.mrs' } }, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Advertising.png', rules: ['RULE-SET,adblockmihomolite,AdBlock'] },
];

// --- 主入口 ---

function main(config) {
  const newConfig = { ...config };

  // ① 获取基础配置里的 Providers 名字列表 (例如: Provider_1, Provider_2)
  const providerNames = Object.keys(config['proxy-providers'] || {});

  if (providerNames.length === 0) {
    throw new Error('未在配置文件中找到 proxy-providers，请确认基础配置中已定义节点提供者！');
  }

  // ② 策略组生成 —— 利用内核 filter 参数实现原生地区分类
  const generatedRegionGroups = [];
  const groupNamesOfSelect = [];

  for (const r of regionDefinitions) {
    const urlTestName = `${r.name}-自动选择`;
    
    generatedRegionGroups.push({
      ...urlTestBaseOption,
      name: urlTestName,
      use: providerNames,
      filter: r.regex,
      'exclude-filter': excludeFilterStr
    });

    generatedRegionGroups.push({
      ...selectBaseOption,
      name: r.name,
      icon: r.icon,
      proxies: [urlTestName],
      use: providerNames,
      filter: r.regex,
      'exclude-filter': excludeFilterStr
    });

    groupNamesOfSelect.push(r.name);
  }

  const functionalGroups = [];

  functionalGroups.push(
    {
      ...selectBaseOption,
      name: '默认代理',
      proxies: [...groupNamesOfSelect, '手动选择', '自动选择', '负载均衡'],
      icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png',
    },
    {
      ...selectBaseOption,
      name: '手动选择',
      use: providerNames,
      'exclude-filter': excludeFilterStr,
      icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Static.png',
    },
    {
      ...urlTestBaseOption,
      name: '自动选择',
      use: providerNames,
      'exclude-filter': excludeFilterStr,
    },
    {
      ...loadBalanceBaseOption,
      name: '负载均衡',
      use: providerNames,
      'exclude-filter': excludeFilterStr,
    },
    {
      ...fallbackBaseOption,
      name: '故障转移',
      proxies: ['新加坡', '香港', '台湾省', '日本', '美国'],
    }
  );

  // ③ 规则与分流策略组生成
  const finalRules = [...rules];
  const finalRuleProviders = { ...baseRuleProviders };

  for (const svc of serviceConfigs) {
    if (!ruleOptionsEnable[svc.name]) continue;

    finalRules.push(...svc.rules);
    Object.assign(finalRuleProviders, svc.providers || {});

    let groupProxies = svc.reject
      ? ['REJECT', 'REJECT-DROP', 'PASS']
      : ['默认代理', '手动选择', '自动选择', '负载均衡', ...groupNamesOfSelect, ...(svc.direct ? ['直连'] : [])];

    if (svc.name === 'Telegram') {
      groupProxies = ['故障转移', '新加坡', '香港', '台湾省', '日本', '美国'];
    }

    functionalGroups.push({
      ...selectBaseOption,
      name: svc.name,
      icon: svc.icon,
      proxies: groupProxies,
      ...(svc.defaultSelected !== undefined && { 'default-selected': svc.defaultSelected }),
    });
  }

  functionalGroups.push(
    {
      ...selectBaseOption,
      name: '漏网之鱼',
      proxies: ['默认代理', '负载均衡', '自动选择', '直连'],
      icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Stack.png',
    },
    {
      ...selectBaseOption,
      name: '直连',
      proxies: ['🇨🇳 直连 | IPv4优先', '🇨🇳 直连 | IPv6优先', '🇨🇳 直连 | 双栈'],
      url: 'https://connectivitycheck.platform.hicloud.com/generate_204',
      icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/China_Map.png',
    }
  );

  const globalGroup = {
    ...selectBaseOption,
    name: 'GLOBAL',
    proxies: [...functionalGroups.map((g) => g.name), ...generatedRegionGroups.map((g) => g.name)],
    icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png',
  };

  // --- 补充静态直连节点 ---
  newConfig['proxies'] = [
    { name: '🇨🇳 直连 | IPv4优先', type: 'direct', 'ip-version': 'ipv4-prefer' },
    { name: '🇨🇳 直连 | IPv6优先', type: 'direct', 'ip-version': 'ipv6-prefer' },
    { name: '🇨🇳 直连 | 双栈',     type: 'direct' },
  ];

  // --- 核心：替换为你提供的自定义 DNS 配置 ---
  newConfig['dns'] = {
    enable: true,
    ipv6: false,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'use-hosts': true,
    'respect-rules': true,
    'default-nameserver': [
      '223.5.5.5',
      '119.29.29.29',
      '114.114.114.114'
    ],
    'proxy-server-nameserver': [
      'https://cn.ali-oss.cn:44443/dns-query/6dafe708-d9d6-48cc-a768-e6ed3018a9ec',
      'https://hk.ali-oss.cn:44443/dns-query/6dafe708-d9d6-48cc-a768-e6ed3018a9ec'
    ],
    nameserver: [
      '223.5.5.5',
      '119.29.29.29',
      '114.114.114.114'
    ],
    fallback: [
      '1.1.1.1',
      '8.8.8.8'
    ],
    'fallback-filter': {
      geoip: true,
      'geoip-code': 'CN',
      geosite: [
        'gfw'
      ],
      ipcidr: [
        '240.0.0.0/4'
      ],
      domain: [
        '+.google.com',
        '+.facebook.com',
        '+.youtube.com'
      ]
    },
    'fake-ip-filter': [
      '*.lan',
      '*.localdomain',
      '*.example',
      '*.invalid',
      '*.localhost',
      '*.test',
      '*.local',
      '*.home.arpa',
      'time.*.com',
      'time.*.gov',
      'time.*.edu.cn',
      'time.*.apple.com',
      'time1.*.com',
      'time2.*.com',
      'time3.*.com',
      'time4.*.com',
      'time5.*.com',
      'time6.*.com',
      'time7.*.com',
      'ntp.*.com',
      'ntp1.*.com',
      'ntp2.*.com',
      'ntp3.*.com',
      'ntp4.*.com',
      'ntp5.*.com',
      'ntp6.*.com',
      'ntp7.*.com',
      '*.time.edu.cn',
      '*.ntp.org.cn',
      '+.pool.ntp.org',
      'time1.cloud.tencent.com',
      'stun.*.*',
      'stun.*.*.*',
      'swscan.apple.com',
      'mesu.apple.com',
      'music.163.com',
      '*.music.163.com',
      '*.126.net',
      'musicapi.taihe.com',
      'music.taihe.com',
      'songsearch.kugou.com',
      'trackercdn.kugou.com',
      '*.kuwo.cn',
      'api-jooxtt.sanook.com',
      'api.joox.com',
      'y.qq.com',
      '*.y.qq.com',
      'streamoc.music.tc.qq.com',
      'mobileoc.music.tc.qq.com',
      'isure.stream.qqmusic.qq.com',
      'dl.stream.qqmusic.qq.com',
      'aqqmusic.tc.qq.com',
      'amobile.music.tc.qq.com',
      'localhost.ptlogin2.qq.com',
      '*.msftconnecttest.com',
      '*.msftncsi.com',
      '*.xiami.com',
      '*.music.migu.cn',
      'music.migu.cn',
      '+.wotgame.cn',
      '+.wggames.cn',
      '+.wowsgame.cn',
      '+.wargaming.net',
      '*.*.*.srv.nintendo.net',
      '*.*.stun.playstation.net',
      'xbox.*.*.microsoft.com',
      '*.*.xboxlive.com',
      '*.ipv6.microsoft.com',
      'teredo.*.*.*',
      'teredo.*.*',
      'speedtest.cros.wr.pvp.net',
      '+.jjvip8.com',
      'www.douyu.com',
      'activityapi.huya.com',
      'activityapi.huya.com.w.cdngslb.com',
      'www.bilibili.com',
      'api.bilibili.com',
      'a.w.bilicdn1.com'
    ]
  };

  if (config.hosts) {
    newConfig.hosts = config.hosts;
  }

  newConfig['tun'] = {
    enable: true,
    stack: 'system',
    'auto-route': true,
    'strict-route': true,
    'auto-redirect': true,
    'auto-detect-interface': true,
  };

  // 挂载最终配置
  newConfig['proxy-groups'] = [globalGroup, ...functionalGroups, ...generatedRegionGroups];
  newConfig['rule-providers'] = finalRuleProviders;
  newConfig['rules'] = [
    'RULE-SET,github,默认代理',
    ...finalRules,
    'RULE-SET,gfw,默认代理',
    'RULE-SET,cn_additional,直连',
    'RULE-SET,cn_ip,直连',
    'MATCH,漏网之鱼',
  ];

  return newConfig;
}
