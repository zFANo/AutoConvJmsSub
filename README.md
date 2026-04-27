# AutoConvJmsSub

一个本地小服务，把 JustMySocks 风格的 base64 订阅（含 `ss://` / `vmess://` 链接）转换成 Clash YAML，供 clash-verge-rev / Clash Meta 等客户端直接订阅使用。

## 它做什么

- 拉取上游订阅（base64 编码的 ss/vmess 链接列表）
- 解码并解析每条链接为 Clash proxy
- 为**每个节点**单独生成一个 `select` 类型的 proxy-group（前缀 `G-`），里面包含 `[<节点>, DIRECT, REJECT]`，方便后续按域名指定单节点出口
- 生成总 `PROXY` 选择组，包含所有 `G-*` 组以及 `DIRECT` / `REJECT`
- 内置 [Loyalsoldier 规则集](https://github.com/Loyalsoldier/clash-rules) 的 `rule-providers` 与默认 `rules`

## 快速使用

### 1. 编译

```bash
git clone https://github.com/zFANo/AutoConvJmsSub.git
cd AutoConvJmsSub
go build -ldflags "-s -w" -o autoconv .
```

### 2. 运行

```bash
./autoconv                          # 默认监听 127.0.0.1:25500
./autoconv -addr 127.0.0.1:8080     # 自定义端口
./autoconv -timeout 60s             # 自定义上游超时
./autoconv -ua "ClashMeta/1.0"      # 自定义 UA（部分订阅商按 UA 鉴别）
```

健康检查：`curl http://127.0.0.1:25500/health`

### 3. 在 Clash 客户端订阅

把 JMS 原始订阅 URL **URL-encode** 后，作为 `url` 参数填入：

```
http://127.0.0.1:25500/sub?url=https%3A%2F%2Fjmssub.net%2Fmembers%2Fgetsub.php%3Fservice%3DXXX%26id%3DYYY
```

把上面这串填到 clash-verge-rev 的「新建订阅 → 远程」即可。客户端拉到的就是合法 Clash YAML，且自带 Loyalsoldier 规则集分流。

> 提示：原始 JMS URL 中的 `&` 等字符在浏览器/curl 中需要 URL-encode；若直接粘到 clash-verge-rev 的 URL 输入框，多数情况下不 encode 也能跑（看客户端实现）。

## 生成的 Clash 配置结构

```yaml
proxies:
  - { name: HK-Premium, type: ss, server: ..., cipher: aes-256-gcm, password: ... }
  - { name: JP-Premium, type: vmess, server: ..., uuid: ..., network: ws, ... }

proxy-groups:
  - { name: G-HK-Premium, type: select, proxies: [HK-Premium, DIRECT, REJECT] }
  - { name: G-JP-Premium, type: select, proxies: [JP-Premium, DIRECT, REJECT] }
  - { name: PROXY,        type: select, proxies: [G-HK-Premium, G-JP-Premium, DIRECT, REJECT] }

rule-providers:
  reject:  { type: http, behavior: domain, url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt, ... }
  proxy:   ...
  direct:  ...
  private: ...
  gfw:     ...
  telegramcidr: { ... behavior: ipcidr ... }
  cncidr:       { ... behavior: ipcidr ... }

rules:
  - RULE-SET,private,DIRECT
  - RULE-SET,reject,REJECT
  - RULE-SET,direct,DIRECT
  - RULE-SET,cncidr,DIRECT
  - RULE-SET,proxy,PROXY
  - RULE-SET,gfw,PROXY
  - RULE-SET,telegramcidr,PROXY
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
```

### 想让特定域名走特定节点

在 clash-verge-rev 的「Merge」配置里加：

```yaml
prepend-rules:
  - DOMAIN-SUFFIX,github.com,G-JP-Premium
  - DOMAIN-KEYWORD,netflix,G-HK-Premium
```

命中后流量会被钉到该节点对应的 `G-*` 组，不影响其他流量的默认分流。

## 命令行参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-addr` | `127.0.0.1:25500` | 监听地址。**强烈建议保持 127.0.0.1**，避免局域网其他机器经此中转你的订阅凭据 |
| `-timeout` | `30s` | 抓取上游订阅的超时 |
| `-ua` | `ClashforWindows/0.20.39` | 上游请求 UA |

## 安全提示

- **只在本机运行**，不要部署到公网 VPS。`url` 参数包含你的 JMS 凭据，监听地址改成 `0.0.0.0` 等于把凭据暴露给所有能访问该端口的人。
- 本程序不持久化任何订阅内容，全在内存里转换后返回。
- 不上报任何遥测数据。

## 开发

```bash
go test ./...           # 跑单元测试
go vet ./...
go build -o autoconv .
```

## 后续可扩展

- 支持更多协议：`trojan://`、`hysteria://`、`hy2://`、`ssr://`
- 缓存上游订阅（按 URL + TTL）
- 按 query 参数选择规则集变体（精简版、流媒体增强版等）
- macOS launchd / Linux systemd 自启脚本

## License

MIT
