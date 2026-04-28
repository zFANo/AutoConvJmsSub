# AutoConvJmsSub

一个本地小服务，把 JustMySocks 风格的 base64 订阅（含 `ss://` / `vmess://` 链接）转换成 Clash YAML，供 clash-verge-rev / Clash Meta 等客户端直接订阅使用。

订阅 URL 写在 `config.yaml` 里，**不再在 HTTP query 中传递凭据**。

## 工作方式

```text
 ┌─────────────────┐                ┌──────────────┐                ┌──────────┐
 │ clash-verge-rev │ ─── 订阅 ───►  │ AutoConvJmsSub│ ─── 拉订阅 ──►│   JMS    │
 │  (本地 Clash)   │  http://       │  (本机:25500) │   https://    │ jmssub.net│
 └─────────────────┘ 127.0.0.1/sub  └──────────────┘                └──────────┘
                          ▲
                          │
                  fixed local URL，无凭据
```

clash-verge-rev 拉一个**固定的本地 URL**（不含任何敏感信息），AutoConvJmsSub 在后台读 `config.yaml` 拿到真订阅链接，去 JMS 抓内容、转 Clash YAML、返回。

## 快速开始

### 1. 编译

```bash
git clone https://github.com/zFANo/AutoConvJmsSub.git
cd AutoConvJmsSub
go build -ldflags "-s -w" -o autoconv .
```

### 2. 第一次运行 → 自动生成模板配置

```bash
./autoconv
# 输出：config not found; wrote a template at /path/to/config.yaml — edit it and re-run
```

### 3. 编辑 `config.yaml`

把里面的占位 URL 换成你的真实 JMS 订阅链接：

```yaml
subscriptions:
  default: https://jmssub.net/members/getsub.php?service=YOUR_SERVICE_ID&id=YOUR_UUID
  # 可选：多个订阅
  # backup: https://jmssub.net/members/getsub.php?service=...&id=...

server:
  addr: 127.0.0.1:25500
  upstream_timeout: 30s
  upstream_user_agent: ClashforWindows/0.20.39
```

### 4. 再次运行

```bash
./autoconv
# 2026/04/27 13:21:00 loaded config: /path/to/config.yaml
# 2026/04/27 13:21:00 AutoConvJmsSub listening on http://127.0.0.1:25500
# 2026/04/27 13:21:00 Configured subscriptions: default
# 2026/04/27 13:21:00 Use:  http://127.0.0.1:25500/sub            (returns 'default')
# 2026/04/27 13:21:00       http://127.0.0.1:25500/sub/<name>     (returns named entry)
```

### 5. 在 clash-verge-rev 里订阅

「新建订阅 → 远程」，URL 填：

```text
http://127.0.0.1:25500/sub
```

**就这一行**，没有任何凭据。所有敏感信息留在 `config.yaml`。

## HTTP 接口

| 路径 | 用途 |
|---|---|
| `GET /sub` | 返回 `subscriptions.default` 对应的 Clash YAML |
| `GET /sub/<name>` | 返回 `subscriptions.<name>` 对应的 Clash YAML |
| `GET /list` | 列出所有已配置的订阅名（便于核对） |
| `GET /health` | 返回 `ok`，用于探活 |

例如配置了 `default` 和 `backup` 两个订阅：

```bash
curl http://127.0.0.1:25500/list
# Configured subscriptions:
#   http://127.0.0.1:25500/sub/default
#   http://127.0.0.1:25500/sub/backup
```

## 命令行参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-config` | 自动查找 | 显式指定 config.yaml 路径 |

配置查找顺序：`-config` 指定路径 > 当前目录 `./config.yaml` > 与二进制同目录的 `config.yaml`。

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

每个节点有独立的 `G-<名字>` select 组，方便后续在 clash-verge-rev 的 Merge 配置里写自定义规则路由：

```yaml
prepend-rules:
  - DOMAIN-SUFFIX,github.com,G-JP-Premium
  - DOMAIN-KEYWORD,netflix,G-HK-Premium
```

## 安全

- ✅ 凭据只在本地 `config.yaml`（权限 `0600`），不在 URL 中流转
- ✅ 服务默认监听 `127.0.0.1`，外部网络无法访问
- ✅ 不持久化任何订阅响应内容，全在内存中转换
- ✅ 不上报任何遥测
- ⚠️ **不要** `git add config.yaml`（已经在 `.gitignore` 中排除）
- ⚠️ **不要**把 `addr` 改成 `0.0.0.0`，否则同网段任何人请求 `/sub` 都能拿到你的全部节点凭据

## 开发

```bash
go test ./...
go vet ./...
go build -o autoconv .
```

## macOS 安装为后台服务（开机自启 + 崩溃自动重启）

仓库自带 `install.sh`，跑一次即可：

```bash
./install.sh
```

它做的事（**幂等**，二次运行就是升级流程）：

1. `go build` 出 `autoconv` 二进制
2. 把二进制装到 `~/Library/Application Support/AutoConvJmsSub/autoconv`（Finder 默认隐藏 Library，不易误删）
3. **首次安装**才拷贝 `config.yaml` 过去；二次运行**不会覆盖**你已经编辑过的 config
4. 写 LaunchAgent plist 到 `~/Library/LaunchAgents/com.zfano.autoconvjmssub.plist`
5. `launchctl bootstrap` 加载服务，立即开始监听 `127.0.0.1:25500`，并且：
   - `RunAtLoad: true` — 每次登录 macOS 自动启动
   - `KeepAlive: true` — 进程崩溃 / 被 kill 后立即重启
   - `ProcessType: Background` — 不占用前台调度优先级

成功后 clash-verge-rev 的订阅 URL 永久填：

```text
http://127.0.0.1:25500/sub
```

### 文件落点

| 用途 | 路径 |
|---|---|
| 二进制 | `~/Library/Application Support/AutoConvJmsSub/autoconv` |
| 配置（含凭据，权限 600） | `~/Library/Application Support/AutoConvJmsSub/config.yaml` |
| LaunchAgent plist | `~/Library/LaunchAgents/com.zfano.autoconvjmssub.plist` |
| stdout 日志 | `~/Library/Logs/AutoConvJmsSub.log` |
| stderr 日志 | `~/Library/Logs/AutoConvJmsSub.err.log` |

### 常用管理命令

```bash
# 看运行状态
launchctl print gui/$(id -u)/com.zfano.autoconvjmssub | head -20

# 改完 config.yaml 后重启服务
launchctl kickstart -k gui/$(id -u)/com.zfano.autoconvjmssub

# 暂时停止（关掉自启）
launchctl bootout gui/$(id -u)/com.zfano.autoconvjmssub

# 重新启用
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.zfano.autoconvjmssub.plist

# 看实时日志
tail -f ~/Library/Logs/AutoConvJmsSub.log
```

### 升级（改了源码后）

直接再跑一次 `./install.sh` —— 它会重编 → 覆盖二进制 → 保留 config → 重启服务。一条命令搞定。

### 卸载

```bash
./uninstall.sh
```

会停掉服务、删二进制和 plist；删 `config.yaml` 之前会问一次（因为含凭据）；日志保留供你回看。

## 后续可扩展

- 支持更多协议：`trojan://`、`hysteria://`、`hy2://`、`ssr://`
- 缓存上游订阅（按 URL + TTL）
- 配置热重载（监听 config.yaml 变化）
- Linux systemd 自启脚本（目前仅 macOS launchd）

## License

MIT
