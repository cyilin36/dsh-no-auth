# dsh-no-auth

一个 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 插件（Host-only Cordis bundle）：让 DSH Web 免去启动 token 校验，可选地把界面通过**插件自带的局域网监听**暴露出去，并用 **客户端 IP / CIDR 白名单**控制准入，全部可在 DSH 设置页里配置。

插件**不修改 DSH 源码或安装目录**：它在运行时包装 `connection` 服务、自己起一个监听端口，卸载时精确还原。

## 功能

- **免 token**：浏览器不需要 `?token=` / 已签名 cookie。
- **自带局域网入口**：插件绑定一个局域网地址/端口，反向代理到 DSH 的回环监听（自动改写 `Host`/`Origin`），因此不需要 `dsh web --host`，也不需要额外的 nginx。
- **IP / CIDR 白名单**：只有 TCP 源地址命中配置项（如 `192.168.1.42`、`192.168.1.0/24`、`fd00::/8`）的客户端才放行；空列表表示不做 IP 限制（`0.0.0.0/0` 语义）。
- **设置页**：`Settings → 免 Token 直连` 可编辑白名单、局域网监听开关/地址/端口，保存即生效。
- **局域网页面修正**：为明文 HTTP 页面注入 `crypto.randomUUID` polyfill，并在内存中改写 Connection 客户端 bundle，让局域网页面保持 `isLoopback: true`。

## 安装

通过 DSH 插件管理器（或 Web 插件页）从 GitHub 安装：

```
plugin_manager install_bundle  target=github:cyilin36/dsh-no-auth
```

如果设置页没有立刻出现，重启一次 DSH 即可（DSH 在启动时缓存客户端插件元数据；从"仅 Host"旧版本升级时会出现这种情况）。

卸载：

```
plugin_manager remove_bundle  target=dsh-no-auth
```

## 工作原理

```
局域网客户端 ──► <lanProxy.host>:<lanProxy.port>   插件监听（白名单在这里生效）
                      │
                      └──► 127.0.0.1:<dsh 端口>   DSH 监听（token 校验已被插件绕过）

本机客户端 ────────► 127.0.0.1:<dsh 端口>          不受影响
```

DSH 监听地址仍由启动参数决定（`dsh web --host <地址>`），插件不会改绑它。局域网访问由插件自己的监听完成：

1. 用真实客户端地址匹配 `allowedClients`，名单外直接 `403`；
2. 把 `Host`/`Origin` 改写为上游 DSH authority，让 Host/Origin 防护通过；
3. 反向代理 HTTP 请求与 WebSocket 升级；
4. 在返回的页面里注入 `crypto.randomUUID` polyfill，并在内存中改写 `/plugins/` 下的 JavaScript（不落盘、不改 DSH 文件）。

在 DSH 一侧，插件包装了 Connection 服务的 `admit`、`authorizeConnect`、`authorizeIndex`、`authenticatedUrl`：通过 Host/Origin 防护的请求即使没有 cookie 也会以共享的主人 browser Peer 放行；非回环 `--host` 部署下，非空白名单成为唯一入口。

## 配置

bundle patch 提供默认值；设置页把改动持久化到 `$DSH_HOME/dsh-no-auth/settings.json`。

```yaml
- insert:
    - id: dsh-no-auth
      name: dsh-no-auth
      config:
        enabled: true
        keepTokenInUrl: false
        allowedClients: []
        lanProxy:
          enabled: false      # 可在设置页开启，或在这里改为 true 并填 host
          host: ""            # 本机一个具体接口地址，不能是 0.0.0.0
          port: 3080
          patchClientBundle: true
```

| 字段 | 默认 | 含义 |
| --- | --- | --- |
| `enabled` | `true` | 关闭插件功能但保留安装。 |
| `keepTokenInUrl` | `false` | 保留启动打印/自动打开 URL 中的 `?token=`。 |
| `allowedClients` | `[]` | 客户端 IP / CIDR 白名单；空 = `0.0.0.0/0`（不限制）。 |
| `lanProxy.enabled` | `false` | 是否启动插件自带的局域网监听。 |
| `lanProxy.host` | `""` | 要绑定的局域网接口地址（一个具体地址）。 |
| `lanProxy.port` | `3080` | 局域网监听端口。 |
| `lanProxy.patchClientBundle` | `true` | 改写 Connection 客户端 bundle，让局域网页面保持 `isLoopback: true`。 |

### 白名单语义

| 监听位置 | `allowedClients` | 结果 |
| --- | --- | --- |
| DSH 回环监听 | 任意 | 免 token 全放行；白名单不作用于回环监听本身（只有本机能连）。 |
| DSH 非回环监听（`--host`） | `[]` | 所有可达客户端都放行。 |
| DSH 非回环监听（`--host`） | 非空且合法 | 白名单是**唯一入口**；名单外首页、`/api`、WebSocket、`/connect` 一律 `403`，即使持有有效 token。 |
| 插件局域网监听 | `[]` | 所有可达客户端都放行。 |
| 插件局域网监听 | 非空且合法 | 白名单是**唯一入口**；名单外在到达 DSH 之前就收到 `403`。 |
| 任意 | 含非法条目 | Fail-closed：整体不启用，保持官方 token 校验。 |

- 匹配依据是 TCP 源地址（`req.socket.remoteAddress`），不是请求头。
- 支持 IPv4、IPv6 以及 IPv4-mapped 写法（`::ffff:192.168.1.7` 自动归一到 IPv4）。
- 条目可以是单个 IP 或 CIDR 网段；任何一条非法都会让整个机制不启用，避免"手滑打成 /33"却悄悄放行或锁死。
- 不信任 `X-Forwarded-For`：经过反向代理时所有客户端都会显示为代理地址，应把访问控制放在代理层，或让插件监听直接面对真实客户端。
- 白名单不是身份认证：无法防御同网段 ARP 欺骗或被攻陷的主机。

## 设置页

`Settings → 免 Token 直连`：

- 编辑白名单（每行一条；也接受逗号、空格、分号分隔）；
- 开关局域网监听并修改地址/端口；
- **保存并应用** 立即生效：白名单马上作用，地址/端口变化会重启监听；
- 持久化到 `$DSH_HOME/dsh-no-auth/settings.json`；
- 页面同时显示当前模式、白名单条目数、局域网监听 URL 或绑定错误。

### 设置接口

设置页使用一个需要认证的 exact route，也可以手动调用：

```sh
curl -sS http://127.0.0.1:3080/api/dsh-no-auth/settings

curl -sS -X POST -H 'content-type: application/json' \
  -d '{"allowedClients":["192.168.1.0/24"],"lanProxy":{"enabled":true,"host":"192.168.1.5","port":3080}}' \
  http://127.0.0.1:3080/api/dsh-no-auth/settings
```

## 安全警告

**这个插件会主动关闭认证。被白名单放行（或白名单为空时所有可达）的客户端等同于 DSH owner：shell、文件、全部工具权限。**

- 只在可信网络使用；不要把监听端口暴露到公网。
- 插件监听是明文 HTTP，局域网流量不加密；网络不可信时请在前面加 TLS。
- 名单为空不等于安全；不可信网络下请配置 `allowedClients`，或在防火墙层限制端口。
- 建议只保留一个预期入口；停用插件会立即恢复官方的启动 token 行为。

## 验证

```sh
# 本机 GUI（免 token）
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3080/

# 局域网入口（换成你的地址/端口，且白名单要包含本机）
curl -sS -o /dev/null -w '%{http_code}\n' http://192.168.1.5:3080/

# 鉴权已通过时，未知 /api 端点返回 404
curl -sS -o /dev/null -w '%{http_code}\n' -X POST -H 'content-type: application/json' \
  -d '{}' http://192.168.1.5:3080/api/x

# 页面里的构建/模式/局域网标记
curl -sS http://192.168.1.5:3080/ | grep -o '__DSH_NO_AUTH__[^<]*'

# Host/Origin 防护仍然生效
curl -sS -o /dev/null -w '%{http_code}\n' -X POST -H 'Host: evil.example:3080' \
  -H 'content-type: application/json' -d '{}' http://127.0.0.1:3080/api/x   # 403

# 设置接口
curl -sS http://127.0.0.1:3080/api/dsh-no-auth/settings
```

## 兼容性与限制

- 针对 `@deepseek-ai/dsh@0.2.1-rc.5` 编写并实测。Connection 服务形状或客户端 bundle 锚点可能随版本变化：服务形状不匹配时保持官方 token 校验（fail-closed）并只打印告警；客户端锚点缺失时跳过改写，不影响其他功能。
- 插件只支持明文 HTTP 上游；DSH 自身用 TLS 时不会启动局域网监听，并在状态里报告。
- 仓库不包含测试文件；本地开发可自行维护测试。
- 不修改任何 DSH 文件：运行时包装服务、提供自己的客户端 bundle、用自己的监听转发局域网流量。

## License

MIT，见 [LICENSE](LICENSE)。
