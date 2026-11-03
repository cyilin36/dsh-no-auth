# dsh-no-auth

DSH（DeepSeek Harness）插件：让 Web 界面**免启动 token** 访问，并可选地用**插件自带的局域网监听 + IP/CIDR 白名单**对外开放。不修改 DSH 源码或安装文件。

## 作用

- 浏览器直接打开 DSH 端口，不需要 `?token=` / cookie。
- 插件自己监听一个局域网地址/端口，反代到 DSH 的回环端口；不用 `dsh web --host`，也不用额外的 nginx。
- 按客户端 IP / 网段白名单放行；空名单 = 不限制（`0.0.0.0/0`）。
- 白名单和监听地址/端口可在 DSH 设置页修改，保存即生效。

## 安装

```
plugin_manager install_bundle  target=github:cyilin36/dsh-no-auth
```

卸载：

```
plugin_manager remove_bundle  target=dsh-no-auth
```

## 使用

1. 打开 `Settings → 免 Token 直连`。
2. 「允许的客户端」每行一个 IP 或网段，例如：

```yaml
192.168.1.42            # 单个设备
192.168.1.0/24          # 整个网段
fd00::/8                # IPv6 网段
```

留空 = `0.0.0.0/0`（任何可达客户端都放行）；填写后名单就是唯一入口，名单外即使有有效 token 也会被拒绝。

3. 勾选「启用插件自带局域网入口」，填监听地址和端口（例如 `192.168.1.5` / `3080`），点「保存并应用」。
4. 其他设备访问 `http://<监听地址>:<端口>` 即可。

配置持久化在 `$DSH_HOME/dsh-no-auth/settings.json`。也支持接口调用：

```sh
curl -sS http://127.0.0.1:3080/api/dsh-no-auth/settings
```

## 安全提示

被放行的客户端 = DSH owner（shell、文件、全部工具权限）。LAN 监听是明文 HTTP，只在可信网络使用，不要暴露到公网。停用插件即恢复官方 token 校验。

## 限制

- 适配 `@deepseek-ai/dsh@0.2.1-rc.5`，仅支持明文 HTTP 上游。
- 不解析 `X-Forwarded-For`；反向代理场景请让插件监听直接面对真实客户端。
- 仓库不含测试文件。

## License

MIT
