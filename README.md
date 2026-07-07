# ACLClouds Auto Renew

自动检测并续期 [aclclouds](https://dash.aclclouds.com) 面板下的服务器，基于 GitHub Actions 定时运行，使用 Playwright 模拟浏览器操作。

## 功能

- 使用 Cookie 免登录访问面板
- 自动检测并点击「重新激活」（Réactiver）已暂停的服务器
- 自动检测「立即续期」（Renouveler maintenant）入口并续期
- 检测剩余时间，低于 2.5 小时自动点击续期并确认
- 检测服务器是否停止运行，自动点击 Start 开机
- 可选：支持通过节点链接（vless/vmess/trojan/hysteria2/tuic/anytls/socks5）自建本地代理，或使用外部代理访问面板

## 使用前准备

### 1. 获取 Cookie

登录 `https://dash.aclclouds.com`，从浏览器开发者工具的 Network 或 Application 面板中复制该站点的 Cookie，格式为：

```
name1=value1; name2=value2; name3=value3
```

### 2. 配置 GitHub Secrets

进入仓库 `Settings → Secrets and variables → Actions`，添加：

| Secret 名称 | 必须 | 说明 |
|---|---|---|
| `ACL_COOKIES` | 是 | 上一步获取的 Cookie 字符串 |
| `NODE_LINK` | 否 | 代理节点链接，设置后脚本会自动下载 sing-box 并启动本地代理访问面板 |
| `IS_PROXY` | 否 | `true`/`false`，是否使用下面的外部代理（仅在未设置 `NODE_LINK` 时生效） |
| `PROXY_SERVER` | 否 | 外部代理地址，如 `http://1.2.3.4:8080` |
| `PROXY_USERNAME` | 否 | 外部代理认证用户名 |
| `PROXY_PASSWORD` | 否 | 外部代理认证密码 |


## 运行方式

- **自动运行**：默认每天 UTC 02:05（北京时间 10:05）通过 `cron` 触发
- **手动运行**：仓库 `Actions` 标签页 → 选择 `ACLClouds Auto Renew` → `Run workflow`

如需修改运行频率，编辑 `.github/workflows/renew.yml` 中的 `cron` 表达式。


## 免责声明

本项目仅用于自动化管理你自己拥有权限的 aclclouds 账号下的服务器，请勿用于未经授权访问他人账号或服务。
