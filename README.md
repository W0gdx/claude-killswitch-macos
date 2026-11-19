# Claude Kill Switch for macOS

**代理断开时，阻止 Claude 经物理网卡直连 Anthropic 官方固定网段。** 适用于使用本机代理或 TUN 的 Claude Code / Claude Desktop 用户。

- 使用 macOS 原生 `pf`，阻断物理网卡上的官方入站 IPv4 网段及公网 IPv6/NAT64。
- 保留本机代理、TUN 和局域网连接，不修改代理或 Claude 设置。
- 开机自动生效，每 10 秒检查并修复规则；代理退出后防护仍保留。

## 安装与升级

需要 macOS 和管理员权限。从 [Releases](https://github.com/W0gdx/claude-killswitch-macos/releases/latest) 下载并解压，在源码目录执行：

```bash
chmod +x ./claude-killswitch
./claude-killswitch check
sudo ./claude-killswitch install
sudo /usr/local/sbin/claude-killswitch status
```

**升级时下载新版，重复上述步骤即可，无需先卸载。** 状态应显示「官方入站 IPv4 网段：完整（2/2）」且守护服务运行正常。

## 验证与卸载

验证物理出口是否能被规则阻断：

```bash
sudo /usr/local/sbin/claude-killswitch verify
```

测试非 Anthropic 的 IPv4/TCP 地址，检查「可达 → 阻断 → 恢复」。退出码：`0` 通过，`1` 失败，`2` 未能验证；不代表 IPv6、UDP/QUIC 或正式目标也已通过实测。

卸载：

```bash
sudo /usr/local/sbin/claude-killswitch uninstall
```

卸载移除本项目规则与守护服务，恢复安装前的 pf 启用状态，保留配置备份。

## 保护范围

- 按目的地址过滤，影响所有进程；第三方遥测、MCP、插件等其他 IPv4 地址不在覆盖范围内。
- 公网 IPv6/NAT64 阻断影响整机物理出口，局域网 IPv6 保留。
- 外部程序关闭或改写 pf 后，自动修复前可能有空档；本工具不保证避免账号风控或封禁。

网段依据：[Anthropic 官方文档](https://platform.claude.com/docs/en/api/ip-addresses)。更新记录见 [CHANGELOG](CHANGELOG.md)。可选网络诊断用法：`python3 ./network-audit.py --help`。

## 致谢与许可

思路源自 [yoruuuchan/claude-desktop-killswitch](https://github.com/yoruuuchan/claude-desktop-killswitch)，macOS 版使用 `pf` 与 `launchd` 独立实现，由 OpenAI Codex 协助开发。

[MIT License](LICENSE)
