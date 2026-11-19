# Claude Kill Switch for macOS

一个面向代理用户的 macOS 网络防泄漏工具：代理或 TUN 失效时，阻止物理网卡直连 Anthropic 官方固定入站 IPv4 网段，并阻断物理出口公网 IPv6/NAT64。覆盖边界见下文。

> This project prevents Claude traffic from falling back to a physical network interface when a proxy or TUN tunnel fails. The documentation is currently Chinese-first.

## 它解决什么问题

代理正常时：

```text
Claude Code / Claude Desktop → localhost 或 utun → 代理 → Internet
```

代理失效时，macOS 可能重新选择 Wi-Fi、以太网或雷雳桥作为出口。本工具使用系统原生 `pf`，在物理接口上：

- 阻断 Anthropic 官方固定入站 IPv4 网段；
- 阻断公网 IPv6 与 NAT64，防止 IPv6 绕过仅支持 IPv4 的代理；
- 保留回环、局域网、链路本地和组播 IPv6；
- 不阻断 `utun` 和本机代理端口。

当前覆盖官方列出的两个入站 IPv4 网段；官方向外调用 MCP 等服务使用的出站源网段不属于客户端连接目的地，不加入该表。

Anthropic 网段来源：[Anthropic IP addresses](https://platform.claude.com/docs/en/api/ip-addresses)。

## 安全语义

本工具采用 **fail-closed** 设计：

- 代理正常：Claude 经代理使用；
- 代理退出或崩溃：规则继续存在，覆盖范围内的物理出口连接被阻断；
- 代理重新启动：流量重新经过代理，无需重启本工具；
- 守护进程退出：`launchd` 自动重启；
- `pf` 被关闭、规则丢失、`pf.conf` 引用被覆盖或出现新物理网卡：守护进程自动修复。

守护进程每 10 秒检查一次。外部程序主动关闭或改写 `pf` 后，检查和修复之间可能存在空档；自动修复不等于连续不可绕过的保护。

它不会修改代理客户端、Claude、账号、钥匙串、登录凭据或系统代理设置。

## 系统要求

- macOS；
- 管理员权限；
- 使用本机代理或 TUN 的网络环境；
- `/etc/pf.conf` 可由系统 `pfctl` 正常解析。

安装位置及其父目录必须由 root 所有，禁止组或其他用户写入、写入授权 ACL 和自定义符号链接。不满足条件时安装会拒绝执行，不会自动更改这些目录的权限。

## 安装

下载仓库后执行：

```bash
chmod +x ./claude-killswitch
./claude-killswitch check
sudo ./claude-killswitch install
sudo /usr/local/sbin/claude-killswitch verify
sudo /usr/local/sbin/claude-killswitch status
```

安装过程会：

1. 自动识别 `en*` 和 `bridge*` 物理接口；
2. 在写入前验证候选 `pf` 配置；
3. 备份原 `/etc/pf.conf`；
4. 写入独立 anchor；
5. 安装 root `LaunchDaemon`；
6. 保留安装前 `pf` 是否启用的状态，以便卸载时恢复。

## 从旧版升级

下载新版后，直接重新执行安装命令，无需先卸载：

```bash
sudo ./claude-killswitch install
sudo /usr/local/sbin/claude-killswitch status
sudo /usr/local/sbin/claude-killswitch verify
```

升级会刷新管理的地址表与阻断规则，保留已加载的防护及安装前状态。主配置未变化时，仅重新加载本项目的 anchor。已有守护服务保留注册并重启，不先注销服务。

状态检查应显示“官方入站 IPv4 网段：完整（2/2）”。缺网段、规则不匹配或服务未运行时会返回失败，不能只凭“已安装”判断保护有效。

## 验证

```bash
sudo /usr/local/sbin/claude-killswitch verify
```

验证不会连接 Anthropic。它会从多个非 Anthropic 诱饵地址中选择一个可达基线，完成：

```text
同一物理出口、同一目标：可达 → 加载同构阻断规则后不可达 → 恢复后再次可达
```

验证使用绑定到物理接口的 TCP 连接及作用域主机路由，不修改系统默认路由或代理。连接失败后，还必须读取本项目带标签规则的非零命中计数；清理时核对路由的目的地址、接口与网关，只删除本次创建且身份未变化的路由，并回读确认。

退出码：`0` 表示上述 IPv4/TCP 诱饵测试通过；`1` 表示阻断、恢复或清理等步骤失败；`2` 表示基线不可达或缺少命中证据，尚未验证。清理失败始终返回 `1`。本测试不证明正式 Anthropic 目标、IPv6 或 UDP/QUIC 的端到端阻断。

## 可选网络诊断

独立的 `network-audit.py` 需要 Python 3，不影响核心脚本安装。默认只读取本地接口、默认路由与 DNS 配置，输出不含地址的 JSON：

```bash
python3 ./network-audit.py
```

默认不会发外部探测，退出码为 `2`（出口一致性未验证）。可显式指定 `--proxy-url` 为本地 HTTP/mixed 代理 URL，启用经代理的 HTTPS 出口查询；`--probe-stun` 单独启用 UDP STUN 探测。只有两项都取得有效 IPv4 结果时才比较：相同返回 `0`，不同返回 `1`，其他情况返回 `2`。

STUN 会对外发送 UDP，服务器可以看到实际来源地址；仅在你愿意进行该探测时使用。结果不输出 IP，也不代表浏览器 WebRTC、加密 DNS或所有网络路径均已验收。默认服务器及可选参数见 `python3 ./network-audit.py --help`。

## 状态检查

```bash
sudo /usr/local/sbin/claude-killswitch status
```

状态页会核对磁盘配置、实际加载的两个入站 IPv4 网段、IPv6/NAT64 地址表、每张物理接口的出站阻断规则、主规则引用和守护进程运行状态，并显示本地 HTTP 代理及路由类别。路由类别本身不代表连接成功或防护有效。

## 卸载

```bash
sudo /usr/local/sbin/claude-killswitch uninstall
```

卸载会：

- 停止并移除 LaunchDaemon；
- 删除本项目的 anchor 和 `pf.conf` 管理片段；
- 恢复安装前 `pf` 的启用状态；
- 保留配置备份供人工审计。

备份目录：`/var/backups/io.github.claude-killswitch.macos/`。

## 威胁边界

本工具能保护：

- 任意进程经物理接口直连 Anthropic 官方固定 IPv4 网段；
- 任意进程经物理接口访问公网 IPv6 或 NAT64。

本工具不能保证：

- 阻断所有第三方托管的遥测、MCP、插件或未来新增地址；
- 判断当前代理究竟使用了哪个出口节点；
- 防止代理服务自身泄漏流量；
- 避免账号风控、停用或封禁；
- 在第三方安全软件完全替换或禁用 macOS `pf` 时继续工作。

macOS `pf` 不提供适合此场景的可靠“按应用路径”出站过滤，因此本项目没有声称完整复刻 Windows 按进程规则。

## 与上游更新的对应

核对 Windows 上游截至 [`c64ead3`](https://github.com/yoruuuchan/claude-desktop-killswitch/commit/c64ead335c954bfac81db9304442a1ff69be4426) 的源代码和提交记录后：

| 上游改进 | macOS 实现 |
| --- | --- |
| 两个官方入站网段、完整规则健康检查 | 核对地址表、出站阻断、全部物理接口、主 anchor 和运行中的守护进程 |
| 测试归因、恢复、清理与退出码 | 非 Anthropic 诱饵基线、带标签 pf 命中计数、正式规则恢复回读和精确路由清理 |
| 提权路径安全 | 固定 PATH；检查安装链所有者、权限、ACL 与符号链接 |
| 发现失败和卸载失败必须显式报告 | 接口发现失败不视为空集；停止服务和规则移除均须确认 |
| DNS、代理出口和 UDP STUN 审计 | 独立 Python 工具，默认本地只读，外部探测必须显式启用 |
| Windows 进程路径规则、WFP、计划任务及适配器功能 | 使用 pf/launchd 对应机制；不提供 Windows 按应用阻断全部第三方 IPv4 目的地的能力 |

离线回归测试使用替身命令，不改动实际防火墙、不访问网络。运行：`python3 -m unittest discover -s tests -v`。离线通过和真实机器验收分别记录，不能互相替代。

## 为什么不在代理退出时撤掉规则

主动退出和崩溃在进程层面可能完全相同。如果代理一消失就撤防，恰好会在最危险的时刻开放直连。本项目因此始终保持核心规则，只有显式执行 `uninstall` 才撤销。

## 致谢

项目思路受 Windows 版 [yoruuuchan/claude-desktop-killswitch](https://github.com/yoruuuchan/claude-desktop-killswitch) 启发。macOS 实现为独立编写，使用 `pf` 与 `launchd`，未直接移植 PowerShell 代码。

本项目由 ChatGPT（OpenAI Codex）协助设计、实现与验证。

## License

[MIT](LICENSE)
