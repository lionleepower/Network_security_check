# Network Security Check

用于检查和配置个人代理网络环境的 Codex 技能。当前提供 **proxy-env-doctor（代理网络环境诊断与配置）**。

## 能做什么

- 盘点 Clash Verge Rev／Mihomo、系统网络、代理模式及实际生效配置。
- 区分 DNS 泄漏、WebRTC／STUN 直连、本机 IPv6 绕过与远端代理 IPv6 出口。
- 按用户授权配置 AI 服务分流、同地区自动回退、TUN 与 DNS，并备份和复测。
- 检查 Claude 专用浏览器、桌面应用 Code 页面、终端 CLI、WSL 及远端会话的联网路径。
- 在用户只要求检查时保持现有环境；需要修改时说明范围、结果和恢复方法。

本技能不用于漏洞扫描或账号风控规避，也不保证固定出口、服务账号可用性或所有应用零泄漏。

## 使用

将本仓库的 [`skills/proxy-env-doctor`](skills/proxy-env-doctor) 文件夹复制到用户技能目录，例如 `~/.codex/skills/proxy-env-doctor`。已有同名技能时先备份并比较，避免覆盖个人修改。

调用示例：

```text
请使用 $proxy-env-doctor 只读检查我的代理网络环境。
先确认我使用的软件、执行环境、DNS 和实际分流路径，不修改设置。
```

```text
请使用 $proxy-env-doctor 检查 Claude 的联网问题。
先定位原因，确认必要取舍，再按授权备份、配置和复测。
```

技能使用环境中已有的终端、浏览器及必要权限。不会为了检查自动安装软件、购买节点或要求用户在聊天中发送密钥。

## 文件

| 路径 | 内容 |
| --- | --- |
| `skills/proxy-env-doctor/SKILL.md` | 技能入口、范围和操作边界 |
| `skills/proxy-env-doctor/references/` | DNS／TUN、AI 分流、浏览器、Claude、验证与官方资料 |
| `skills/proxy-env-doctor/scripts/inspect_clash_config.py` | 本地 Clash YAML 配置的只读脱敏摘要 |
| `skills/proxy-env-doctor/scripts/test_inspect_clash_config.py` | 离线验证脱敏、循环依赖、解析错误与只读性 |

摘要脚本需要 Python 3 和 PyYAML（本地已用 Python 3.8 验证）；仅输出允许字段、匿名引用和数量，不联网、不重载配置。它不能替代运行核心与实际网络验证。技能文档本身不要求安装 Python。

```bash
python -X utf8 skills/proxy-env-doctor/scripts/inspect_clash_config.py --config /path/to/config.yaml
python -X utf8 skills/proxy-env-doctor/scripts/test_inspect_clash_config.py
```

官方资料入口见 [`references/sources.md`](skills/proxy-env-doctor/references/sources.md)。实施前按实际版本核对；检测站结论需要与连接明细和规则链对照。

## 数据范围

本仓库只包含可复用技能和离线脚本，不包含个人代理订阅、节点密码、浏览器会话、配置备份或本机检测截图。实际配置与备份应保存在用户本机私有目录中。
