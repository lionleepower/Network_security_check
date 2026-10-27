# Network Security Check

用于检查和配置个人代理网络环境的 Codex 技能。当前提供 **proxy-env-doctor（代理网络环境诊断与配置）**。

## 新手从这里开始

把项目文件夹交给能访问本地文件的 agent，然后复制：

```text
请阅读这个项目的 README.md 和 skills/proxy-env-doctor/SKILL.md，
按照 references/workflow.md 帮我检查代理网络。
我是新手，请先用简短问题确认目标和电脑访问权限，解释需要我决定的取舍。
首轮展示本次适用的全部编号步骤；推进时告诉我总步数、已完成数、当前步骤和剩余检测。
先检查事实，再按我的授权备份、配置、验证和交付恢复方法。
不要打开或操作我已经登录的 Claude 或其他账号会话。
在已有授权内把必要步骤做完；缺少工具或无法验证时如实说明。
```

你需要已有代理客户端和可用线路，项目不提供节点、订阅或账号。agent 需要终端和相应文件权限，真实网页复测还需要浏览器控制接口；只有文字对话的模型无法直接配置电脑。工具审批时核对具体操作，不要关闭安全保护来放行。

首次通常只需决定允许只读还是备份后修改、保护哪些流量、故障时是否接受换出口。路径、端口和配置来源由 agent 在授权后发现，不要求新手手工填写。

## 当前支持范围

主要现场经验来自 Windows／Clash Verge Rev／Mihomo／Edge。通用诊断、配置说明和离线工具已具备；应用配置仍需按实际客户端版本和权限验收。

**持续守护目前是实验性能力。** 公开 v2 已包含本地 Mihomo 适配器、可配置地区／端口／专用 profile、停用草稿、安装回滚与手动恢复／卸载。agent 可从公开文件开始部署，但仍需用户已有可用节点、受支持的客户端、正式浏览器和调度工具以及相应授权。新 v2 尚未完成全新电脑上的真实部署验收；旧版本机演练和离线测试不能替代这一证据，也不能证明 Claude 桌面会话已受保护。

## 文档入口

| 文档 | 用途 |
| --- | --- |
| [SKILL.md](skills/proxy-env-doctor/SKILL.md) | agent 的权限边界和参考路由 |
| [执行流程](skills/proxy-env-doctor/references/workflow.md) | 从首次提问到验证、恢复、交付 |
| [踩坑记录](skills/proxy-env-doctor/references/lessons.md) | 集中维护现象、处理依据和验证边界 |
| [可移植守护](skills/proxy-env-doctor/references/portable-guard.md) | v2 前提、安装、真实采集、持续调度和手动恢复 |
| [防护范围与启动检查](skills/proxy-env-doctor/references/protection-and-startup.md) | 已完成任务、能应对的故障、固定主节点与桌面预检 |
| [独立本地采集](skills/proxy-env-doctor/references/native-guard.md) | 无需 agent 在线的实际页面采集、启动时刷新和后台循环 |
| [发布准备](docs/release-readiness.md) | GitHub 发布范围、缺口和新电脑验收条件 |

Workflow 放在技能内，无需新手再安装工作流系统。`.github/workflows/` 用于开发测试，与操作用户电脑的流程不同。

执行进度按任务编号展示：完整配置与守护模板为八步，只读诊断可合并为四步，文档维护可用三步。首轮列出所有适用步骤；每次进入新步骤提示“共 N 步，已完成 K 步，正在第 Y 步”，并列出尚未完成的检测。未知、未测和受阻项明确保留，不计作防护验收通过；跨轮继续沿用已有进度。详见 [步骤编号与进度提示](skills/proxy-env-doctor/references/workflow.md#步骤编号与进度提示)。

## 能做什么

- 首先询问电脑访问与操作授权，区分只读检查、可恢复配置和仅分析资料。
- 盘点 Clash Verge Rev／Mihomo、系统网络、代理模式及实际生效配置。
- 区分 DNS 泄漏、WebRTC／STUN 直连、本机 IPv6 绕过与远端代理 IPv6 出口。
- 按用户授权配置 AI 服务分流、同地区自动回退、TUN 与 DNS，并备份和复测。
- 检查 Claude 专用浏览器、桌面应用 Code 页面、终端 CLI、WSL 及远端会话的联网路径。
- 为 Claude 设计独立指定链路，明确失败拒绝或获准回退，并核对全局模式下的实际出站。
- 保持现有已登录的 Claude Code 会话不动，必要网页验证使用隐私窗口或隔离浏览器。
- 在用户只要求检查时保持现有环境；需要修改时说明范围、结果和恢复方法。

本技能不用于漏洞扫描或账号风控规避，也不保证固定出口、服务账号可用性或所有应用零泄漏。

## 已完成的任务与防护

独立模式的 [六步操作与验收流程](skills/proxy-env-doctor/references/native-guard.md#独立守护的六步流程) 已纳入技能：确认授权、环境备份、真实采集、有界处置、恢复验收、交付观察。后台服务无需可见终端；出现空白窗口应先核对进程归属，不能仅凭标题关闭。检测未知和未完成的真实应用验证会单独标注。

2026-10-27 新增独立本地采集方案：`native_ippure_service.py` 配合 `native_ippure_collector.cjs`，用新建无账号的隐藏 Edge 读取真实 IPPure 页面，后台按间隔复测；专用桌面入口可在启动前自动请求刷新。日常采集不需要模型逐次操作，也不要求保留可见检测页。首次部署仍需授权和本机适配，Clash 核心仍需运行。具体依赖、真实通道证明、退出恢复及限制见 [独立本地采集](skills/proxy-env-doctor/references/native-guard.md)。

新增独立模式与既有工具的本轮回归为 70 项 Python／19 项 Node 测试通过，本机启动器另有 8 项测试通过。实际九行页面采集、工作进程退出后重建和重复调用复用已验证；未通过关闭当前 agent 应用来实测跨退出存活。公共脚本已提供，配置发现、桌面入口及安装适配仍需按机器准备，不代表其他电脑已完成现场验收。

以下是截至 2026-10-26 的已记录实现和验收；本节不是用户电脑当前状态的实时报告。节点、地区、间隔及故障策略由使用者决定，不复制某台机器的配置作为默认值。

| 已完成内容 | 可以应对什么 | 验证范围 |
| --- | --- | --- |
| 代理环境检查，核对系统代理、TUN、DNS、IPv6 与实际规则链 | 文件写了但核心未生效；HTTPS、DNS、STUN 路径不同造成的误判 | 有现场检查和离线工具；单项状态不证明全流量安全 |
| 全局模式下的专用回环 HTTP 入口及独立策略组 | 指定流量需要与 GLOBAL 的日常选择分开 | 公开 HTTPS 请求已在本机观察到专用入站／守护组，无 GLOBAL 或 DIRECT |
| 固定首选节点和有序同地区备用 | 日常保持同一节点，主节点故障时才回退，避免按延迟轮换 | 四条候选曾测到同地区、不同出口；部署前后主节点和出口保持一致 |
| 隔离浏览器、真实 IPPure 九项采集和持续守护 | 不接触已有登录资料；发现已知宽带基线在 STUN 中暴露；识别采集过期 | 真实页面与通道已接入，定时任务已恢复；无候选仍记为未知 |
| 单次泄漏换线、同页复测、入口拒绝和精确 Edge 暂停 | 切换未验证、复测仍泄漏、动作中断或重复触发 | 有策略测试和独立暂停／恢复演练；仅暂停指定 Edge，不是桌面或系统级断网 |
| 桌面专用启动前检查原型 | 代理不可用、检测过期、已有失败状态、旧进程仍在、安装版本改变 | 六项离线测试通过，真实过期拒绝与更新采集后预检通过；没有启动 Claude 补测 |
| 备份、恢复、公开守护 v2 和脱敏发布候选 | 配置回滚、保留后来人工修改、避免把私有资料打包 | 干净副本 61 项 Python／15 项 Node 测试通过；尚未上传 GitHub |

固定首选使用 Fallback 的节点顺序，不按最低延迟追逐节点；上层守护 Selector 选中 Fallback 才启用普通健康回退。泄漏事件的单次换线与普通连通性回退分别处理。固定节点仍可能由供应商分配新 IP，故障回退也可能改变出口。

**桌面启动器、固定顺序的本机部署适配和快捷方式仍在使用者的私有部署中。** 公开 skill 已补充其准备、检查和验收规范，仓库尚未提供已验收的通用桌面安装器；下载项目不会自动获得现有机器的桌面入口。公共守护 v2 的路径、节点和地区均需重新发现并验证。

启动前检查通过只表示当时的预检条件满足。实际 Claude Code 会话、MCP、开发服务器、云端／远端／WSL 及其他旁路流量仍需分别验证；现有保护不保证零泄漏，也不能撤回已经暴露的信息。完整对应关系见 [防护范围与启动检查](skills/proxy-env-doctor/references/protection-and-startup.md)。

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

Claude 独立链路流程见 [`references/claude-dedicated-route.md`](skills/proxy-env-doctor/references/claude-dedicated-route.md)。仅添加域名规则不能在全局模式下隔离 Claude；需要按客户端能力选择并验证专用路径。

## 文件

| 路径 | 内容 |
| --- | --- |
| `skills/proxy-env-doctor/SKILL.md` | 技能入口、范围和操作边界 |
| `skills/proxy-env-doctor/references/` | DNS／TUN、AI 分流、浏览器、Claude、验证与官方资料 |
| `skills/proxy-env-doctor/scripts/inspect_clash_config.py` | 本地 Clash YAML 配置的只读脱敏摘要 |
| `skills/proxy-env-doctor/scripts/test_inspect_clash_config.py` | 离线验证脱敏、循环依赖、解析错误与只读性 |
| `skills/proxy-env-doctor/assets/intent.example.json` | 默认无授权的执行目标模板，实际记录保存在私有目录 |
| `skills/proxy-env-doctor/scripts/collect_runtime.cjs` | 只读本地运行采集，不生成业务请求或启动应用 |
| `skills/proxy-env-doctor/scripts/verify_route.py` | 离线判定路径证据，区分通过、失败、未验证 |
| `skills/proxy-env-doctor/scripts/prepare_changes.py`／`apply_changes.py`／`restore_changes.py` | 分离候选校验、文件应用和恢复，运行重载仍走正式客户端 |

Python 工具统一按 Python 3.10+ 使用，解析 YAML 的工具还需 PyYAML。摘要脚本仅输出允许字段、匿名引用和数量，不联网、不重载配置。它不能替代运行核心与实际网络验证。技能文档本身不要求安装 Python。

```bash
python -X utf8 skills/proxy-env-doctor/scripts/inspect_clash_config.py --config /path/to/config.yaml
python -X utf8 skills/proxy-env-doctor/scripts/test_inspect_clash_config.py
```

官方资料入口见 [`references/sources.md`](skills/proxy-env-doctor/references/sources.md)。实施前按实际版本核对；检测站结论需要与连接明细和规则链对照。

新增工具的参数、依赖、授权记录、证据边界和恢复流程见 [`references/tool-workflow.md`](skills/proxy-env-doctor/references/tool-workflow.md)。新 Python 工具需要 Python 3.10+；只读运行采集器需要已有 Node.js 18+。开发依赖在获准的隔离环境中通过 `requirements-dev.txt` 安装，CI 执行跨平台离线测试，不连接真实 Claude。

## 数据范围

公开内容应限于技能、通用脚本、虚构样例、测试和脱敏文档。本机 `reports/`、`.proxy-env-local/` 已被忽略，保留现场记录但不随普通 Git 添加发布。忽略规则不会清除已经进入 Git 历史的内容，发布前还需核对暂存区和历史。

真实订阅、节点、出口地址、浏览器 profile、凭据、授权记录和备份保存在使用者本机私有位置。不要打包整个工作目录上传。

## 发布候选

公开包按白名单构建，不包含 Git 历史或现场数据。验收范围与发布前剩余决定见 [发布准备](docs/release-readiness.md)。当前尚未选择许可证，不能据此假定已获得某种开源许可。

已生成的发布 ZIP 是构建当时的快照，后续文档或脚本修改不会自动进入旧包；实际发布前需重新构建并核对清单和哈希。
