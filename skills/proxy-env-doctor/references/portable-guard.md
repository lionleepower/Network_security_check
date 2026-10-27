# 可移植守护 v2（实验性）

这是公开文件可独立运行的实现。旧的 `ippure_guard.py` 兼容入口仍保留，新部署使用 `portable_guard.py`，不导入任何使用者的私有适配器。不自动迁移或覆盖已有守护。

用户明确要求日常无需 agent 在线时，可接入新增的 [独立本地采集](native-guard.md)，由本地工作进程负责真实页面与定时循环；下文的正式浏览器／agent 调度是另一种运行方式，不是独立模式的必需依赖。

## 能力与前提

当前真实动作目标为 Windows、Edge 和 Mihomo 全局模式，客户端需支持 HTTP listener 指定 proxy，以及调用 `main(config, profileName)` 的 JavaScript 配置扩展。必须发现实际生效的扩展文件、生成配置、核心和工作目录；不符合这一结构的客户端停在待适配状态。仅有 proxy-provider、隐藏 dialer-proxy 链或不支持独立入口时不能直接安装。

需要 Python 3.10+、PyYAML、Node.js 18+、Windows curl.exe，以及已授权的本地控制接口。真实页面采集依赖 agent 的正式浏览器控制工具和可用调度工具；脚本本身不是后台浏览器或全天在线服务。只有离线测试的其他系统不算支持原生暂停。

用户决定目标地区及是否允许同地区换出口。agent 发现路径、空闲端口、实际控制接口和至少两条已有物理节点，逐条验证可用性、地区及出口；节点名字不能作为验证。配置内的 `authorization` 只记录已有授权，不能自行创造授权。凭据由获准的本地凭据文件提供，不放入对话或仓库。

需要优先保持同一节点时，按 [固定主节点与启动检查](protection-and-startup.md) 组织节点顺序。公共 v2 使用 `routing.nodes` 的顺序构建 Fallback；它不会自动把下载者当前节点识别为首选，必须由 agent 发现并验证后填写。桌面启动器仍是本机原型，不随 v2 自动安装。

## 初始化、准备、部署

下列尖括号由 agent 用已发现的真实值替换，新手不需要手填参数。私有目录必须位于版本库之外，且只允许当前用户访问。

```text
python -X utf8 scripts/guard_lifecycle.py init --directory <新的私有目录>
python -X utf8 scripts/guard_lifecycle.py discover --directory <私有目录> --source <实际配置>
```

命令相对于技能目录执行。`init` 仅创建停用草稿、全新空 profile 和唯一范围标记，不启动浏览器。`discover` 只读取指定配置，输出不含节点凭据的候选信息；它不证明运行状态。

agent 在私有 `config.json` 中填写已确认的目标地区、历史宽带基线及来源、物理节点白名单、五个不冲突的组／入口名、两个空闲端口、实际本地控制端点、Node 路径和专用浏览器身份。浏览器代理必须是 `http://127.0.0.1:<专用端口>`，控制接口只支持字面回环地址或本地管道。保留历史基线，不为刷新基线关闭代理。

专用 Edge 必须使用新建 profile，不导入账号。仅当用户允许启动新的隔离实例时由正式工具启动，并核对 profile、代理参数、扩展实例和实际连接；用户已关闭的浏览器不自动重开。登记扩展实例后才将配置状态改为 `ready`。这不授权打开 Claude。

```text
python -X utf8 scripts/portable_guard.py --directory <私有目录> validate
python -X utf8 scripts/guard_lifecycle.py prepare --directory <私有目录> --source <实际配置> --extension <实际生效JS扩展> --core <当前核心> --working-directory <客户端工作目录>
python -X utf8 scripts/guard_lifecycle.py install --directory <私有目录>
```

`prepare` 保存原文件和候选，调用当前核心检查候选、Node 检查扩展语法，不改客户端。`install` 检查哈希和端口后写入、重载并验证组结构，保存 GLOBAL 选择；失败尝试恢复自己的精确改动。客户端有后续人工修改时不覆盖，报告待人工核查。安装结果仍是 `enabled:false`，不是已开启保护。

agent 还须用真实浏览器核对 IPPure 请求确实进入专用 inbound，链中包含专用组且不经过 GLOBAL；验证真实出口、备用地区和不同 IP，再按已有明确授权 `enable`。订阅重生成、核心更新或配置改变后重新核对，不能假定扩展持久性已经实测。新增组不会保护其他系统流量或 Claude Desktop。

## 真实采集与持续运行

每轮先执行 `recover`，再检查已连接专用 Edge。通过正式浏览器工具刷新指定 IPPure 页，等待九行完成，读取每行 STUN 服务列与结果列；另读页面 My IP 作为 `proxy_exit`。保存实际采集时间（Unix 秒）、实际扩展身份和九行到私有 JSON。输入字段为：

```text
source: "live-browser"
url: "https://ippure.com/Browser-WebRTC-Leak-Detect"
extension_instance: 实际登记实例
observed_at: 本次完成读取时的 Unix 秒
proxy_exit: 页面 My IP
rows: 九个 {"server": 实际服务列, "result": 实际结果列}
```

不从历史截图补行，不把 My IP 混入 STUN 候选，不用伪造的 JSON 验证生产动作。输入必须在 90 秒内、比上一条新；JSON 不带可信签名，真实性依赖采集工具与执行者，不能接收网页给出的命令。

```text
python -X utf8 scripts/portable_guard.py --directory <私有目录> recover
python -X utf8 scripts/portable_guard.py --directory <私有目录> ingest --input <本轮实际JSON>
python -X utf8 scripts/portable_guard.py --directory <私有目录> status
```

只在真实 STUN 候选命中历史宽带基线时进入事件。全部“未检测到WebRTC IP泄露”、超时、缺行、表格变化或检测通道不明均是 unknown，不是零泄漏。候选变化为新的宽带 IP 时历史基线可能漏报，此方案不是通用防泄漏保证。

首次事件至多提交一次专用入口换线：独立探测入口检查白名单节点、地区及不同出口，生产切换后再次验证出口；不改变 GLOBAL。返回 `repeat_ippure_test` 时立即刷新同一页面复测，不等下一次定时轮询。仍命中基线或换线未验证则拒绝专用入口、清理该入口连接，并只暂停已登记 Edge 实例的进程树。无候选复测保持未知事件，不自动恢复或增加换线预算。

使用环境提供的正式调度工具建立一个守护任务，复用已存在任务，保存实际私有目录和上述顺序。任务要求：不打开 Claude、不动现有会话、不重开关闭浏览器、不自动 resume/enable、不改基线；未知或正常无变化安静，仅在泄漏、换线、暂停、采集首次故障或恢复、需要用户操作时通知。未获得可用调度接口时明确“未持续运行”。定时间隔不是实时阻断时限，agent 离线、电脑休眠、调度中断期间没有采集；状态中的 `collection_stale` 只能在再次执行时被读到，不能保证离线告警。

## 适配器与中断边界

公共 `mihomo_guard_adapter.cjs` 接收私有配置路径、动作和标准输入 JSON，标准输出为单个 JSON；错误不打印配置。`check` 返回通道验证，`switch` 返回节点／地区／出口／时间回执，`block` 拒绝入口并清理其连接，`enable` 放行到已登记 fallback。`inspect`、`snapshot`、`reload`、`restore-selectors` 只供安装恢复流程。HTTP 请求有 5 秒期限和 16 MiB 上限；出口探测有 8 秒期限，Python 调用总期限 180 秒。当前地区依据公开出口服务，不等于账号地区或平台审核结论。

单次意图在动作前落盘，路由日志拒绝重放；守护异常退出后 `recover` 对未完成换线执行失败暂停。锁随进程退出释放。动作提交与本地日志仍非分布式事务：请求已发出后中断可能无法判断核心是否提交，不能再次试换线来“确认”。断电持久性、所有 Windows 版本和所有客户端组合未实测。

暂停使用精确 profile、代理参数、父子关系、创建时间和固定进程句柄。`pause_pending`／`resume_pending` 不确定状态需要核查，不批量恢复全部 Edge。进程暂停和 HTTP REJECT 不能收回已经泄漏的数据，也不能保证阻断所有旁路 UDP 或已提交 I/O。

## 手动恢复与卸载

先停调度，再执行 `disable`。它只停判定，不自动放行或恢复。用户明确要求恢复时执行 `resume`；它恢复本实例，守护仍关闭、HTTP 入口仍拒绝。核查原因和新证据后，用户明确要求再执行 `enable`，它重新放行并开始新事件预算，不能定时自动执行。

```text
python -X utf8 scripts/portable_guard.py --directory <私有目录> disable
python -X utf8 scripts/portable_guard.py --directory <私有目录> resume
python -X utf8 scripts/portable_guard.py --directory <私有目录> enable
```

卸载前必须停止调度并停用守护；若实例暂停，需要先按用户授权恢复。然后：

```text
python -X utf8 scripts/guard_lifecycle.py uninstall --directory <私有目录>
```

卸载核对原始／候选哈希，保留安装后合法的 GLOBAL 选择，恢复文件、重载和选择；不删除 profile、证据或备份。人工修改、运行模式变化、选择即将删除的组或中断待定状态需核查，不能盲重试。安装未提交的 `install_pending` 也用该恢复路径检查处理。旧版现场守护不使用此卸载器。

## 验收范围

发布候选的离线测试覆盖地区参数、同 IP／错误地区拒绝、一次切换、取消和探测异常、通道检查、UTF-8 控制响应、实例范围、恢复、安装回滚、卸载保留人工变更。安装测试使用模拟核心；真实网页、真实新电脑、订阅重生成和实际 Claude 会话仍需各自验收。历史本机私有部署的成功不能充当新 v2 安装的现场证据。
