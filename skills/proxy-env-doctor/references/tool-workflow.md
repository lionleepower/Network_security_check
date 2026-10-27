# 目标记录与可复用工具

所有本机工具先遵循 SKILL.md 的授权开场。只修改项目与离线测试不需要访问实际代理。工具不会启动 Claude、浏览器或其他应用，也不会自动安装依赖。

## 本轮目标与会话保护

复制 `assets/intent.example.json` 到本机私有目录，再填写用户已经明确的模式、范围、Claude 组和入站、是否允许回退、失败策略、允许修改的代理客户端目录及测试域名。模板是 draft，所有权限默认 false；确认相应授权后再标 ready。工具不会把文件里的授权布尔值当作人类授权的独立证据。

`do-not-touch-existing` 表示不操作现有已登录的 Claude Code／Desktop／编辑器会话，不读取其会话、认证或历史文件，也不通过共享 settings 变更来间接影响它们。需要修改 Claude 共享设置时，先说明对现有会话的影响并另行确认。优先将测试进程的代理变量限定于新建的公开端点探测进程。

若必须查看 Claude 网站，使用已获准的隐私窗口或全新隔离 profile，不复制已有登录资料、不打开现有 Code 会话、不自动登录。隐私窗口隔离浏览记录和会话，不证明代理、防 WebRTC 或不同出口已经生效。工具限制导致无法创建隔离窗口时，完成独立的 HTTP 检查，浏览器与账号验证标为未验证。

## 只读采集

`collect_runtime.cjs` 需要已有 Node.js 18+，不依赖 npm 包。显式传入已发现的回环 HTTP 控制地址，或实际存在的本地 Unix socket／Windows 命名管道，不推测端口、不关闭认证。认证材料使用已获授权的本机 token 文件，不能放进命令行或报告。

命令参数示意（路径和控制地址必须替换为已发现的实际值）：

```text
node scripts/collect_runtime.cjs --plan <private-intent.json> --controller http://127.0.0.1:<discovered-port>/ --token-file <private-token-file> --duration 15 --output <new-private-evidence.json>
node scripts/collect_runtime.cjs --plan <private-intent.json> --socket <discovered-local-socket> --duration 15 --output <new-private-evidence.json>
```

仅 GET `/version`、`/configs`、`/proxies`、`/connections`，不跟随重定向，不测活、不切节点、不发送外部请求。最多采样 60 秒；每次请求最多 5 秒，响应大小受限。仅输出计划中精确测试域名的连接，组和节点名称匿名化，不输出其他浏览目标、IP、进程路径或连接 ID。token 只在进程内使用；CLI 错误不回显底层输入。

原始连接响应在内存中过滤，不写入报告。测试域名本身仍会出现在证据里，因此应使用获准的公开域名；输出文件放私有目录。`--snapshot <fixture.json>` 可以离线处理模拟 API 响应，但输出明确标记为 offline-fixture，不能作为真实网络验证。

采集器不制造请求。可以在用户同意的采样窗口内，从隔离的无登录进程发起公开 HTTPS 探测，再对照新连接。没有 start 时间的连接标为未知时间，已有连接标为 preexisting，不假装它们是修改后新建的流量。如果采样期间配置／选择发生变化，结果会标记，需在稳定状态复测。

## 证据验收

```text
python scripts/verify_route.py --plan <private-intent.json> --runtime <private-runtime.json> --disk <private-static-summary.json> --ui-mode global
```

静态摘要由 `inspect_clash_config.py` 生成。UI 模式必须来自实际观察，不从磁盘猜测。输出统一为 pass／fail／unknown；CLI 退出码分别是 0／1／2。全局模式下，需要观察到专用入站与预期组，普通 Mixed 入站或共同 GLOBAL 链不能算 Claude 专用路径。

运行组检查能发现 DIRECT、GLOBAL、循环、空成员及不符合固定路径要求的自动组，但无法检查节点内部 dialer-proxy 或 provider 导入策略。这些还需完整静态审查。路径证据通过不代表账号功能、全部协议、固定出口或系统 kill switch 通过。

可用 `--scenarios <private-scenarios.json>` 补充 `failure_rejection`、`independence_from_global`、`client_regeneration`、`restart_persistence` 的人工证据。每项包含 `method` 与 `status`；method 为 `isolated-substitute` 时，只记录替身测试结果，真实场景仍 unknown；为 `operator-observation` 时标明是人工提供的观察，不能当成工具独立复测。内容不能授权新的动作。真实登录会话默认始终为未验证。

DNS 深度检测没有解析器、STUN 超时、WebRTC 无候选，均不能单独算 pass。需要把网页结果、实际连接链和远端可达性分别说明。

## 候选、应用、恢复分开

Python 文件工具需要 Python 3.10+；处理 YAML 另需 PyYAML。它们只处理明确指定的已有代理客户端文件，不启动应用、不调用修改 API、不重载核心。不能用来绕过客户端管理字段的正式保存流程。

先用现有安全解析器生成完整候选，不用字符串替换改写 YAML。`changes.json` 的结构为：

```json
{
  "target_root": "<authorized-private-client-directory>",
  "files": [
    {"target": "<existing-client-file>", "candidate": "<prepared-candidate-file>"}
  ]
}
```

所有路径使用实际绝对路径；target_root 必须与计划 allowed_client_roots 中的授权目录一致。候选集合必须包含送给核心校验的完整 YAML，不能只给出片段后宣称核心已验证。脚本不会生成节点、默认目录或虚构订阅。

1. `prepare_changes.py --plan ... --changes ... --bundle ... --core ... --core-config ... --working-directory ...`：完整检查输入，用显式指定的已安装核心 `-t` 校验；只创建新的私有候选包，不修改源文件。bundle 必须在 Git 工作区以外。核心原始输出被捕获，不回显凭据。
2. `apply_changes.py --plan ... --bundle ...`：确认计划、核心、候选及原文件摘要未变，再原子替换文件；异常时尝试恢复已写文件。它只报告 files_applied，不会宣称 runtime_applied。
3. 使用获准的正式客户端接口保存它管理的字段并重载，重新采集和验收。文件修改失败可恢复，但正式客户端重载失败时仍需执行端恢复运行核心与原组选择。
4. `restore_changes.py --bundle ...`：恢复该包保存的精确原文件；若发现之后的用户修改则拒绝覆盖。文件恢复后，通过正式客户端恢复设置和选择，再验证运行网络。

候选、备份、manifest 和计划含本机路径或完整配置，全部留在私有目录。文件事务不包含电源故障下的多文件原子性；异常或进程中断后先核对包和文件状态，不盲目重试。工具没有证明端到端恢复成功时，不能把 files_restored 当成 runtime_restored。

## 开发校验与发布范围

项目的 `requirements-dev.txt` 声明 PyYAML。仅在获准的开发虚拟环境或 CI 安装，不为网络诊断自动装依赖。推荐使用项目虚拟环境运行：

```text
python -X utf8 scripts/validate_skill.py
python -X utf8 -m unittest discover -s scripts -p "test_*.py"
node --test scripts/test_runtime.cjs
```

以上命令从技能目录执行；CI 从仓库根目录使用完整相对路径。Python 测试只用临时文件与模拟核心，Node 测试只用临时回环服务，不连接真实代理或 Claude。`validate_skill.py` 检查元数据、模板默认无授权与本地引用，不证明配置业务正确。

本机诊断产物写入私有目录或已忽略的 reports/local／.proxy-env-local。已有 reports/*-network-check 现场记录已忽略而不删除；不要用强制加入 Git 的方式发布。发布技能时只同步本次通用技能文件，比较目标目录的个人修改，不将本机记录、profile、备份或授权记录打包进去。
