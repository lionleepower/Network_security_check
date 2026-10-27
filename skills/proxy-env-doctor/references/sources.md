# 按需核对的资料

以下链接于 2026-10-20 核对可访问。实施时按已发现的客户端、内核和 OS 版本复查相关节，不假设最新示例适用于旧版。

Claude Code 网络配置与 Mihomo 入站文档于 2026-10-25 再次核对，用于 [Claude 独立链路流程](claude-dedicated-route.md)。用户提供文章的采用范围与未采纳的默认操作在该流程末节说明，文章不作为厂商风控机制的证据。

| 资料 | 用途 |
| --- | --- |
| [Mihomo TUN](https://wiki.metacubex.one/config/inbound/tun/) | dns-hijack、strict-route、接口、系统限制 |
| [Mihomo DNS](https://wiki.metacubex.one/config/dns/) | AAAA、上游、启动解析、策略与代理组 |
| [Mihomo API](https://wiki.metacubex.one/api/) | 认证、运行配置、测活、重载、SAFE_PATHS |
| [Clash Verge Rev 扩展](https://www.clashverge.dev/guide/extend.html) | 合并顺序、DNS 替换、设置优先级、持久化 |
| [回退组](https://wiki.metacubex.one/config/proxy-groups/fallback/)／[通用字段](https://wiki.metacubex.one/config/proxy-groups/) | 顺序、检测、expected-status、empty-fallback |
| [dialer-proxy](https://wiki.metacubex.one/config/proxies/dialer-proxy/) | 入口与落地链路方向 |
| [入站](https://wiki.metacubex.one/config/inbound/listeners/) | 回环诊断与指定 proxy |
| [Claude Code 网络要求](https://code.claude.com/docs/en/network-config) | 代理变量与业务端点；以官方最新清单为准 |
| [Claude 桌面 Code](https://code.claude.com/docs/en/desktop) | 本地／云端／SSH／WSL、环境设置和域名要求 |
| [Edge 按来源 WebRTC 策略](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/webrtciphandlingurl) | 版本、URL 模式、处理值及配置文件适用范围；状态不替代复测 |
| [Chromium profile 偏好定义](https://github.com/chromium/chromium/blob/main/chrome/common/pref_names.h) | webrtc.ip_handling_policy 与按来源偏好；衍生浏览器仍需行为验证 |
| [MetaCubeX 规则数据](https://github.com/MetaCubeX/meta-rules-dat) | 补充服务域名，检查维护者和范围，不盲目导入整个分类 |
| [Net.Coffee Claude 检测](https://ip.net.coffee/claude/) | 第三方出口／连通性线索 |
| [Net.Coffee DNS 检测](https://ip.net.coffee/dns/) | 用户浏览器修改前后对比 |
| [IPPure WebRTC 检测](https://ippure.com/Browser-WebRTC-Leak-Detect.html) | 第三方 STUN 候选明细；与当前宽带出口及规则链对照 |

Net.Coffee 非 Anthropic 官方，不把信任分作为风控事实或采购依据。Web 抓取页面不是用户网络实测，需本机浏览器／宿主请求验证。检测失败时用已授权替代诊断或限定抓包，不上传完整配置。

其他 AI 先找厂商官方网络说明，再结合实际连接与可信规则。不能声称关闭 IPv6、住宅出口或链式代理保证不验证、不封号或绕过产品地区／账号限制。
