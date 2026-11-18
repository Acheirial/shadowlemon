# V0.2 Rust 实现：已知缺口与后续工作

Rust 已是 ShadowLemon 的唯一实现，Go 实现已随 V0.2 一起移除；V0.2 没有向后兼容性基线，也不存在与旧实现互通的路径。本文记录当前实现中仍未闭环的跨模块问题。实现已具备完整的 V0.2 线协议（线版本 4）、CLI 与端到端加密数据面（UDP-only 外部传输上的 SOCKS5 CONNECT / UDP associate × 三种套件均有测试），以下问题不影响主路径，但应在后续版本中处理。

外部传输现为 UDP-only：TCP 端口绑定在配置校验阶段即被拒绝，SOCKS5 CONNECT（TCP 目标）通过 UDP 隧道的可靠层承载；握手为 0-RTT（early key + piggyback，数据面 I/O gated 到前向安全 key swap 完成，early data 无前向安全）。

## 1. UDP 全双工回复通道（已实现）

大响应卡住问题已修复。`ServerHandshake::accept_udp` 接收 mux 监听 socket 的共享句柄（`Arc<UdpSocket>`）并返回 `Vec<Vec<u8>>`；服务端会话持有客户端地址与该句柄，用后台 reply flusher 直接把排队回复帧发回客户端，绕过"每入站一轮"的模型。flusher 在入站 ACK 推进发送窗口后被唤醒，继续冲刷剩余帧。客户端会话有周期性 ticker 驱动延迟 ACK 与重传（此前客户端从不 `tick()`，导致服务端窗口不前进）。CONNECT 大响应（64KB body、约 50 个加密帧）端到端已验证：SHA-1 校验与完整 body 均通过，`end_to_end_connect_large_response_is_not_truncated` 覆盖该回归。残余风险：`client` 与 `server` 的 ticker 使用固定 2ms 间隔而非 `next_timer()` 精确唤醒，高吞吐下可能增加少量空转与 ACK 延迟。

## 2. Android socket protect 尚未介入建连

`shadowlemon_app::platform` 已实现 `SocketProtector` trait、UDS `SCM_RIGHTS` 传输与 1 字节确认握手，但外部传输改为 UDP-only 后，驱动直接在拨号路径创建 UDP 套接字发送数据报，没有暴露 protector 钩子。Android VPN 模式下必须在发送前 protect fd，否则流量会成环。需要在 mux/驱动的 UDP 拨号路径中注入 `Arc<dyn SocketProtector>`，并封装成单一 `protect_and_bind()` 入口（不再有 TCP `connect()` 路径）。

## 3. DNS 配置已移除；流量特征配置已删除

- 服务端 `dns` 配置已删除：域名解析统一使用系统解析器，不再支持配置双栈偏好与静态 hosts 映射。
- `trafficPattern`（含 nonce / padding / tcpFragment / lowEntropy）已删除：这些字段在 Go V0.1 中只被解析，从未进入 Rust 真实数据面。V0.2 的流量形态由协议层的随机 24 字节 nonce、AEAD 保护头部、随机填充与混淆信封、随机会话 ID 决定，没有配置开关。保留它们只会误导运维，因此有意整体移除。
- 前置 socks5 代理的 UDP ASSOCIATE 目前返回明确的 "unsupported" 错误，而不是静默伪装成支持。由于外部传输已是 UDP-only，`ClientProfile.dialer` 无法用于连接服务端（上游 socks5 UDP ASSOCIATE 未实现）；示例 `configs/examples/client_config_with_dialer.json` 已移除该块。

## 4. `shadowlemon_socks5::proto` 模块可见性

`proto` 模块当前是私有的；`driver.rs` 使用 crate 根的重导出（已包含 `encode_request`、`read_request`、`parse_udp_datagram` 等），并在本地定义了少量未导出的认证常量。后续可将 `proto` 改为 `pub` 以澄清 API。

## 5. UDP 路由器层无 underlay 级认证

`ServerMux` 的 UDP 监听用零密钥 `PacketUnderlay` 只做 `recv_raw`/`send_to`，认证完全依赖帧本身的端到端 AEAD。这在当前设计下是可接受的（伪造帧无法通过解密），但没有线路级的早期过滤，后续可加基于 user hint 的快速丢弃。

## 6. 与规格 §2.2 的密钥派生偏差

凭据存储层保存的 32 字节 credential 已经是 `SHA256(password ‖ 0x00 ‖ username)`，而 `crypto::derive_static_key` 内部又做一次 `hash_password`，因此实际 PBKDF2 输入比规格公式多一次 SHA-256。两端完全一致，且 V0.2 没有兼容性基线，故不影响正确性。若要严格对齐公式，需同时修改 `crypto::kdf`、`serveruser::User` 与 `handshake::ClientHandshake::with_password` 三处。

## 7. 尚未验证的平台目标

本地仅完成 x86_64-unknown-linux-gnu 的编译与测试；其余目标（musl、Windows、macOS、Android、MIPS）只通过 CI 配置与文档描述，未在实际设备上运行。由于 Go 实现已移除，不能再依赖原 Go 版本的交叉编译结果作为这些平台的验证依据，所有目标都必须用 Rust 工具链重新验证。MIPS 目标尤其需要真机验证：它是 Rust Tier 3，需要 nightly `-Z build-std` 与匹配 OpenWrt SDK 的工具链。详见 `platform-notes.md`。

## 8. 残余流量指纹

抗指纹加固（见 `protocol-v0.2.md` §10.1）已消除 UDP 固定明文头、顺序会话 ID 与零填充。四个 SubAgent 的专项审计（线格式 / UDP 传输 / 应用层 / 已有调研）先前指出的以下实现层特征，现已修复：

- **握手响应定长（已修）**：`handshake.rs::encode_response` 现在加 `0..=MAX_SUFFIX_PADDING` 随机后缀，响应长度不再恒定；客户端 `decode_segment` 本就按元数据长度读取。
- **piggyback 长度泄露目标类型（已修）**：`build_request` 在 SOCKS5 请求前加 2 字节长度前缀并把 piggyback 区填满到 `piggyback_capacity()`，`accept` 按前缀剥离，所有 CONNECT/UDP ASSOCIATE 请求密文长度一致。
- **重传逐字节相同（已修）**：`session.rs` 缓存明文片段，重传用原 seq 配新 nonce 与新随机填充重新加密。
- **心跳时序（已修）**：心跳间隔改为 2–15 秒均匀分布（原 5±1 秒 + 长尾使 87.5% 落在 4–6 秒）。
- **UDP `kind` 混淆（已修）**：`wrap_udp`/`unwrap_udp` 改为用部署秘密 `SHADOWLEMON_ENVELOPE_SECRET`（默认回退到旧 pepper）从每包 nonce 派生 5 字节 keystream，对 5 字节路由信封整体加密，会话内前缀不再恒定、kind 不可反推。
- **用户名 hint 泄漏（已修）**：user hint 改用同一部署秘密，不再是公开常量，观察者无法离线枚举用户名。
- **目标域名明文 DNS（已修）**：客户端 SOCKS5 入口注入 `PassThroughResolver`，不本地解析域名；域名经隧道在服务端出口解析。UDP ASSOCIATE 的 per-datagram 域名通过 `DatagramSocket::send_to_host` 传递，reply header 映射增加按端口的回退。服务端出口 DNS 仍为明文，建议在服务器上用本地 DoH/DoT stub。
- **客户端 ticker 2ms 量化（已修）**：改为 `next_timer()` 精确唤醒 + 入站帧 `Notify` 唤醒；ACK 包络 padding 扩到 255 字节。

**仍存在的统计型特征**：大响应被拆成约 54 个近 MTU 的定长数据报——曾尝试每数据报随机分片大小，但会导致重组不稳定、大 body 卡住，已回退为定长分片（正确性优先）。包长双峰（~80B 控制 / ~1350B 数据）、cwnd 慢启动爬坡、单向心跳等仍可被协议感知型 DPI 利用；真正的覆盖流量与长度桶不在 V0.2 范围。评估缺口见 §9。

## 9. 抗指纹效果的实测结果与残留未测项

已用 `unshare -Urnm` 用户/网络/挂载命名空间在 `lo` 上完成真实抓包对比（命名空间内可执行 tcpdump、可写 `/var/run/shadowlemon`）：

- **TCP（60 条新连接，各发一个 HTTP 请求）**：整改前客户端载荷长度仅 4 种、香农熵 1.501，握手请求长度 60/60 全为 **150 字节**（完美指纹）；整改后客户端载荷长度 110 种、熵 3.411，握手请求长度分布在 150–182 字节的 25 个取值上，单一取值最多出现 6 次。服务端载荷长度熵从 3.310 增至 4.758。**握手响应仍恒为 115 字节 × 60**，印证 §8 的残留缺口。
- **UDP（同一份配置）**：整改前 878 个数据报，首字节只有 4 种取值 `{1,2,3,4}`（熵 1.048），前 5 字节高频值为 `0300000001`、`0300000002`、`0400000001` 等——固定签名 + 顺序会话 ID；整改后首字节取值为 `{8,9,11,14}` 等非 1–4 值，会话 ID 变为随机值（`07da7cc7`），不再有跨会话稳定的 5 字节前缀。

**nDPI 6.0 已实测**（见 `docs/traffic-analysis.md` §3.3）：四份 pcap 的 100% 流都被判为 `TPLINK_SHP`，置信度来源全是 `Match by port`——默认端口 9999/10000 命中了 TP-Link 协议端口，是纯端口误报；整改前后判定一致，说明 nDPI 没有 ShadowLemon 内容特征。把端口改为 23456 后，20 个流全部判为 `Unknown`，误报消失。所有流仍 100% 命中 `Susp Entropy` 风险，这是加密流量的通用启发式，需 cover 协议才能消除。

UDP 客户端因已知的半双工回复缺口在压测下超时，样本量偏小（193 包），但首字节与会话 ID 的结论不受影响。

## 10. GFW 被动全加密检测：TCP-only 检测器已不适用于 UDP-only 传输

按 USENIX Security 2023 对 GFW 全加密流量检测算法的复现，早期**TCP 外部传输**的首个载荷（随机 nonce + AEAD 密文）平均 1 比特数约 4.0–4.2、可打印比例 33–41%、无可打印前缀、无 TLS/HTTP 魔数——实测整改前后 60/60 首包**均不满足任何豁免规则**，在该系统覆盖的 IP 范围内会被阻断。这些是历史实测基线。

**现状：外部传输已是 UDP-only，该系统不再适用。** USENIX'23 的被动检测器只检查客户端发出的第一个 TCP 数据包（§4.4–4.5），不做 UDP 检测；因此当前 ShadowLemon 的所有流量都不进入该判定路径。换端口对 GFW 无效（它按目标 IP 段与首包特征判定，且所有端口都可封），但这一点对 UDP 同样只是次要因素。QDPI 的 `entropy_score` 分析仍然成立：加密数据报的高熵特征依然可被统计型分类器利用，与传输是 TCP 还是 UDP 无关。详见 `docs/gfw-assessment.md`。

已落地 `tools/gfw-search.rs`（OpenGFW FET 分析器离线移植 + 规避前缀自动搜索）：对历史 TCP 首包实测整改前后均 60/60 BLOCK；搜索确认 6 字节随机可打印前缀、TLS 魔数、HTTP 方法三类方案均在 20 条首包 × 4 次采样（80/80）下稳定豁免。**这些方案从未实施，也不再需要实施到 TCP 路径**——TCP accept 路径已随外部 TCP 传输一并移除。若未来要针对 UDP 做规避，需要在 UDP 握手/早期数据路径上做等价的前缀处理并重新抓包验证；当前暂无此计划。
