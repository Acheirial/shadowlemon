# V0.2 Rust 实现：已知缺口与后续工作

Rust 已是 ShadowLemon 的唯一实现，Go 实现已随 V0.2 一起移除；V0.2 没有向后兼容性基线，也不存在与旧实现互通的路径。本文记录当前实现中仍未闭环的跨模块问题。实现已具备完整的 V0.2 线协议（线版本 4）、CLI 与端到端加密数据面（TCP/UDP × 三种套件均有测试），以下问题不影响主路径，但应在后续版本中处理。

## 1. UDP 全双工回复通道

`mux::ServerMux` 的 UDP 监听任务对每个入站数据报只调用一次 `ServerHandshake::accept_udp`，因此每个入站数据报只能回一个加密数据报。`driver::RealServerHandshake` 把多余的回复排队，等下一个入站数据报时再发出。单向请求/响应场景正常；真正的全双工 UDP 转发需要 mux 暴露异步回复通道（例如带 `tokio::sync::mpsc` 的 reply sink）。

## 2. Android socket protect 尚未介入建连

`shadowlemon_app::platform` 已实现 `SocketProtector` trait、UDS `SCM_RIGHTS` 传输与 1 字节确认握手，但 `ClientMux` 目前直接用 `TcpStream::connect` 建连，没有暴露 protector 钩子。Android VPN 模式下必须在 `connect()` 之前 protect fd，否则流量会成环。需要在 mux 的拨号路径中注入 `Arc<dyn SocketProtector>`，并封装成单一 `connect_protected()` 入口。

## 3. 配置中的 DNS / 流量特征未全部接入拨号

- `dns.hosts` 与 `dns.dualStack` 尚未接入 `ClientMux` 的域名解析；目前使用系统解析器。
- `trafficPattern.nonce` 的 nonce 前缀重写规则已在 underlay 层实现，但 `trafficPattern.lowEntropy` 尚未从配置贯穿到 wire 的 feature 开关（feature 本身可用、默认关闭）。
- 前置 socks5 代理的 UDP ASSOCIATE 目前返回明确的 "unsupported" 错误，而不是静默伪装成支持。

## 4. `shadowlemon_socks5::proto` 模块可见性

`proto` 模块当前是私有的；`driver.rs` 使用 crate 根的重导出（已包含 `encode_request`、`read_request`、`parse_udp_datagram` 等），并在本地定义了少量未导出的认证常量。后续可将 `proto` 改为 `pub` 以澄清 API。

## 5. UDP 路由器层无 underlay 级认证

`ServerMux` 的 UDP 监听用零密钥 `PacketUnderlay` 只做 `recv_raw`/`send_to`，认证完全依赖帧本身的端到端 AEAD。这在当前设计下是可接受的（伪造帧无法通过解密），但没有线路级的早期过滤，后续可加基于 user hint 的快速丢弃。

## 6. 与规格 §2.2 的密钥派生偏差

凭据存储层保存的 32 字节 credential 已经是 `SHA256(password ‖ 0x00 ‖ username)`，而 `crypto::derive_static_key` 内部又做一次 `hash_password`，因此实际 PBKDF2 输入比规格公式多一次 SHA-256。两端完全一致，且 V0.2 没有兼容性基线，故不影响正确性。若要严格对齐公式，需同时修改 `crypto::kdf`、`serveruser::User` 与 `handshake::ClientHandshake::with_password` 三处。

## 7. 尚未验证的平台目标

本地仅完成 x86_64-unknown-linux-gnu 的编译与测试；其余目标（musl、Windows、macOS、Android、MIPS）只通过 CI 配置与文档描述，未在实际设备上运行。由于 Go 实现已移除，不能再依赖原 Go 版本的交叉编译结果作为这些平台的验证依据，所有目标都必须用 Rust 工具链重新验证。MIPS 目标尤其需要真机验证：它是 Rust Tier 3，需要 nightly `-Z build-std` 与匹配 OpenWrt SDK 的工具链。详见 `platform-notes.md`。
