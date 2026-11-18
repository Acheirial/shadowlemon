# ShadowLemon V0.2 流量特征分析与整改报告

> 本报告基于源码级静态审计、整改前后的真实抓包对比，以及 nDPI 6.0 检测测试。抓包在 `unshare -Urnm` 用户/网络/挂载命名空间内完成（命名空间内可执行 tcpdump 并可写 `/var/run/shadowlemon`），使用同一份配置分别运行整改前（`7be03ce`）与整改后（`7cfe986`）二进制，由 `sockshttpclient` / `socksudpclient` 产生流量。nDPI 为 Homebrew Linux 安装的 6.0.0（`/home/linuxbrew/.linuxbrew/bin/ndpiReader`，需设置 `LD_LIBRARY_PATH`）。

## 1. 结论摘要

> **现状说明**：外部传输已是 **UDP-only**——TCP 端口绑定被配置校验拒绝，SOCKS5 CONNECT（TCP 目标）走 UDP 隧道的可靠层。本报告中的 TCP 抓包数据来自改造前的历史基线，用于对照；当前实际上线流量只有 UDP 数据报。USENIX'23 的 GFW 全加密检测器只针对 TCP 首包，对现在的 UDP-only 流量不再适用；但 QDPI 的 `entropy_score` 高熵分析依然成立（见 `gfw-assessment.md`）。

V0.2 的密码学设计是扎实的：链路上无明文 magic / 版本 / 类型 / 会话 ID，全部包头在 AEAD 内，nonce 真实随机，不存在 V0.1 的时间盐与 timestamp。但整改前存在三类结构性指纹：

1. **UDP 5 字节明文路由头**：`kind ∈ {1,2,3,4}` + 顺序递增会话 ID，构成可直接匹配、跨会话稳定的字节签名（P0）。
2. **零填充 → 帧长确定**：所有帧 `prefixLen=suffixLen=0`，长度与载荷一一对应（P0）。
3. **整个 `trafficPattern` 配置失效**：`seed`/`unlockAll`/`tcpFragment`/`padding`/`lowEntropy`/`dns` 乃至 `nonce.*` 都被解析校验，但从未进入真实数据路径——历史 TCP 驱动在 `driver.rs` 构造 `StreamUnderlay` 后立刻 `into_inner()` 丢弃，握手用 `random_wire_nonce()`、数据面用 `random_nonce()`。这制造了严重的安全错觉（P0）。该配置字段现已从 schema 中整体删除；当前 UDP-only 传输下，数据面会话由 0-RTT early key 启动并在握手完成后 swap 到前向安全密钥（early data 无前向安全）。

## 2. 整改内容（已在 `7cfe986` 落地）

| 措施 | 实现 |
|---|---|
| UDP 路由头混淆 | `kind` 字节改为 `kind XOR mix(session_id)`（MurmurHash3 finalizer 取低 8 位） |
| 随机会话 ID | `mux.rs` 用随机非零 u32 并查重，替代 `fetch_add` 递增 |
| 始终随机填充 | 数据帧 / ACK / 关闭帧 / 握手请求带逐帧重抽的 0–32 字节随机前后缀 |
| MTU 修正 | `udp_payload_budget` 扣除 5 字节路由头与最大填充预算 |
| 死配置清理 | 从 schema / 校验 / URL 分享 / 示例配置整体删除 `trafficPattern`、`dns` |
| 文档诚实化 | 重写 `docs/traffic-pattern.md`，更新协议规范 §10.1 与 `known-gaps.md` |

## 3. 实测对比数据

### 3.1 TCP（历史基线：60 条新连接，每条一个 HTTP 请求）

> 该场景属于改造前的外部 TCP 传输，当前版本已不再产生 TCP 外部连接；数据保留作对照。

| 指标 | 整改前 | 整改后 |
|---|---|---|
| 抓包总数 | 1308 | 1272 |
| 客户端载荷长度种类 | **4** | **110** |
| 客户端载荷长度熵 | **1.501** | **3.411** |
| 服务端载荷长度种类 / 熵 | 42 / 3.310 | 186 / 4.758 |
| 握手请求长度 | **60/60 全为 150 字节** | 150–182 字节、25 个取值，单值最多 6 次 |
| 握手响应长度 | 115 字节 × 60 | 115 字节 × 60（**未修复**，见 §4） |

结论：整改前只要看到"客户端首包 150 字节"即可高置信识别；整改后握手长度分散、载荷长度熵翻倍，统计分类器的特征向量被显著削弱。

### 3.2 UDP（同一份配置，`socksudpclient` 压测）

| 指标 | 整改前 | 整改后 |
|---|---|---|
| 代理端口数据报数 | 878 | 193 |
| 首字节取值 | `{1,2,3,4}`，4 种，熵 1.048 | `{8,9,11,14}` 等非 1–4 值 |
| 前 5 字节高频值 | `0300000001`(210)、`0300000002`(217)、`0400000001`(163)、`0400000002`(171) | `0907da7cc7`、`0e07da7cc7`（会话 ID 已随机化） |

结论：整改前 `03 00 00 00 01` 这类固定 5 字节前缀是教科书式可匹配签名；整改后首字节不再是固定 kind，会话 ID 不再是 `00 00 00 01` 序列，**不存在跨会话稳定的前缀字节**。

> UDP 压测客户端因已知的半双工回复缺口（`known-gaps.md` §1）出现超时，故整改后样本量较小（193 包），但首字节取值与会话 ID 的结论不受影响。

## 3.3 nDPI 6.0 检测测试

对四份历史 pcap（TCP/UDP × 整改前后）运行 `ndpiReader`（当前版本只有 UDP 流量，TCP 行仅作对照）：

| 场景 | 流数 | nDPI 判定 | 置信度来源 | `Susp Entropy` 风险 |
|---|---|---|---|---|
| TCP 整改前 | 60 | **TPLINK_SHP**（IoT-Scada）100% | `Match by port` 60 | 100% |
| TCP 整改后 | 60 | **TPLINK_SHP**（IoT-Scada）100% | `Match by port` 60 | 100% |
| UDP 整改前 | 3 | **TPLINK_SHP** 100% | `Match by port` 3 | 100% |
| UDP 整改后 | 1 | **TPLINK_SHP** 100% | `Match by port` 1 | 100% |

**结论**：nDPI 没有 ShadowLemon 特征，因此"检测率"这个概念在当前场景下不成立——它把流量 100% 判为 `TPLINK_SHP` 纯粹是因为默认监听端口 9999/10000 命中了 TP-Link 智能家居协议的已知端口，属于**端口误报**，与协议内容无关。整改前后判定完全一致，说明我们的加固不影响 nDPI（它根本没看内容）。

**验证与建议**：把服务端监听端口改为非知名端口（如 23456）后重新抓包，`ndpiReader` 把全部 20 个流判为 **`Unknown`**（`Confidence: Unknown`），TPLINK_SHP 误报消失。因此**避免使用 9999/10000 等知名端口**是消除 nDPI 误报的直接措施。

`Susp Entropy` 风险在全部场景 100% 命中：这是任何无 cover 协议的加密代理都会触发的高熵启发式，单靠随机填充无法消除，除非外层套 TLS/HTTP 等伪装。

## 4. 残余指纹（未闭环）

1. **握手响应定长**：当前 UDP 响应恒 144 字节，因客户端读取端依赖定长约定；需改为先读 48 字节元数据、解密取长度后再读变长部分。（历史 TCP 115 字节响应已随 TCP 外部传输移除。）
2. **重传逐字节相同**：`session.rs` 重传复用同一密文帧；可用新 nonce 重加密或追加随机填充。
3. **心跳时序**：空闲 TCP 每 3–14 秒发空 ACK，空闲 UDP 不发；可被时序分类识别。
4. **UDP `kind` 混淆不是加密**：协议感知的观察者仍可用会话 ID 反推消息类型；真正的路由元数据保密需要握手协商密钥。
5. **nDPI 的 `Susp Entropy` 风险标记未消除**：100% 流被命中，因为这是高熵加密流量的通用启发式。要消除需外层 cover 协议（TLS/HTTP 伪装），不在当前 V0.2 范围内。端口误报可通过换非知名端口规避（见 §3.3）。

## 5. 参考方法论

- USENIX Security 2024《Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS》：随机填充**单独**不足以对抗统计分类，需与其他措施组合。[论文](https://www.usenix.org/system/files/usenixsecurity24-xue-fingerprinting.pdf)
- 结构化网站指纹研究（arXiv 2608.20692）：代理协议在包携带的额外字节上暴露结构指纹。[论文](https://arxiv.org/html/2608.20692v1)
- nDPI 4.12 已加入加密/混淆/代理流量检测与 TCP 指纹。[公告](https://www.ntop.org/released-ndpi-4-12-obfuscated-encrypted-proxied-traffic-and-fingerprints)
