# Go V3 行为参考（Rust 重写 checklist）

> 本文是对现存 Go 实现（`github.com/Acheirial/shadowlemon/v3`，`AppVersion=3.38.1`）的**只读**行为摘录，供 Rust 移植者逐条对照。不是设计文档，不复制代码，只列常量、算法、状态迁移与边界。每个小节末尾有 **V0.2 决策**。
>
> **版本基线差异（务必先读）**：Go 代码里 `protocolVersion = 3`（`min=max=3`），握手字节、HKDF info 里的版本字节都是 3；protobuf 包名也带 `v3`。V0.2 的**线路版本是 4**，且**删除时间槽与所有 timestamp 字段**。因此本文凡涉及“版本 3 / timestamp / 3 槽时间盐”的地方，Rust V0.2 都要替换为版本 4、无 timestamp、无时间槽扫描；其余密码学结构（X25519、HKDF、套件协商、AEAD nonce 派生）保持。
>
> 所有多字节字段均为 **big endian**；AEAD 认证标签恒 16 字节；线路 nonce 恒 24 字节。

---

## 0. 全局常量速查

| 常量 | 值 | 源码 |
|---|---|---|
| `protocolVersion` / min / max | 3 / 3 / 3 | `pkg/protocol/handshake.go:29-47` |
| `DefaultNonceSize` / `DefaultOverhead` / `DefaultKeyLen` | 24 / 16 / 32 | `pkg/cipher/api.go:31-43` |
| `HintPepperLen` / 用户提示输入前缀 / 输出后缀 | 16 / 16 / 4 | `pkg/cipher/api.go:36-42` |
| `KeyIterV3` / `KeyRefreshInterval` | 4096 / 2 min | `pkg/cipher/keygen.go:27-40` |
| `MaxUserNameLen` | 64 | `apis/constant/user.go:18` |
| `MetadataLength` / `MaxSessionOpenPayload` | 32 / 1024 | `pkg/protocol/metadata.go:92-98` |
| `maxPDU` | 32 KiB (32768) | `pkg/protocol/segment.go:34-43` |
| `DefaultMTU` | 1400 | `pkg/common/mtu.go:18-19` |
| `packetOverhead` | 24+32+16*2 = 88 | `pkg/protocol/underlay_packet.go:39-41` |
| `packetIPUDPHeaderMax` | 48 (40 IPv6 + 8 UDP) | `pkg/protocol/underlay_packet.go:43-55` |

套件表（`pkg/cipher/suite.go:31-43, 106-127`）：

| 编号 | 套件 | 枚举名 | KeyLen | AEAD nonce 长度 | 默认 |
|---|---|---|---|---|---|
| 0 | XChaCha20-Poly1305 | `SuiteXChaCha20Poly1305` | 32 | 24（整条 wireNonce） | ✅ |
| 1 | AES-256-GCM | `SuiteAES256GCM` | 32 | 12（`wireNonce[12:24]`） | |
| 2 | AES-128-GCM | `SuiteAES128GCM` | 16 | 12（`wireNonce[12:24]`） | |

`AllSuites()` 顺序固定为 `[0,1,2]`（`suite.go:148-153`）。`ParseSuite` 大小写不敏感，忽略 `_ - 空格`（`suite.go:129-146`）。

**V0.2**：KEEP 套件编号与 AEAD nonce 派生规则；`ProtocolIdentifier()` 字符串前缀从 `"ShadowLemon V0.1"` 改为版本 4 对应标识，HKDF info / pepper 派生都随之变化（Rust 需统一常量，不要混用 V0.1 与 V4）。

---

## 1. 握手与会话校验

### 1.1 常量（`pkg/protocol/handshake.go:29-81`）

| 常量 | 值 |
|---|---|
| `protocolVersion` | 3 |
| `maxHandshakeSuites` | 4 |
| `handshakeRequestHeaderLen` | 3 |
| `handshakeRequestFixedLen` | 51 |
| `handshakeResponseLen` | 51 |
| `handshakeEphemeralKeyLen` | 32 |
| `handshakeSaltLen` | 16 |
| `handshakeStatusOK` / `handshakeStatusNoSuite` | 0 / 2 |
| `handshakeTimeout`（客户端等响应） | 10 s |

### 1.2 请求/响应布局

请求 = `openSessionRequest`（protocol type 2）载荷前缀：

| 偏移 | 字段 | 长度 |
|---|---|---|
| 0 | versionMin | 1 |
| 1 | versionMax | 1 |
| 2 | suiteCount | 1 |
| 3 | suite list（每项 1 字节） | suiteCount |
| 3+suiteCount | ephPubClient (X25519) | 32 |
| 35+suiteCount | clientSalt | 16 |

总长 `51 + suiteCount`（suiteCount=1 → 52）。**解析返回 consumed，允许应用数据 piggyback 在后面**（`handshake.go:100-151`）。

响应 = `openSessionResponse`（type 3）载荷全部，恒 51 字节：`status(1) | version(1) | suite(1) | ephPubServer(32) | serverSalt(16)`。

### 1.3 解析失败模式：`handshake.go:119-176, 209-234`

请求 `parseHandshakeRequest`：
- 长度 < 3 → 拒绝；
- `suiteCount ∉ [1,4]` → 拒绝；
- 总长不足 `51+suiteCount` → 拒绝；
- 未知套件 → 拒绝；
- **重复套件 → 拒绝（不折叠）**；`versionMin > versionMax` → 拒绝。

响应 `parseHandshakeResponse`：
- 长度必须恰好 51；
- status 0：suite 必须有效，且 `version == protocolVersion`；
- status 2（NoSuite）：**直接返回，不检查 version / suite**（微妙：失败响应里的 version/suite 被忽略）；
- 其它 status → 拒绝。

### 1.4 服务端 `acceptHandshake`（`session.go:915-1007`）流程与“静默 drop”规则

输入：`seg.payload` 为解密后的 openSessionRequest 载荷，`requestCipher` 为解出该包的静态 cipher。

1. 若 `isClient` 或 `requestCipher==nil` → 返回 error，无响应。
2. **首字节必须 == 3**（`seg.payload[0] != protocolVersion`）；否则 `response=nil`（**不写任何字节**），记录 Debug 日志，返回 error。
3. `parseHandshakeRequest` 失败 → `response=nil`（**静默丢弃**）。
4. `negotiateVersion(min,max)`：要求 `min<=max && min<=3 && max>=3`；不满足 → `response=nil`（**静默丢弃**）。
5. `negotiateSuite(request.suites, allowedSuites)`：**按服务端 allowed 顺序**取交集中第一个；交集为空 → 返回 `status=2` 的响应（**唯一一种会写响应字节的失败**），不安装会话密钥。
6. 成功：生成 eph X25519 key + 16B serverSalt，`deriveSessionKeys(...)`，剥离请求前缀（前缀后的应用数据保留并更新 `payloadLen`），`installSessionCiphers(c2s,s2c,false)`，`handshakeDone=true`。

> 不兼容旧版：版本 1/2 的首字节不是 3 → 一个字节都不回。**绝不为了兼容而关闭握手校验**。

### 1.5 版本/套件协商（`handshake.go:236-270`）

- 版本不协商，唯一合法值 3；区间含 3 即可。
- 套件：`allowed` 为空时退化为 `AllSuites()`；按 `allowed` 顺序遍历，再按客户端顺序匹配，命中第一个即返回。**不受信封套件密钥长度限制**（可协商出比信封更长的套件，例如信封 AES-128-GCM 仍可选 XChaCha20-Poly1305）。
- 命中套件的记录只作为后续查找加速，`tryState` 里 suite hint 失败会回退到全量 decryptor（`registry.go:703-754`）。

### 1.6 密钥与 cipher 发现流（服务端首包试解）

- 客户端：`newUnderlay` 用 `cipher.BlockCipherFromPassword(cipherSuites[0], password, stateless)` 建静态 cipher；`password` 实为**哈希凭据** `HashPassword(rawPassword, username)`（`appctl/appctlcommon/client.go:140-151`）。设置 `BlockContext{UserName, Pepper=HintPepper(name, credential)}`（`mux.go:944-986`）。
- 服务端：注册表 `Registry.Discover` → `discoverUser` → `tryState`，按 4 个阶段尝试用户（见 §6.2）；每个用户用 `StatelessDecryptor.TryDecrypt`（`api.go:352-398`）：
  - **外层按配置套件顺序**（`discoverySuites` = allowed 套件优先 + 其余套件补齐，`registry.go:339-359`）；
  - **内层按 3 个时间槽**（`saltFromTime` 生成 prev/current/next 三个 salt，`keygen.go:66-83`；`selectDecryptStateless` 按此顺序 `tryDecryptAt`，`cipher.go:553-565`）；
  - 首个通过 AEAD tag 的 (suite, slot) 胜出，返回该 block（信封套件），用于保护响应。
- 时间盐：`salt = SHA256(uint64(time.Round(2min).Unix()) BE)`，3 个槽为 `rounded-2min, rounded, rounded+2min`（`keygen.go:66-83`）。
- 静态密钥：`PBKDF2-HMAC-SHA256(password=credential, salt=时间盐, iter=4096, len=32)`，套件密钥 = 前 `KeyLen()` 字节（`cache.go:203-226`）。客户端用当前槽；服务端试 3 槽。

### 1.7 会话密钥派生（`cipher/kex.go:90-164`）

```
shared    = X25519(ephPriv_local, ephPub_peer)          // 必须 32B，且非全零
salt      = SHA256(staticKey ‖ clientSalt ‖ serverSalt) // staticKey = 信封套件 key 前 KeyLen() 字节
info_c2s  = "ShadowLemon V0.1 c2s" ‖ byte(3) ‖ byte(negotiatedSuite)
info_s2c  = "ShadowLemon V0.1 s2c" ‖ byte(3) ‖ byte(negotiatedSuite)
c2sKey    = HKDF-SHA256(secret=shared, salt=salt, info=info_c2s, L=negotiatedSuite.KeyLen())
s2cKey    = HKDF-SHA256(secret=shared, salt=salt, info=info_s2c, L=negotiatedSuite.KeyLen())
```

- **关键细节**：salt 里混入的是**信封套件的静态密钥**（长度由信封套件 KeyLen 决定），派生长度与 info 里的 suite 编号用的是**协商后套件**。两者可能不同。
- 客户接收用 s2cKey、发送用 c2sKey；服务端相反（`session.go:880-891`）。
- 全零 shared / 非法 peerPub → 拒绝（`kex.go:65-88`）。
- 客户端对响应**不做时间槽扫描**：用建连时的那把信封 cipher 一次解密（`session.go:1009-1065, 1086-1101`）。
- 客户端还需校验响应 suite 在自己 offer 列表里（`slices.Contains`），否则失败（`session.go:1053-1056`）。

### 1.8 会话校验（`server_session_validation.go`）

- `validateNewServerSessionSegment`：仅允许 openSessionRequest 创建服务端会话；`sessionID != 0`（0 是保留值）。
- `validateServerSegmentDirection`：服务端只允许收到 c2s 方向的协议（openSessionRequest、closeSessionRequest/Response、dataClientToServer(LowEntropy)、ackClientToServer）；其它方向拒绝，但 unknown-session 的 data/close 仍可 dispatch（用于既有 close 行为），只是不建立 source-user 关联。

### 1.9 时间戳校验（V0.2 将整体删除）

`sessionStruct.Unmarshal` / `dataAckStruct.Unmarshal`（`metadata.go:168-195, 266-322`）：`timestamp = uint32(time.Now().Unix()/60)`，要求 `|当前分钟 - timestamp| <= 1`（`mathext.WithinRange(current, original, 1)`）。**握手请求/响应和所有数据段都带此字段**，因此端到端有效时钟容差是 ±1 分钟（比密钥槽的 ±2 分钟更严）。

### 1.10 客户端握手生命周期

- 首次 `Write`：构造 openSessionRequest（含 handshake 请求），尝试 piggyback 应用数据：`!sendLowEntropy && len(handshake)+len(b) <= MaxSessionOpenPayload(1024)`（`session.go:450-494`）。
- `startHandshakeTimer()`：`time.AfterFunc(10s)`，超时 `closeWithError`；`stopHandshakeTimer` 在成功后停。
- `handshakeStarted=true` 后，data/ack 段进入 sendQueue 但被 `shouldDeferUntilHandshake` 拦住，直到 `handshakeDone` 才发送（`session.go:797-827, 1314-1321`）。
- 内部 deadline：`writeChunk` 末尾设置 `internalDeadline = now + serverRespTimeout(10s)`，只用于握手未完成时，不覆盖应用 deadline（`session.go:1314-1321, 655-711`）。

### V0.2 决策（§1）

- **KEEP**：1-RTT 握手结构、versionMin/Max 字段、suite list、eph X25519、client/serverSalt、HKDF 派生（info 前缀随版本 4 改）、套件协商按服务端偏好、重复套件拒绝、静默 drop 规则、status=2 语义、前向安全、piggyback、握手超时/defer、会话 ID 校验与方向校验。
- **SIMPLIFY**：去掉 `negotiateVersion` 区间判断（版本固定 4，直接校验首字节/版本 == 4）；请求/响应长度不变（仍 51+suiteCount / 51）。
- **DROP**：所有 `timestamp` 字段及其 ±1 分钟校验；时间槽扫描与 3 组时间盐；min/max 双端范围（改为单版本字节）。静态密钥派生改为单一 epoch 盐（无 prev/next 槽）。

---

## 2. 会话（pkg/protocol/session.go）

### 2.1 常量（`session.go:45-126`, `segment.go:34-43`）

| 常量 | 值 | 含义 |
|---|---|---|
| `segmentChanCapacity` | 256 | underlay→session 的 recvChan/inputChan 容量 |
| `segmentTreeCapacity` | 4096 | sendBuf/recvBuf/recvQueue 容量，也是 maxWindowSize |
| `segmentSendQueueTreeCapacity` | 1024 | sendQueue 容量（更早产生写背压） |
| `minWindowSize` / `maxWindowSize` | 16 / 4096 | CUBIC 窗口上下界 |
| `serverRespTimeout` | 10 s | 客户端等握手响应的内部 deadline |
| `sessionHeartbeatInterval` | 5 s | 心跳基准间隔 |
| `sessionHeartbeatJitterMs` | 1000 ms | 抖动基数（见 §2.4） |
| `minOutputInterval` | 1 ms | 输出循环最小间隔 |
| `backPressureDelay` | 100 µs | 等接收队列空位的轮询间隔 |
| `packetAckDelay` | 1 ms | 延迟 ACK 最大窗口 |
| `retransmissionCheckDelay` | 10 ms | 空 sendBuf 后首次重传检查提前量 |
| `earlyRetransmission` | 3 | 触发早期重传的 ACK 数 |
| `earlyRetransmissionLimit` | 1 | 早期重传最大次数（`txCount<=1`） |
| `txTimeoutBackOff` | 1.5 | 超时退避乘数 |
| `maxBackOffDuration` | 10 s | 退避上限 |
| `txCountLimit` | 20 | 超过则关闭会话 |
| `ackWindowUpdateThreshold` | 2048 (=4096/2) | 应用读多少个段后主动发窗口更新 ACK |
| `maxUnreadSegments` | 512 | stream 会话未读段硬上限（超限 `errUnreadLimit` 关闭） |
| `streamSendWindowFloor` | 1 | stream 每轮至少发送的段数 |
| `copyBufferSize` | 32768 | ReadFrom/WriteTo 缓冲 = maxPDU |

### 2.2 状态机（`session.go:134-156`）

`INITIALIZED(0) → ATTACHED(1) → ESTABLISHED(2) → CLOSED(3)`，只能**单向前进**（`forwardStateTo` 用 CAS，且 `next<=old` 直接返回）。客户端收到 openSessionResponse 时从 ATTACHED→ESTABLISHED（`Read` 里 `session.go:379-381`，packet 传输在 input 里 `session.go:1803-1806`）。

### 2.3 序列号 / 窗口 / ACK

- `nextSend` / `nextRecv` 为 `atomic.Uint32`；`segment.Less` 用 **`int32(a-b) < 0`** 做环绕安全比较（`segment.go:151-163`）。注意所有队列里的 seq 字段不能为 0 之外的值（session ID 0 保留，段 seq 从 0 开始）。
- `receiveWindowSize() = max(0, 4096 - recvBuf.Len() - recvQueue.Len())`（`session.go:2148-2151`）。
- `remoteWindowSize` 初始 = 16（`session.go:322`）；收到的窗口更新用 `unAckSeq` 判新旧，只有 `unAckSeq >= 已应用的最大 unAckSeq` 才接受，避免乱序/重复包缩小窗口（`updateRemoteWindowSize`, `session.go:2124-2141`）。
- packet 发送窗口：`sendWindowSize() = max(0, min(cubic.cwnd - sendBuf.Len(), remoteWindowSize))`（`session.go:2143-2146`）。
- stream 发送窗口：`max(streamSendWindowFloor=1, remoteWindowSize)`（窗口只是 advisory，不会让会话停住，`session.go:1422-1482, 2153-2159`）。
- 发送段填充：`seq=nextSend++`、`unAckSeq=nextRecv`、`windowSize=receiveWindowSize()`、`fragment=i`（倒序插入）、低熵时另填 mode/extractedLen/rotation（`session.go:1223-1289`）。
- ACK：packet 输出循环里 `ackDue = ackOnDataRecv && now>=ackDeadline`；`requestPacketAck()` 把 `ackDeadline = now + 1ms` 并置位 `ackOnDataRecv`（`session.go:1706-1716`）。ACK 不受窗口限制，直接输出，seq 填 `max(0, nextSend-1)`（`session.go:1632-1668`）。应用层每读 2048 段主动触发一次 ACK 以刷新窗口（`session.go:382-391`）。stream 收到 ACK 不做任何事（`session.go:1899-1903`）。

### 2.4 重传（`runOutputOncePacket`, `session.go:1484-1669`）

- 触发条件（对每个 sendBuf 段）：
  - **早期重传**：`ackCount >= 3 && txCount <= 1`；
  - **超时重传**：`now - txTime >= txTimeout`；
  - 二者满足其一即重传，`ackCount=0, txCount++, txTime=now`，
    `txTimeout = min(RTO() * 1.5^txCount, 10s)`。
- `txCount >= 20` → 关闭会话（too many retransmission）。
- 重传后 `hasLoss=true`（早期）或 `hasTimeout=true`（超时），分别调用 `cubic.OnLoss()` / `cubic.OnTimeout()`；**两者不会同时发生**（if/else）。
- RTO 的 RTTStats 乘数保持默认 1.0（避免与 1.5 退避重复相乘，`session.go:289-294`）。
- 新段首次发送也设置 `txTimeout = min(RTO()*1.5^1, 10s)`；若 sendBuf 原为空，首次重传检查提前到 `txTime + 10ms`（`session.go:1591-1606`）。
- 收到 ACK/数据携带的 `unAckSeq` 时，删除 sendBuf 中 `seq < unAckSeq` 的段；**只有 `txCount==1` 才更新 RTT 样本**（Karn 算法，`session.go:1843-1862, 1904-1943`）；对每个 `seq == unAckSeq` 的段 `ackCount++`（`session.go:1929-1939`）。

### 2.5 心跳抖动（`randomHeartbeatJitter`, `session.go:2222-2233`）

```
jitterMs = UniformInt[-1000, +1000]
if rand.Intn(8) == 0:            // 1/8 概率
    jitterMs += UniformInt[1, 8000]   // 长尾，最多再 +8s
jitteredInterval = 5s + jitterMs
```
每次发完心跳后重新抽 jitter（`session.go:1667`）。这样空闲会话的心跳不是固定周期信标。

### 2.6 背压与缓冲

- 写：`writeChunk` 在 `sendQueue.Remaining() <= nFragment` 时阻塞等待 `chanEmptyEvent`（`session.go:1208-1221`）；插入完成后还等待自己写的段从 sendQueue 头部移走（`session.go:1291-1312`）。
- 读：recvQueue 空时阻塞在 `chanNotEmptyEvent` / closedChan / inputErr / deadline（`session.go:400-417`）。
- stream 收端：`unreadSegments() >= 512` → 关闭（`session.go:1826-1832`）；`waitForRecvQueueSpace()` 以 100µs 轮询（`session.go:2167-2185`）。
- packet 收端：recvChan 满时**直接丢弃段**并计数（每 100 条记一次 Debug 日志），依赖对端重传（`underlay_base.go:511-549`）。
- 发送路径 segment/metadata 用 `sync.Pool` 复用（recv 路径不复用，`session.go:1116-1185`）。

### 2.7 close

`closeSession(err, notifyPeer)`（`session.go:2008-2111`）：CAS `closeRequested`，先推进到 CLOSED 并 close(closedChan)，再 drain sendQueue/sendBuf（仅在 oLock 可 TryLock 时），最后**仅在 data plane 状态且未处于 pending handshake 时**用独立 goroutine 发 closeSessionRequest（best effort，不等响应）。`dropWithError` 用于首包非本协议：不发任何字节。收到 closeSessionRequest → 回 closeSessionResponse 并立即关闭；收到 response → 立即关闭（`session.go:1949-1982`）。

### V0.2 决策（§2）

- **KEEP**：状态机、序列号环绕比较、窗口公式、ACK 规则与延迟 ACK、早期重传/超时重传/退避/次数上限、心跳抖动算法、所有缓冲容量与背压、Karn RTT 采样、sendBuf/recvBuf 顺序、close 流程。CUBIC 交互完全保留（见 §4）。
- **SIMPLIFY**：Rust 可把 4 个 `segmentTree` + channel 结构按等价的 BTreeMap/ring buffer 实现，但必须保持上述容量与“packet 丢段、stream 等空位”的差异；时间戳字段删除后，元数据不再含 timestamp。
- **DROP**：无（会话层本身不依赖时间槽；仅 metadata 里的 timestamp 字段随 §1 删除）。

---

## 3. Mux（pkg/protocol/mux.go）

### 3.1 常量

| 常量 | 值 | 源码 |
|---|---|---|
| `underlayCleanInterval` | 5 s | `mux.go:44-47` |
| `minUnderlayCapacityReclaim` | 16 | `mux.go:44-47` |
| `maxUnderlays` | 4096 | `mux.go:68-124` |
| `serverUnderlayTTL` | 3 min | `mux.go:78-83` |
| `acceptBurst` | 2048 | `mux.go:85-93` |
| `acceptRefillPerSecond` | 512 | `mux.go:95-100` |
| `acceptBucketIdleTimeout` | 10 min | `mux.go:102-104` |
| `acceptMaxSourceBuckets` | 4096 | `mux.go:106-109` |
| `maxMultiplexFactor` | 3 | `mux.go:111-118` |
| `baseUnderlayTrafficVolumeLimit` | 512 MiB (`512*1024*1024`) | `mux.go:120-124` |
| `packetUnderlayRebuildBackoffInitial` / `Max` | 1 s / 30 s | `mux.go:57-66` |
| `sessionChanCapacity`（mux Accept） | 64 | `underlay_base.go:36-40` |
| `sessionCleanInterval` | 5 s | `underlay_base.go:40` |
| `maxSessionsPerUnderlay` | 64*1024 | `underlay_base.go:46-60` |
| `removeSessionWaitTimeout` | 5 s | `underlay_base.go:62-85` |
| `readOneSegmentTimeout()` | `[60,120]` s 随机 | `underlay_base.go:88-93` |
| `streamWriteTimeout` | 30 s | `underlay_stream.go:61-88` |
| `idleSessionTimeout`（packet） | 1 min | `underlay_packet.go:68` |
| `readySessionTimeout` | 100 ms | `underlay_packet.go:70-78` |
| `sessionReaperQueueCapacity` / `sessionReaperStopTimeout` | 64 / 5 s | `underlay_packet.go:80-89` |

### 3.2 underlay 生命周期

- 一个 Mux 持有 `underlays []Underlay`，上限 4096；**只在新建时检查**，达到上限只拒绝新 underlay，不影响已有会话（`mux.go:932-936, 677-683, 783-793`）。
- client：`DialContext` 先 `cleanUnderlay(true)`，再 `maybePickExistingUnderlay()`。**stream underlay 永不复用**（握手后 cipher chain 被替换为会话密钥）；packet underlay 可复用（`mux.go:1073-1106`）。复用概率：`len(active)*factor` 个“复用槽”+1 个“新建槽”中均匀抽（`factor∈[0,3]`）。
- server stream underlay：每个 TCP 连接一个，serves 单会话；`SetRemainingTime(serverUnderlayTTL=3min)`，无会话且超时后由 cleaner 关闭（`mux.go:684-689`）。
- server packet underlay：就是 endpoint 的监听 socket，无 TTL，不随 mux 运行结束外回收；其事件循环退出（socket 故障）后由外层 for 循环重建 listener。

### 3.3 接受限流（token bucket，仅 server TCP accept）

`sourceRateLimiter`（`mux.go:1219-1359`）：每个**源 IP**（去端口、`Unmap()` IPv4-mapped）一个桶：burst=2048，refill=512/s，`tokens=min(burst, tokens+elapsed*rate)`，`tokens<1` 拒绝并立即关连接。桶数上限 4096；空闲 10 min 回收；满时先清空闲桶，仍满则淘汰最久未见的桶。`shouldLogRefusal` 每秒最多打一条拒绝日志。无有效 IP 的地址直接放行。

### 3.4 packet endpoint 重建退避（`packetUnderlayRebuildBackoff`, `mux.go:1029-1071`）

```
delay = 1s
for attempt 次且 delay < 30s: delay *= 2      // 1,2,4,8,16,30
delay = clamp(delay, ..., 30s)
return delay/2 + rand[0, delay/2]              // 在 [d/2, d] 抖动
```
成功服务 ≥30s 后 `attempt` 归零（忘掉之前的失败），下次故障立刻重建。失败重建不退出循环。

### 3.5 清理（`cleanUnderlay`, `mux.go:1108-1181`）

每 5s：关闭已完成（Done）的 underlay；关闭无会话且 `underlayFinished`（client：调度已 idle；server：调度被 disabled）的 underlay。client 还会：无会话时 `TryDisableIdle()`；当 `InBytes()>limit || OutBytes()>limit`（`limit = 512MiB << multiplexFactor`）时 `SetRemainingTime(0)` 禁用调度。slice 容量 >16 且 `len*4<=cap` 时回收底层数组。

### 3.6 加密/cipher 细节

- client 静态 cipher 用首选套件（`cipherSuites[0]`）派生；server 允许集合只约束最终协商，不约束发现阶段解密（用全部套件）。
- 每个 serveruser 的 `decryptor` 覆盖 discoverySuites（allowed 优先 + 其余），见 §1.6/§6。
- 客户端 packet underlay 按 sessionID 找 `sendBlock`（会话密钥）或回退 `u.block`（静态）；server 同理（`underlay_packet.go:1316-1330`）。

### V0.2 决策（§3）

- **KEEP**：全部容量/TTL/退避/限流常量与算法、underlay 复用规则、清理规则、每源 token bucket。
- **SIMPLIFY**：Rust 可用 tokio 定时任务实现 5s cleaner 与退避；保持数值一致。
- **DROP**：无。

---

## 4. 拥塞控制（pkg/congestion/cubic.go, rtt.go）

### 4.1 CUBIC 常量（`cubic.go:31-50`）

| 常量 | 值 |
|---|---|
| `cubicBeta` (β_cubic) | 0.7 |
| `cubicC` (C) | 0.4 |
| `cubicAIMDAlpha` | `3*(1-0.7)/(1+0.7) = 9/17 ≈ 0.5294118` |
| `timeoutSsthreshDivisor` | 2 |
| 初始 cwnd / ssthresh / mode | minWindowSize(16) / maxWindowSize(4096) / slowStart |

### 4.2 精确公式

- `epochSeconds()` = `now.UnixMicro()/1e6 - epochStart`（`cubic.go:213-217`）。
- `W_cubic(t) = C*(t - K)^3 + W_max`（`wCubic`, `cubic.go:219-223`）。
- `W_est(t) = W_max*β + α*(t / RTT_seconds)`（`wEst`, `cubic.go:225-230`），RTT 必须 >0。
- `OnAck(rtt)`（`cubic.go:119-163`）：
  - rtt<=0 → 用 `lastRTT`；仍<=0 → `defaultInitialRTT=1s`。
  - slowStart：`cwnd++`，clamp 后若 `cwnd > ssthresh` → 进入 normal，`startEpoch(cwnd, 0)`。
  - normal：`w = max(max(W_cubic(t), W_est(t)), 0)`，`w=min(w, maxWindowSize)`，`cwnd = round(w)`，再 clamp 到 [16,4096]。
- `OnLoss()`（`cubic.go:165-179`）：`W_max=cwnd`，`ssthresh=max(round(cwnd*0.7),16)`，`cwnd=ssthresh`，mode=normal，`startEpoch(W_max, cbrt(W_max*(1-0.7)/0.4))`。
- `OnTimeout()`（`cubic.go:181-202`）：`ssthresh=max(cwnd/2,16)`，`cwnd=16`，mode=slowStart，`W_max=0, K=0, epochStart=0`。
- `startEpoch` 用当前时间设 `epochStart`（秒，`cubic.go:204-211`）。

### 4.3 RTT（`rtt.go:33-54, 111-152`）

| 常量 | 值 |
|---|---|
| `rttAlpha` / `oneMinusAlpha` | 0.125 / 0.875 |
| `rttBeta` / `oneMinusBeta` | 0.25 / 0.75 |
| `defaultInitialRTT` | 1 s |
| `minRTO` | 200 ms |
| `rtoMultiplier` | 1.0（默认，session 不改） |
| session 设置的 `maxAckDelay` | `packetAckDelay = 1 ms`（`session.go:289-290`） |

- 首样本：`srtt = sample`，`rttvar = sample/2`。
- 后续：`rttvar = 0.75*rttvar + 0.25*|srtt-sample|`，`srtt = 0.875*srtt + 0.125*sample`（用微秒整数转 float32 计算，`rtt.go:134-152`）。
- `RTO()`（`rtt.go:111-132`）：无测量 → `2*defaultInitialRTT = 2s`；否则 `rto = srtt + max(4*rttvar, 10ms) + maxAckDelay(1ms)`，乘 `rtoMultiplier(1.0)`，最后 `max(rto, 200ms)`。
- 无效样本（`MaxInt64` 或 <=0）忽略。
- `SetInitialRTT` 仅允许在首样本前调用；`Reset` 清空估计但保留 maxAckDelay/rtoMultiplier。

> session 的 `txTimeout = min(RTO() * 1.5^txCount, 10s)`，与 CUBIC 的 OnAck/OnLoss/OnTimeout 共同构成拥塞响应（§2.4）。

### V0.2 决策（§4）

- **KEEP**：整个 CUBIC 与 RTT 估计（协议规定的拥塞控制必须逐字节等价），所有常量、公式、四舍五入方式、clamp、Karn 采样。
- **SIMPLIFY**：无（建议 Rust 直接照抄数值与运算顺序，`round()` 与浮点运算顺序会影响 cwnd）。
- **DROP**：无。

---

## 5. 重放防护（pkg/replay/replay.go）

### 5.1 签名（`computeSignature`, `replay.go:313-334`）

FNV-1a 64（offset `0xcbf29ce484222325`，prime `0x100000001b3`），输入顺序：
1. `uint64(len(data))` 按 **big-endian 8 字节**逐字节 hash；
2. 1 字节 `domain`；
3. `data` 全部字节。

调用方传入的 `data` 是**完整 24 字节线路 nonce**（不是只前 16 字节）。这样 noncePattern 固定前 12 字节后仍有熵。

Domain（枚举从 1 起，`replay.go:31-47`）：`DomainStream=1`（TCP）、`DomainPacketClientToServer=2`、`DomainPacketServerToClient=3`。客户端收包用 s2c，服务端收包用 c2s（`underlay_packet.go:785-790`）。

### 5.2 缓存结构与轮换（`replay.go:57-134, 242-282`）

- 每方向一个 `ReplayCache`，shared：`packetReplayCache`/`streamReplayCache = NewCache(64*1024, KeyRefreshInterval*3 = 6min)`（`underlay_packet.go:92`, `underlay_stream.go:40`）。
- 16 个 shard（`shardBits=4`），分片索引 `(signature >> 60) & 15`（取**高位**避免低位结构化碰撞）。每 shard 有 `current` 和 `previous` 两张 `map[uint64]Tag`。
- `Seen(domain,data,tag)` **只读**：同时查 current 与 previous，命中时返回 `!canRetransmit(recordedTag, tag)`；绝不写缓存、不刷新 tag、不轮换。
- `Record(domain,data,tag)` **唯一写入口且必须在认证/填充校验通过后调用**：当 `count >= capacity` 或 `now > expireAt` 时触发 `rotate()`；把签名写入 current（已存在则覆盖 tag）。previous 中的签名被 Record 时会**提升**到 current（延长去重窗口）。
- `rotate()`：`now-expireAt > expireInterval` → 清空两代、重置 expireAt；否则 `current→previous`，current 清空；重置 expireAt = now+6min。
- 容量 65536 是软上限，并发可略微超出（只增加去重窗口，不减少）。记录从写入到彻底消失至少跨两次轮换。

### 5.3 TCP vs UDP 来源标签（`replay.go:25-29, 234-240`）

`Tag = netip.AddrPort`；`canRetransmit(recordedTag, tag) = tag.IsValid() && recordedTag==tag`。
- **stream**：`Seen/Record` 都传空 `Tag{}` → 永不豁免，任何重复投递都判为重放并关闭连接；只对**每条 cipher chain 的第一条消息**检查（后续消息 nonce 隐式递增，复制会认证失败）（`underlay_stream.go:634-644, 717-726`）。
- **UDP**：tag = 对端 `netip.AddrPort`（`udpAddrPortKey`，IP+端口，Unmap 后带 zone）；同源同密文的重传豁免；不同源或空 tag 判重放 → **丢弃该数据报，端点继续服务**（`underlay_packet.go:772-792, 841-845, 892, 915`）。

### V0.2 决策（§5）

- **KEEP**：FNV-1a 签名组成（长度+domain+nonce）、两代缓存、16 shard、容量 65536、轮换触发条件、先 Seen 后 Record 的时序、TCP 空 tag / UDP AddrPort tag 规则。
- **SIMPLIFY**：`expireInterval` 原本绑定 `KeyRefreshInterval*3`（V0.2 无时间槽概念），应改为独立的 6 分钟常量（或直接固定 6min）。
- **DROP**：无（重放缓存本身保留；只是别再用“密钥刷新周期”来解释 6min）。

---

## 6. serveruser（pkg/protocol/serveruser/*.go）

### 6.1 Registry 与 generation（`registry.go:93-112, 251-283`）

- `Registry` 用 `atomic.Pointer[state]` 保存当前 generation；`SetUsers` 原子替换并 `retire()` 旧 generation 的 source-user 缓存和 fail 缓存（reload 立即生效）。
- `user` 记录：`id`（按名字排序后从 1 递增，0 保留）、`name`、`credential`（32B SHA256）、`pepper`（16B）、`suites`（发现顺序）、`decryptor`、`policy`，以及按需构建的 `preferredSuite`/`preferred` 单套件 decryptor。
- `buildCredential`：优先用 `hashedPassword`（hex 解码必须 32B），否则 `HashPassword(password, name)`（`registry.go:448-469`）。空名/重名/超长名（>64B）用户被跳过并告警；用户按名字排序，重名全部跳过。
- `allowedSuites` 为空 → `AllSuites()`；仅约束最终协商，不约束发现。
- `hintMandatory` 默认 **true**（`appctl/server.go:82-87`，配置缺省即 true）。

### 6.2 keyed hint 与发现顺序（`registry.go:322-359, 490-673`, `cipher/api.go:182-199, 259-294`）

Pepper / hint（全流程）：
```
cred = HashPassword(rawPassword, name) = SHA256(rawPassword ‖ 0x00 ‖ name)
pepper = HashPassword(cred, "ShadowLemon V0.1 user hint pepper" ‖ name)[:16]
hint   = SHA256(pepper ‖ name ‖ nonce[0:16])[:4]   // 写入 nonce[20:24]
```
`HintPepper` 空用户名或空密码返回 nil（该 block 不能写提示）；`CheckUserFromHintV3` 对 pepper/名字/长度有 panic 校验。

`tryState` 四阶段（每用户最多试一次，suite hint 失败会回退全量 decryptor）：
1. source-user cache 里 hint 匹配的候选用户（按最近使用顺序）；
2. registry 中其余 hint 匹配用户（全量扫描）；
3. 若 hint 非必需：cache 中 hint 不匹配的候选；
4. 若 hint 非必需：registry 中 hint 不匹配的其余用户。
hint 必需时阶段 3/4 直接跳过（`registry.go:635-637`）。hint 命中只触发该用户的 AEAD 试解；不命中只做 SHA256 过滤、不做 AEAD。

### 6.3 source-user cache（`source_user_cache.go`）

- 容量布局：4096 buckets × 4 ways × 16 users；256 lock stripes；key = IP16 字节（`SourceFromAddr`：忽略端口与 zone，IPv4 与 IPv4-mapped IPv6 同 key）。
- 生命期 `sourceUserCacheLifeSeconds = 600`（10 min），32 位单调 tick（进程启动起秒数，用无符号减法处理回绕）。
- `lookup` 返回按 age 升序（最近使用优先）的候选，并从 slot 附带上次成功的 suite（仅用于试解顺序）。
- `recordAuthenticated(key, userID, suite)` 在认证通过后写：slot 选择顺序 = same → empty → expired → oldest；先写 suite 再写 userID（原子发布顺序保证读者不会配对旧 suite）。
- 表用 atomic pointer 可整体 detach（retire）；写者按 bucket 串行。

### 6.4 source-fail cache（负面缓存，`source_fail_cache.go`）

- `sourceFailCacheLifeSeconds = 10`（**10 s 负缓存**）；1024 buckets × 4 ways × 64 stripes；key 同样为 IP16。
- `miss(key,hint)` 与 `recordFailure(key,hint)`：仅在 **hint mandatory** 时 consulted；同一 (source, hint) 10s 内重复失败直接拒绝，不进入试解循环；成功 `clear(key)` 清除该 source 记录。
- hint 以 4 字节小端打包成 uint32；entry 为原子替换的不可变 key + 可更新 hint/failedAt；淘汰顺序 empty → expired → 最久未失败。
- hint 非必需时完全不查/不写该缓存（避免把无 hint 的合法包误伤，`registry.go:518-530`）。

### 6.5 并发/sharding 要点

- Registry 的 users/allowedSuites/lastUsers/hintMandatory 全为 atomic；generation 内 cache 表用 `atomic.Pointer` + bucket 锁，读路径除 bucket 写外基本 lock-free。
- `Authentication` 只在初始分发的短生命周期内持有 generation；`Record()` 之后 generation 引用置 nil，已建立会话不得长期持有（`registry.go:151-198`）。

### V0.2 决策（§6）

- **KEEP**：用户注册表（atomic generation reload）、keyed hint 公式、发现顺序、source-user 正缓存与 source-fail 10s 负缓存、sharding 与并发语义。
- **SIMPLIFY**：胡椒字符串前缀随版本 4 调整；Rust 可简化锁实现但需保留 4 个阶段顺序与“hint 命中不等于认证”。
- **DROP**：无。

---

## 7. 线格式（segment.go / metadata.go / padding.go / low_entropy.go / underlay*.go）

### 7.1 段布局（`docs/protocol.md:163-198`, `underlay_packet.go:39-41`）

```
[nonce(0 或 24)] [encrypted metadata(32)] [meta auth tag(16)] [padding1] [encrypted payload body] [payload auth tag(16)] [padding2]
```
- TCP：每条 cipher chain **首条消息**带 24B nonce；后续消息不带 nonce（每条先读 48B = 32+16）。chain 切换（握手完成）后 `sendNoncePending/recvNoncePending=true`，下一条重新带 nonce（`underlay_stream.go:97-109, 473-489, 548-550`）。
- UDP：每个数据报都带 24B nonce；最小 88B（24+32+16+0+16）。
- 接收：`nonce` 用于解密 metadata；payload 必须用**不同 nonce**（见 7.4）。

### 7.2 metadata 字段偏移（大端，`metadata.go:121-227`）

32 字节固定。sessionStruct（type 2/3/4/5）：

| byte | 字段 |
|---|---|
| 0 | protocol |
| 1 | 保留（低熵模式下为 mode） |
| 2-5 | **timestamp**（分钟；V0.2 删除） |
| 6-9 | sessionID |
| 10-13 | seq |
| 14 | statusCode |
| 15-16 | payloadLen (≤1024) |
| 17 | suffixLen |
| 18-31 | 未用（清零） |

dataAckStruct（type 6/7/8/9，及低熵 10/11 复用）：

| byte | 字段 |
|---|---|
| 0 | protocol |
| 1 | 低熵 mode（仅 type10/11） |
| 2-5 | **timestamp**（V0.2 删除） |
| 6-9 | sessionID |
| 10-13 | seq（或 ack number） |
| 14-17 | unAckSeq |
| 18-19 | windowSize |
| 20 | fragment（倒数，0 为最后一片） |
| 21 | prefixLen |
| 22-23 | payloadLen |
| 24 | suffixLen |
| 25-28 | lowEntropyMask（仅低熵） |
| 29-30 | extractedPayloadLen（仅低熵） |
| 31 | lowEntropyMaskRotation（仅低熵） |

校验：sessionStruct 的 payloadLen>1024 拒绝；dataAckStruct 非低熵 payloadLen>maxPDU(32768) 拒绝；低熵另有约束（7.6）。`marshalTo` 会清空所有未用字节（含 timestamp 由当前时间重算），保证线上字节确定（`metadata.go:148-166, 239-264`）。

协议类型（`metadata.go:29-42`）：0 closeConnRequest，1 closeConnResponse，2 openSessionRequest，3 openSessionResponse，4 closeSessionRequest，5 closeSessionResponse，6 dataC2S，7 dataS2C，8 ackC2S，9 ackS2C，10 dataC2S-low-entropy，11 dataS2C-low-entropy。

### 7.3 AEAD nonce 派生（`cipher/suite.go:45-90`, `cipher/cipher.go:126-131`）

```
aeadNonce = wireNonce[len(wireNonce) - aead.NonceSize():]
```
XChaCha20 用 24B（整条）；AES-GCM 用末 12B `wireNonce[12:24]`。**前 12B 绝不可作 GCM nonce**（可被 noncePattern 固定为确定性值）。noncePattern 重写长度被 `maxNoncePatternLen = 24-12 = 12` 钳制（`suite.go:69-90`, `cipher.go:483-497`）。

### 7.4 payload nonce（TCP 隐式 / UDP 翻转字节 16）

- UDP（stateless）：`payloadNonce = copy(messageNonce); payloadNonce[16] ^= 0x01`（`payloadNonceOffset=16, mask=0x01`，`cipher.go:256-316`）；元数据与载荷 AEAD nonce 必不同（16 落在 GCM 的 [12,24) 内）。
- TCP（implicit nonce mode）：`Encrypt()` 首次取随机 nonce（+user hint）写入线上，之后每次调用 `increaseNonce()` 把整个 24B 当作大端整数 +1（`cipher.go:143-189, 499-510`）。元数据和载荷各调用一次 Encrypt → nonce 连续，天然不同。
- 客户端发送静态/会话 cipher 的 `stateless` 标志：stream=false（implicit），packet=true（`mux.go:946-984`）。

### 7.5 nonce 生成与 user hint（`cipher.go:420-551`）

1. `crand.Read(nonce[0:24])` 随机。
2. noncePattern 改写前缀（每消息随机长度/随机选固定串；UDP 默认只首个包应用：`applyToAllUDPPacket=false` 时 `noncePatternApplied` 后不再改写）。
3. `addUserHintToNonce` 把 `SHA256(pepper ‖ username ‖ nonce[0:16])[:4]` 写入 `nonce[20:24]`（§6.2）。
4. 服务端 `CheckUserFromHintV3` 反向校验；hint 只是过滤，不参与认证。

### 7.6 低熵编码（`low_entropy.go`）

- 块长 8B；模式参数（nominal）：mode 1/2/3/4 → sourceBytesPerChunk 4/5/6/7，halfMaskOnes 16/20/24/28（`low_entropy.go:68-81`）。
- 每消息独立抽 half-mask 的 1 位数 `K ∈ {K0-4, K0, K0+4}`（截断到 ≤28 且 >0），`rng.Uint32WithBits(K)`；把 32 位半掩码重复成 64 位初始 mask（`newLowEntropyHalfMask`, `halfMaskOnesChoices`, `low_entropy.go:83-100, 190-199`）。
- 实际步长 `C = chunkOnes/8 = (2*popcount(halfMask))/8 = popcount(halfMask)/4`，必须落在 `{C0-1, C0, C0+1}`，否则段无效（`validateLowEntropyCodecParams`, `low_entropy.go:312-331`）。
- 编码（`PDEP`）：源块按大端放入低 `sourceLen*8` 位，`chunk = PDEP(source, chunkMask)`；填充位统一取本消息随机的 `paddingBit∈{0,1}`（`chunk |= ^dataMask`）。第 i 块初始 mask 旋转 `i*R` 位（右旋低 4 位值；左旋高 4 位值×16；每块都从初始 mask 算，`low_entropy.go:167-188`）。
- 解码：从第 0 块推断填充极性（padding 全 0 → bit0，全 `paddingMask` → bit1，混合 → 无效），后续块极性必须一致；无填充位（全 1 mask）时跳过推断；`PEXT` 提取数据位（`low_entropy.go:252-302`）。
- 长度：`encodedLen = ceil(N/C)*8`（`lowEntropyEncodedPayloadLen`, `low_entropy.go:122-143`）；`extractedPayloadLen` = 原密文正文长度；**AEAD tag(16B) 不参与低熵变换**，紧跟编码正文（`underlay_base.go:551-608`）。
- 分片上限（TCP）：minStride = 模式下界/K，chunkCount = 65535/8=8191，mode32→24573B，mode40→32764B，mode48/56→仍受 32768 限制（`segment.go:45-90`, `low_entropy.go:102-120`）。

### 7.7 填充（`padding.go`）

- 上限：stream 恒 255；packet = `min(255, MTU - fragmentSize - 88 - existingPadding)`，再受 trafficPattern 的 `maxMiddlePaddingLen`/`maxEndPaddingLen` 限制（配置值 <0 → 0，`padding.go:75-112`）。
- 策略每消息随机二选一：
  - ASCII：`minConsecutiveASCIILen = min(maxLen, 24+rand[0,16])`（进程启动抽一次，避免主机指纹）；至少 1 个可打印字节。
  - Entropy：用已有数据（metadata+payload）的 bit 分布，把较低概率 bit 的比例降到 `targetProbability=0.325`，需要 `p = x/t - 8*len(data)` 字节填充。
  - `choosePaddingLength` 保证 maxLen≥2 时至少两种长度等概率；min 等于 max 时取 max-1（`padding.go:114-169, 199-290`）。

### 7.8 packet-over-stream 分帧（`apis/common/packet_over_stream.go`）

`0x00 ‖ uint16 BE 长度 ‖ 载荷 ‖ 0xff`。长度 ≤65535；Read 遇到短缓冲返回 `io.ErrShortBuffer` 并记住 pendingLength，下次 Read 继续同一包，保持边界。用于 TCP 上的 UDP associate。

### 7.9 UDP Associate 封装（`docs/protocol.md:301-309`）

原始 UDP associate 包封装为 `0x00 ‖ uint16 BE 长度 ‖ 数据 ‖ 0xff`（同 packet-over-stream），作为应用数据交给代理协议加密。

### V0.2 决策（§7）

- **SIMPLIFY**：metadata **删除 byte 2-5 timestamp 字段**；需重新定义 32B 布局（可将原 reserved 字节并入保留区，但保持 len=32 与其余字段偏移不变，尤其低熵字段的 25-31 偏移不要动）。Wire version=4。
- **SIMPLIFY**：低熵编码**简化并 feature-gate，默认关闭**——可只实现固定的 nominal 步长、单一填充极性、无旋转或固定旋转；但若要与 Go 互通测试，需能解析 §7.6 的完整变体。line format 长度不变。
- **KEEP**：段布局、nonce/intermediate AEAD 派生（含 AES-GCM 取末 12B）、payload nonce 翻转字节 16、TCP 隐式 nonce +1、user hint 公式、padding 算法、packet-over-stream 分帧、协议类型编号。
- **DROP**：timestamp 字段及其校验；时间槽相关注释。

---

## 8. SOCKS5（pkg/socks5/*.go）

### 8.1 常量（`apis/constant/socks5.go`）

version=5；CMD CONNECT=1 / BIND=2 / UDP ASSOCIATE=3；ADDR IPv4=1 / FQDN=3 / IPv6=4；AUTH NO_AUTH=0 / USERPASS=2 / NO_ACCEPTABLE=255，userpass 版本=1，SUCCESS=0 / FAILURE=1；REPLY SUCCESS=0 / NOT_ALLOWED=2 / NETWORK_UNREACHABLE=3 / HOST_UNREACHABLE=4 / CONNECTION_REFUSED=5 / COMMAND_NOT_SUPPORTED=7 / ADDR_TYPE_NOT_SUPPORTED=8。

### 8.2 认证（`auth.go`）

- 服务端 `handleAuthentication`：读 version(必须5)、nmethods(≠0)、methods；只认 NO_AUTH(0) 和 USERPASS(2)。
  - 两者都无 → 回 `[5,255]` 并失败；
  - NO_AUTH 且**未配置 ingress 凭据** → 回 `[5,0]` 允许；
  - USERPASS（且配置了凭据）→ 回 `[5,2]`，读子版本(必须1)、user、password（长度≤255），**遍历所有凭据做 constant-time 比较且不提前退出**（`authenticated |= userMatch & passwordMatch`），成功回 `[1,0]`，失败回 `[1,1]`；
  - 仅 NO_AUTH 但服务端要求凭据 → 失败（不写响应）。
- 客户端 `clientNegotiateAuthentication`：只发一种方法（有凭据→2，否则→0），校验响应的 version 与方法一致；user/pass 各 ≤255B。

### 8.3 CONNECT / 转发流程（`handler.go`, `socks5.go`）

- `serverServeConn`：若 `ClientSideAuthentication=true` 则跳过 ingress 认证（由 client 侧代做）；读 request；`FindAction` 做 egress 决策：
  - `DIRECT` → `handleRequest`：FQDN 先解析（DNS 失败回 HOST_UNREACHABLE；双栈选择后无合适 IP 回 NETWORK_UNREACHABLE），再按 IP 复核 egress；CONNECT→拨号（超时=`HandshakeTimeout`，按错误字符串含 "refused"/"network is unreachable" 映射 reply code），成功后回 `[5,0,bind]`，再 BidiCopy；BIND→永远 COMMAND_NOT_SUPPORTED；UDP ASSOCIATE→见 8.4。
  - `PROXY` → `handleForwarding`：拨号 egress proxy，认证，转发原始 request.Raw；write timeout=1min。
  - `REJECT` → 回 `[5,2,0.0.0.0:0]` 并报错。
- `clientServeConn`（UseProxy=true）：可先做 client 侧 ingress 认证 → `ProxyDialer.DialContext()` → 透传/协商认证 → `proxySocks5ConnReq`。
- **HandshakeNoWait**（仅客户端、仅 CONNECT）：伪造成功响应（bind 用 proxyConn.RemoteAddr），**不等服务端真实响应**直接返回 pending 请求，`BidiCopySocks5` 一边拷贝一边补发（`socks5.go:358-362`, `handler.go:376-405`）。

### 8.4 UDP ASSOCIATE

- 每用户最多 `maxUDPAssociationsPerUser = 32` 个并发 association（`handler.go:135-157`），超限回 NOT_ALLOWED。
- server 默认模式 `UDPAssociateModePacketOverStream`（另一模式 Datagram）：`net.ListenUDP("udp", nil)` 随机端口，回 `[5,0,0.0.0.0:port]`，之后 `RunUDPAssociateLoop(udpConn, PacketOverStreamTunnel(proxyConn), resolver, checker)`。
- 客户端：收到响应后改写 bind port 为本地随机 UDP 端口（`net.ListenUDP("udp4", nil)`），用 `BidiCopyUDP` + PacketOverStreamTunnel 转发。
- 每个数据报都做 egress 检查（`newUDPDestinationChecker`，因为每个 datagram 目的可不同）。
- 缓冲：初始 `udpCopyBufferSize=2KiB`，按需要翻倍到 `maxUDPDatagramSize=64KiB`（`copy.go:35-51`）。

### 8.5 Egress 规则（`egress.go`）

- 决策顺序：非 SOCKS5 / len<4 / version≠5 / 解析失败 → DIRECT；CONNECT 与 UDP_ASSOCIATE 才检查：①私网/环回拒绝；②转发代理。
- IP 分类（`classifyIP`）：unspecified > loopback > private（含 `IsPrivate`、link-local unicast/multicast、CGNAT `100.64.0.0/10`）> public。
- 访问判定（`allowIPAccess`）：public 总是允许；private 需 `user.allowPrivateIP`；loopback/unspecified 需 `user.allowLoopbackIP` 或全局 `AllowLoopbackDestination`（测试用）。未知用户一律按未授权。
- FQDN 不为避免 DNS 泄漏，**只匹配已知本地域名**（`localhost`, `localhost4`, `localhost.localdomain`, `localhost4.localdomain4` → 127.0.0.1；`localhost6`, `ip6-localhost`, `ip6-loopback`, `localhost6.localdomain6` → ::1），匹配后缀（含子域）。域名归一化：小写 + 去尾点。
- 规则匹配（`matchEgressRule`）：IP 用 CIDR（`"*"` 通配）；domain 用精确或 `.suffix`（`"*"` 通配），同样归一化。PROXY 动作从 `proxyNames` 随机选一个存在的 proxy（`mrand.Intn`）；无 proxy 列表或找不到 → 退化为规则 action。默认 DIRECT。
- 配置校验（`appctl/server.go:421-515`）：port 1-65535；CIDR 合法；domain 非空且不以 `.` 开头/结尾；PROXY 必须引用已定义 proxy；非 PROXY 不能带 proxyNames。

### V0.2 决策（§8）

- **KEEP**：SOCKS5 全部行为（auth、CONNECT、UDP ASSOCIATE、egress PROXY/DIRECT/REJECT、CIDR/域匹配、handshake timeout、no-wait）。这是 V0.2 明确保留项。
- **SIMPLIFY**：无强制简化；Rust 保持 `HandshakeNoWait` 与 packet-over-stream 边界语义。
- **DROP**：无。

---

## 9. CLI / appctl

### 9.1 命令集（`pkg/cli/server.go:31-106`, `client.go:42-141`）

`shadowlemon {client,server} <cmd>`；首个参数选模式（`main.go:43-53`，日志前缀 C/S）。精确前缀匹配注册（`parser.go:45-100`，空串=`*` 通配）。

| 命令 | 说明 |
|---|---|
| `help` | 帮助（有 advanced 分组：`run`） |
| `start` | 校验配置后后台启动 daemon |
| `run` | 前台运行（advanced；读环境变量配置） |
| `stop` / `status` | 停 / 查（基于 pidfile） |
| `apply config <FILE>` | 合并 patch 到现有配置（users 按名字覆盖、其余字段有则覆盖） |
| `replace config <FILE>` | 完整替换（省略的 users/设置被删除） |
| `describe config` | 输出当前配置 JSON |
| `version` | 输出 AppVersion + ProtocolIdentifier |
| `import config <URL>`（client） | 从 URL 导入 profile（`shadowlemon://` protobuf / `shadowlemons://` 简单 URL） |
| `export config [simple]`（client） | 导出 URL（simple=每个 server 一条可读 URL） |

参数个数由 `unexpectedArgsError` 校验；`apply/replace/import` 要求恰好 1 个文件/URL。

### 9.2 配置加载/校验/合并/替换

- 文件类型（`config_file_type.go`）：`.json` 结尾 → JSON，否则 protobuf。环境变量 `SHADOWLEMON_{CLIENT,SERVER}_CONFIG_FILE`（protobuf）与 `..._CONFIG_JSON_FILE`（JSON）优先（`client.go:320-344`, `server.go:544-562`）。默认 client 路径 `$UserConfigDir/shadowlemon/client.conf.pb`（lazy 创建目录 0755），server `/etc/shadowlemon/server.conf.pb`。
- 校验（patch / full）：
  - server patch（`server.go:400-515`）：listen IP、端口绑定、用户名唯一、MTU∈[1280,1500]（0 表示未设）、egress proxy（name 非空唯一、protocol 有效、host 非空、port 1-65535、auth user/pass 同时有无）、egress rule（CIDR/`*`、domain 不以点首尾、PROXY 引用存在）、DNS、trafficPattern、cipher suites。full 额外：配置非空、至少一个 port binding；**无用户不是错误**（但不可用）。
  - client patch（`client.go:239-259`）：profile 名唯一且各自合法、socks5 auth user/pass 非空。full 额外：≥1 profile、activeProfile 存在、socks5Port∈[1,65535]。
- 合并：`MergeServerConfig`（`server.go:311-398`）users 按名字合并（src 覆盖同名），其余字段 src 非 nil 才覆盖；结果 users 按名字排序。`mergeClientConfigByProfile`（`client.go:364-`）按 profile 名合并，src 覆盖同名。
- 存储：`StoreServerConfig`/`StoreClientConfig` 写 0660；**存储前把明文 password 转成 hashedPassword**（`appctlcommon/user.go:55-83`，`HashUserPassword(s, true/false)`）后再落盘。
- 生效：修改后需 `stop`+`start`（`docs/traffic-pattern.md:239-241`）。

### 9.3 URL 格式（`pkg/appctl/url.go`）

- 完整配置：`shadowlemon://` + `base64.StdEncoding(proto.Marshal(ClientConfig))`（`ClientConfigToURL` / `URLToClientConfig`）。
- 简单 URL：`shadowlemons://user:pass@host?profile=...&mtu=...&multiplexing=...&handshake-mode=...&cipher-suites=NAME,NAME&traffic-pattern=<base64 proto>&port=...&protocol=...`（可多个 port/protocol 对；port 支持 `a-b` 范围 1-65535；host 为 IP 则 ipAddress 否则 domainName）。`ClientProfileToMultiURLs` 每 server 产一条；`URLToClientProfile` 反向解析并校验（`url.go:60-287`）。
- `import` 若本地无配置先写一个空 ClientConfig 再合并；`ParseURLClientConfig` 按前缀分流，简单 URL 包装成单 profile 的 ClientConfig（`client.go:204-231, 461-468`）。

### 9.4 daemon / pidfile（`pidfile.go`, `daemon_unix.go`）

| 常量 | 值 |
|---|---|
| server pid 路径 | `/var/run/shadowlemon/shadowlemon.pid` |
| client pid 路径 | `<configdir>/shadowlemon.pid` |
| daemonStartTimeout / StopTimeout | 10 s / 10 s |
| start/stop poll interval | 100 ms |
| pid 文件获取重试 | 10 次 × 20 ms |
| daemon 启动 | exec `execPath {client|server} run`，`SysProcAttr{Setsid:true}`，_release 进程_ |
| 停止 | `SIGTERM` → 等 pidfile 消失/进程退出（10s）→ `SIGKILL` → 等 10s → 清 pidfile |
| 日志前缀 | client="C", server="S"（`main.go`） |
| `SHADOWLEMON_LOG_NO_TIMESTAMP` | 存在则用 `DaemonFormatter{NoTimestamp:true}`（`cli/server.go:192-197`） |
| 日志级别 | 配置 `loggingLevel` 非 DEFAULT 时 `SetLevel`（FATAL/ERROR/WARN/INFO/DEBUG/TRACE，`log/exported.go:40-65`） |

pid 文件内容 `"<pid> <identity>"`，identity 取 `/proc/<pid>/stat` 的进程启动时间（字段 22）；用于检测 PID 复用。`AcquirePidFile` 原子创建（O_EXCL），陈旧 pid 文件先校验进程/身份再删；`RemoveOwnPidFile` 只在记录当前进程时删。`debug.SetGCPercent(90)`，启动时间用 `RecordAppStartTime/Elapsed`（微秒截断）。

### V0.2 决策（§9）

- **KEEP**：CLI 命令集、配置 JSON shape（V0.2 明确保留 config JSON 形状）、apply/replace/merge 语义、URL 格式、daemon/pidfile、日志设置。
- **SIMPLIFY**：Rust 可只实现 JSON 配置（Go 的 protobuf 二进制配置与双格式探测可简化），但需保留 JSON 字段形状。
- **DROP**：无。

---

## 10. 流量模式（apis/trafficpattern/config.go）

### 10.1 配置生成与校验

`NewConfig(original)`：nil→空对象；先 `Validate(original)`；`proto.Clone` 得 effective；`generateImplicitTrafficPattern()` 为未显式字段生成值；`normalizeImplicitTrafficPattern()` 修复隐式 minLen>显式 maxLen（把 minLen 降到 maxLen）；再 `Validate(effective)`。

隐式生成用 seed：`Seed==nil` → `mrand.Int32()`（**每次启动不同，且与主机名/版本无关**）；显式 seed → `rng.FixedInt(range, "<seed>:<field>")` 可复现。

| 字段 | 隐式值 |
|---|---|
| `tcpFragment.enable` | unlockAll→随机 bool；否则 false |
| `tcpFragment.maxSleepMs` | unlockAll→[1,100]；否则 0 |
| `nonce.type` | unlockAll→随机 0..2（**绝不生成 FIXED=3**）；否则 NONCE_TYPE_RANDOM(0) |
| `nonce.applyToAllUDPPacket` | 随机 bool |
| `nonce.minLen` | unlockAll→[0,12]；否则 [6,12] |
| `nonce.maxLen` | `[minLen, 12]` |
| `padding.maxMiddlePaddingLen` | `[0,127]` 均匀 |
| `padding.maxEndPaddingLen` | unlockAll→[0,255]；否则 255 |
| `lowEntropy.mode` | unlockAll→随机枚举；否则 OFF |
| `lowEntropy.maskRotation` | 随机枚举索引（≤15 直接值；>15 → `(idx-15)*16` 左旋） |

校验：maxSleepMs∈[0,100]；minLen/maxLen∈[0,12] 且 min≤max；customHexStrings 解码后 ≤12B；padding 上限≤255；mode/rotation 为合法枚举值（`config.go:249-339`）。

### 10.2 noncePattern 重写规则与 AES-GCM 交互（关键）

- 生效点 `newNonceTo`（`cipher/cipher.go:428-478`）：先随机 24B，再按 type 改前缀：
  - RANDOM：不动；
  - PRINTABLE：`ToPrintableChar(nonce, 0, rewriteLen)`（0x20-0x7E）；
  - PRINTABLE_SUBSET：`ToCommon64Set`；
  - FIXED：随机选一个 customHexStrings，解码后 copy 长度 **钳到 `maxNoncePatternLen=12`**（即使配置里写 ≤12，这里再保证一次）。
- `rewriteLen` = 在 `[minLen, maxLen]` 均匀抽，再 `min(maxLen,12)`、`minLen=min(minLen,maxLen)`（`cipher.go:483-497`）。
- UDP 非 stateless 场景下 `applyToAllUDPPacket=false` 时，pattern 只应用首个包（`noncePatternApplied` 标记，`cipher.go:441-445`）。
- **AES-GCM 安全不变量**：GCM AEAD nonce = `wireNonce[12:24]`，而 pattern 最多写前 12B，且 payload nonce 翻转的 byte16 也落在 [12,24) → 前 12B 的固定值永远不会成为 GCM nonce，元数据/载荷 nonce 也不会因为 pattern 而重复。这是 `maxNoncePatternLen=12` 的根本原因（`suite.go:45-90`）。
- 但 user hint 写在 `nonce[20:24]`，属于 GCM nonce 区；同一凭据下 hint 确定性，随机区 `[12:20]` 提供熵，碰撞可忽略。

### V0.2 决策（§10）

- **KEEP**：noncePattern 类型、长度校验、随机长度抽取、applyToAllUDPPacket、URL/JSON 中 trafficPattern 形状、seed/unlockAll 隐式生成规则。
- **SIMPLIFY**：低熵模式 encoding 简化 + feature gate 默认 off（见 §7.6）；implicit 生成可保留 seed 可复现语义。
- **DROP**：与 timestamp/时间槽相关的任何模式字段（无）。

---

## 附：最容易被移植者忽略的微妙点

1. **版本二元性**：Go 线路版本=3、包名 v3、ProtocolIdentifier="ShadowLemon V0.1"；V0.2 必须统一切到版本 4，且 HKDF info/pepper 字符串前缀也要一起换（否则与 Go 测试向量不符）。
2. **套件协商不受信封密钥长度限制**：AES-128-GCM 信封也能协商出 32B 密钥套件；只有交集为空才回 status=2。
3. **静默 drop vs status=2**：只有“双方认证成功但无共同套件”写响应；所有解析/版本/区间失败都不写任何字节（防服务探测）。
4. **失败响应不校验 version**：`parseHandshakeResponse` 对 status=2 直接返回，忽略 version/suite。
5. **salt 与 keyLen 来源不同**：HKDF salt 混入信封静态 key（其长度由信封套件决定），派生长度/编号由协商套件决定。
6. **时间容差取交集**：密钥槽 ±2min，metadata timestamp ±1min → 实际 ±1min（V0.2 全删）。
7. **hint 不是认证**，且负缓存只在 hint mandatory 时启用；hint 匹配仅改变试解顺序。
8. **GCM nonce 取末 12B** + pattern 只写前 12B + payload 翻转 byte16，三者共同保证 (key,nonce) 不复用。
9. **早期重传只发生一次**（`txCount<=1`），且早期重传与超时重传互斥地喂给 CUBIC（OnLoss vs OnTimeout）。
10. **RTO 不叠加**：RTTStats.rtoMultiplier 固定 1.0，退避只靠 `1.5^txCount`，上限 10s，txCount≥20 关会话。
11. **重放 Seen 只读、Record 在认证后**：伪造包永远进不了缓存；只有 Record 能改 tag（防止“洗白”来源）；流模式空 tag 无豁免，UDP 同 AddrPort 才豁免。
12. **packet 丢包、stream 等空位**：两种传输的收端背压行为相反；stream 还有 512 未读段硬上限。
13. **TCP cipher chain 首包带 nonce、握手后链切换**：切换后下一条消息重新带 nonce， framing 长度变化。
14. **padding 长度不能恒为 max**（会成指纹），`choosePaddingLength` 在 min==max 时主动取 max-1；padding 策略每消息随机。
15. **TCP 分片 & 低熵 nomimal 长度**：低熵发送端在 mask 生成前用 nominal 长度填 metadata，真正发送时用 mask 派生步长重算（Rust 若简化低熵需保持 length 字段自洽）。
