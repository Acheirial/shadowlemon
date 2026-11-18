# ShadowLemon V0.2 协议规范（Rust 重写版）

本文件是 ShadowLemon V0.2 协议的**实现级规范**。所有长度单位均为字节，除非另有说明所有多字节整数均为**大端（big endian）**编码。本文取代旧的 `docs/protocol.md`（下称 V0.1）；两者不兼容，且不存在互通路径。

> **破坏性重写（big-bang）**：V0.2 的线协议版本字节为 `4`。V0.1 的版本字节为 `3`。二者没有任何向后兼容，Go 实现与 Rust 实现之间**不需要互通**。升级必须两端同步；只升级一端时所有会话都会在握手阶段失败。

> **外部传输为 UDP-only**：所有 `portBindings` 必须是 UDP，TCP 外部绑定在配置校验阶段即被拒绝（"TCP external transport has been removed; use protocol UDP"）。SOCKS5 CONNECT（TCP 目标）通过 UDP 隧道内的可靠层（`DatagramStream` / `StreamUnderlay`）承载。本规范中残留的 "TCP 密码链 / TCP 规则" 等措辞描述的是**隧道内可靠流的会话模式**，不是外部 TCP 传输；外部线路上只有 UDP 数据报。

---

## 1. 符号与常量

| 常量 | 值 | 说明 |
| :-- | :-- | :-- |
| 协议名 | `ShadowLemon V0.2` | 协议族标识 |
| `PROTOCOL_VERSION` | `4` | 唯一的线协议版本号 |
| `MIN_SUPPORTED_VERSION` / `MAX_SUPPORTED_VERSION` | `4` / `4` | 服务端支持区间退化为单点 |
| `WIRE_NONCE_LEN` | `24` | 线路 nonce 恒为 24 字节 |
| `METADATA_LEN` | `32` | 元数据明文恒为 32 字节 |
| `TAG_LEN` | `16` | AEAD 认证标签恒为 16 字节 |
| `MAX_SESSION_PAYLOAD` | `1024` | 会话元数据可携带的最大载荷 |
| `MAX_FRAGMENT` | `32768` | TCP 单个应用分片的最大长度 |
| `MAX_HANDSHAKE_SUITES` | `4` | 握手中套件数量的上限 |
| `EPH_PUB_LEN` | `32` | X25519 一次性公钥长度 |
| `SALT_LEN` | `16` | 握手 clientSalt / serverSalt 长度 |
| `USER_HINT_LEN` | `4` | 用户提示长度 |
| `STATIC_KEY_SALT` | `SHA256("ShadowLemon V0.2 static key salt")` | 固定 32 字节，可预计算 |
| `HINT_PEPPER` | `"ShadowLemon V0.2 user hint pepper"` | 用户提示 pepper 常量（ASCII/UTF-8） |
| `HKDF_INFO_C2S` | `"ShadowLemon V0.2 c2s" ‖ 0x04 ‖ suite` | c2s 会话密钥 info |
| `HKDF_INFO_S2C` | `"ShadowLemon V0.2 s2c" ‖ 0x04 ‖ suite` | s2c 会话密钥 info |
| `PBKDF2_ITERATIONS` | `4096` | 静态密钥派生迭代次数 |
| `REPLAY_CACHE_GEN_SIZE` | `65536` | 每代签名表容量 |
| `REPLAY_CACHE_TTL` | `360` 秒（6 分钟） | 代轮换时间阈值 |
| `NEGATIVE_HINT_CACHE_TTL` | `10` 秒 | `(hint, sourceIP)` 负缓存有效期 |
| `MAX_PREFIX_PADDING` / `MAX_SUFFIX_PADDING` | `32` / `32` | 实现层每条数据帧随机前缀/后缀填充上限（见 §10.1） |
| `UDP_ROUTING_ENVELOPE_LEN` | `5` | UDP 路由明文头长度，已从 MTU 预算中扣除（见 §9） |

记 `‖` 为字节串拼接；记 `byte(x)` 为单字节无符号整数；`u16be` / `u32be` / `u64be` 为大端整数编码。`rotr64(x, n)` 为 64 位循环右移。

---

## 2. 密码套件与密钥

### 2.1 密码套件表

套件编号是**线格式的一部分，永不改变**。新增套件只能追加在编号末尾。配置枚举名与线套件号是两套独立编号空间，映射见 `config-v0.2.md`。

| 套件名 | 线套件号 `suite` | 配置枚举名 | 密钥长度 `KeyLen()` | AEAD nonce 长度 `N` | 默认 |
| :-- | :--: | :-- | :--: | :--: | :--: |
| XChaCha20-Poly1305 | `0` | `CIPHER_SUITE_XCHACHA20_POLY1305` | 32 | 24 | ✅ |
| AES-256-GCM | `1` | `CIPHER_SUITE_AES_256_GCM` | 32 | 12 | |
| AES-128-GCM | `2` | `CIPHER_SUITE_AES_128_GCM` | 16 | 12 | |

认证标签长度恒为 16 字节。客户端配置 `cipherSuites` 为空时只使用套件 0；服务端配置 `cipherSuites` 为空时接受全部三种套件（按服务端偏好顺序 0 → 1 → 2）。

### 2.2 静态密钥派生（无时间盐）

V0.2 **彻底移除基于时间的盐**：不再计算 `timeSalt`，不再需要时钟同步，服务端不再扫描 3 个时间槽。静态密钥只用于保护握手的两个数据包。派生算法：

```
hashedPassword = SHA256( utf8(password) ‖ 0x00 ‖ utf8(username) )
staticKeySalt  = STATIC_KEY_SALT                       // 固定 32 字节，见常量表
pbkdf2Output   = PBKDF2-HMAC-SHA256(
                     password    = hashedPassword,
                     salt        = staticKeySalt,
                     iterations  = 4096,
                     dkLen       = 32)
staticKey      = pbkdf2Output[0 .. envelopeSuite.KeyLen()]   // 前缀截取
```

- `envelopeSuite` 是客户端首选列表的第 0 项（信封套件）。客户端用该套件的 `staticKey` 加密握手请求。
- 服务端在发现阶段对**每一个受支持套件**分别用 `pbkdf2Output[..suite.KeyLen()]` 派生候选静态密钥并尝试解密；认证标签校验通过者即为客户端的信封套件。
- 前缀截取在密码学上等价于一次独立派生：PBKDF2 输出块可视为随机，任何前缀都不泄露后续字节。
- 截取长度只决定**握手信封**密钥的长度；会话密钥长度由协商出的最终套件决定，与信封套件无关。

> **实现说明（与上述公式的偏差）**：当前 Rust 实现的凭据存储层保存的 32 字节 credential 已经是 `SHA256(password ‖ 0x00 ‖ username)`（`serveruser::User::from_password` / `from_hashed_password` 与客户端 `ClientHandshake::with_password` 一致），而 `derive_static_key` 内部又做一次 `hash_password`。因此实际 PBKDF2 输入是「哈希凭据再哈希」，比本节的公式多一次 SHA-256。两端完全自洽，且 V0.2 不与任何旧实现互通，因此不影响正确性与安全性；如未来要严格对齐公式，需同时修改 `crypto::kdf`、`serveruser::User` 与 `handshake::ClientHandshake::with_password` 三处。

### 2.3 AEAD nonce 的派生

线路 nonce 恒为 24 字节；实际传给 AEAD 的 nonce 取其后 `N` 字节：

```
aeadNonce = wireNonce[24 - N : 24]
```

- 套件 0（`N=24`）：使用完整 24 字节线路 nonce。
- 套件 1、2（`N=12`）：使用 `wireNonce[12:24]`。

> **禁止事项**：AES-GCM 套件**绝不可**使用 `wireNonce[0:12]` 作为 nonce。 traffic pattern 的 `noncePattern` 可能把线路 nonce 前 12 字节重写为确定性常量，同一密钥下重复的 GCM nonce 会直接摧毁 GCM 的机密性与认证能力。`wireNonce[12:24]` 包含随机区 `[12:20]` 与用户提示区 `[20:24]`，重复概率可忽略；且 UDP 载荷 nonce 翻转下标 16（落在 `[12:20]` 内），因此元数据与载荷不会共用同一 `(key, nonce)` 对。

### 2.4 用户提示（keyed hint）

用户提示放置于线路 nonce 的最后 4 字节 `wireNonce[20:24]`，是**查表加速器，绝不是认证凭据**。

```
hintInput = HINT_PEPPER ‖ utf8(username) ‖ wireNonce[0:16]
userHint  = SHA256(hintInput)[0:4]          // 4 字节，写入 wireNonce[20:24]
```

注意 `HINT_PEPPER` 是协议内置的固定常量字符串，并非机密；提示与 16 字节随机前缀绑定，主要作用是缩小服务端试解范围。服务端**默认要求**首包携带的提示与某个已注册用户匹配（配置项 `ServerConfig.advancedSettings.userHintIsMandatory`，默认 `true`）。提示不匹配的数据包直接丢弃；不存在为兼容旧客户端而关闭该要求的场景。

负缓存：当某个 `(hint, sourceIP)` 试解失败（认证未通过）时，服务端在 `10` 秒内拒绝相同 `(hint, sourceIP)` 的后续报文，不再进入试解密循环。负缓存只是优化，不能改变「认证只由 AEAD 标签决定」这一事实。

### 2.5 前向安全

握手后的数据面密钥来自一次性 X25519 交换（`shared`）加上双方随机盐，具备前向安全；会话结束后双方应尽力清零一次性私钥。即使用户名/密码或静态密钥事后泄露，攻击者若未持有该次握手的两包密文与一次性私钥，也无法还原握手后的会话密钥。

但 **0-RTT early data 没有前向安全**：首包 piggyback 中的 SOCKS5 请求以及紧跟其后的应用字节，使用的是由静态密钥派生的 early key（见 §2.6）。静态密钥泄露即可还原这些早期数据。因此 early key 只在首 flight 使用，一旦 `openSessionResponse` 处理完成（客户端）/发送完成（服务端），立即切换到前向安全密钥，且首 flight 之后到达的应用字节会被缓存到密钥切换完成才提交。

### 2.6 0-RTT 早期密钥（early key）

两端在 X25519 交换完成之前，仅凭已认证的静态密钥、会话 ID 与信封套件即可各自推导出一对方向独立的 early key：

```
salt       = SHA256(staticKey ‖ u32be(sessionID))
info_c2s   = "ShadowLemon V0.2 0rtt c2s" ‖ 0x04 ‖ byte(envelopeSuite)
info_s2c   = "ShadowLemon V0.2 0rtt s2c" ‖ 0x04 ‖ byte(envelopeSuite)
early_c2s  = HKDF-SHA256(ikm=staticKey, salt=salt, info=info_c2s, L=envelopeSuite.KeyLen())
early_s2c  = HKDF-SHA256(ikm=staticKey, salt=salt, info=info_s2c, L=envelopeSuite.KeyLen())
```

- `sessionID` 绑定进 salt，因此不同会话的 early key 独立；但没有临时私钥输入，所以 early data 不具前向安全（见 §2.5）。
- 数据面 `Session` 以 early key 创建，首 flight 的 SOCKS5 请求（piggyback）与紧随的应用字节即在 early key 下发送；服务端可在同一 flight 内解析并转发。
- `openSessionResponse` 处理/发送完成后，调用 `Session::upgrade_keys` swap 为 §3.3 派生的前向安全 `c2sKey` / `s2cKey`。首 flight 之后到达的应用数据在 swap 完成前被 gate，保证每条数据帧只属于一个密钥 epoch。
- early key 与 §3.3 的会话密钥在密码学上互不相关（不同的 HKDF info 前缀）。

---

## 3. 握手（0-RTT）

V0.2 握手是 **0-RTT**：客户端发出的**第一个数据报**就同时携带握手请求与 SOCKS5 请求（piggyback），这些数据在 §2.6 的 early key 下加密。服务端在同一个 flight 内完成发现、套件协商、解析 piggyback 并转发到目标；无需等客户端再发一轮数据。外部传输只有 UDP，因此这里说的"会话"是 UDP 上的一条逻辑流（CONNECT 的可靠流，或 UDP associate 的数据报会话）。

握手请求是 `openSessionRequest`（协议类型 2）载荷的**前缀**；握手响应是 `openSessionResponse`（协议类型 3）载荷的**全部内容**。所有 `HandshakeMode`（`HANDSHAKE_DEFAULT`、`HANDSHAKE_STANDARD`、`HANDSHAKE_NO_WAIT`）都使用这一 0-RTT 流程；其中 `HANDSHAKE_NO_WAIT` 明确表示客户端在返回流/数据报句柄前不等待响应，其余模式名保留仅为兼容旧配置。

> 数据面 gate：CONNECT 流会立即返回给上层，但它的读写被 gate 直到前向安全 key swap 完成（`openSessionResponse` 处理完成）。因此 early data 虽在首 flight 即被服务端转发，首 flight 之后的应用字节仍会在客户端等待密钥切换。early data 无前向安全（§2.5）。

### 3.1 握手请求载荷前缀

| 偏移 | 字段 | 长度 | 说明 |
| :--: | :-- | :--: | :-- |
| 0 | `versionMin` | 1 | 必须等于 `4` |
| 1 | `versionMax` | 1 | 必须等于 `4` |
| 2 | `suiteCount` | 1 | 取值范围 `1..4` |
| 3 | `suite list` | `suiteCount` | 客户端首选套件编号，顺序即偏好；**禁止重复** |
| 3+`suiteCount` | `ephPubClient` | 32 | 一次性 X25519 公钥 |
| 35+`suiteCount` | `clientSalt` | 16 | 客户端随机盐 |

前缀总长 `51 + suiteCount` 字节（`suiteCount=1` 时为 52）。**应用数据可以紧跟在该前缀之后，放在同一载荷内**（其长度计入元数据的 `payload length`）。在 0-RTT 流程中，这段 piggyback 的开头是 SOCKS5 `CONNECT` 或 `UDP ASSOCIATE` 请求，后面可紧跟立即可用的应用字节（受 `piggyback_capacity` 限制）。载荷用信封套件的静态密钥加密，与元数据相同密钥、不同 nonce（见 §4.2）；数据面会话则以 §2.6 的 early key 启动并在握手完成后 swap 到前向安全密钥。

### 3.2 握手响应载荷

| 偏移 | 字段 | 长度 | 说明 |
| :--: | :-- | :--: | :-- |
| 0 | `status` | 1 | `0` = 成功；`2` = 无共同套件 |
| 1 | `version` | 1 | 最终版本（`4`）；失败时为 `0` |
| 2 | `suite` | 1 | 最终套件编号；失败时为 `0` |
| 3 | `ephPubServer` | 32 | 服务端一次性 X25519 公钥；失败时全 0 |
| 35 | `serverSalt` | 16 | 服务端随机盐；失败时全 0 |

总长**恒为 51 字节**，不携带应用数据。响应**恒定使用解出请求时所用的那把静态密钥**（信封套件）加密；此时不能使用会话密钥，因为会话密钥派生依赖响应中的 `ephPubServer` 与 `serverSalt`，会形成循环依赖。客户端只需用建连时的信封 cipher 做一次认证标签校验即可解开响应。

### 3.3 会话密钥派生

协商出最终 `suite` 后，双方各自计算：

```
shared    = X25519(ephPriv_local, ephPub_peer)                  // 32 字节
salt      = SHA256(staticKey ‖ clientSalt ‖ serverSalt)          // 32 字节
info_c2s  = "ShadowLemon V0.2 c2s" ‖ 0x04 ‖ byte(finalSuite)
info_s2c  = "ShadowLemon V0.2 s2c" ‖ 0x04 ‖ byte(finalSuite)
c2sKey    = HKDF-SHA256(ikm=shared, salt=salt, info=info_c2s, L=finalSuite.KeyLen())
s2cKey    = HKDF-SHA256(ikm=shared, salt=salt, info=info_s2c, L=finalSuite.KeyLen())
```

- `staticKey` 是**解出握手包时所用的信封静态密钥**（两端一致：客户端用首选第 0 项的静态密钥，服务端用试解命中的同一把）。
- `finalSuite` 是协商出的最终套件；它决定 `info` 中的套件号与派生长度 `L`，**不受信封套件密钥长度限制**（可以协商出比信封套件更长的密钥）。
- `shared` 为全零，或对端公钥非法（X25519 低阶点等）时，双方必须拒绝本次会话。
- `c2s` 客户端发/服务端收，`s2c` 服务端发/客户端收；两方向 `info` 不同，密钥互相独立，且与静态密钥独立。
- 握手完成后，元数据与载荷两条加密路径都换成会话密钥；线路 nonce 生成方式与 AEAD nonce 截取规则不变。一次性私钥用后尽力清零。

### 3.4 版本与套件协商

1. **版本**：唯一版本为 `4`。客户端发出的 `versionMin = versionMax = 4`。请求若版本区间不含 `4`，按 §3.5「零响应字节」处理。
2. **发现**：服务端无法预知客户端信封套件，必须对**全部受支持套件**（0/1/2）× 全部用户/提示候选尝试解密；AEAD 标签校验通过即完成发现。提示与 source-IP 缓存命中的套件只能作为试解顺序提示，**失败必须回退到全集**；提示永远不构成认证。
3. **交集**：`intersection = clientSuiteList ∩ serverAllowedSet`。
4. **失败**：`intersection` 为空时返回 `status=2` 的握手响应（信封静态密钥加密，`version=0`、`suite=0`、eph/salt 全 0），随后关闭会话。这是**唯一**会返回响应字节的失败情形。
5. **成功**：交集非空时，最终套件 = **按服务端偏好顺序（`ServerConfig.cipherSuites` 顺序）在交集中第一个条目**，不按信封套件密钥长度过滤。因此只要交集非空，必能协商出套件，不存在「交集非空仍失败」的情况。

### 3.5 解析失败与零响应字节

下列任一情形，服务端**不写任何响应字节**，直接丢弃该 UDP 数据报并继续监听（外部传输为 UDP-only，不存在 TCP 连接可关闭）：

- 载荷截断，或不足 `51 + suiteCount` 字节；
- `suiteCount` 不在 `1..4`；
- 套件列表出现重复项或未知套件号；
- `versionMin > versionMax`，或版本区间不含 `4`（例如首包版本字节为 `3` 的 V0.1 对等端）；
- 载荷无法解析。

上述失败都必须记录日志，不得静默丢弃一个已通过认证的请求，更不得终止进程。「已认证但套件交集为空」除外，它返回 `status=2`。

---

## 4. 数据段格式

### 4.1 帧布局

| 字段 | 长度 | 是否必有 |
| :-- | :--: | :-- |
| `wire nonce` | `0` 或 `24` | TCP 每条密码链首条消息携带；UDP 每个数据报携带 |
| `encrypted metadata` | `32` | 是 |
| `auth tag of metadata` | `16` | 是 |
| `padding 1`（prefix） | `prefixLen` | 当 `prefixLen > 0` |
| `encrypted payload body` | `payloadLen` | 当 `payloadLen > 0` |
| `auth tag of payload` | `16` | 当 `payloadLen > 0` |
| `padding 2`（suffix） | `suffixLen` | 当 `suffixLen > 0` |

- 定长部分：`24 + 32 + 16 = 72` 字节（携带 nonce 时）。无载荷的数据段总长 `72 + prefixLen + suffixLen`。带载荷的数据段总长 `72 + prefixLen + payloadLen + 16 + suffixLen`。
- `payloadLen == 0` ⇒ 不存在载荷正文与其认证标签；`payloadLen > 0` ⇒ 载荷正文后紧跟 16 字节标签。
- `padding 1` / `padding 2` 是非加密随机字节，用于调节信息熵与连续可打印字符长度；其长度分别由元数据 `prefixLen` / `suffixLen` 决定。
- 元数据与载荷使用**同一把密钥**（握手期：静态密钥；握手后：会话密钥），但必须使用不同 nonce（见 §4.2）。

### 4.2 同一数据段内元数据与载荷的 nonce 分离

- **可靠流（隧道内）**：每条密码链维护一个 24 字节计数器 `nonce`。元数据用当前 `nonce` 的派生 nonce 加密，随后 `nonce` 自增 1；若存在载荷，载荷用自增后 `nonce` 的派生 nonce 加密，随后 `nonce` 再自增 1。`inc()` 把 24 字节视作大端整数 `mod 2^192` 加一。每条消息执行 1 次（无载荷）或 2 次（有载荷）加密与自增。
- **UDP**：每个数据报自带 24 字节 `wireNonce`。载荷 nonce 为其副本，令 `payloadNonce[16] ^= 0x01`，再按 §2.3 截取 AEAD nonce。下标 16 不属于 `[0:12]`（可被 traffic pattern 重写）也不属于 `[20:24]`（用户提示），且异或非零值保证 `payloadNonce ≠ wireNonce`。

### 4.3 可靠流（隧道内）规则

- 每条密码链的**第一条消息**携带显式 24 字节 nonce；后续消息省略 nonce，接收端按 §4.2 隐式重建。
- 握手完成时密钥链切换（静态密钥 → 会话密钥），**新密码链的第一条消息再次携带一个全新的 24 字节随机 nonce**，隐式计数器随之重置；一条连接最多切换一次链，切换后收到的第二个 `openSessionRequest` 直接丢弃。
- 单个应用分片最大 `32768` 字节；启用低熵模式时按 `low_entropy` 一节的编码上限进一步收紧（见 §7.6）。

### 4.4 UDP 规则

- 每个数据报都携带自己的 24 字节 `wireNonce`，会话密钥不跨会话复用。
- 带载荷的数据报最小为 `24 + 32 + 16 + 0 + 16 = 88` 字节。
- `mtu` 是 **L3 MTU**（配置项取值范围 `1280..1500`），即 IP 报文总长上限。UDP 有效载荷预算 = `mtu − IP头 − UDP头`：IPv4 扣除 `20+8=28` 字节，IPv6 最多扣除 `40+8=48` 字节。加密数据段总长不得超过该预算；超出时把应用数据拆分到多个数据报。

---

## 5. 协议类型总表

| 值 | 名称 | 类别 | 元数据布局 |
| :--: | :-- | :-- | :-- |
| 0 | `closeConnRequest` | 保留（V0.1 遗留，V0.2 不产生） | — |
| 1 | `closeConnResponse` | 保留（V0.1 遗留，V0.2 不产生） | — |
| 2 | `openSessionRequest` | 会话 | 会话元数据 |
| 3 | `openSessionResponse` | 会话 | 会话元数据 |
| 4 | `closeSessionRequest` | 会话 | 会话元数据 |
| 5 | `closeSessionResponse` | 会话 | 会话元数据 |
| 6 | `dataClientToServer` | 数据 | 数据元数据 |
| 7 | `dataServerToClient` | 数据 | 数据元数据 |
| 8 | `ackClientToServer` | 数据（确认） | 数据元数据 |
| 9 | `ackServerToClient` | 数据（确认） | 数据元数据 |
| 10 | `dataClientToServerLowEntropy` | 低熵数据 | 低熵数据元数据 |
| 11 | `dataServerToClientLowEntropy` | 低熵数据 | 低熵数据元数据 |

接收端遇到类型 0、1 或 `>11` 的值一律视为非法并丢弃（它们处于 AEAD 保护之下，合法发送端永远不会产生）。

---

## 6. 元数据格式（精确字节偏移）

元数据明文长度恒为 32 字节，解密后按下列布局解析。所有整数字段均为大端。**V0.2 已删除 V0.1 的 `timestamp` 字段**，所有字段相对 V0.1 左移 4 字节，尾部空出更多保留字节。

保留字节规则：`byte 1` 的 flags（非低熵类型）以及各类型尾部的 `reserved` 区间——发送端**必须**置 `0x00`；接收端**忽略**其内容，不得将其作为认证或解析依据（为未来扩展留白）。这些字节都处于 AEAD 认证范围内。

### 6.1 会话元数据（类型 2/3/4/5）

| 偏移 | 长度 | 字段 | 说明 |
| :--: | :--: | :-- | :-- |
| 0 | 1 | `protocol type` | 2 / 3 / 4 / 5 |
| 1 | 1 | `flags / reserved` | V0.2 恒 0 |
| 2 | 4 | `session ID` | u32be |
| 6 | 4 | `sequence number` | u32be，会话内每方向递增 |
| 10 | 2 | `payload length` | u16be，`≤ 1024`；载荷长度（不含 16 字节标签） |
| 12 | 1 | `suffix length` | padding 2 长度 |
| 13 | 19 | `reserved` | 全 0 |

校验：`protocol type ∈ {2,3,4,5}`；`payload length ≤ 1024`。V0.1 中的 `status code` 字段已删除——握手状态由响应载荷的 `status` 表达，关闭会话无需状态码。

### 6.2 数据元数据（类型 6/7/8/9）

| 偏移 | 长度 | 字段 | 说明 |
| :--: | :--: | :-- | :-- |
| 0 | 1 | `protocol type` | 6 / 7 / 8 / 9 |
| 1 | 1 | `flags / reserved` | V0.2 恒 0 |
| 2 | 4 | `session ID` | u32be |
| 6 | 4 | `sequence number` | u32be |
| 10 | 4 | `unack sequence number` | u32be，滑动窗口左沿 |
| 14 | 2 | `window size` | u16be，接收窗口（单位：段） |
| 16 | 1 | `fragment number` | 从某正值递减到 `0`，`0` 表示最后一个分片 |
| 17 | 1 | `prefix length` | padding 1 长度 |
| 18 | 2 | `payload length` | u16be，`≤ 32768`；载荷正文长度（不含标签） |
| 20 | 1 | `suffix length` | padding 2 长度 |
| 21 | 11 | `reserved` | 全 0 |

`sequence number` / `unack sequence number` / `window size` 用于流量控制。确认包（类型 8/9）通常 `payload length = 0`。

### 6.3 低熵数据元数据（类型 10/11）

| 偏移 | 长度 | 字段 | 说明 |
| :--: | :--: | :-- | :-- |
| 0 | 1 | `protocol type` | 10 / 11 |
| 1 | 1 | `low entropy mode` | 1 / 2 / 3 / 4（0 = 禁用，不得用于类型 10/11） |
| 2 | 4 | `session ID` | u32be |
| 6 | 4 | `sequence number` | u32be |
| 10 | 4 | `unack sequence number` | u32be |
| 14 | 2 | `window size` | u16be |
| 16 | 1 | `fragment number` | 同 §6.2 |
| 17 | 1 | `prefix length` | padding 1 长度 |
| 18 | 2 | `payload length` | u16be，编码后正文长度（见 §7），必为 8 的倍数 |
| 20 | 1 | `suffix length` | padding 2 长度 |
| 21 | 4 | `low entropy mask` | u32be 半掩码，重复成 64 位掩码 |
| 25 | 2 | `extracted payload length` | u16be，编码前的密文正文长度 |
| 27 | 1 | `low entropy mask rotation` | 旋转值 `R`，取值范围 `0..63` |
| 28 | 4 | `reserved` | 全 0 |

校验见 §7.5。注意 `payload length` 是**编码后**的 8 字节块总长，`extracted payload length` 是编码前的原始密文正文长度（因 AEAD 保长，也等于应用分片长度）。

---

## 7. 低熵扩展（类型 10/11）

> **Rust 中该扩展是 feature-gated 的，默认关闭（default OFF）**。`shadowlemon-wire` 中保留了类型 10/11 的编解码实现，但配置层已移除 `trafficPattern.lowEntropy` 字段，当前应用**不会**产生或请求低熵数据段；接收端仍可解析合法的低熵帧以兼容未来版本。实际抗指纹措施见 §10.1。

V0.2 对低熵编码做了**简化**（相对 Go V0.1 实现）：保留核心思想（把密文正文按 8 字节块编码、掩码标记数据位、填充位携带逐段随机极性、认证标签不参与变换、`extracted payload length` 记录原文长度），但**去掉步长家族与「由掩码反推步长」的歧义约束**，改为「模式固定步长 + 掩码popcount固定 + 单字节简单旋转」。实现只需少量状态。

### 7.1 模式与固定步长

| `low entropy mode` | 配置枚举 | 固定步长 `C`（每 8 字节块承载的明文字节数） | 半掩码必须含有的 1 位数 `K = 4·C` |
| :--: | :-- | :--: | :--: |
| 1 | `LOW_ENTROPY_MODE_32` | 4 | 16 |
| 2 | `LOW_ENTROPY_MODE_40` | 5 | 20 |
| 3 | `LOW_ENTROPY_MODE_48` | 6 | 24 |
| 4 | `LOW_ENTROPY_MODE_56` | 7 | 28 |

半掩码（32 位）重复成 64 位掩码后，其 1 位数为 `2K = 8C`，即每个 8 字节块恰有 `8C` 个数据位、`64 − 8C` 个填充位。因为 `C ≤ 7`，每块至少有 8 个填充位，故**不存在「无填充位」的特殊情形**。

### 7.2 掩码旋转

`low entropy mask rotation` 字段 `R ∈ [0, 63]`，直接表示「每个后续块循环右移的位数」。第 `i` 个（0-based）8 字节块使用的掩码：

```
chunkMask(i) = rotr64(initialMask, (i * R) mod 64)      // initialMask = repeat32(halfMask)
```

`R = 0` 表示不旋转（所有块同掩码）。旋转不改变 popcount，故每块数据位数恒为 `8C`。每个块都从 `initialMask` 单独计算旋转，不做累积旋转。

配置枚举 `LowEntropyMaskRotation` 到线字节 `R` 的转换（统一在配置层完成）：

| 配置值 | 线字节 `R` | 含义 |
| :-- | :--: | :-- |
| `LOW_ENTROPY_MASK_NO_ROTATION` (0) | `0` | 不旋转 |
| `LOW_ENTROPY_MASK_ROTATE_RIGHT_k`（k=1..15，枚举值 = k） | `k` | 右移 k 位 |
| `LOW_ENTROPY_MASK_ROTATE_LEFT_k`（k=1..15，枚举值 = 16·k） | `64 − k` | 左移 k 位 ≡ 右移 (64−k) 位 |

该映射把所有配置枚举值落入 `[0,63]`，接收端只需校验 `R ≤ 63`，无需再处理 V0.1 的低/高半字节编码。

### 7.3 编码算法（发送端，伪代码）

输入：密文正文 `body`（长度 `N = extractedPayloadLen`）、模式 `mode`、`R`。随机生成满足 popcount `K=4·C` 的 32 位半掩码 `halfMask` 与极性位 `p ∈ {0,1}`。

```
C     = STRIDE[mode]
K     = 4 * C
chunks = ceil(N / C)
initialMask = repeat32(halfMask)                 // (halfMask << 32) | halfMask
encoded = bytes[chunks * 8]

for i in 0 .. chunks-1:
    cm    = rotr64(initialMask, (i * R) mod 64)
    pos   = [j for j in 0..63 if bit_j(cm) == 1]  // 长度 8C，低→高
    sLen  = min(C, N - i*C)
    src   = uint64be( zeroPadLeft(body[i*C : i*C+sLen], 8) )  // sLen 字节置于低 sLen*8 位
    chunk = 0 (uint64)
    for k in 0 .. sLen*8-1:                       // 放置真实数据位
        if bit_k(src) == 1: chunk |= 1 << pos[k]
    dataMask  = OR_{k=0..sLen*8-1} (1 << pos[k])
    fillerMask = ^dataMask                        // 含未用数据位 + 所有非数据位
    if p == 1: chunk |= fillerMask                // p==0 时填充位保持 0
    encoded[i*8 : i*8+8] = uint64be_bytes(chunk)

return encoded, halfMask, p                        // halfMask 写入元数据 byte21..24
```

说明：源数据块按大端解释并放入低 `sLen*8` 位；第 `k` 个低位源比特写入掩码中第 `k` 个 1 位的位置（低→高）。最后一个不完整块中，掩码选中但未使用的位置同样按 `p` 填充。极性 `p` 是本条消息随机生成、全消息所有填充位共用。

认证标签在编码**之前**由 AEAD 产生，放在编码正文之后，**不参与**上述变换，也不计入 `payload length`。

### 7.4 解码算法（接收端，伪代码）

顺序：先按 §8 只读检查重放 → 解密元数据 → 校验低熵参数（§7.5）→ 用下面算法把编码正文还原为密文正文 → 用 AEAD 校验载荷标签。

```
C = STRIDE[mode]; K = 4*C; expectedLen = ceil(extractedLen / C) * 8
if len(encoded) != expectedLen: error
initialMask = repeat32(halfMask)
decoded = bytes[extractedLen]
p = null

for i in 0 .. chunks-1:
    cm    = rotr64(initialMask, (i * R) mod 64)
    pos   = [j for j in 0..63 if bit_j(cm) == 1]
    sLen  = min(C, extractedLen - i*C)
    dataMask   = OR_{k=0..sLen*8-1} (1 << pos[k])
    fillerMask = ^dataMask                        // 必非 0（因 8C < 64）
    chunk  = uint64be(encoded[i*8 : i*8+8])
    filler = chunk & fillerMask

    if i == 0:                                    // 从首块推断极性
        if filler == 0:          p = 0
        elif filler == fillerMask: p = 1
        else: error "混合填充位"
    else:
        if p == 0 and filler != 0:          error "填充极性不一致"
        if p == 1 and filler != fillerMask: error "填充极性不一致"

    v = 0
    for k in 0 .. sLen*8-1:
        if bit_{pos[k]}(chunk) == 1: v |= 1 << k
    decoded[i*C : i*C+sLen] = low_sLen_bytes( uint64be_bytes(v) )

return decoded                                    // 交给 AEAD 校验标签
```

填充极性由首块推断，并要求所有块的每个非数据位置都使用该极性；混合填充视为无效。被掩码选中的密文位或认证标签的任何篡改都会导致后续 AEAD 校验失败。

### 7.5 元数据有效性校验（接收端，解密元数据后立即执行）

对类型 10/11，下列任一不满足即丢弃该数据段：

1. `low entropy mode ∈ {1,2,3,4}`；
2. `popcount(halfMask) == 4·C(mode)`（精确相等，无家族容差）；
3. `R ≤ 63`；
4. `payload length % 8 == 0`，且 `payload length == ceil(extractedPayloadLen / C(mode)) · 8`；
5. `extractedPayloadLen ≤ 32768`（且 `payload length ≤ 65535`，由 u16 字段自然保证）；
6. 若 `extractedPayloadLen == 0`，则必须 `payload length == 0`（无载荷，不产生类型 10/11 帧体）；
7. §7.4 解码过程中的掩码一致性、填充极性一致性校验全部通过。

> **与 Go V0.1 的差异**：V0.1 的步长由掩码 popcount 反推且允许 `{C0−1, C0, C0+1}` 家族、旋转用 4 位低/高半字节编码、并存在「半掩码全 1 无填充位」特例。V0.2 这些歧义约束全部移除；两端必须同步升级，否则接收端会拒绝所有低熵数据段。该变更**不改变任何协议类型号或 AEAD 语义**。

### 7.6 分片上限

启用低熵模式时，每个 8 字节块最多承载 `C` 字节，编码后长度 `ceil(N/C)·8` 必须能装入 16 位 `payload length`（最大 `65535`）。由于 `payload length` 必为 8 的倍数，实际可用的最大块数为 `floor(65535/8) = 8191`，对应编码后长度 `65528`。因此单分片上限为 `min(32768, 8191·C)`：

| 模式 | `C` | 编码长度约束上限 `8191·C` | 总上限 `32768` | 实际单分片上限 |
| :--: | :--: | :--: | :--: | :--: |
| 1 (`LOW_ENTROPY_MODE_32`) | 4 | `32764` | `32768` | **`32764`** |
| 2 (`LOW_ENTROPY_MODE_40`) | 5 | `40955` | `32768` | `32768` |
| 3 (`LOW_ENTROPY_MODE_48`) | 6 | `49146` | `32768` | `32768` |
| 4 (`LOW_ENTROPY_MODE_56`) | 7 | `57337` | `32768` | `32768` |

只有模式 1 受 16 位 `payload length` 约束（应用分片超过 `32764` 字节时必须拆分）；其余模式仍受 `32768` 字节总上限约束。

---

## 8. 重放防护

TCP 字节流、UDP c2s、UDP s2c 三个域各用独立缓存。

### 8.1 签名

对被检查的报文计算 64 位 FNV-1a 签名：

```
m   = u32be(inputLen) ‖ byte(domain) ‖ wireNonce[0:24]     // 4+1+24 = 29 字节
sig = FNV1a64(m)
```

- `inputLen` = 被检查报文的总字节长度（对于携带 nonce 的帧，含 24 字节 nonce）。
- `domain`：`0` = TCP 流，`1` = UDP c2s，`2` = UDP s2c，用于隔离互不相关的流量。
- FNV-1a 64 参数：offset basis `0xcbf29ce484222325`，prime `0x100000001b3`；逐字节 `hash ^= b; hash = hash * prime (mod 2^64)`。
- 签名覆盖完整 24 字节 nonce，因此 traffic pattern 固定前 12 字节时仍有足够熵；长度置于最前保证不同长度的报文不会被当作同一序列。

### 8.2 检查与入表

- **检查（只读）**：收到数据段后，先用其 nonce 计算签名做只读查表；**不解密，也不改变缓存状态**。
- **入表（写入）**：仅当数据段通过 AEAD 标签校验、且元数据/载荷/填充/低熵解码全部结构自洽后，才把签名写入缓存（提升到当前代并写入本次来源标记）。伪造/截断/认证失败的报文永远进不了缓存，无法灌满缓存挤掉合法签名。
- 命中（只读查表）本身**不更新**缓存；只有认证成功后的写入才更新记录。

### 8.3 缓存规模与轮换

每方向 2 代，每代容量 `65536` 条签名。满足任一条件即轮换：当前代写满 `65536` 条，或距创建超过 `360` 秒（6 分钟）。轮换时：丢弃最老一代 → 当前代降为上一代 → 清空并创建新当前代。查表同时检查当前代与上一代，因此一条记录从写入到彻底消失至少跨两次轮换。

### 8.4 可靠流与 UDP 数据报的差异

- **可靠流（隧道内，原 TCP 模式）**：只对**每条密码链的第一条消息**做重放检查（后续消息用隐式递增 nonce，复制会因 nonce 不匹配在认证阶段失败）。检查携带**空来源标记**——因此任何重复投递都会被判为重放，会话以重放错误关闭。
- **UDP**：检查携带来源地址标记 `tag = addrFamily(1) ‖ ip(4 或 16) ‖ u16be(port)`，其中 `addrFamily = 4 或 6`。仅当「命中记录的标记与本次标记相同」且「标记非空」时豁免放行（同源重传）。来自其它地址的同一密文一律判为重放；**空标记永不豁免**。被判为重放的 UDP 数据报直接丢弃，端点继续处理后续报文，不下线。

---

## 9. UDP Associate 封装

为保留 socks5 UDP associate 数据报边界，对原始 UDP 数据包封装如下：

| 字段 | 长度 | 值 |
| :-- | :--: | :-- |
| `marker 1` | 1 | `0x00` |
| `data length` | 2 | `X`（u16be，data 的字节数） |
| `data` | X | 原始 UDP associate 数据报 |
| `marker 2` | 1 | `0xff` |

封装结果作为应用数据交给 UDP 隧道（可靠流或数据报会话）加密传输；外部不再有 TCP 传输路径。

---

## 10. 实现校验顺序（推荐）

接收端处理一个数据段的推荐顺序，确保「先只读查表、后写入」不变量：

1. 读取**定长部分**：携带 nonce 时先读 `24` 字节，再读 `32` 字节元数据密文与 `16` 字节标签（共 72 字节）；同一密码链的后续 TCP 消息只读后 48 字节（nonce 由隐式计数器重建）。
2. 用报文的完整 24 字节 `wireNonce` 计算 `sig`，做只读重放查表；若命中且不豁免 → 丢弃该 UDP 数据报（外部传输为 UDP-only）。此步不解密、不改动缓存。
3. 用相应密钥与派生 nonce 解密元数据；失败 → 丢弃。
4. 解析元数据并做结构校验（类型合法、长度上限、保留字段忽略、低熵参数校验 §7.5）。
5. **按元数据中的 `prefixLen` / `payloadLen` / `suffixLen` 读取剩余变长部分**（padding 1 / 载荷正文 / 载荷标签 / padding 2）；读取长度与字段不一致 → 丢弃。
6. 若 `payloadLen > 0`：低熵类型先解码（§7.4），再用载荷 nonce 与同一密钥校验 AEAD 标签；失败 → 丢弃。
7. 会话/序列号/流控/填充长度一致性校验；失败 → 丢弃。
8. 将 `sig` 写入重放缓存（提升到当前代，写入来源标记）。
9. 提交上层处理。

---

## 10.1 实现的抗指纹加固

以下措施是 V0.2 实现层为削弱被动流量指纹而采取的约定，不改变线格式字段的长度与语义，但要求两端同时升级：

1. **随机会话 ID**：`session ID` 不再从 1 递增分配，而是随机取非零 `u32`（与当前存活会话查重）。UDP 路由头中不再出现递增的 `00 00 00 01` 序列。
2. **UDP 路由头混淆**：§9 的 5 字节头保留，但 `kind` 字节改为 `kind XOR mix(session ID)`，其中 `mix` 为 32 位 MurmurHash3 finalizer 取低 8 位。这是对**固定字节 DPI 签名**的混淆，不是加密；协议感知的观察者仍可反推 `kind`。
3. **始终随机填充**：实现层为每条数据帧、ACK、关闭帧以及握手请求生成随机长度的前缀/后缀填充（各 `0..=32` 字节，随机内容）。长度逐帧重抽，避免固定长度指纹；接收端仍按元数据 `prefixLen` / `suffixLen` 读取。握手响应保持固定长度，因为 TCP 读取端依赖该定长约定。
4. **MTU 预算**：`udp_payload_budget` 在 L3 MTU 中额外扣除 5 字节路由头与最大填充预算，确保 IP 总长不超过配置值。
5. **配置层清理**：`trafficPattern`（含 nonce / padding / lowEntropy / tcpFragment / seed / unlockAll）与 `dns` 等被解析但从未贯穿到数据面的配置项已从配置 schema 中移除；真实生效的流量相关配置仅为 `mtu`、`multiplexing`、`egress`、`handshakeMode`、`cipherSuites` 与 `userHintIsMandatory`。

---

## 11. 与 V0.1 的差异

| 项 | V0.1（Go，版本 3） | V0.2（Rust，版本 4） |
| :-- | :-- | :-- |
| 版本字节 | `3` | `4`；big-bang，不互通 |
| 时间盐 | `timeSalt` 按 2 分钟槽，服务端扫描 3 槽 | **完全移除**；`staticKeySalt` 为固定 32 字节，无需时钟同步 |
| 静态密钥 | `PBKDF2(hashedPassword, timeSalt, 4096, 32)` | `PBKDF2(hashedPassword, 固定 staticKeySalt, 4096, 32)`；`hashedPassword` 不变 |
| 元数据 `timestamp` | 所有元数据含 4 字节 timestamp（±1 分钟校验） | **删除**；全部字段左移 4 字节，尾部保留字节增加 |
| HKDF info 前缀 | `"ShadowLemon V0.1 c2s/s2c"` + byte(3) + suite | `"ShadowLemon V0.2 c2s/s2c"` + `0x04` + finalSuite |
| 会话密钥长度 | 由协商套件决定 | 不变（由协商套件决定，不受信封套件限制） |
| 握手请求前缀 | versionMin/Max=3，字段布局相同 | versionMin/Max=4，字段布局与长度不变（51+suiteCount） |
| 握手失败 | 版本不符/解析失败零响应；交集空返回 status=2 | 不变 |
| 套件号 | 0/1/2 | 不变，永不改变 |
| 信封套件发现 | 试全部套件 × 3 时间槽 | 试全部套件（无时间槽维度） |
| AEAD nonce 派生 | 取末 N 字节，AES-GCM 禁用前 12 字节 | 不变 |
| UDP 载荷 nonce | `wireNonce[16] ^= 0x01` | 不变 |
| 帧布局 | 24 nonce + 32 meta + 16 tag + padding + payload + 16 tag + padding | 不变 |
| 用户提示 pepper | `"ShadowLemon V0.1 user hint pepper"` | `"ShadowLemon V0.2 user hint pepper"`；仍为 keyed 查表加速器，负缓存 10s |
| 低熵编码 | 步长家族 {C0−1,C0,C0+1}、由掩码反推步长、nibble 旋转、无填充位特例 | **简化**：模式固定步长 C、掩码 popcount 固定 =4C、单字节 R 旋转、无特例；feature-gated，默认 OFF |
| 重放签名 | FNV-1a(长度‖域‖完整24B nonce) | 不变 |
| 重放缓存 | 2 代 × 65536，6 分钟轮换 | 不变 |
| UDP 重传豁免 | 同源非空标记豁免，空标记不豁免 | 不变 |
| UDP Associate 封装 | `0x00 ‖ u16be(len) ‖ data ‖ 0xff` | 不变 |
| 配置字段 | 见 config-v0.2.md | JSON 字段名与结构保持不变（详见配置规范），时间相关概念在协议层消除 |
| 外部传输 | TCP 或 UDP 端口绑定 | **仅 UDP**；TCP 绑定被校验拒绝，SOCKS5 CONNECT 改用 UDP 隧道可靠层 |
| 握手往返 | `HANDSHAKE_NO_WAIT` 为 0-RTT，其余模式 1-RTT | 所有模式均为 0-RTT：首包 piggyback + 静态密钥派生 early key（§2.6）；数据面 I/O gated 到前向安全 key swap 完成，early data 无前向安全 |
