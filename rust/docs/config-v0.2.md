# ShadowLemon V0.2 配置规范（Rust 重写版）

本文描述 ShadowLemon V0.2（Rust 重写）的客户端/服务端配置格式与行为。**推荐格式是 YAML**（`client.yaml` / `server.yaml`，见 `configs/examples/*.yaml`）。JSON 仍然完全支持，用于兼容现有配置和自动化工具，但**不推荐**：程序读到 JSON 时会打印一次迁移提示，写回时仅 `.json` 路径保留 JSON。两种格式使用**完全相同的字段名与形状**，并保持与 Go V0.1 一致，因此现有 `configs/examples/*.json` 可被 Rust 版本直接加载。协议层的破坏性变更（版本 4、移除时间盐、移除 timestamp、低熵简化）**不体现在配置字段名上**——没有新增时间相关字段，也没有需要改名的字段。V0.2 删除了从未接入数据面的 `trafficPattern` 与服务端 `dns`：含这些字段的旧配置仍可加载（未知字段被忽略），但它们不再被解析，也不再影响流量形态。

> 底层数据模型在 Go 中是 protobuf（见 `pkg/appctl/proto/*.proto`），Rust 版本用 **serde** 对同样的字段形状做序列化/反序列化。枚举以**字符串枚举名**表示（例如 `CIPHER_SUITE_AES_256_GCM`），而非数字。格式按**文件内容**自动识别（以 `{` 开头视为 JSON，否则按 YAML 解析），与文件扩展名无关；写回时按扩展名决定格式。

---

## 1. 总览

配置分两类：

- **客户端配置** `ClientConfig`：对应 `configs/examples/client_config*.yaml` / `*.json`。
- **服务端配置** `ServerConfig`：对应 `configs/examples/server_config*.yaml` / `*.json`。

二者都是单个 YAML 映射（或等价的 JSON 对象），所有字段均为 optional（serde 中带 `#[serde(default)]`），缺失时使用默认值。枚举字符串大小写敏感，必须与下表枚举名完全一致（未知枚举名在校验阶段报错）。

最小可用示例（YAML）：

```yaml
# client.yaml
profiles:
  - profileName: default
    user: { name: user1, password: password1 }
    servers:
      - ipAddress: "12.34.56.78"
        portBindings:
          - { portRange: "2012-2022", protocol: UDP }
activeProfile: default
socks5Port: 1080
```

```yaml
# server.yaml
portBindings:
  - { portRange: "2012-2022", protocol: UDP }
users:
  - { name: user1, password: password1 }
```

---

## 2. CipherSuite 枚举与线套件号映射（重要）

**配置枚举值不是线协议套件号。** 配置枚举沿用 Go protobuf 的 `CipherSuite` 编号（0/1/2/3），而线协议套件号是 `cipher.Suite` 的 0/1/2。二者是两套独立编号空间，映射必须显式完成：

| 配置 JSON 字符串（`CipherSuite` 枚举） | 配置枚举数值 | 线套件号 `suite` | AEAD | 密钥长度 | AEAD nonce 长度 |
| :-- | :--: | :--: | :-- | :--: | :--: |
| `CIPHER_SUITE_UNSPECIFIED` | 0 | —（非法，校验拒绝） | — | — | — |
| `CIPHER_SUITE_XCHACHA20_POLY1305` | 1 | `0` | XChaCha20-Poly1305 | 32 | 24 |
| `CIPHER_SUITE_AES_256_GCM` | 2 | `1` | AES-256-GCM | 32 | 12 |
| `CIPHER_SUITE_AES_128_GCM` | 3 | `2` | AES-128-GCM | 16 | 12 |

实现要求：

- 在「配置 → 握手首选列表」转换处建立唯一映射函数 `config_suite_to_wire(CipherSuite) -> Option<u8>`；`CIPHER_SUITE_UNSPECIFIED` 返回 `None` 并被校验拒绝。
- 新增套件时必须**同时**在配置枚举末尾追加新值、在线格式末尾追加新套件号；已存在的值（无论枚举还是线号）永不改变。
- 客户端 `cipherSuites` 的顺序即客户端首选顺序，握手时写入 `suite list`（写入的是**线套件号**）；信封套件 = 列表第 0 项的线套件号。
- 服务端 `cipherSuites` 的顺序即服务端偏好顺序，用于最终套件选择；空列表表示接受全部套件（顺序 0→1→2）。
- 客户端 `cipherSuites` 为空表示只使用 `CIPHER_SUITE_XCHACHA20_POLY1305`（线号 0）。

---

## 3. 客户端配置 ClientConfig

完整字段表（JSON 字段名与 Go proto 一致）：

| JSON 字段 | 类型 | 必填 | 默认 | 说明 |
| :-- | :-- | :--: | :-- | :-- |
| `profiles` | `ClientProfile[]` | 否 | 空 | 已知客户端配置档案列表 |
| `activeProfile` | `string` | 否 | 空 | 当前激活的档案名，须匹配某个 `profileName` |
| `socks5Port` | `int32` | 否 | 实现默认（示例为 1080） | socks5 监听端口 |
| `loggingLevel` | `LoggingLevel` | 否 | `DEFAULT` | 日志级别 |
| `socks5ListenLAN` | `bool` | 否 | `false` | true 时监听 LAN 而非 localhost |
| `socks5Authentication` | `Auth[]` | 否 | 空 | socks5 代理认证账户；空表示不需要认证 |

### 3.1 ClientProfile

| JSON 字段 | 类型 | 必填 | 默认 | 说明 |
| :-- | :-- | :--: | :-- | :-- |
| `profileName` | `string` | 是（导出/校验时） | 空 | 档案名 |
| `user` | `User` | 是 | 空 | 代理账号 |
| `servers` | `ServerEndpoint[]` | 是 | 空 | 服务器列表 |
| `mtu` | `int32` | 否 | 实现默认 | L3 MTU，取值 `1280..1500`（UDP egress 用） |
| `multiplexing` | `MultiplexingConfig` | 否 | 见枚举 | 复用行为 |
| `handshakeMode` | `HandshakeMode` | 否 | `HANDSHAKE_DEFAULT` | 建连握手模式 |
| `dialer` | `ClientDialer` | 否 | 空 | 连接服务端前经过的前置代理；与 UDP-only 外部传输不兼容（上游 socks5 UDP ASSOCIATE 未实现），见 §3.2 |
| `cipherSuites` | `CipherSuite[]` | 否 | 空→仅 XChaCha20-Poly1305 | 客户端首选套件（枚举字符串），顺序即偏好 |

### 3.2 ClientDialer

| JSON 字段 | 类型 | 说明 |
| :-- | :-- | :-- |
| `protocol` | `ProxyProtocol` | 前置代理协议 |
| `host` | `string` | 代理 IP 或域名 |
| `port` | `int32` | 代理端口 |
| `socks5UDPAssociate` | `bool` | UDP underlay 是否走 socks5 UDP ASSOCIATE |
| `socks5Authentication` | `Auth` | socks5 代理认证凭据（非 socks5 时忽略） |

> **UDP-only 不兼容**：外部传输现已只支持 UDP，而前置 socks5 代理的 UDP ASSOCIATE 尚未实现（返回明确的 "unsupported" 错误）。因此 `dialer` 无法用于连接服务端，`configs/examples/client_config_with_dialer.json` 已移除该块作为 UDP-only 示例。该字段保留在 schema 中只是为了兼容旧配置的加载，不应在新配置中使用。

### 3.3 ServerEndpoint / PortBinding

`ServerEndpoint`：`ipAddress`（string）、`domainName`（string，设置时忽略 `ipAddress`）、`portBindings`（PortBinding[]）。

`PortBinding`：`port`（int32，单端口）、`portRange`（string，如 `"2012-2022"`）、`protocol`（TransportProtocol）。`port` 与 `portRange` 互斥，不可同时设置。`protocol` 在 V0.2 中**只能为 `UDP`**：TCP 外部传输已移除，设置为 `TCP` 会在校验阶段被拒绝（"TCP external transport has been removed; use protocol UDP"）。SOCKS5 CONNECT（TCP 目标）通过 UDP 隧道的可靠层承载，不需要 TCP 外部绑定。

---

## 4. 服务端配置 ServerConfig

| JSON 字段 | 类型 | 必填 | 默认 | 说明 |
| :-- | :-- | :--: | :-- | :-- |
| `portBindings` | `PortBinding[]` | 否 | 空 | 监听端口-协议绑定 |
| `users` | `User[]` | 否 | 空 | 注册用户列表 |
| `listenIPAddress` | `string` | 否 | 全网卡 | 监听 IP；未设置监听所有接口 |
| `advancedSettings` | `ServerAdvancedSettings` | 否 | 见下 | 高级设置 |
| `loggingLevel` | `LoggingLevel` | 否 | `DEFAULT` | 日志级别 |
| `mtu` | `int32` | 否 | 实现默认 | L3 MTU，`1280..1500` |
| `egress` | `Egress` | 否 | 空 | 出口代理与规则 |
| `cipherSuites` | `CipherSuite[]` | 否 | 空→接受全部 | 服务端允许/偏好套件 |

### 4.1 User / Auth

`User`：

| JSON 字段 | 类型 | 说明 |
| :-- | :-- | :-- |
| `name` | `string` | 用户名（也是用户 ID，通常是邮箱） |
| `password` | `string` | 明文密码；出于安全考虑服务端不应持久化明文 |
| `hashedPassword` | `string` | 哈希密码，hex 编码；可作为 `password` 的替代 |
| `allowPrivateIP` | `bool` | 是否允许目标是私网 IP（仅服务端有效） |
| `allowLoopbackIP` | `bool` | 是否允许目标是 loopback IP（仅服务端有效） |

> Go proto 中 `User` 的字段号 4 曾是已删除的 `quotas`，**永不复用**。Rust schema 保留这一历史说明但不实现该字段。

`Auth`：`user`（string）、`password`（string）。

### 4.2 ServerAdvancedSettings

| JSON 字段 | 类型 | 默认 | 说明 |
| :-- | :-- | :--: | :-- |
| `userHintIsMandatory` | `bool` | `true` | 是否强制要求首包携带可匹配已注册用户的 keyed 用户提示 |

V0.1 中该消息的两个旧字段 `allowLocalDestination`（字段号 1）与 `metricsLoggingInterval`（字段号 2）已删除，Rust 不实现。

### 4.3 Egress

`Egress`：`proxies`（EgressProxy[]）、`rules`（EgressRule[]）。无规则匹配时默认 `DIRECT`。

`EgressProxy`：`name`、`protocol`（ProxyProtocol）、`host`、`port`、`socks5Authentication`（Auth，非 socks5 忽略）。

`EgressRule`：

| JSON 字段 | 类型 | 说明 |
| :-- | :-- | :-- |
| `ipRanges` | `string[]` | 匹配的 CIDR 列表；`"*"` 匹配所有 IP |
| `domainNames` | `string[]` | 匹配的域名列表；`"*"` 匹配所有域名 |
| `action` | `EgressAction` | `PROXY` / `DIRECT` / `REJECT` |
| `proxyNames` | `string[]` | `action=PROXY` 时必填，引用 EgressProxy.name；多个时随机选择 |

---

## 6. 枚举清单

所有枚举在 JSON 中以字符串名表示（与 Go proto 枚举名一致）：

| 枚举 | 合法字符串值 |
| :-- | :-- |
| `LoggingLevel` | `DEFAULT`, `FATAL`, `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE` |
| `TransportProtocol` | `UNKNOWN_TRANSPORT_PROTOCOL`, `UDP`（唯一合法外部传输）, `TCP`（**已移除/被校验拒绝**） |
| `ProxyProtocol` | `UNKNOWN_PROXY_PROTOCOL`, `SOCKS5_PROXY_PROTOCOL` |
| `MultiplexingLevel` | `MULTIPLEXING_DEFAULT`, `MULTIPLEXING_OFF`, `MULTIPLEXING_LOW`, `MULTIPLEXING_MIDDLE`, `MULTIPLEXING_HIGH` |
| `HandshakeMode` | `HANDSHAKE_DEFAULT`, `HANDSHAKE_STANDARD`, `HANDSHAKE_NO_WAIT` —— 三者现在都使用 0-RTT（首包 piggyback + early key）；数据面读写被 gate 直到前向安全 key swap 完成，early data 无前向安全 |
| `EgressAction` | `PROXY`, `DIRECT`, `REJECT` |
| `CipherSuite` | 见 §2 映射表（`CIPHER_SUITE_UNSPECIFIED` 非法） |

---

## 7. serde schema（Rust 类型草图）

以下为字段形状示意（实际实现中的类型名/可见性可调整，但 JSON 名必须一致）：

```rust
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
#[serde(default, rename_all = "camelCase")]
pub struct ClientConfig {
    pub profiles: Vec<ClientProfile>,
    pub active_profile: Option<String>,        // JSON: activeProfile
    pub socks5_port: Option<i32>,              // JSON: socks5Port
    pub logging_level: Option<LoggingLevel>,   // JSON: loggingLevel
    pub socks5_listen_lan: Option<bool>,       // JSON: socks5ListenLAN
    pub socks5_authentication: Vec<Auth>,      // JSON: socks5Authentication
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
#[serde(default, rename_all = "camelCase")]
pub struct ClientProfile {
    pub profile_name: Option<String>,
    pub user: Option<User>,
    pub servers: Vec<ServerEndpoint>,
    pub mtu: Option<i32>,
    pub multiplexing: Option<MultiplexingConfig>,
    pub handshake_mode: Option<HandshakeMode>,
    pub dialer: Option<ClientDialer>,
    pub cipher_suites: Vec<CipherSuite>,       // JSON: cipherSuites
}
// ServerConfig、User、Auth、Egress 等同理。
// CipherSuite 用自定义 serde：以字符串名反序列化，映射为内部枚举；
// "CIPHER_SUITE_UNSPECIFIED" 与未知名称在反序列化/校验阶段拒绝。
```

要求：

- 使用 `#[serde(default)]` 让缺失字段取默认值；用 `rename_all = "camelCase"` 匹配现有字段名（注意 `socks5ListenLAN`、`ipAddress`、`allowPrivateIP` 等大小写需逐字匹配，必要时对个别字段用 `#[serde(rename = "...")]` 精调）。
- 未知字段：实现统一采用宽松忽略（不使用 `deny_unknown_fields`），以便旧配置平滑加载；已删除的字段（含 `trafficPattern`、`dns`）会被静默丢弃。
- 枚举反序列化必须接受字符串名；也接受对应数值（兼容 protobuf JSON），但输出统一为字符串名。

---

## 8. 校验规则（validate）

加载后、落盘前与 URL 导入后都要执行校验。失败应返回明确错误路径（例如 `profiles[0].cipherSuites[1]`）：

1. **CipherSuite**：任何 `CIPHER_SUITE_UNSPECIFIED` 或未知名称 → 错误；同一列表重复项可去重或报错（建议去重并保留首次顺序）。
2. **端口**：`port` / `portRange` 互斥；端口 `1..65535`；`portRange` 形如 `begin-end` 且 `begin ≤ end`。
3. **`port` 与 `portRange` 不可同时为空**（对需要监听/连接的绑定）。
4. **`mtu`**：若设置，必须 `1280..1500`。
5. **`advancedSettings.userHintIsMandatory`**：默认 `true`。
6. **Egress**：`action=PROXY` 时 `proxyNames` 非空，且每个名字都能解析到某个 `EgressProxy.name`。
7. **`activeProfile`**：若非空，须匹配某个 `profileName`。
8. **`hashedPassword`**：若为 hex，长度须为偶数且可解码（建议 32 字节 SHA-256）。
9. **外部传输协议**：任何 `portBinding.protocol` 为 `TCP` 的绑定都以 "TCP external transport has been removed; use protocol UDP" 错误拒绝；仅 `UDP` 合法。

已删除的 `trafficPattern` 与 `dns` 不再校验；它们作为未知字段被忽略。

---

## 9. apply（合并补丁）/ replace（整体替换）/ describe（查看）

CLI 行为与 Go 版本一致（对应 `pkg/cli/client.go`、`pkg/cli/server.go`）：

| 命令 | 行为 |
| :-- | :-- |
| `apply config <文件>` | 把输入 YAML（或 JSON）作为**合并补丁**应用到当前配置。规则：标量字段出现即覆盖；对象字段递归合并（子对象中未出现的键保持不变）；`null` 表示删除该键；数组字段整体替换（不做逐元素合并），因此修改 `profiles`/`users` 时需提交完整数组。合并后整体校验。 |
| `replace config <文件>` | 用输入 YAML（或 JSON）**整体替换**当前配置（先校验通过再原子落盘）。 |
| `describe config` | 按当前配置文件的格式输出（YAML 文件输出 YAML，JSON 文件输出 JSON；若文件不存在，先落盘一个空 YAML 配置再输出）。 |

实现要点：

- 三种操作都先反序列化为相同 schema，再执行校验；`replace` 必须整体校验通过后才写入，`apply` 合并后也必须整体校验通过。补丁格式按内容自动识别，落盘格式由目标文件扩展名决定（`.json` 保持 JSON，其余写 YAML）。
- 落盘采用「写临时文件 + 原子重命名」，避免部分写入损坏配置。
- 默认文件路径：Linux 通常 `~/.config/shadowlemon/client.yaml`（服务端 `server.yaml`），macOS `~/Library/Application Support/shadowlemon`，Windows `%AppData%\shadowlemon`。若同目录下已存在旧的 `client.json` / `server.json`，则继续使用它（并提示迁移到 YAML）。
- 环境变量：`SHADOWLEMON_{CLIENT,SERVER}_CONFIG_YAML_FILE` 指定 YAML 文件；`..._CONFIG_JSON_FILE` 指定 JSON 文件；通用的 `..._CONFIG_FILE` 接受两种格式，但拒绝旧 protobuf 内容。

---

## 10. URL 导入 / 导出

对应 `pkg/appctl/url.go`。两种 scheme：

### 10.1 `shadowlemon://`（完整配置分享链接）

- **导出**：把整个 `ClientConfig` 序列化（Go 中为 protobuf 二进制；Rust 中用等价的确定性二进制编码，如 `bincode`/自定义），再做 **标准 base64**（`base64.StdEncoding`，带 padding），前面拼接 `shadowlemon://`。

  ```
  shadowlemon://<base64(config_binary)>
  ```

- **导入**：解析 scheme 必须为 `shadowlemon`，不接受 opaque 形式；去掉前缀后标准 base64 解码，再反序列化为 `ClientConfig`，最后校验。
- 该链接承载**全部**客户端配置（含所有 profiles）。注意链接中含明文密码，分享时需谨慎。

### 10.2 `shadowlemons://`（人类可读的单档案分享链接）

每个服务器生成一个 URL，字段手工编码进 URL：

```
shadowlemons://<user>:<password>@<host>/?<query>
```

- `user:password` 取自 `profile.user`；`host` 取 `server.domainName`（优先）或 `ipAddress`（IPv6 用方括号包裹）。
- query 参数（`url.Values` 编码）：

| 参数 | 来源 | 说明 |
| :-- | :-- | :-- |
| `profile` | `profileName` | 必填 |
| `mtu` | `mtu` | 可选，十进制整数 |
| `multiplexing` | `multiplexing.level` | 枚举名，如 `MULTIPLEXING_HIGH` |
| `handshake-mode` | `handshakeMode` | 枚举名，如 `HANDSHAKE_NO_WAIT` |
| `cipher-suites` | `cipherSuites` | 枚举名逗号分隔，如 `CIPHER_SUITE_AES_256_GCM,CIPHER_SUITE_XCHACHA20_POLY1305` |
| `port` | 每个 `portBindings[].portRange` 或 `port` | 可重复，与 `protocol` 一一对应 |
| `protocol` | 每个 `portBindings[].protocol` | 可重复；V0.2 仅允许 `UDP`，`TCP` 会被校验拒绝 |

- **导入**：解析 scheme 必须为 `shadowlemons`；要求 user/password/host/`profile` 齐全；`cipher-suites` 中每个名称须能解析到合法 `CipherSuite`（未知名称报错，不得静默回退默认套件，见 protocol-v0.2.md §3.5）；`port` 与 `protocol` 数量必须一致；端口/portRange 校验同 §8。
- 导出时若 `profileName`/用户名/密码/服务器/端口绑定缺失，应报错而非生成不完整链接。

---

## 11. 旧配置（Go）→ 新配置（Rust）字段映射

JSON 字段名 **全部保留**，无需改名。下表给出完整对照并标注协议层变更：

| Go（V0.1）字段/概念 | Rust（V0.2）字段/概念 | 变化说明 |
| :-- | :-- | :-- |
| `ClientConfig.profiles` | `profiles` | 不变 |
| `ClientConfig.activeProfile` | `activeProfile` | 不变 |
| `ClientConfig.rpcPort`（已保留字段号 3） | — | **已删除，不实现** |
| `ClientConfig.advancedSettings`（已保留字段号 5） | — | **已删除，不实现** |
| `ClientConfig.httpProxyPort` / `httpProxyListenLAN`（已保留 8/9） | — | **已删除，不实现** |
| `ClientConfig.socks5Port` | `socks5Port` | 不变 |
| `ClientConfig.loggingLevel` | `loggingLevel` | 不变 |
| `ClientConfig.socks5ListenLAN` | `socks5ListenLAN` | 不变 |
| `ClientConfig.socks5Authentication` | `socks5Authentication` | 不变 |
| `ClientProfile.profileName` | `profileName` | 不变 |
| `ClientProfile.user` | `user` | 不变 |
| `User.name` / `User.password` | `name` / `password` | 不变；V0.2 派生密钥时不再依赖当前时间 |
| `User.hashedPassword` | `hashedPassword` | 不变（hex） |
| `User.quotas`（已保留字段号 4） | — | **已删除，不实现** |
| `User.allowPrivateIP` / `allowLoopbackIP` | `allowPrivateIP` / `allowLoopbackIP` | 不变 |
| `ClientProfile.servers` | `servers` | 不变 |
| `ClientProfile.mtu` | `mtu` | 不变；语义为 L3 MTU，`1280..1500` |
| `ClientProfile.multiplexing.level` | `multiplexing.level` | 不变 |
| `ClientProfile.handshakeMode` | `handshakeMode` | 不变；V0.2 所有模式都使用 0-RTT 首包 piggyback（early key），数据面 I/O gated 到前向安全 key swap 完成，early data 无前向安全 |
| `ClientProfile.trafficPattern` | — | **已删除，不再实现**（配置从未接入数据面） |
| `ClientProfile.dialer` | `dialer` | 不变 |
| `ClientProfile.cipherSuites` | `cipherSuites` | 字段名不变；枚举名不变；**映射到新的线套件号 0/1/2（见 §2）** |
| `ServerConfig.listenIPAddress` | `listenIPAddress` | 不变 |
| `ServerConfig.portBindings` | `portBindings` | 不变 |
| `ServerConfig.users` | `users` | 不变 |
| `ServerConfig.advancedSettings.userHintIsMandatory` | `advancedSettings.userHintIsMandatory` | 不变，默认 `true`；pepper 字符串改为 V0.2 |
| `ServerConfig.advancedSettings.allowLocalDestination`（已保留 1） | — | **已删除，不实现** |
| `ServerConfig.advancedSettings.metricsLoggingInterval`（已保留 2） | — | **已删除，不实现** |
| `ServerConfig.loggingLevel` / `mtu` / `egress` | 同名 | 不变 |
| `ServerConfig.dns` | — | **已删除，不再实现**；域名解析使用系统解析器 |
| `ServerConfig.trafficPattern` | — | **已删除，不再实现**（配置从未接入数据面） |
| `ServerConfig.cipherSuites` | `cipherSuites` | 字段名不变；枚举名不变；线套件号映射见 §2 |
| `Egress` / `EgressProxy` / `EgressRule` 全部字段 | 同名 | 不变 |
| 协议层 `timeSalt` / 时间槽 / 元数据 `timestamp` | **无对应配置字段** | V0.2 从协议层彻底移除；无需时钟同步；配置中从未有过这些字段，故无字段可迁移 |
| 协议版本 3（隐含） | 版本 4（隐含） | 不在配置中体现；big-bang 不兼容 |

**被删除/不实现的字段汇总**：`rpcPort`、`ClientConfig.advancedSettings`、`httpProxyPort`、`httpProxyListenLAN`、`User.quotas`、`ServerAdvancedSettings.allowLocalDestination`、`ServerAdvancedSettings.metricsLoggingInterval`、`ClientProfile.trafficPattern`、`ServerConfig.trafficPattern`、`ServerConfig.dns`。其中与「时间」相关的是协议层的 `timeSalt`/`timestamp` 概念（在 V0.1 中也没有对应的配置字段），V0.2 一并从协议中消除。`trafficPattern` 与 `dns` 被删除是因为它们只被解析、从未进入数据面；保留它们只会误导运维。

---

## 12. 与 V0.1 的差异

| 项 | V0.1（Go） | V0.2（Rust） |
| :-- | :-- | :-- |
| 配置序列化 | protobuf（`appctlpb`）+ `common.MarshalJSON` | serde 直接对同样的 JSON 形状序列化 |
| JSON 字段名 | 见本文各表 | 除已删除的 `trafficPattern` / `dns` 外完全保留，现有 JSON 可直接加载 |
| `CipherSuite` 枚举 | `UNSPECIFIED=0, XCHACHA20=1, AES256=2, AES128=3` | 不变；新增到线套件号 0/1/2 的显式映射函数 |
| 线套件号 | `cipher.Suite` 0/1/2 | 不变 |
| 时间相关配置 | 无（时间在协议层由系统时钟推导） | 无；协议层移除时间盐与 timestamp，配置无需变更 |
| 低熵配置（原 `trafficPattern.lowEntropy`） | `trafficPattern.lowEntropy` 控制编码 | 配置字段已删除；线协议语义不再有配置入口 |
| 用户提示 pepper | `"ShadowLemon V0.1 user hint pepper"` | `"ShadowLemon V0.2 user hint pepper"`（协议常量，非配置） |
| `apply/replace/describe` | 合并补丁 / 整体替换 / 查看 | 语义保持一致 |
| URL scheme | `shadowlemon://`（protobuf+base64）、`shadowlemons://`（手工 query） | 保持一致；未知套件名必须报错 |
| 已删除字段 | 见 §11 | 不实现；遇到这些字段时宽松忽略 |
| 外部传输 | TCP 或 UDP 端口绑定 | **仅 UDP**；TCP 绑定在校验阶段被拒绝，SOCKS5 CONNECT 走 UDP 隧道可靠层 |
| 握手模式 | `HANDSHAKE_NO_WAIT` 为 0-RTT，其余 1-RTT | 所有模式均为 0-RTT（early key + piggyback），数据面 I/O gated 到前向安全 key swap 完成；early data 无前向安全 |
