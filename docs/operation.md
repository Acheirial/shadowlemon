# 运营维护与故障排查

> **本版本线协议版本为 4；两端必须使用同一版本，否则会话会在握手阶段失败。**
>
> 外部传输为 UDP-only：端口绑定只能是 UDP，SOCKS5 CONNECT（TCP 目标）走 UDP 隧道可靠层，握手为 0-RTT（early data 无前向安全）。

本指南涵盖 shadowlemon 的两个角色——服务器 `shadowlemon server` 与客户端 `shadowlemon client`——的日常运维：查看运行状态、查看日志、排查常见故障，以及说明配置文件的存放位置、可用环境变量和修改设置后的生效方式。

- [查看运行状态](#查看运行状态)
- [查看日志](#查看日志)
- [打开和关闭调试日志](#打开和关闭调试日志)
- [密码套件协商](#密码套件协商)
- [常见问题速查](#常见问题速查)
  - [应用配置时提示 unknown field](#症状应用配置时提示-unknown-field)
  - [完全无法连接](#症状完全无法连接)
  - [连接一段时间后断开](#症状连接一段时间后断开)
  - [速度非常慢](#症状速度非常慢)
  - [客户端无法启动](#症状客户端无法启动)
- [配置文件存放位置](#配置文件存放位置)
- [环境变量](#环境变量)
- [修改设置后如何生效](#修改设置后如何生效)

> **说明**：本版本已删除连接列表、流量统计、配额与指标查询等命令。因此排查问题只依赖两样东西：**运行状态**和**日志**。

---

## 查看运行状态

### 服务器

```sh
shadowlemon server status
```

如果输出 `shadowlemon server status is "RUNNING"`，说明代理服务正在运行。如果输出 `"STOPPED"`，说明守护进程没有在运行，可以用 `shadowlemon server start` 启动。`shadowlemon server start`（以及 `shadowlemon client start`）会先校验配置，配置非法时立即报错且不会启动守护进程，因此如果 `start` 立即失败，请先检查配置。

### 客户端

```sh
shadowlemon client status
```

如果输出 `shadowlemon client status is "RUNNING"`，说明客户端正在运行；输出 `"STOPPED"` 说明客户端没有在运行。客户端监听的 socks5 地址记录在客户端日志中。

---

## 查看日志

### 服务器 (shadowlemon server)

服务器日志输出到守护进程的标准输出。由 systemd 托管时，可以用 journalctl 查看：

```sh
sudo journalctl -u shadowlemon-server -xe --no-pager
```

只看最后若干行可以加上 `-n`，例如：

```sh
sudo journalctl -u shadowlemon-server -xe --no-pager -n 200
```

如果是用 `shadowlemon server start` 直接启动后台守护进程，可以按需把 `shadowlemon server start` 的标准输出重定向到文件。调试时更简单的方式是用 `shadowlemon server run` 在前台运行，日志直接打印到终端。

### 客户端 (shadowlemon client)

| 操作系统 | 日志目录 | 示例 |
|----------|----------|------|
| Linux | `$HOME/.cache/shadowlemon/` 或 `$XDG_CACHE_HOME/shadowlemon/` | `/home/enfein/.cache/shadowlemon/` |
| macOS | `$HOME/Library/Caches/shadowlemon/` | `/Users/enfein/Library/Caches/shadowlemon/` |
| Windows | `%USERPROFILE%\AppData\Local\shadowlemon\` | `C:\Users\enfein\AppData\Local\shadowlemon\` |

日志文件命名格式：`yyyyMMdd_HHmm_PID.log`。每次重启 shadowlemon 客户端会生成新文件。日志数量过多时，旧文件会被自动清理。

客户端以 `shadowlemon client start` 后台运行时，日志写入上表中的日志目录；直接用 `shadowlemon client run` 在前台运行时，日志打印到当前终端。

---

## 打开和关闭调试日志

默认情况下，shadowlemon 客户端与服务器打印的日志非常少，且不包含 IP 地址、端口号等敏感信息。如需诊断单个网络连接，可以打开调试日志。

仓库在 `configs/templates/` 目录下提供了模板文件。

**服务器：**

```sh
# 启用
shadowlemon server apply config server_enable_debug_logging.json
shadowlemon server stop
shadowlemon server start

# 关闭
shadowlemon server apply config server_disable_debug_logging.json
shadowlemon server stop
shadowlemon server start
```

**客户端：**

```sh
# 启用
shadowlemon client apply config client_enable_debug_logging.json
shadowlemon client stop
shadowlemon client start

# 关闭
shadowlemon client apply config client_disable_debug_logging.json
shadowlemon client stop
shadowlemon client start
```

日志等级由 `loggingLevel` 字段控制，可选值为 `FATAL`、`ERROR`、`WARN`、`INFO`、`DEBUG`、`TRACE`。改动 `loggingLevel` 也需要重启对应的程序才能生效。

---

## 密码套件协商

客户端与服务端在握手时协商密码套件。可选套件为 `CIPHER_SUITE_XCHACHA20_POLY1305`、`CIPHER_SUITE_AES_256_GCM` 和 `CIPHER_SUITE_AES_128_GCM`，配置字段的含义与协商规则见[密码套件](../rust/docs/protocol-v0.2.md#2-密码套件与密钥)与[版本与套件协商](../rust/docs/protocol-v0.2.md#34-版本与套件协商)。日常运维需要注意下面几点。

1. **协议版本与兼容性。** 客户端与服务端使用协议版本 4 完成握手，并且**不提供任何向后兼容**：唯一支持的协议版本是 4，首包版本字节不是 4 的对等端会被服务端直接丢弃——服务端不写任何响应字节、直接丢弃该 UDP 数据报并继续监听。不存在任何协商或降级路径，套件协商发生在握手的内部，因此也无法用来规避这一要求。因此两端必须使用同一版本：混用不同版本会让所有会话在握手阶段失败，现象与「完全无法连接」相同。
2. **查看生效的套件。** 服务端用 `shadowlemon server describe config`，客户端用 `shadowlemon client describe config`，查看输出里的 `cipherSuites` 字段。如果没有该字段或者列表为空，说明仍在使用默认行为：客户端只使用 `CIPHER_SUITE_XCHACHA20_POLY1305`，服务端接受全部套件。实际使用的套件由两端在握手时协商：先取两个列表的交集，再在交集中按服务端偏好顺序选出最终成员；挑选最终套件时**不**按密钥长度过滤，客户端把 `CIPHER_SUITE_AES_128_GCM` 放在首位只会让保护握手请求（信封）的静态密钥长度为 16 字节，交集中两种 32 字节密钥的套件同样可能被选中。只有双方都已认证、但套件交集为空时握手才会失败，此时服务端返回 `status` = 2、关闭会话并记录日志（客户端日志为 `no common cipher suite with the server`）。由于握手是 0-RTT，客户端可能先返回流句柄，但数据面读写被 gated 到前向安全 key swap 完成，因此套件不匹配首先表现为数据 I/O 失败/超时，而不是建连调用本身失败。
3. **建议优先使用 XChaCha20-Poly1305。** 也就是保持默认，或者把 `CIPHER_SUITE_XCHACHA20_POLY1305` 写在客户端与服务端列表的第一项。它的性能不依赖 CPU 的硬件特性；而在没有 AES 硬件指令的 CPU 上，AES-GCM 的软件实现必须使用常数时间的实现，速度会明显下降。
4. **两端 CPU 差异较大、并且都支持 AES-NI 时，可以改用 AES-256-GCM。** 如果服务器与客户端的 CPU 都支持 AES 硬件指令（x86 的 AES-NI、ARM 的 Crypto Extension），可以把两端的 `cipherSuites` 都设置为以 `CIPHER_SUITE_AES_256_GCM` 开头的列表。只有在确认两端都有硬件加速时才建议这样做，其余情况请保留 XChaCha20-Poly1305。

---

## 常见问题速查

### 症状：应用配置时提示 unknown field

错误示例（V0.2 使用 serde 反序列化 JSON，错误信息由 serde 给出）：

```text
unknown field `profiles`, expected one of ...
```

```text
unknown field `portBindings`, expected one of ...
```

这通常表示配置文件被应用到了错误的角色。如果 `shadowlemon server` 报告 `profiles` 等未知字段，很可能是它正在读取客户端配置；如果 `shadowlemon client` 报告 `portBindings` 或 `users` 等未知字段，很可能是它正在读取服务器配置。

配置由 serde 严格校验枚举名（例如 `CIPHER_SUITE_UNSPECIFIED` 或拼写错误的套件名会直接报错）。JSON 字段名与格式见 `rust/docs/config-v0.2.md`。

请使用匹配的命令：

```sh
shadowlemon server apply config <server_config.yaml>
shadowlemon client apply config <client_config.yaml>
```

另外，配置中可能含有当前 schema 不支持的字段：客户端配置里的 `httpProxyPort`、`httpProxyListenLAN`、`noCheckUpdate`、`rpcPort` 与 `advancedSettings`，以及服务器配置里 `users` 下的 `quotas`。请先从配置文件中删除这些字段，再重新应用。

### 症状：完全无法连接

| 步骤 | 命令/操作 | 检查内容 |
|------|-----------|----------|
| 1 | `ping <server_ip>` | 确认基础网络可达性。 |
| 2 | `shadowlemon server status`（服务器端） | 确认代理服务处于 `RUNNING` 状态。 |
| 3 | `shadowlemon client status`（客户端） | 确认客户端已启动。 |
| 4 | `shadowlemon client describe config` 与 `shadowlemon server describe config` | 对比**端口**、**协议**、**用户名**和**密码**，必须完全一致；同时确认两端的 `cipherSuites` 有交集（两端至少要有一个共同的套件，见[密码套件协商](#密码套件协商)），并确认两端使用同一版本：本版本只使用协议版本 4，混用不同版本时所有会话都会在握手阶段被服务端直接丢弃。 |
| 5 | `shadowlemon --protocol-info`（两端均执行） | 打印协议标识与版本字节（当前为 `4`）。协议不依赖基于时间的盐，时钟偏差不会导致握手失败，因此无需用 `date` 排查时间同步问题。 |
| 6 | 在两端启用调试日志并重启 | 在日志中查找 `handshake`、`cipher` 或 `underlay` 相关错误；服务器的解密失败通常表现为无法识别用户或密钥不匹配。 |
| 7 | 检查服务器防火墙 | 确认配置文件里 `portBindings` 声明的 UDP 端口对公网开放（外部传输为 UDP-only，没有 TCP 端口）。 |
| 8 | `shadowlemon server describe config`（服务器端） | 服务端默认要求首包携带匹配的用户提示，配置项 `advancedSettings` -> `userHintIsMandatory` 的默认值是 `true`；未命中提示的源还会在 10 秒内被负缓存直接拒绝。两端用户名/密码不一致、或者首包没有携带提示/提示与任何已注册用户都不匹配时，首包会被丢弃。只有该字段被显式设置为 `false` 才会关闭这一要求。 |

### 症状：连接一段时间后断开

| 可能原因 | 如何检查 | 解决方法 |
|----------|----------|----------|
| 服务器防火墙关闭了空闲端口 | 调试日志显示连接被重置，且断开前一段时间没有流量 | 使用更大的端口范围，或在应用层启用 keepalive。 |
| 客户端或服务器重启 | 检查日志时间戳与断开时间是否吻合 | 服务器端确保守护进程随系统启动（例如配置 systemd 服务）。 |
| 网络链路限速 / QoS | 仅在高峰时段降速 | 外部传输已是 UDP-only；可换端口、启用流量混淆或降低 `mtu` 以减少分片。 |
| 服务器侧的端口映射（NAT）超时 | 空闲一段时间后必断 | 缩短客户端的空闲时间或改用流量混淆，避免长时间无数据。 |

### 症状：速度非常慢

| 可能原因 | 如何检查 | 解决方法 |
|----------|----------|----------|
| TCP 拥塞控制未使用 BBR | `sysctl net.ipv4.tcp_congestion_control` | BBR 只影响内核 TCP，不影响 UDP-only 外部传输；参见 [BBR 拥塞控制算法](./server-install.md#bbr-拥塞控制算法)。 |
| MTU 不匹配导致分片 | `ping -M do -s 1372 <server>`（Linux） | 在两端将 `mtu` 设为相同的值（取值范围 1280 到 1500，例如 1280）后再次测试。 |
| 多路复用过于激进 | 调试日志显示短时间内建立大量连接 | 将 `multiplexing` 的 `level` 降为 `MULTIPLEXING_LOW` 或 `MULTIPLEXING_MIDDLE`。 |
| 服务器负载过高 | `top` / `uptime` 查看 CPU 与负载 | 减少单机用户数量，或增加服务器数量分摊流量。 |
| 随机填充与加密开销 | 每条数据帧附带逐帧随机的 0–32 字节填充 | 填充是协议内置的抗指纹措施，不可配置；若带宽敏感，可适度降低两端 `mtu`，或使用 `embedded` 构建。详见[流量模式](./traffic-pattern.md)。 |

### 症状：客户端无法启动

| 可能原因 | 如何检查 | 解决方法 |
|----------|----------|----------|
| 端口已被占用 | `lsof -i :1080`（macOS/Linux）或 `netstat -ano \| findstr 1080`（Windows） | 更换 `socks5Port` 为未占用的端口。 |
| 配置文件 JSON 语法错误 | `shadowlemon client apply config` 打印错误 | 修正 JSON 语法后重新应用。 |
| 权限不足（Linux） | 客户端二进制文件无执行权限 | `chmod +x shadowlemon` 或通过软件包安装。 |
| 日志目录不可写 | 启动日志提示无法创建日志文件 | 检查上表中的日志目录权限。 |

---

## 配置文件存放位置

V0.2 推荐用 YAML 格式保存配置，默认文件名为 `client.yaml` / `server.yaml`；JSON 仍可加载但不推荐（会打印迁移提示），旧的 `.json` 文件会被继续使用。字段名与格式见 `rust/docs/config-v0.2.md`。

### 服务器

| 文件 | 默认路径 | 格式 |
|------|----------|------|
| 配置 | `$XDG_CONFIG_HOME/shadowlemon/server.yaml`，未设置 `XDG_CONFIG_HOME` 时为 `~/.config/shadowlemon/server.yaml` | YAML（旧的 `.json` 仍可用） |

使用 systemd 时通常通过环境变量 `SHADOWLEMON_SERVER_CONFIG_YAML_FILE` 把配置指向 `/etc/shadowlemon/server.yaml`。服务器**不**存储密码明文，仅保存校验码。

### 客户端

| 操作系统 | 配置路径 | 示例 |
|----------|----------|------|
| Linux | `$XDG_CONFIG_HOME/shadowlemon/client.yaml` 或 `~/.config/shadowlemon/client.yaml` | `/home/enfein/.config/shadowlemon/client.yaml` |
| macOS | `$HOME/Library/Application Support/shadowlemon/client.yaml` | `/Users/enfein/Library/Application Support/shadowlemon/client.yaml` |
| Windows | `%AppData%\shadowlemon\client.yaml` | `C:\Users\enfein\AppData\Roaming\shadowlemon\client.yaml` |

`apply config`、`replace config`、`describe config`、`import config` 等命令读写的都是上表中的文件（或被环境变量覆盖后的路径）。OpenWrt 上通常把配置放在 `/etc/shadowlemon_client_config.yaml` 并通过 `SHADOWLEMON_CLIENT_CONFIG_YAML_FILE` 指定。

---

## 环境变量

| 变量 | 用途 |
|------|------|
| `SHADOWLEMON_SERVER_CONFIG_YAML_FILE` | 从该路径加载 YAML 格式服务器配置文件。V0.2 的默认路径为 `~/.config/shadowlemon/server.yaml`（见上文）。 |
| `SHADOWLEMON_CLIENT_CONFIG_YAML_FILE` | 从该路径加载 YAML 格式客户端配置文件。OpenWrt 上通常用它指向 `/etc/shadowlemon_client_config.yaml`。 |
| `SHADOWLEMON_SERVER_CONFIG_JSON_FILE` | 从该路径加载 JSON 格式服务器配置文件（兼容旧部署，不推荐）。 |
| `SHADOWLEMON_CLIENT_CONFIG_JSON_FILE` | 从该路径加载 JSON 格式客户端配置文件（兼容旧部署，不推荐）。 |
| `SHADOWLEMON_PROTECT_PATH` | Android 平台上与 `VpnService.protect()` 通信的 Unix domain socket 路径（仅 `android` feature 下使用）。 |
| `SHADOWLEMON_LOG_NO_TIMESTAMP` | 非空时关闭日志时间戳（配合 journald 等已自带时间戳的日志系统使用）。 |

配置支持 YAML（推荐）与 JSON（兼容但不推荐）两种格式，按内容自动识别；从自定义路径加载时使用上表中的环境变量。通用的 `SHADOWLEMON_{CLIENT,SERVER}_CONFIG_FILE` 也接受两种格式，但会拒绝旧的 protobuf 内容。

**示例：使用自定义配置文件在前台运行客户端**

```sh
SHADOWLEMON_CLIENT_CONFIG_YAML_FILE=/etc/shadowlemon_client_config.yaml shadowlemon client run
```

日志直接输出到终端。按 `Ctrl+C` 退出。

---

## 修改设置后如何生效

修改设置分两步：先用命令把 JSON 文件写入本地配置，再重启对应的程序。

```sh
# 服务器
shadowlemon server apply config <FILE>       # 合并写入；要整体替换则用 shadowlemon server replace config <FILE>
shadowlemon server stop
shadowlemon server start

# 客户端
shadowlemon client apply config <FILE>      # 合并写入；要整体替换则用 shadowlemon client replace config <FILE>
shadowlemon client stop
shadowlemon client start
```

需要重启的原因：守护进程在启动代理服务时读取一次配置，之后配置文件的改动不会自动作用于已经运行的代理服务。因此**本版本不再提供局部重载配置的能力**，任何改动（包括 `loggingLevel`、监听端口、用户列表）都要通过 `stop` + `start` 生效。

如果只想确认当前生效的设置，用 `shadowlemon server describe config` 或 `shadowlemon client describe config` 查看。
