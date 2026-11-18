# ShadowLemon

ShadowLemon 是一款基于 TCP 或 UDP 协议的 SOCKS5 加密代理软件，在客户端与代理服务器之间建立加密通道。中间网络设备无法解密传输内容，也无法判定最终访问的目标地址。

本项目当前版本为 **V0.2（Rust 重写版）**。编译产物只有一个二进制 `shadowlemon`，它同时承担客户端与代理服务器两种角色：`shadowlemon client <命令>` 以客户端角色运行，`shadowlemon server <命令>` 以代理服务器角色运行。

> **注意：V0.1 的 Go 实现已经从仓库中移除。** V0.2 的线协议版本字节为 `4`（V0.1 为 `3`），与包括 V0.1 在内的任何旧版本**线协议不兼容**，也不提供互通或向后兼容路径。升级必须客户端与服务器端同步进行；只升级一端时所有会话都会在握手阶段失败。

## 特性

1. 提供 SOCKS5 代理接口；客户端与服务器之间可使用 TCP 或 UDP 承载。
2. 不使用 TLS 协议，无需注册域名和架设伪装站点。
3. 1-RTT 握手：每个会话在传输应用数据前只经过一次请求/响应往返即可建立。
4. 使用 X25519 临时密钥交换，HKDF 派生每会话、每方向的会话密钥，具备前向安全性。
5. 三种 AEAD 密码套件：XChaCha20-Poly1305（默认）、AES-256-GCM、AES-128-GCM，由两端在握手中协商。
6. 带密钥的用户提示（keyed user hint）：用于服务端快速定位用户，提示本身不是认证凭据。
7. 重放攻击检测：结合代轮换签名缓存与来源标记，丢弃重放的报文。
8. 抗指纹措施：每条数据帧带逐帧重抽的随机填充、随机会话 ID、混淆的 UDP 路由头，线 nonce 始终随机；低熵编码仅作为 wire 层可选扩展保留（默认关闭，当前未通过配置暴露）。
9. 支持多个用户共享同一台代理服务器。
10. 支持 IPv4 和 IPv6，含双栈地址选择。

## 快速开始

### 1. 编译

可以使用仓库根目录的 Makefile 封装目标（产物为 `bin/shadowlemon`）：

```sh
make build
```

也可以直接使用 Cargo：

```sh
cargo build --release --manifest-path rust/Cargo.toml
# 产物：rust/target/release/shadowlemon
```

Rust 工具链默认把 `cargo` / `rustc` 安装到 `~/.cargo/bin`，若该目录不在 `PATH` 中，请先执行 `export PATH="$HOME/.cargo/bin:$PATH"`。

### 2. 应用配置

配置格式与示例见 [`configs/examples/`](./configs/examples/) 和 [`docs/`](./docs/)。分别编写服务器端与客户端的 JSON 配置文件后，用 `apply` 子命令写入：

```sh
# 服务器端
shadowlemon server apply config server_config.json

# 客户端
shadowlemon client apply config client_config.json
```

### 3. 启动

```sh
# 服务器端（后台守护进程）
shadowlemon server start

# 客户端（后台守护进程）
shadowlemon client start
```

也可以在前台运行 `shadowlemon server run` / `shadowlemon client run`，便于交给 systemd 等进程管理器托管。确认运行状态可使用 `shadowlemon server status` / `shadowlemon client status`。

## 文档

- 安装、配置、流量模式、运营维护与编译说明： [`docs/`](./docs/)
- V0.2 协议（实现级规范）： [`rust/docs/protocol-v0.2.md`](./rust/docs/protocol-v0.2.md)
- 平台适配与交叉编译说明： [`rust/docs/`](./rust/docs/)
- 配置字段说明： [`rust/docs/config-v0.2.md`](./rust/docs/config-v0.2.md)

## 许可证

使用本软件需遵从 GPL-3 协议。
