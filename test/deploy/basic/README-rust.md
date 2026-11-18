# 基础集成测试（Rust 实现）

`test/deploy/basic/` 下的场景脚本测试 Rust 版本的 `shadowlemon`。服务端与客户端始终使用同一个二进制，因此不会出现两端线协议版本混用的情况。

被测二进制和四个辅助程序（`httpserver`、`udpserver`、`sockshttpclient`、`socksudpclient`）都由 Rust 工作区构建；Docker 镜像只复制预先构建好的可执行文件，不在镜像内编译。

## 0. 传输与握手模型

外部传输是 **UDP-only**：配置中所有 `portBindings` 都必须使用 `"protocol": "UDP"`，TCP 绑定在配置校验阶段会被拒绝（"TCP external transport has been removed; use protocol UDP"）。两种 SOCKS5 请求都承载在同一个 UDP 隧道上：

- **SOCKS5 CONNECT**（TCP 目标）：走 UDP 隧道内的可靠层（`DatagramStream` / `StreamUnderlay`）。测试脚本名 `test_tcp.sh` 沿用旧称，但它测试的是 "CONNECT over UDP tunnel"，不是 TCP 外部传输。
- **UDP ASSOCIATE**：以数据报方式走 `PacketUnderlay`，保持数据报边界。

握手是 **0-RTT**：客户端发出的第一个数据报同时携带握手请求与 SOCKS5 请求（piggyback），使用由静态密钥派生的 early key 加密，服务端在一个 flight 内完成转发。CONNECT 流会立即返回，但数据面的读写会被 gate，直到前向安全密钥交换（key swap）完成；early data 不具备前向安全。配置中的 `HANDSHAKE_STANDARD`、`HANDSHAKE_DEFAULT` 与 `HANDSHAKE_NO_WAIT` 现在都使用 0-RTT。

## 1. 构建二进制

Rust 工具链默认把 `cargo`/`rustc` 安装到 `~/.cargo/bin`，该目录不一定在 `PATH` 中：

```sh
export PATH="$HOME/.cargo/bin:$PATH"

# 在仓库根目录执行，产物放在 bin/ 下：
#   bin/shadowlemon, bin/httpserver, bin/udpserver,
#   bin/sockshttpclient, bin/socksudpclient
make test-binary
```

也可以单独构建被测二进制：

```sh
cd rust
cargo build --release --target x86_64-unknown-linux-gnu
# 产物：rust/target/x86_64-unknown-linux-gnu/release/shadowlemon
```

体积敏感的 Linux 构建使用 `embedded` profile 与 feature，见 [`docs/compile.md`](../../../docs/compile.md)。

## 2. 本地运行场景

把辅助程序和 JSON 配置放到 `test/deploy/basic/` 目录（脚本以当前目录作为工作目录），然后运行入口脚本：

```sh
cd test/deploy/basic
cp ../../../bin/{shadowlemon,httpserver,sockshttpclient,socksudpclient,udpserver} .

./test.sh

# 只跑单个场景
./test_tcp.sh
./test_aes_udp.sh
```

场景脚本默认使用当前目录下的 `./shadowlemon`。如果被测二进制放在别处，可设置 `TEST_BINARY`（绝对路径或相对脚本工作目录的路径）：

```sh
TEST_BINARY=../../../rust/target/x86_64-unknown-linux-gnu/release/shadowlemon ./test.sh
```

`test.sh` 会先启动 `./httpserver`（端口 8080）和 `./udpserver -port=9090`，然后依次运行 CONNECT over UDP tunnel（`test_tcp.sh`）、UDP、UDP associate、AES-256-GCM over UDP 以及 cipher suite 不匹配等场景。所有场景都使用 UDP 绑定。任何请求失败、校验不匹配或断言失败都会使脚本以非零状态退出。

## 3. 在 Docker 中运行

`Dockerfile` 从 `bin/` 复制所有预构建二进制、场景脚本和 JSON 配置，不包含任何编译步骤：

```sh
make test-binary
make test-container-image-basic
make run-container-test-prebuilt
```

单独运行某个场景（直接进入容器运行脚本，或用 `TEST_BINARY` 指定本地二进制后直接运行脚本）：

```sh
make test-container-image-basic
# 在容器内执行 test_tcp.sh（它测试 CONNECT over UDP tunnel）
./test_tcp.sh

# 或在主机上用本地二进制：
TEST_BINARY=./shadowlemon ./test_tcp.sh
```

注意：Makefile 没有 `run-container-test-script` 目标；不要用该名称调用。

## 4. 注意事项

- 客户端日志由 `libtest.sh` 的 `start_client()` 捕获到 `$HOME/.cache/shadowlemon/client.log`。Rust 后台守护进程默认把 stdout/stderr 丢弃，因此检查 cipher suite 协商结果的场景（`test_aes.sh`、`test_aes_udp.sh`、`test_suite_mismatch.sh`）以前台方式启动客户端。
- 这些场景断言的日志字符串来自 `rust/crates/shadowlemon-protocol/src/driver.rs`（当前实际字符串）：
  - `UDP stream session opened to StreamUnderlay{` —— CONNECT 流立即返回时打印（不含 `suite` 字段）。
  - `UDP stream handshake completed` —— CONNECT 的前向安全 key swap 完成时打印，带 `suite=<name>` 字段；`test_aes.sh` 据此断言套件。
  - `UDP session established to PacketUnderlay{` —— UDP associate 会话建立时打印，带 `suite=<name>` 字段；`test_aes_udp.sh` 据此断言套件。
  - `no common cipher suite with the server` —— 套件不匹配时打印（WARN），`test_suite_mismatch.sh` 据此断言失败原因。
  - `UDP handshake timed out` / `UDP stream handshake response timed out` —— 握手响应超时（数据面 I/O 会以超时/失败告终）。
  - 另有 `ShadowLemon V0.2 cipher suite configuration loaded` 由 `rust/crates/shadowlemon-app/src/runtime.rs` 打印。
- `libtest.sh` 中的 `run_socks5_test <TCP|UDP>` 标签仅为历史场景名：`TCP` 表示 SOCKS5 CONNECT（TCP 目标走 UDP 隧道可靠层），`UDP` 表示 UDP associate；两者都使用 UDP 绑定，不选择外部传输。
- 客户端默认配置文件名是 `client.yaml`，服务端是 `server.yaml`；可用 `SHADOWLEMON_CLIENT_CONFIG_YAML_FILE` / `SHADOWLEMON_SERVER_CONFIG_YAML_FILE` 覆盖。JSON 仍可用但不推荐；集成测试中的 `*.json` 配置用于验证向后兼容。
- 线协议版本字节为 `4`，两端必须一致。
