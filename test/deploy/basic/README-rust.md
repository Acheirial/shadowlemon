# 基础集成测试（Rust 实现）

`test/deploy/basic/` 下的场景脚本测试 Rust 版本的 `shadowlemon`。服务端与客户端始终使用同一个二进制，因此不会出现两端线协议版本混用的情况。

被测二进制和四个辅助程序（`httpserver`、`udpserver`、`sockshttpclient`、`socksudpclient`）都由 Rust 工作区构建；Docker 镜像只复制预先构建好的可执行文件，不在镜像内编译。

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

体积敏感的目标（OpenWrt / musl）使用 `embedded` profile 与 feature，见 [`docs/compile.md`](../../../docs/compile.md)。

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

`test.sh` 会先启动 `./httpserver`（端口 8080）和 `./udpserver -port=9090`，然后依次运行 TCP、UDP、UDP associate、AES-256-GCM 以及 cipher suite 不匹配等场景。任何请求失败、校验不匹配或断言失败都会使脚本以非零状态退出。

## 3. 在 Docker 中运行

`Dockerfile` 从 `bin/` 复制所有预构建二进制、场景脚本和 JSON 配置，不包含任何编译步骤：

```sh
make test-binary
make test-container-image-basic
make run-container-test-prebuilt
```

单独运行某个场景：

```sh
make test-container-image-basic
make run-container-test-script TEST_SCRIPT=test_tcp.sh
```

## 4. 注意事项

- 客户端日志由 `libtest.sh` 的 `start_client()` 捕获到 `$HOME/.cache/shadowlemon/client.log`。Rust 后台守护进程默认把 stdout/stderr 丢弃，因此检查 cipher suite 协商结果的场景（`test_aes.sh`、`test_aes_udp.sh`、`test_suite_mismatch.sh`）以前台方式启动客户端。
- 这些场景断言的日志字符串来自 `rust/crates/shadowlemon-protocol/src/driver.rs`（`ShadowLemon V0.2 cipher suite configuration loaded`、`no common cipher suite with the server`、`to StreamUnderlay{`、`to PacketUnderlay{`）。
- 客户端默认配置文件名是 `client.json`，服务端是 `server.json`；可用 `SHADOWLEMON_CLIENT_CONFIG_JSON_FILE` / `SHADOWLEMON_SERVER_CONFIG_JSON_FILE` 覆盖。
- 线协议版本字节为 `4`，两端必须一致。
