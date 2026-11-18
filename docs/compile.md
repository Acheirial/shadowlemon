# 编译

> **本版本线协议版本为 4；两端必须使用同一版本，否则会话会在握手阶段失败。** 外部传输为 UDP-only（无 TCP 外部绑定），握手为 0-RTT。

ShadowLemon **仅支持 Linux**。编译（唯一二进制，同时承担客户端与服务器两种角色）使用 Rust / Cargo 工具链，工作区位于仓库根目录下的 `rust/`。编译过程需要从互联网下载依赖的软件包。

## 准备编译环境

编译所需的软件包括：

- git
- Rust 工具链（通过 [rustup](https://rustup.rs/) 安装；工作区声明的最低版本见 `rust/Cargo.toml` 的 `rust-version`，当前为 1.85）
- C 链接器（原生 Linux x86_64 上通常已经存在）
- make（可选，仅用于使用仓库提供的封装目标）

Rust 工具链默认把 `cargo` / `rustc` 等可执行文件安装到 `~/.cargo/bin`。该目录**不一定**已经在 `PATH` 中（尤其是精简的容器或 CI 镜像），如果遇到 `cargo: command not found`，请先执行：

```sh
export PATH="$HOME/.cargo/bin:$PATH"
```

建议把这一行写入 `~/.profile` / `~/.bashrc` 以长期生效。仓库的 Makefile 封装目标已经在内部自动加上了这个路径。

## 编译发布版本

进入 Rust 工作区并编译：

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cd rust
cargo build --release
```

产物位于 `rust/target/release/shadowlemon`。它同时承担客户端与服务器两种角色，分别通过 `shadowlemon client <command>` 与 `shadowlemon server <command>` 调用。

显式指定目标三元组时：

```sh
cargo build --release --target x86_64-unknown-linux-gnu
# 产物：rust/target/x86_64-unknown-linux-gnu/release/shadowlemon
```

在仓库根目录也可以使用 Makefile 封装目标，无需手动设置 `PATH`。`make`（或 `make build` / `make rust-build`）会在 `rust/target/release/shadowlemon` 构建后把二进制复制到 `bin/shadowlemon`：

```sh
make                   # 或 make build / make rust-build，产物 bin/shadowlemon
make test              # cargo test --workspace（make rust-test 为同一目标的别名）
make fmt-check         # cargo fmt --all -- --check（别名：make rust-fmt-check）
make clippy            # cargo clippy ...（别名：make rust-clippy）
make fuzz-list         # cargo fuzz list（别名：make rust-fuzz-list；需要 nightly + cargo-fuzz）
make rust-embedded     # 体积优先构建，见下节
```

编译完成后，可以把可执行文件复制到系统路径 `PATH` 中，例如：

```sh
sudo install -m 755 rust/target/release/shadowlemon /usr/local/bin/shadowlemon
# 若使用 Makefile 构建，也可以复制 bin/shadowlemon
```

## 体积优先的 Linux 构建

`embedded` 是独立的 Cargo profile（继承 `release`，使用 `opt-level = "z"`、fat LTO、`panic = "abort"` 与去除符号），配合同名 `embedded` feature 一起裁剪 egress / DNS 递归 / 低熵兼容 / 详尽日志，用于体积敏感的 Linux 设备：

```sh
cd rust
cargo build --profile embedded --no-default-features --features embedded
```

`--no-default-features` 是必需的：它关闭二进制默认的 `low-entropy` feature，从而真正去掉低熵编码代码。在仓库根目录可用 `make rust-embedded` 完成同样的构建。

## Linux 多架构与 musl 静态构建

本项目仅支持 Linux，可在 x86_64 与 aarch64 上原生构建，也可构建 musl 静态产物。musl 目标由 CI 使用 `cross` 验证：

```sh
cross build -p shadowlemon --target x86_64-unknown-linux-musl --profile embedded --no-default-features --features embedded
cross build -p shadowlemon --target aarch64-unknown-linux-musl --profile embedded --no-default-features --features embedded
```

musl 静态链接需要 `-C target-feature=+crt-static`（可在 `.cargo/config.toml` 中配置）。其他架构或非 Linux 目标不在支持范围内。
