# 编译

> **本版本线协议版本为 4；两端必须使用同一版本，否则会话会在握手阶段失败。**

编译 shadowlemon（唯一二进制，同时承担客户端与服务器两种角色），建议在 Linux 系统中进行。V0.2 使用 Rust / Cargo 工具链，工作区位于仓库根目录下的 `rust/`。编译过程需要从互联网下载依赖的软件包。

## 准备编译环境

编译所需的软件包括：

- git
- Rust 工具链（通过 [rustup](https://rustup.rs/) 安装；工作区声明的最低版本见 `rust/Cargo.toml` 的 `rust-version`，当前为 1.85）
- C 链接器（原生 Linux x86_64 上通常已经存在）
- make（可选，仅用于使用仓库提供的封装目标）
- `cross`、`cargo-ndk` 与 OpenWrt SDK（仅交叉编译时需要根据目标平台安装，见下文）

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

显式指定目标三元组时（用于交叉编译或让路径与 CI 一致）：

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
make rust-embedded     # cargo build --profile embedded --features embedded
```

编译完成后，可以把可执行文件复制到系统路径 `PATH` 中，例如：

```sh
sudo install -m 755 rust/target/release/shadowlemon /usr/local/bin/shadowlemon
# 若使用 Makefile 构建，也可以复制 bin/shadowlemon
```

## 嵌入式（OpenWrt）构建

`embedded` 是独立的 Cargo profile（继承 `release`，使用 `opt-level = "z"`、fat LTO、`panic = "abort"` 与去除符号），配合同名 `embedded` feature 一起裁剪 egress / DNS 递归 / 低熵兼容 / 详尽日志，用于体积敏感的设备：

```sh
cd rust
cargo build --profile embedded --features embedded
```

交叉编译时把 `--target <三元组>` 加到上面的命令中。常用的 musl 目标需要 `-C target-feature=+crt-static` 才能得到静态链接的可执行文件（可在 `.cargo/config.toml` 中配置）。更多体积优化与 feature 裁剪说明见 `rust/docs/platform-notes.md`。

## 交叉编译

不要试图用单一 `rustup target add` 流程覆盖所有目标：`x86_64` / `aarch64` / `armv7` 的 musl 目标是 Tier 2，可以用 `cross`；MIPS 是 **Tier 3**，没有官方预编译 `std`，必须用 nightly + `-Z build-std` 和匹配 OpenWrt SDK 的自定义镜像。以下命令来自 `rust/docs/platform-notes.md` §(b)：

```sh
# Linux 桌面/服务器（原生）
cargo build --release --target x86_64-unknown-linux-gnu

# Linux musl（通用）
cross build --release --target x86_64-unknown-linux-musl --features embedded

# OpenWrt ARMv7
cross build --release --target armv7-unknown-linux-musleabihf --features embedded

# OpenWrt MIPS：需要 nightly + -Z build-std + OpenWrt SDK 镜像
# 链接器指向 mips-openwrt-linux-gcc，STAGING_DIR 指向 SDK；musl 静态链接需 +crt-static。
cargo +nightly build --release -Z build-std=std,panic_abort \
  --target mipsel-unknown-linux-musl --features embedded \
  -C target-feature=+crt-static

# Windows（在 windows-latest runner 上）
cargo build --release --target x86_64-pc-windows-msvc --features windows

# macOS（在 macOS runner 上）
cargo build --release --target aarch64-apple-darwin

# Android（cargo-ndk + NDK）
cargo ndk -t arm64-v8a -t armeabi-v7a --platform 24 -o jniLibs build --release --features android
```

> **MIPS 注意事项**：`mips-unknown-linux-musl` / `mipsel-unknown-linux-musl` 是 Rust Tier 3 目标，稳定版 `rustup target add` 通常拿不到预编译 `std`。构建必须固定 nightly 版本、使用 `-Z build-std`（见上文），并配置匹配目标设备的 OpenWrt SDK 工具链、`STAGING_DIR` 与 musl 版本。MIPS 的 ABI（soft-float / hard-float、24Kc / 74Kc）也必须在真实设备上验证后才能冻结 CI 镜像。

**注意，shadowlemon 的服务端角色可能无法在 Linux 之外的操作系统中运行。**
