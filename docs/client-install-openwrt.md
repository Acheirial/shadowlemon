# 客户端安装与配置 - OpenWrt

> **本版本线协议版本为 4；两端必须使用同一版本，否则会话会在握手阶段失败。**
>
> 外部传输为 UDP-only：客户端配置的端口绑定只能用 `"protocol": "UDP"`；SOCKS5 CONNECT（TCP 目标）走 UDP 隧道可靠层，握手为 0-RTT（early data 无前向安全）。

OpenWrt 是一个极简 Linux 环境，在 OpenWrt 环境运行 shadowlemon 客户端软件需要额外的步骤。请参照[客户端安装与配置](./client-install.md)，同时按照这里的提示安装和配置 shadowlemon 客户端。

## 选择二进制

OpenWrt 设备应优先使用 **musl 静态链接** 的 Rust 二进制，以避免目标设备上缺少 glibc 等运行时依赖。按 CPU 架构选择构建目标：

| 设备架构 | 目标三元组 | 说明 |
| :-- | :-- | :-- |
| x86_64 | `x86_64-unknown-linux-musl` | Tier 2，可用 `cross` 构建 |
| ARMv7 | `armv7-unknown-linux-musleabihf` | Tier 2，可用 `cross` 构建 |
| MIPS / MIPS64 | `mipsel-unknown-linux-musl` / `mips-unknown-linux-musl` | **Tier 3**，见下方注意事项 |

构建时使用 `embedded` profile 与同名 feature，它们会裁剪 egress 与详尽日志，并使用 `opt-level = "z"`、fat LTO、`panic = "abort"` 与去除符号以尽量减小体积：

```sh
export PATH="$HOME/.cargo/bin:$PATH"

# 以 ARMv7 为例；产物在 rust/target/armv7-unknown-linux-musleabihf/embedded/shadowlemon
cd rust
cross build --profile embedded --features embedded \
  --target armv7-unknown-linux-musleabihf
```

musl 静态链接通常需要 `-C target-feature=+crt-static`（可在 `.cargo/config.toml` 中为对应 target 配置），否则生成的二进制可能仍是动态链接。完整的交叉编译命令与体积优化说明见 [`docs/compile.md`](./compile.md) 与 `rust/docs/platform-notes.md`。

> **MIPS 注意事项**：`mips(el)-unknown-linux-musl` 属于 Rust Tier 3 目标，稳定版 `rustup target add` 通常拿不到预编译 `std`。必须使用固定版本的 nightly 工具链加上 `-Z build-std=std,panic_abort`，并配置匹配目标设备的 OpenWrt SDK 工具链（链接器、`STAGING_DIR`、musl 版本）。MIPS 的 ABI（soft-float / hard-float、24Kc / 74Kc）也必须在真实设备上验证后才可冻结构建流程。若设备 flash 空间紧张，建议优先选择有官方预编译 std 的 x86_64 / ARMv7 目标。

**体积参考**：使用 `embedded` profile 与 feature 的实现会显著小于默认构建；由于具体数值随依赖树与目标架构变化，请在发布前用 `ls -l` 量出实际大小并确认目标设备有足够的 flash 余量。可用 `cargo bloat --profile embedded --crates -n 20` 与 `cargo tree -e features --no-default-features --features embedded` 检查哪些依赖仍被包含进来。

## 下载 / 安装 shadowlemon 客户端

把静态链接后的 `shadowlemon` 可执行文件复制到 OpenWrt 系统的 `/usr/bin/` 目录下，并赋予可执行权限：

```sh
install -m 755 shadowlemon /usr/bin/shadowlemon
```

## 修改客户端的设置

为了能让其他设备连接至 OpenWrt 上的代理客户端，必须将 `socks5ListenLAN` 设置成 `true`。

在 OpenWrt 中，请勿使用 `shadowlemon client apply config <FILE>` 和 `shadowlemon client describe config` 指令，直接把 YAML 配置保存至 `/etc/shadowlemon_client_config.yaml`，并通过环境变量告知客户端：

```sh
export SHADOWLEMON_CLIENT_CONFIG_YAML_FILE=/etc/shadowlemon_client_config.yaml
```

Rust 版本默认配置路径是 `~/.config/shadowlemon/client.yaml`；OpenWrt 上通常使用上面的环境变量覆盖到 `/etc/`。字段名与格式见 `rust/docs/config-v0.2.md`。旧的 JSON 文件仍可用（通过 `SHADOWLEMON_CLIENT_CONFIG_JSON_FILE` 指定），但不推荐。

另外，建议将日志等级 `loggingLevel` 设置成 `ERROR` 防止日志打满硬盘。`embedded` 构建本身也会裁掉详尽日志。

## 启动客户端

仓库提供的 `configs/examples/etc_initd_shadowlemon`  init 脚本只调用 `shadowlemon client start` / `shadowlemon client stop`，并通过 pid 文件管理进程；Rust 版本保持同一套 CLI 子命令与 pid 文件路径语义，因此该脚本**无需修改即可继续使用**。请把该文件复制并保存为 `/etc/init.d/shadowlemon`，并赋予可执行权限。此后，shadowlemon 客户端将在 OpenWrt 开机后自行启动。

init 脚本需要能读到上面设置的环境变量（可在 `/etc/init.d/shadowlemon` 中显式 `export SHADOWLEMON_CLIENT_CONFIG_YAML_FILE=/etc/shadowlemon_client_config.yaml`）。

如果需要手动启动或停止 shadowlemon 客户端，可以使用指令 `/etc/init.d/shadowlemon start` 和 `/etc/init.d/shadowlemon stop`。
