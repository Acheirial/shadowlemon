# ShadowLemon Rust 重写：平台适配笔记

> 本文面向后续实现 agent，目标是把现有 Go 实现中与平台相关的行为逐一映射到 Rust。Go 代码仅作参考，不作修改。
>
> 研究日期：2026-11-18。文中凡标注「已核实」的结论均附了我实际查看的来源链接；无法核实的部分已明确标注为「未核实/需实验」。

---

## 0. 目标平台与 cargo feature 约定

目标平台：Linux（服务器/桌面）、OpenWrt（MIPS/ARM 交叉编译、musl 静态、体积敏感）、Windows、macOS、Android。

推荐 feature（与任务约定一致，下面各节会引用）：

| feature | 含义 |
|---|---|
| `default` | = `["std-resolver"]`（见 DNS 决策节），面向 Linux/桌面/服务器 |
| `embedded` | 裁剪 egress、DNS 递归、低熵握手兼容、详尽日志；面向 OpenWrt；**不含** `android`/`windows` |
| `android` | 启用 `SocketProtector` 的 Android 实现 + JNI 入口 |
| `windows` | 启用 Windows Service 入口与平台特化 |

注意：`embedded` 与 `android` 可同时开启（Android 客户端同样体积敏感），`windows` 与 `android` 互斥（由 target cfg 保证，见第 6 节 trait 的 `#[cfg]` 设计）。

---

## (a) 现有 Go 平台代码 → Rust 方案清单

### a.1 socket 选项 / 保护

| Go 文件 | 职责 | Rust 方案 | 关键注意点 |
|---|---|---|---|
| `pkg/sockopts/control.go` | 定义 `Control`/`RawControl` 回调；`DefaultDialerControl`（SO_REUSEADDR + Android protect）、`DefaultListenerControl`（仅 SO_REUSEADDR）、`ReusePortListenerControl`（+SO_REUSEPORT）；`ApplyTCPControl`/`ApplyUDPControl` | 用 `socket2::Socket` 在 bind/connect **之前**设置选项（`socket.set_reuse_address(true)` / `set_reuse_port(true)`）；Rust 不需要 Go 的 `Control` 回调模型，因为 `socket2::Socket` 可直接转成 `std`/`tokio` 的 `TcpListener`/`TcpStream`。抽象成 `apply_socket_opts(&Socket, Role)` | 顺序：先 `socket()` → 设置选项 → `bind()` → `listen()`/`connect()`。Go 的 `ReusePortListenerControl` 是**可选**的零停机重启能力，应保持为显式配置开关，不默认开启 |
| `pkg/sockopts/reuse_unix.go` | Linux/Android/macOS/BSD：`setsockopt(SO_REUSEADDR, 1)` + 可选 `SO_REUSEPORT` | `socket2::Socket::set_reuse_address` / `set_reuse_port`（Unix 可用） | tokio `TcpSocket::set_reuseport` 仅在 Unix 且排除 Solaris/Illumos/Cygwin/NuttX（已核实：docs.rs/tokio `TcpSocket`）。优先用 `socket2` 以保持统一 |
| `pkg/sockopts/reuse_windows.go` | Windows **故意 no-op**：不设 SO_REUSEADDR/REUSEPORT | `#[cfg(windows)]` 下 `apply_socket_opts` 直接返回 `Ok(())` | Windows 的 SO_REUSEADDR 语义是「允许另一个 socket 抢占同一 addr:port，行为不确定」，存在劫持风险（已核实：MS Learn《Using SO_REUSEADDR and SO_EXCLUSIVEADDRUSE》）。Go 明确注释 Windows 默认即可重启监听，因此保持 no-op |
| `pkg/sockopts/reuse.go` | 其他平台（Solaris/illumos/js/wasip1/plan9…）no-op | 对于 Rust 本次目标平台无需此文件；如未来支持 Solaris/illumos，用 `#[cfg(any(target_os = "solaris", ...))]` no-op 分支 | 不需要为本次目标引入 |
| `pkg/sockopts/protect.go`（`!android`） | `ProtectPath*` 为空实现 | `SocketProtector` trait 的 `NoopProtector` 默认实现（见 6.1） | — |
| `pkg/sockopts/protect_android.go` | 建 AF_UNIX SOCK_STREAM，connect 到 `SHADOWLEMON_PROTECT_PATH`，`sendmsg` 带 `SCM_RIGHTS` 传 fd，读 1 字节确认 | `android` feature 下 `UnixSocketProtector` 实现：用 `std::os::unix::net::UnixStream` + `sendmsg`+SCM_RIGHTS（可自行 `extern` libc，或用 `sendfd`/`nix` 的 `sendmsg`+`ControlMessageOwned::ScmRights`）；或改用 `jni` 直接调 `VpnService.protect(fd)` | **推荐保留 UDS SCM_RIGHTS 路径**：与现有 Go 部署完全兼容（Java 侧已监听该 socket），无需改动 Java APK；JNI 直调作为备选（见 6.1） |
| `pkg/sockopts/control.go` 中 `DefaultDialerControl` 读 `SHADOWLEMON_PROTECT_PATH` | 仅当环境变量存在时调用 protect | 在构造 dialer 时按 `protect_path: Option<PathBuf>` 显式注入 `SocketProtector`，**不推荐**用环境变量做隐式全局状态 | 保留读取环境变量的兼容入口，但把它收敛到 `main` 配置层，核心库只认 `Arc<dyn SocketProtector>` |

### a.2 守护进程生命周期

| Go 文件 | 职责 | Rust 方案 | 关键注意点 |
|---|---|---|---|
| `pkg/appctl/daemon_unix.go` | `setsid` 后台化；`kill(pid,0)` 存活检测；SIGTERM 优雅退出、SIGKILL 强杀 | Unix：`CommandExt::process_group(0)`（等价于 setsid，std 已提供）；`libc::kill(pid, 0)` / `kill(pid, SIGTERM/SIGKILL)`；或用 `nix::sys::signal::kill` | `process_group(0)` 在 Rust std 稳定版可用（已核实语义：std::os::unix::process::CommandExt）。EPERM 视为存活（Go 已处理） |
| `pkg/appctl/daemon_windows.go` | `CREATE_NEW_PROCESS_GROUP\|DETACHED_PROCESS`；`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` 存活检测；`TerminateProcess` 强杀 | `windows-sys` / `windows` crate：`CREATE_NEW_PROCESS_GROUP \| DETACHED_PROCESS`；`OpenProcess` + `GetExitCodeProcess` 或 `WaitForSingleObject(0)`；`TerminateProcess` | 作为进程级 start/stop 的兼容路径保留；**同时**提供 Windows Service 入口（见 a.4） |
| `pkg/appctl/daemon_other.go` | 其他平台 no-op | 本次目标平台不需要 | — |
| `pkg/appctl/pidfile.go` | pid 文件：原子创建、`ErrPidFileExists`、读取校验、用 `/proc/<pid>/stat` 的 start time 做身份 token 防 PID reuse、stale 清理、start/stop 轮询超时 | 用 `fs2`/`nix::fcntl::open(O_CREAT\|O_EXCL)` 原子创建；`libc::getpid()`；Linux 下读 `/proc/<pid>/stat` 提取第 22 字段 starttime 作 identity；轮询用 tokio `sleep` + `Instant` 超时 | 这套 pid 文件协议是上层 CLI（`client start/stop`）与 init.d/systemd 脚本交互的契约，**必须逐字节兼容**（`encodePidFile` 格式 `"<pid> <starttime>"`）。Windows 无 `/proc`，identity 为空，退化为纯 liveness |
| `pkg/appctl/appctlcommon/*`、`apis/common/dns.go` | 配置校验与 DNS 映射 | 见 DNS 决策节 | `TransformDNSHosts` 的域名规范化（去尾点、小写、去重）需保留 |

### a.3 平台查询

| Go 文件 | 职责 | Rust 方案 | 关键注意点 |
|---|---|---|---|
| `pkg/common/tcp_congestion_control.go` | Linux 读 `/proc/sys/net/ipv4/tcp_congestion_control` | `#[cfg(target_os = "linux")]` 下 `fs::read_to_string` + `trim()`；其他平台 `""` | 仅用于 `server run` 启动时打印信息（见 `pkg/cli/server.go:226`），非功能依赖 |
| `pkg/common/ipdualstack.go` | `LocalIPAddr()` 固定 `127.0.0.1`；`MaybeDecorateIPv6`；`SelectIPFromList(ips, DualStackPreference)`；5 个 preference 枚举 | 用 `std::net::IpAddr`/`Ipv4Addr`/`Ipv6Addr` 重写 `select_ip(&[IpAddr], DualStackPreference) -> Option<IpAddr>`；枚举值 0..4 与 proto 对齐（serde 显式 tag） | 未知 preference 必须返回 `Err`/`None`，不得静默当作 USE_FIRST_IP（Go 原注释明确要求） |
| `pkg/common/mtu.go` | `const DefaultMTU = 1400` | `pub const DEFAULT_MTU: u16 = 1400;` | 无平台分支 |
| `apis/common/dns.go` | `DNSResolver` trait；`HostMapResolver`（静态 hosts 优先）；`NilDNSResolver`；`ResolveTCP/UDPAddrs`（IPv4 优先排序 `sortIPs`、10s 默认超时、字面量 IP 短路） | 见 DNS 决策节的 `Resolver` trait 设计 | 直接映射到 `tokio::net::lookup_host` + 自写排序/选择；无需外部 DNS 库即可达成同语义 |

### a.4 部署形态 / 文档 / 构建

| 文件 | 现状 | Rust 产物建议 |
|---|---|---|
| `configs/examples/etc_initd_shadowlemon` | OpenWrt `/etc/rc.common` init 脚本，只调 `client start/stop`，pid 文件由程序自己维护 | 已改用 `SHADOWLEMON_CLIENT_CONFIG_YAML_FILE` 指向 `/etc/shadowlemon_client_config.yaml`；Rust 必须保持同一 pid 文件路径语义 |
| `configs/examples/shadowlemon-{client,server}.service` | systemd `Type=exec`，`ExecStart=... client run` / `server run` | 原样保留；`run` 子命令必须在前台运行并把日志写到 stdout（systemd 交给 journal） |
| `docs/client-install-openwrt.md` | 要求 `socks5ListenLAN=true`、直接写 `/etc/shadowlemon_client_config.yaml`、`loggingLevel=ERROR`、用 init 脚本管理 | 增加 Rust 章节：musl 静态二进制、`embedded` feature、体积数字、MIPS 构建说明 |
| `docs/compile.md` | `make` 构建单一二进制；交叉编译示例含 `GOARCH=mips CGO_ENABLED=0` | 改为 `cargo build --release --target ...` 与 `make` 封装；补充本文件第 4、5 节 |
| `docs/operation.md` | 记录各 OS 配置/日志目录、环境变量 | Rust 用 `dirs`/`directories` crate 复现：`$XDG_CACHE_HOME`/`$HOME/.cache`、`~/Library/Caches`、Windows `%LOCALAPPDATA%`；配置 dirs 同理 |
| `Makefile` / `CGO_ENABLED=0` / `-trimpath -ldflags="-s -w"` | Go 的纯静态、去符号构建 | 对应 Rust：`+crt-static`、`strip="symbols"`、`panic="abort"`、`lto`、`codegen-units=1`；见第 5 节 |
| `.github/workflows/*.yaml` | 目前只有 Ubuntu + Go 单元测试/集成测试/基准/模糊 | 新增交叉编译矩阵（见第 4 节）；集成测试继续在 x86_64 Linux 跑（Docker） |

---

## 目标平台技术细节与核实情况

### MIPS / OpenWrt（最大风险区）

- **已核实**：`mips-unknown-linux-musl`、`mipsel-unknown-linux-musl`、`mips64-openwrt-linux-musl` 在 rustc 平台支持表中属于 **Tier 3**，标注 std ✓（源码层面）但**没有官方预编译 std、没有 host tools、不带注脚 4 的自动构建/测试**。来源：<https://doc.rust-lang.org/rustc/platform-support.html>（表格 Tier 3 段，注脚 4 "On these targets, the treatment of floating-point NaN values is non-compliant..." 对应 MIPS 行）。同时 Tier 3 明确写 "Official builds are not available"。
  - 实际含义：`rustup target add mips(el)-unknown-linux-musl` 在**当前稳定版**上通常拿不到预编译 `std`；需要 nightly + `-Z build-std`。
  - 历史佐证（已核实）：Reddit r/rust 讨论称 MIPS target 因 LLVM 维护不足被降级为 Tier 3、不再有预编译 std：<https://www.reddit.com/r/rust/comments/1ajethc/mipsunknownlinuxmusl_support_dropped/>；cross issue #1416 显示用户必须用 `-Zbuild-std`：<https://github.com/cross-rs/cross/issues/1416>。
  - 反向佐证：Rust 官方 2025-12 博客《Updating Rust's Linux musl targets to 1.2.5》把 mips/mipsel-musl 列入 musl 1.2.5 更新表并标 std ✓，但**这不等于有预编译产物**（Tier 3 表格仍如此）。来源：<https://blog.rust-lang.org/2025/12/05/Updating-musl-1.2.5>。
- **已核实**：MIPS musl 交叉编译默认可能**不是静态链接**，需要 `-C target-feature=+crt-static`（cross issue #504，维护者回复）：<https://github.com/cross-rs/cross/issues/504>。
- **已核实**：社区成功路径是 nightly `cargo +nightly build -Zbuild-std --target mips-unknown-linux-musl`，并配置 `mips-linux-gnu-gcc` 链接器及 OpenWrt SDK 的 `STAGING_DIR`/sysroot；必要时 `patchelf --set-interpreter /lib/ld-musl-mips-sf.so.1`（博客：<https://blog.habets.se/2024/04/Cross-compiling-Rust-fixed.html>；OpenWrt 交叉编译经验：<https://blog.davidv.dev/posts/cross-compiling-for-openwrt-platforms>；复杂项目需 `TARGET_CC`/`HOST_CC`/`PKG_CONFIG` 的踩坑记录：<https://medium.com/althea-mesh/cross-compiling-complex-rust-programs-for-openwrt-targets-80897fcf7648>）。
- **未核实 / 必须实测**：具体 OpenWrt 版本（musl 1.1 vs 1.2.5）、CPU 子架构（24Kc/74Kc，soft-float vs hard-float）与所生成二进制的 ABI 匹配；MIPS16 指令在某些芯片上有 bug（社区提及，未核实）。**必须在目标设备上跑一次真实二进制**再冻结 CI 镜像。
- tokio/mio 在 MIPS 上：mio 依赖 `epoll`（Linux 通用），不依赖 x86 专有指令；但完整依赖树（尤其含 C 代码的 crate，如 ring/openssl/aws-lc）在 MIPS 工具链上可能编译失败。**未核实** tokio 全特性组合在 MIPS 上的可用性——因此 `embedded` feature 必须严格剔除这类依赖，并在早期做「hello world + tokio 最小 runtime」的 MIPS 验证（见 checklist P0）。

### 其他目标（均已核实 tier，来源同上 rustc 平台支持表）

| 目标 | 三元组 | Tier | std |
|---|---|---|---|
| Linux x86_64 glibc | `x86_64-unknown-linux-gnu` | 1 with host tools | ✓ |
| Linux x86_64 musl | `x86_64-unknown-linux-musl` | 2 with host tools | ✓ |
| Linux aarch64 musl | `aarch64-unknown-linux-musl` | 2 with host tools | ✓（musl 1.2.5） |
| Linux ARMv7 musl | `armv7-unknown-linux-musleabihf`（及 `armv7-unknown-linux-musleabi`） | 2 without host tools | ✓ |
| OpenWrt MIPS | `mips-unknown-linux-musl` / `mipsel-unknown-linux-musl` | **3** | 源码 ✓，无预编译 |
| OpenWrt MIPS64 | `mips64-openwrt-linux-musl` / `mips64el-unknown-linux-muslabi64` | 3 | 源码 ✓ / ?，无预编译 |
| Windows x86_64 MSVC | `x86_64-pc-windows-msvc` | 1 with host tools | ✓ |
| Windows x86_64 GNU | `x86_64-pc-windows-gnu` | 1 without host tools | ✓ |
| macOS ARM64 | `aarch64-apple-darwin` | 1 with host tools | ✓ |
| macOS x86_64 | `x86_64-apple-darwin` | 2 with host tools | ✓ |
| Android ARM64 | `aarch64-linux-android` | 2 without host tools | ✓ |
| Android ARMv7 | `armv7-linux-androideabi` | 2 without host tools | ✓ |

### Windows 细节

- IOCP：tokio 在 Windows 上自动使用 IOCP（mio 的 `iocp` 后端），**无需**业务代码处理；使用 `tokio::net::TcpListener/TcpStream` 即可。
- `socket2`：Unix 的 `set_reuse_address(true)` 放在 Windows 上语义完全不同（劫持端口风险，见上文 MS Learn 链接），所以 `#[cfg(windows)]` 必须 no-op，与 Go `reuse_windows.go` 一致。Windows 上如需「独占绑定」应显式设 `SO_EXCLUSIVEADDRUSE`，但本项目不需要。
- Windows Service：推荐 `windows-service`（库名 `windows_service`，仓库 <https://github.com/mullvad/windows-service-rs>），提供 `define_windows_service!` 宏与 `service_dispatcher::start`；安装用 `sc.exe create shadowlemon binPath= "...\shadowlemon.exe --service"`。更高层的跨平台抽象可选 `qsu`（同时封装 systemd/launchd/Windows Service，支持 tokio，来源：Rust 用户论坛讨论 <https://users.rust-lang.org/t/windows-service-in-rust/137389>）。
- 路径/日志：`dirs` crate 映射到 `%APPDATA%`（配置）与 `%LOCALAPPDATA%`（日志），与 `docs/operation.md` 表格一致；服务账户运行时需确保对日志目录有写权限。
- MSVC vs GNU：**CI 主目标选 `x86_64-pc-windows-msvc`**（Tier 1、官方运行时、生态兼容最好）；`x86_64-pc-windows-gnu` 作为可选次目标（避免对 msvc 构建工具的依赖，但要注意与 `windows-sys`/`windows` crate 链接行为一致）。`windows` crate 对两者都可用。

### macOS 细节

- 三元组：Apple Silicon 用 `aarch64-apple-darwin`，Intel 用 `x86_64-apple-darwin`；建议 CI 两者都测（用 `macos-14`/`macos-15` runner 出 ARM，matrix 加 x86_64）。
- 部署：提供 launchd plist（`~/Library/LaunchAgents/io.shadowlemon.client.plist` / `/Library/LaunchDaemons/...`），`ProgramArguments` 指向 `shadowlemon client run`，`KeepAlive`/`RunAtLoad`；对应 Go 的 systemd 单元。
-沙盒/公证：若只做 CLI 二进制分发（未打包 `.app`、未启用 App Sandbox/Hardened Runtime），通常**不需要**公证；如果未来做 GUI/安装包并启用 Hardened Runtime，则需 `codesign --options runtime` + `notarytool`，且 `SocketProtector`/socket 相关 syscall 需确认 entitlement。**未核实**本项目分发形态——需在发布流程确定时确认。
- 注意 Go 代码把 macOS 也纳入 `reuse_unix.go`（`SO_REUSEPORT` 可用），Rust 用 `socket2` 在 macOS 同样可用，保持「仅显式开启时设置」。

### Android 细节

- 构建：他用 `cargo-ndk` 最省心（`cargo install cargo-ndk`; `rustup target add aarch64-linux-android armv7-linux-androideabi ...`; `cargo ndk -t arm64-v8a -t armeabi-v7a --platform 24 -o ../app/src/main/jniLibs build --release`）。裸 `cargo build --target aarch64-linux-android` 会把 ELF 链接参数交给 host linker 而失败（来源：<https://www.davthecoder.com/blog/rust-android-ndk-toolchain-setup-cargo-ndk>、<https://medium.com/@ali.alacan/rust-cross-platform-android-together-with-gradle-83a27042cf79>）。
- crate 类型：JNI 入口需 `crate-type = ["cdylib", "rlib"]`；`jni` crate（建议 0.21+）写 `#[no_mangle] pub extern "system" fn Java_...`，用 `extern "system"` 调用约定（来源：Mozilla 文档 <https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-21-rust-on-android.html>、社区教程）。
- `VpnService.protect()` 两条路线：
  1. **UDS + SCM_RIGHTS（推荐，兼容现有 APK）**：完全照搬 Go `protect_android.go`——Java 侧在 `SHADOWLEMON_PROTECT_PATH` 监听，Rust 通过 Unix socket 发送 fd + 1 字节，读 1 字节确认。优点：不改 Java 侧、与现有部署一致；缺点：每次建连一次 IPC 开销。
  2. **JNI 直调**：在 JNI 层拿到 `VpnService` 实例并调用 `protect(FileDescriptor)`。优点：少一层 IPC；缺点：需要改 Java/Kotlin 侧并管理 JNI 全局引用，**不建议首版采用**。
- 关键：protect 必须发生在 **connect() 之前**（Go 放在 dialer control 里正是如此），否则流量会绕过 VPN 形成回路。

---

## (b) 推荐 target triples 与 CI 矩阵

### 推荐构建方式

| 平台 | 构建工具 | 命令要点 |
|---|---|---|
| Linux 桌面/服务器 | rustup 原生 | `cargo build --release --target x86_64-unknown-linux-gnu` |
| Linux musl（通用） | `cross` | `cross build --release --target x86_64-unknown-linux-musl --features embedded` |
| OpenWrt ARMv7 | `cross` | `cross build --release --target armv7-unknown-linux-musleabihf --features embedded` |
| OpenWrt MIPS | **nightly + build-std + OpenWrt SDK 镜像**（`cross` 自定义镜像或自建 Docker） | `cargo +nightly build --release -Z build-std=std,panic_abort --target mipsel-unknown-linux-musl --features embedded -C target-feature=+crt-static`；链接器指向 `mips-openwrt-linux-gcc`，`STAGING_DIR` 指向 SDK |
| Windows | rustup 原生（在 `windows-latest` runner 上） | `cargo build --release --target x86_64-pc-windows-msvc --features windows` |
| macOS | rustup 原生（在 macOS runner 上） | `cargo build --release --target aarch64-apple-darwin`（+ `x86_64-apple-darwin` 交叉） |
| Android | `cargo-ndk` + NDK | `cargo ndk -t arm64-v8a -t armeabi-v7a --platform 24 -o jniLibs build --release --features android` |

> `cross` 与 rustup 的取舍：x86_64/aarch64/armv7 的 musl 目标是 Tier 2，`rustup target add` + `cross` 即可；MIPS 是 Tier 3，`cross` 默认镜像也可能缺 std，必须用 `-Zbuild-std` 和匹配 OpenWrt SDK 的自定义镜像。**结论：不要试图用单一 `rustup target add` 流程覆盖所有目标。**

### CI 矩阵建议

在现有 `.github/workflows/ci.yaml` 基础上增加一个 `build-cross` job（或独立 workflow），`fail-fast: false`：

| job 名 | runner | target | features | 是否硬门禁 |
|---|---|---|---|---|
| linux-gnu | ubuntu-latest | x86_64-unknown-linux-gnu | default | 是 |
| linux-musl | ubuntu-latest | x86_64-unknown-linux-musl | embedded | 是（用 cross） |
| openwrt-armv7 | ubuntu-latest | armv7-unknown-linux-musleabihf | embedded | 是（用 cross） |
| openwrt-mipsel | ubuntu-latest（自建容器） | mipsel-unknown-linux-musl | embedded | 初期**否**（标记 `continue-on-error: true`），设备验证通过后转是 |
| windows-msvc | windows-latest | x86_64-pc-windows-msvc | windows | 是 |
| windows-gnu（可选） | windows-latest | x86_64-pc-windows-gnu | windows | 否 |
| macos-arm64 | macos-14/15 | aarch64-apple-darwin | default | 是 |
| macos-x86_64 | macos-14/15（交叉） | x86_64-apple-darwin | default | 否 |
| android-arm64 | ubuntu-latest | aarch64-linux-android（cargo-ndk） | android | 是 |
| android-armv7 | ubuntu-latest | armv7-linux-androideabi（cargo-ndk） | android | 否 |

另外保留现有 `run-test`（cargo test）、`lint`（clippy + fmt）、集成测试（Docker x86_64）作为门禁；`benchmark`/`fuzzing` 可沿用 weekly 模式（Rust 用 `criterion` + `cargo-fuzz`/`proptest`）。

---

## (c) 精简体积的 Cargo profile 建议

优先在 `embedded`/musl 场景使用独立的 `embedded` profile（继承 release），避免影响桌面/服务器默认构建。

```toml
# Cargo.toml（workspace 根或主 crate）
[package]
name = "shadowlemon"
version = "3.0.0"
edition = "2021"

[features]
default = ["std-resolver"]
# 桌面/服务器：使用 libc getaddrinfo（std::net::lookup_host）
std-resolver = []
# OpenWrt 等嵌入式：裁剪 egress / DNS 递归 / 低熵兼容 / 详尽日志
embedded = []
# 可选：仅在确需递归解析时启用（会显著增大体积，见 DNS 决策节）
dns-recursive = ["dep:hickory-resolver"]
android = ["dep:jni"]
windows = ["dep:windows-service", "dep:windows-sys"]

[dependencies]
hickory-resolver = { version = "0.25", optional = true, default-features = false }
jni = { version = "0.21", optional = true, default-features = false }
# 仅目标平台依赖
[target.'cfg(windows)'.dependencies]
windows-service = "0.7"
windows-sys = { version = "0.59", features = ["Win32_System_Services", "Win32_Foundation", "Win32_System_Console"] }

# ---------------- 发布 profile ----------------
[profile.release]
opt-level = 3
lto = "thin"          # 桌面/服务器用 thin LTO，编译快
codegen-units = 1
panic = "abort"       # 需要 tokio 等依赖同样兼容 panic=abort；若某 crate 不支持则改 "unwind"
strip = "symbols"     # 等价于 Go 的 -ldflags="-s -w"
debug = false
incremental = false

# 嵌入式 / OpenWrt：极致体积
[profile.embedded]
inherits = "release"
opt-level = "z"       # 优先体积；若性能不达标改 "s" 并基准测试
lto = true            # fat LTO，体积最小
codegen-units = 1
panic = "abort"
strip = "symbols"
debug = false

# musl 静态：在 .cargo/config.toml 中补充（见下）
```

```toml
# .cargo/config.toml（MIPS 静态示例，路径按本机 SDK 调整）
[target.mipsel-unknown-linux-musl]
linker = "mips-openwrt-linux-gcc"
rustflags = ["-C", "target-feature=+crt-static"]

[target.armv7-unknown-linux-musleabihf]
rustflags = ["-C", "target-feature=+crt-static"]

[unstable]
build-std = ["std", "panic_abort"]   # 仅 MIPS（Tier 3）需要，且需 nightly
```

构建嵌入式产物：`cargo build --profile embedded --target mipsel-unknown-linux-musl --no-default-features --features embedded`。

体积分析工具与用法（建议在 CI 或发布前手动跑）：
- `cargo install cargo-bloat && cargo bloat --release --profile embedded --crates -n 20`：看 crate 级占用。
- `cargo tree -e features --no-default-features --features embedded`：确认 egress/DNS/日志依赖确实被 feature 裁掉；用 `cargo tree -i <crate>` 追贡献者。
- `cargo install cargo-llvm-lines && cargo llvm-lines`：找泛型膨胀。
- 里程碑：先在 x86_64 musl 上量出 baseline，再与 Go 当前 `-ldflags="-s -w"` 的二进制对比；MIPS 目标以「能塞进目标设备 flash 余量」为硬指标（需实测设备剩余空间）。

**feature 裁剪清单**（`embedded` 必须确认排除）：
- 任何依赖 `ring` / `aws-lc` / `openssl-sys` 的 TLS crate（用 `rustls` 的纯 Rust 后端也需要按 cipher 裁剪，或干脆不在客户端内置 TLS）。
- `hickory-resolver`（放 `dns-recursive` 后，默认不进 embedded）。
- 详细日志格式化（用 `log` + 编译期 `max_level_*` feature 或 `tracing` 的 `release_max_level_warn`）。
- egress 控制器、低熵握手兼容路径（按任务约定裁剪）。

---

## (d) 关键 trait 草图

### d.1 SocketProtector（Android fd 保护）

```rust
// src/platform/protect.rs
use std::net::SocketAddr;
use std::sync::Arc;
use std::io;

/// 在 socket 创建后、connect/bind 之前调用，允许平台接管 fd。
pub trait SocketProtector: Send + Sync + std::fmt::Debug {
    /// 返回是否真的保护了 fd（用于日志/指标）。
    fn protect(&self, fd: i32, peer: Option<&SocketAddr>) -> io::Result<bool>;
}

/// 默认实现：桌面/服务器/Windows/macOS/嵌入式 Linux 均 no-op。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopProtector;
impl SocketProtector for NoopProtector {
    fn protect(&self, _fd: i32, _peer: Option<&SocketAddr>) -> io::Result<bool> { Ok(false) }
}

pub type Protector = Arc<dyn SocketProtector>;

/// 在 socket2::Socket 上应用保护；供 dialer 在 connect 前调用。
pub fn protect_socket(p: &Protector, s: &socket2::Socket, peer: Option<&SocketAddr>) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        p.protect(s.as_raw_fd(), peer)?;
    }
    #[cfg(not(unix))]
    let _ = (p, s, peer); // Windows 上无 fd 概念：protect 由 socket2/JNI 层另做处理
    Ok(())
}
```

```rust
// src/platform/protect_android.rs  （#[cfg(all(unix, target_os = "android", feature = "android"))]）
use std::os::unix::net::UnixStream;
use std::os::unix::io::AsRawFd;
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Debug)]
pub struct UnixSocketProtector { path: PathBuf }

impl UnixSocketProtector {
    pub fn from_env() -> Option<Self> {
        std::env::var_os("SHADOWLEMON_PROTECT_PATH").map(|p| Self { path: p.into() })
    }
}

impl SocketProtector for UnixSocketProtector {
    fn protect(&self, fd: i32, _peer: Option<&SocketAddr>) -> io::Result<bool> {
        // 1) connect(AF_UNIX, self.path)
        // 2) sendmsg(fd_buf=[1], SCM_RIGHTS=[fd]) —— 用 nix::sys::socket::sendmsg
        //    （或自写 libc::sendmsg + cmsg；注意 cmsg 空间用 CMSG_SPACE/CMSG_LEN）
        // 3) read 1 byte；必须为 1，否则视为 protect 失败
        // 4) Java 侧 VpnService.protect() 成功后回写 1 字节
        // 细节与 Go protect_android.go 完全一致；错误均带上下文。
        unimplemented!("按 Go protect_android.go 实现，见本文 a.1")
    }
}
```

```rust
// 选择实现的工厂（cfg 互斥，保证 windows/android 不会同时生效）
pub fn default_protector() -> Protector {
    #[cfg(all(target_os = "android", feature = "android"))]
    { return Arc::new(UnixSocketProtector::from_env().unwrap_or_else(|| /* 记录警告：未配置 protect path */ NoopProtector)); }
    #[cfg(not(all(target_os = "android", feature = "android")))]
    { Arc::new(NoopProtector) }
}
```

### d.2 Daemon / PlatformService（守护进程生命周期）

```rust
// src/platform/daemon.rs —— 平台无关的生命周期抽象
pub struct DaemonSpec {
    pub executable: std::path::PathBuf,
    pub mode: &'static str,          // "client" | "server"
    pub pid_file: std::path::PathBuf,
    pub start_timeout: Duration,     // 10s（对齐 Go）
    pub stop_timeout: Duration,      // 10s
}

pub trait Daemon: Send + Sync {
    fn start(&self) -> anyhow::Result<()>;
    fn stop(&self) -> anyhow::Result<bool>;
    fn is_running(&self) -> (bool, Option<u32>);
}
```

```rust
// Unix 实现（Linux/macOS/OpenWrt/Android）：直接照搬 pidfile.go 协议
// - spawn: Command::new(...).arg(mode).arg("run")
//          .process_group(0)        // setsid 等价（std::os::unix::process::CommandExt）
//          .stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn()
// - pid 文件: O_CREAT|O_EXCL 原子创建，内容 "<pid> <starttime>" 或仅 "<pid>"
// - identity: Linux 读 /proc/<pid>/stat 第 22 字段 starttime
// - alive: kill(pid,0)==Ok 或 EPERM；stop: SIGTERM → 轮询 → SIGKILL
pub struct UnixDaemon { /* ... */ }
impl Daemon for UnixDaemon { /* ... */ }
```

```rust
// Windows 实现：两套入口
// 1) 兼容 CLI start/stop：CREATE_NEW_PROCESS_GROUP|DETACHED_PROCESS + OpenProcess/TerminateProcess
pub struct WindowsProcessDaemon { /* ... */ }

// 2) Windows Service（feature = "windows"）：用 windows-service 接管生命周期
//    - define_windows_service!(ffi_service_main, app_service_main);
//    - app_service_main: 设置 ServiceControlHandler 接受 Stop/Interrogate，
//      进入服务主循环（内部创建 tokio runtime 跑 `client run`/`server run` 等价逻辑），
//      收到 Stop 时置位 AtomicBool 并优雅关闭。
//    - 安装: sc.exe create shadowlemon binPath= "C:\...\shadowlemon.exe --service"
pub fn run_windows_service(mode: &str) -> windows_service::Result<()> { /* ... */ }
```

> 说明：systemd/launchd/init.d 不需要 Rust 侧的 `Daemon` 实现——它们直接调 `run` 前台模式；`Daemon` trait 只服务于 `client/server start|stop` 这组 CLI 命令（Go 的 appctl 行为）。

---

## 补充：静态 musl 下的 DNS 解析决策（含 hosts map 与双栈偏好）

### 背景（已核实）
- Rust std 的 `ToSocketAddrs`/`tokio::net::lookup_host` 底层是 libc `getaddrinfo`（来源：Rust Internals 讨论 <https://internals.rust-lang.org/t/custom-global-dns-resolver/18667>）。musl 静态链接下 `getaddrinfo` 可用，但：读 `/etc/resolv.conf`、`/etc/hosts`，不支持 nsswitch；阻塞调用在 tokio 中会走 blocking pool / 起线程（来源：Reddit 关于 reqwest 与 hickory 的讨论）。
- `hickory-resolver`（原 trust-dns-resolver）是**纯进程内**解析器，不使用宿主 OS 解析器，支持双栈查询与 CNAME，基于 tokio；但会显著增加二进制体积（来源：docs.rs <https://docs.rs/trust-dns-resolver>、hickory-dns GitHub <https://github.com/hickory-dns/hickory-dns>）。

### 推荐方案（默认不引入 hickory）
把 Go 的 `DNSResolver` 设计直接搬到 Rust，使用系统解析器 + 配置 hosts 覆盖：

```rust
#[async_trait]
pub trait Resolver: Send + Sync {
    async fn lookup_ip(&self, network: Network, host: &str) -> io::Result<Vec<IpAddr>>;
}

pub struct HostMapResolver {
    hosts: HashMap<String, IpAddr>,      // 来自配置 dns.hosts（已 NormalizeDomainName）
    inner: Arc<dyn Resolver>,            // SystemResolver
}

pub struct SystemResolver; // tokio::net::lookup_host(host)，10s 超时包装

// 解析顺序与 Go 一致：
// 1) 字面量 IP（含 zone）直接返回，不查询
// 2) 查 hosts map（按 network 过滤 ip4/ip6）
// 3) 委托 SystemResolver
// 4) IPv4 排到 IPv6 前面（sortIPs）
// 5) 由调用方按 DualStackPreference 用 select_ip() 选最终地址
```

理由：
- 与现有配置（`dns.dualStack`、`dns.hosts`）语义 100% 对齐，移植风险最低。
- musl 静态下 `getaddrinfo` 在目标设备能正常工作（依赖 `/etc/resolv.conf`），无需打包 DNS 库，**体积最优**，符合 OpenWrt 要求。
- 把 `dualStack` 选择放在解析之后（而不是交给解析器），与 Go `SelectIPFromList` 完全一致，避免 hickory 的 `lookup_ip` 顺序与偏好模型不匹配。

何时启用 `dns-recursive`：仅当目标环境没有可用的 libc 解析器（例如某些极简容器）或需要避免 getaddrinfo 阻塞线程时，才在**非 embedded** 构建里开 `dns-recursive`，用 `hickory_resolver::TokioAsyncResolver` 替换 `SystemResolver`；并在 CI 里单独测其体积增幅。**不要把 hickory 放进 embedded 默认依赖**。

---

## (e) 风险与缓解

| # | 风险 | 影响 | 缓解措施 |
|---|---|---|---|
| R1 | **MIPS 是 Tier 3，无预编译 std**；`-Zbuild-std` + OpenWrt SDK 工具链脆弱，LLVM MIPS 后端维护不足 | 可能导致 OpenWrt MIPS 目标无法出包，阻塞发布 | 项目启动即做 P0 验证（最小 tokio 程序上板）；使用 nightly 固定版本 + 容器化 SDK；CI 该目标初期 `continue-on-error`；备选：优先保障 MIPS64/OpenWrt ARM（Tier 2/3 中较稳）与 x86_64，MIPS32 作为 best-effort |
| R2 | **静态 musl 的 DNS 行为差异**（无 nsswitch、依赖 `/etc/resolv.conf`、`getaddrinfo` 阻塞） | 域名解析失败或 tokio runtime 被阻塞 | 采用 DNS 决策节的 hosts-first + `lookup_host` 方案；保留 `dns-recursive` feature 作为逃生舱；在真实 OpenWrt 设备上测 DNS + 双栈 |
| R3 | **SO_REUSEADDR 跨平台语义差异**（Windows 可劫持端口、Unix TIME_WAIT 语义） | 安全/可用性问题 | `#[cfg(windows)]` 严格 no-op（对齐 Go）；`SO_REUSEPORT` 仅显式配置且默认关闭；写跨平台 socket 选项单测（在 CI 各 runner 上跑） |
| R4 | Android fd 保护时机错误（在 connect 之后 protect）导致流量环路 | VPN 模式完全失效 | `SocketProtector::protect` 的调用点强制放在connect 前，封装成 `connect_protected()` 单一入口；加注释与 code review 检查项；保留 SCM_RIGHTS 1 字节确认握手 |
| R5 | Windows Service 与 CLI start/stop 两套生命周期互相干扰 | 进程冲突 / 重复启动 | 明确文档：服务托管时不要用 `start/stop`；服务模式通过 `--service` 参数隔离；pid 文件协议对服务模式禁用或独立路径 |
| R6 | 体积超 OpenWrt flash 预算 | 设备刷不进 / 无剩余空间 | `embedded` profile（opt-level=z/fat LTO/panic=abort/strip）+ feature 裁剪；`cargo bloat`/`cargo tree` 纳入发布流程；早期在目标设备量 `ls -l` 与剩余 flash |
| R7 | `panic=abort` 与部分依赖不兼容（某些 crate 期望 unwind） | 编译失败 | 先全量试编；若个别依赖不兼容，桌面 profile 用 `panic=unwind`，仅 embedded 用 abort；或向依赖提 issue/换 crate |
| R8 | 未核实项：MIPS 具体 OpenWrt 版本的 musl 版本、CPU 子架构 ABI、macOS 分发是否需要公证 | 运行期崩溃/发布受阻 | 全部列入 checklist 的「必须实测」项，不凭资料下结论（本文已逐项标注「未核实」） |

---

## (f) 平台适配阶段优先级清单

**P0 — 立项即做（解除最大不确定性）**
1. [ ] 搭最小 Rust 工程 + tokio，`nightly + -Zbuild-std` 在 `mipsel-unknown-linux-musl`（以及 `mips-unknown-linux-musl`）上编译出静态二进制，确认链接器与 OpenWrt SDK sysroot 配置（R1）。
2. [ ] 把该二进制拷到真实 OpenWrt MIPS 设备运行 `hello`+`tokio::net::TcpListener`，记录 musl 版本、CPU 子架构、`file` 输出、体积与剩余 flash（R1/R6）。
3. [ ] 确认 MIPS 目标 libc/ABI 与设备匹配（soft-float/hard-float、o32/n64），固定 SDK 版本与 CI 容器镜像。

**P1 — 核心抽象落地**
4. [ ] 实现 `SocketProtector` trait + `NoopProtector` + `UnixSocketProtector`（SCM_RIGHTS），并用 1 字节确认协议与现有 Java APK 联调（R4）。
5. [ ] 实现 `apply_socket_opts(&socket2::Socket, Role)`：Unix 设 SO_REUSEADDR（可选 REUSEPORT），Windows no-op；各平台 CI 单测（R3）。
6. [ ] 实现 `Resolver` + `HostMapResolver` + `SystemResolver` + `select_ip`（双栈 5 种偏好），与 Go `ipdualstack_test.go`/`dns` 行为对照测试（R2）。
7. [ ] 实现 pid 文件协议（原子创建、identity、stale 清理、start/stop 超时），保证与现有 init.d/systemd 脚本互通。
8. [ ] 建立 `Cargo.toml` features 与两套 profile（`release`/`embedded`），用 `cargo tree` 确认 embedded 裁剪生效（R6/R7）。

**P2 — 平台部署形态**
9. [ ] Unix `Daemon`（setsid/process_group(0)、SIGTERM/SIGKILL、存活检测）。
10. [ ] Windows：进程级 start/stop + `windows-service` 服务入口（`--service`），安装/停止脚本；路径用 `dirs`。
11. [ ] macOS：launchd plist 示例；确认分发是否需签名/公证（本文未核实，需决策）。
12. [ ] Android：cdylib + JNI 入口与 `cargo-ndk` 构建；确认 APK 侧 protect socket 路径注入方式。
13. [ ] 新增 CI 交叉编译矩阵（第 4 节）并启用 MIPS 门禁（设备验证通过后把 `continue-on-error` 去掉）。

**P3 — 收尾**
14. [ ] 用 `cargo bloat`/`cargo llvm-lines` 做体积剖析，记录各目标体积基线；与 Go 二进制对比。
15. [ ] 更新 `docs/compile.md`、`docs/client-install-openwrt.md`、`docs/operation.md` 为 Rust 构建/部署说明。
16. [ ] 把 Go 端 `tcp_congestion_control` 启动信息打印移植为 Linux-only 的 `fs::read_to_string` 实现。

---

## 附：本文核实来源清单

- Rust 目标 tier / std 可用性：<https://doc.rust-lang.org/rustc/platform-support.html>
- musl 1.2.5 更新（含 MIPS 行）：<https://blog.rust-lang.org/2025/12/05/Updating-musl-1.2.5>
- MIPS 降级 Tier 3 讨论：<https://www.reddit.com/r/rust/comments/1ajethc/mipsunknownlinuxmusl_support_dropped/>
- cross `-Zbuild-std` 需求：<https://github.com/cross-rs/cross/issues/1416>
- MIPS musl 静态链接需 `+crt-static`：<https://github.com/cross-rs/cross/issues/504>
- MIPS 交叉编译实操（build-std / 链接器 / patchelf）：<https://blog.habets.se/2024/04/Cross-compiling-Rust-fixed.html>
- OpenWrt SDK 交叉编译经验：<https://blog.davidv.dev/posts/cross-compiling-for-openwrt-platforms>、<https://medium.com/althea-mesh/cross-compiling-complex-rust-programs-for-openwrt-targets-80897fcf7648>
- tokio `TcpSocket` 平台可用性：<https://docs.rs/tokio/latest/tokio/net/struct.TcpSocket.html>
- Windows SO_REUSEADDR 语义：<https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse>
- Windows Service crate：<https://github.com/mullvad/windows-service-rs>、<https://docs.rs/windows-service/latest/windows_service/service/index.html>、<https://users.rust-lang.org/t/windows-service-in-rust/137389>
- Android NDK / jni / cargo-ndk：<https://www.davthecoder.com/blog/rust-android-ndk-toolchain-setup-cargo-ndk>、<https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-21-rust-on-android.html>、<https://medium.com/@ali.alacan/rust-cross-platform-android-together-with-gradle-83a27042cf79>
- DNS：std 使用 getaddrinfo <https://internals.rust-lang.org/t/custom-global-dns-resolver/18667>；hickory/trust-dns 为进程内解析 <https://docs.rs/trust-dns-resolver>、<https://github.com/hickory-dns/hickory-dns>
