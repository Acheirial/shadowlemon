# OpenGFW FET 离线评估与规避前缀自动搜索设施

本目录提供一个**无需 Docker、无需 NFQueue/root** 的规避策略研究工具。它把 OpenGFW 的 FET（Fully Encrypted Traffic）分析器逐行等价移植到 Rust，在已抓取的 pcap 上复现判定，并自动搜索能让首包命中豁免规则的前缀生成器。

## 为什么不用真正的 OpenGFW

OpenGFW（github.com/HyNetworks/OpenGFW）只支持 NFQueue I/O，需要 root、内核连接跟踪模块和 `iptables` 规则；本环境没有 Docker 也没有免密提权。CCS 2026 用 Docker 容器跑 OpenGFW，这里无法照搬。因此直接移植其 `analyzer/tcp/fet.go` 的判定逻辑——这是同一套规则，且可离线、可复现。

判定与 USENIX Security 2023 的算法 1 一致。首客户端 TCP 载荷命中任一条件即豁免：

| 规则 | 条件 |
|---|---|
| Ex1 | 平均 popcount ≤ 3.4 或 ≥ 4.6 |
| Ex2 | 前 6 字节全为可打印 ASCII |
| Ex3 | 可打印字节占比 > 0.5 |
| Ex4 | 最长连续可打印字节 > 20 |
| Ex5 | 前 3 字节匹配 TLS `[\x16-\x17]\x03[\x00-\x09]` 或 HTTP 方法 |

`detected = !exempt`，即 OpenGFW 属性 `yes=true` → 全加密流量 → 阻断。

## 构建

```sh
export PATH="$HOME/.cargo/bin:$PATH"
rustc -O tools/gfw-search.rs -o /tmp/opencode/gfw-search
```

单文件、纯 std、无外部依赖，不向仓库引入 Go 代码。

## 用法

```sh
# 复核一份 pcap 的首包判定（默认代理端口 9999-10003）
/tmp/opencode/gfw-search check /tmp/opencode/after.pcap
/tmp/opencode/gfw-search check /tmp/opencode/altport.pcap 23456

# 自动搜索：在 20 条真实首包 × 多次随机采样下筛选稳健前缀
/tmp/opencode/gfw-search search /tmp/opencode/after.pcap 20 128
```

- `check`：输出首包数量、BLOCK/EXEMPT 计数与样本指标。
- `search`：随机生成候选前缀生成器（可打印 / 低 popcount / 高 popcount / TLS 魔数 / HTTP 方法 × 长度），要求**所有**随机实例在**所有**采样首包上都豁免，再按前缀长度排序，每类保留最短方案。多模板验证避免了"某条样本恰好符合"的假阳性。

## 已验证结果

基线（`check`）：整改前后各 60 条首包均 **60/60 BLOCK**，ex1 ≈ 4.0–4.2、可打印比例 33–41%，无豁免。

搜索（`search`，20 条首包 × 4 次采样 = 80/80 全通过）：

| 策略 | 前缀长度 | 命中规则 | 稳健性 | 是否推荐 |
|---|---|---|---|---|
| **随机可打印前缀** | **6 字节** | Ex2 | 80/80 | ✅ 推荐 |
| TLS 魔数 `16 03 01` | 3 字节 | Ex5 | 80/80 | ❌ 已否决 |
| HTTP 方法（如 `PUT`） | 3 字节 | Ex5 | 80/80 | ❌ 已否决 |

低/高 popcount 前缀在采样长度内不能稳定把 ex1 推出 [3.4, 4.6]，未列为稳健方案。

**推荐**：只有 6 字节随机可打印前缀。它命中 Ex2（可打印前缀），属于 randomization 阵营，不伪装成任何具体协议，每次随机生成避免固定签名。

**TLS/HTTP 魔数前缀已否决**：它们能过 FET 的 Ex5（只查前 3 字节），但属于模仿策略——Houmansadr 等人指出模仿式混淆"fundamentally flawed"；即便隧道进 cover 协议仍可凭实现差异被识别（USENIX Security 2024）；GFW 2012 年就用独特 TLS cipher suite 识别过 Tor；NDSS 2020 证明主动探测可用"服务端如何关闭连接/是否回数据"区分代理与真 TLS 服务器。塞 3 字节头两头不靠：不是真 TLS，又放弃随机化优势。搜索工具保留它们仅供对照，不作为落地候选。

## 局限

- 这是 GFW 2021–2023 算法的离线复现，不能覆盖真实审查系统的全部规则、概率阻断（约 26%）、IP 段定向或后续更新。
- 搜索只验证"FET 豁免"，不验证服务端能否剥离前缀；真正落地需在协议层加入前缀消费并重新抓包验证。
- 真实过墙仍需受审查地区 VPS 的前后对比测试（见 `docs/gfw-assessment.md`）。

## UDP 首包熵评估：`udp_entropy_check.py`

TCP 的 FET 判定和 QDPI `entropy_score` 都只适用于 TCP 首包；ShadowLemon V0.2 是 **UDP-only** 隧道，首包藏在 UDP 数据报里，因此另提供纯 Python（仅标准库，不依赖 scapy）的 UDP 版分析工具：

```sh
# 同时评估整改前后两份抓包
python3 tools/udp_entropy_check.py /tmp/opencode/before_udp.pcap /tmp/opencode/after_udp.pcap

# 只按源端口聚合（而不是完整 5 元组），并限制每包分析前 64 字节
python3 tools/udp_entropy_check.py --by-source-port --limit 64 /tmp/opencode/after_udp.pcap
```

它解析 classic pcap 与 pcapng，按 IP header 的协议号 17 过滤 UDP（正确处理 IPv4 IHL、VLAN/SLL/raw-IP 链路层、UDP 长度字段），对**每条流第一个 payload** 输出：

- Shannon 熵（bits/byte）、可打印字符（`0x20..=0x7e`）比例、最长连续可打印串、popcount 均值；
- QDPI 风格的 `entropy_score`（移植自 `/tmp/opencode/qdpi_check.py`，`processed_bytes_limit` 默认 256）；
- 每份文件的流数与各指标均值/中位数/最大值，以及超过阈值的流数占比（可用 `--entropy-threshold`、`--printable-threshold`、`--run-threshold`、`--popcount-low/high`、`--qdpi-threshold` 调整）。

与现有工具的区别：

| 工具 | 协议 | 判定来源 | 用途 |
|---|---|---|---|
| `tools/gfw-search.rs` | TCP | OpenGFW FET 五条豁免规则 | 搜索能命中豁免的首包前缀 |
| `/tmp/opencode/qdpi_check.py` | TCP | ixEngine `entropy_score` 表 | 复现 QDPI 首包打分 |
| `tools/udp_entropy_check.py` | **UDP** | 同样的熵/可打印性/popcount 指标 + QDPI 表 | 对比 UDP 隧道整改前后的首包特征 |

典型用法：先在受控环境抓 `before_udp.pcap`（未整改客户端）与 `after_udp.pcap`（整改后客户端），逐项对比熵、可打印比例和 `entropy_score` 的分布；目标是把首包从"高熵、低可打印率"推移到 FET/ixEngine 会豁免的区间。注意该工具只做**离线统计**，不模拟审查系统，也不替代真实过墙测试。
