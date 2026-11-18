# ShadowLemon V0.2 抓包特征分析与改进报告

本报告基于当前 HEAD 二进制的真实抓包（`unshare -Urnm` 命名空间、`lo`、tcpdump 4.99.6），覆盖 CONNECT、UDP ASSOCIATE 与混合 TLS/HTTP 流量三类场景。所有数值均为实测，不引用旧版本基线。

## 1. 测试环境与方法

| 项 | 内容 |
|---|---|
| 被测版本 | V0.2，线版本 4，x86_64 Linux release 构建 |
| 抓包 | tcpdump `-s 0 -Z root`，过滤代理端口 UDP 9999–10003 |
| 场景 A（CONNECT） | 60 条新连接各一次 HTTP 请求 + 18 秒空闲心跳：8787 包 / 11.1 MB |
| 场景 B（UDP ASSOCIATE） | 20 连接 × 100 数据报：8684 包 / 4.9 MB |
| 场景 C（混合） | 60 HTTP + 40 TLS 1.3 + 80 ShadowLemon 流：17,391 包 |
| 分析工具 | 纯标准库 pcap 解析、`tools/udp_entropy_check.py`、nDPI 6.0.0 |

## 2. 实测结果

### 2.1 包长分布（三峰）

| 峰 | 实测范围 | 来源 |
|---|---|---|
| 控制 / ACK | 99–587 B（c2s 中位 338，p90 485） | ACK padding 每侧 0–255 |
| 握手首包 | 1117–1149 B（33 取值） | payload 恒 1024 + suffix 0–32（**本报告后已改进**） |
| 数据帧 | 1318–1372 B（s2c 中位 1339） | 应用分片 + padding，近 MTU |

全局包长 374 种、熵 6.33。

### 2.2 握手与随机性

- 握手首包 1117–1149 B、响应 144–176 B（28 种长度）；5 字节路由信封 61/61 全唯一。
- Shannon 熵 7.40–7.85，可打印率 37%，最长可打印串 5–7，popcount ≈4.00。
- GFW 五条豁免规则：popcount 100% 落在 [3.4,4.6]，其余规则全不满足。
- QDPI `entropy_score` 均值 4474–5035（阈值 100）：CONNECT 121/122 流、ASSOCIATE 40/40 流命中。

### 2.3 时序

- 全局包间隔 97.6% < 1 ms（无 pacing、burst 发送）。
- 心跳间隔实测 2.59–14.87 秒，覆盖 3–15 秒、分布均匀（原设计为 2–15 秒均匀随机）。
- 心跳原本单向（仅客户端发，**本报告后已改进**）。

### 2.4 方向与 DPI

- CONNECT：c2s : s2c = 317 : 8470（强下行）；ASSOCIATE：4342 : 4342（对称）。
- nDPI 6.0：两场景全部 80 条流判 `TPLINK_SHP`，置信度 100% 来自 `Match by port`（默认端口命中 TP-Link 端口的误报），全部流命中 `Susp Entropy`。

### 2.5 混合 TLS/HTTP 流量对比（混合 pcap）

| 维度 | ShadowLemon | 明文 HTTP | TLS 1.3 |
|---|---|---|---|
| 包长唯一数 / 熵 | 1253 / 9.04 | 16 / 2.30 | 7 / 2.73 |
| 首字节 | 完全随机（44 种） | `0x47`/`0x48`（100%） | `0x16` 全 50/50 |
| 首包长度 | 1117–1149 / 144–176 双峰 | 116–118 三值 | 1471 / 2409 两种 |
| Shannon 熵 | 7.31 | 5.02 | 7.78 |
| 可打印率 | 0.375 | 0.906 | 0.368 |
| 包间隔 <1ms | 69.6% | 92.4% | 99.7% |
| nDPI | TPLINK_SHP + Susp Entropy | HTTP（DPI） | TLS（DPI） |

结论：内容随机性上 ShadowLemon 与 TLS 几乎不可区分（熵、可打印率、popcount 接近），nDPI 对 TLS 流同样报 `Susp Entropy`。可区分点在于 TLS 的固定首字节 `0x16`、极窄的包长分布与内核态连续发送节拍。QUIC 的 Initial 长头首字节 `0xc0` 与固定版本字段同样构成可 match 的签名——QUIC 的固定头是其弱点，不是 ShadowLemon 的伪装机会；真正的 cover protocol 不在 V0.2 范围。

### 2.6 Mux in Mux 结构

线上层级：`IP → UDP → [5B 混淆信封] → [V0.2 帧] → 加密 payload 内的 [6B message_id/分片头] + SOCKS5 头 + 应用数据`。没有递归"帧套帧"；`DatagramStream` 只是本地 mpsc 门面。每条 SOCKS5 流独占一个 UDP 五元组（`_reuse` 参数被忽略），session_id 随机 u32，message_id / sequence 严格递增但都在 AEAD 内，观察者看不到。服务端端口 9999–10003 由 round-robin 轮换。

## 3. 本轮改进（相对上述基线）

1. **握手首包长度随机化**：`MAX_SESSION_PAYLOAD` 从 1024 提升到 1236，`build_request` 的 piggyback 区在 `1208..=1236` 中随机抽取，首包整包约 1305–1345 B，与数据帧区间重叠，消除固定 1024 B 载荷指纹。
2. **部署秘密必填**：`SHADOWLEMON_ENVELOPE_SECRET` 不再回退到公开 pepper；缺失或为空时启动即报错。观察者无法再由每包 nonce 复算 5 字节信封 keystream 并解出 `kind` / session ID。
3. **服务端对称心跳**：服务端 reply flusher 按 `next_timer()` 精确唤醒并调用 `Session::tick`，空闲时主动发心跳 ACK，消除单向心跳特征。
4. **分片随机化（已回退）**：曾尝试把 `fragment_payload` 的片长随机化（宽区间、仅抖动末两片两种方案），实测都会让 64 KB 大响应在 loopback 上卡住或返回空响应——用户态 ARQ 无 pacing，不均匀分片与发送窗口、重组相互干扰。分片长度保持定长；线层每帧 0–32 字节随机前后缀已提供包长抖动。详见 `rust/docs/known-gaps.md` §8。

`rust/docs/known-gaps.md` §8 与 `docs/operation.md` 已同步上述变化。
