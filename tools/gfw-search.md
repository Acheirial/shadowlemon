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

| 策略 | 前缀长度 | 命中规则 | 稳健性 |
|---|---|---|---|
| **随机可打印前缀** | **6 字节** | Ex2 | 80/80 |
| TLS 魔数 `16 03 01` | 3 字节 | Ex5 | 80/80 |
| HTTP 方法（如 `PUT`） | 3 字节 | Ex5 | 80/80 |

低/高 popcount 前缀在采样长度内不能稳定把 ex1 推出 [3.4, 4.6]，未列为稳健方案。

**推荐**：6 字节随机可打印前缀——最短、无协议模仿缺陷、每次随机生成避免固定签名。TLS/HTTP 方案作为备选，但属于"模仿"，需承担 CCS 2026 指出的深层解析风险。

## 局限

- 这是 GFW 2021–2023 算法的离线复现，不能覆盖真实审查系统的全部规则、概率阻断（约 26%）、IP 段定向或后续更新。
- 搜索只验证"FET 豁免"，不验证服务端能否剥离前缀；真正落地需在协议层加入前缀消费并重新抓包验证。
- 真实过墙仍需受审查地区 VPS 的前后对比测试（见 `docs/gfw-assessment.md`）。
