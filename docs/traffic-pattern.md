# 流量模式

> **本版本线协议版本为 4；两端必须使用同一版本，否则会话会在握手阶段失败。**

## 概述

流量模式功能允许 shadowlemon 修改网络流量特征，以规避深度包检测（DPI）和流量分析。

流量模式可以在客户端和服务器上独立配置。客户端和服务器不需要使用相同的流量模式设置。

## 配置方法

客户端：

```sh
shadowlemon client apply config <FILE>
```

服务器：

```sh
shadowlemon server apply config <FILE>
```

然后重启代理服务使更改生效。

### 客户端配置示例

```js
{
    "profiles": [
        {
            "profileName": "default",
            "user": {
                "name": "user1",
                "password": "password1"
            },
            "servers": [
                {
                    "ipAddress": "12.34.56.78",
                    "portBindings": [
                        {
                            "portRange": "2012-2022",
                            "protocol": "TCP"
                        }
                    ]
                }
            ],
            "trafficPattern": {
                "unlockAll": false,
                "tcpFragment": {
                    "enable": true,
                    "maxSleepMs": 10
                },
                "nonce": {
                    "type": "NONCE_TYPE_PRINTABLE",
                    "applyToAllUDPPacket": true,
                    "minLen": 6,
                    "maxLen": 8
                },
                "padding": {
                    "maxMiddlePaddingLen": 64,
                    "maxEndPaddingLen": 128
                },
                "lowEntropy": {
                    "mode": "LOW_ENTROPY_MODE_32",
                    "maskRotation": "LOW_ENTROPY_MASK_ROTATE_RIGHT_7"
                }
            }
        }
    ],
    "activeProfile": "default",
    "socks5Port": 1080
}
```

### 服务器配置示例

```js
{
    "portBindings": [
        {
            "portRange": "2012-2022",
            "protocol": "TCP"
        }
    ],
    "users": [
        {
            "name": "user1",
            "password": "password1"
        }
    ],
    "trafficPattern": {
        "unlockAll": true,
        "tcpFragment": {
            "enable": false,
            "maxSleepMs": 0
        },
        "nonce": {
            "type": "NONCE_TYPE_FIXED",
            "customHexStrings": ["00010203", "04050607"]
        },
        "padding": {
            "maxMiddlePaddingLen": 0,
            "maxEndPaddingLen": 255
        },
        "lowEntropy": {
            "mode": "LOW_ENTROPY_MODE_56",
            "maskRotation": "LOW_ENTROPY_MASK_ROTATE_LEFT_7"
        }
    }
}
```

## 配置字段说明

`trafficPattern` 对象支持以下字段：

1. 【可选】`seed` - 一个整数，用于为未显式设置的字段生成稳定的隐式流量模式。如果 `seed` 和 `unlockAll` 的值不变，生成的隐式流量模式保持不变。未提供 `seed` 时，每次启动生成的隐式模式都不同，并且与主机名、shadowlemon 版本无关，因此第三方无法离线枚举出你的隐式模式取值；提供 `seed` 时结果可复现。
2. 【可选】`unlockAll` - 一个布尔值，控制隐式流量模式的取值范围。设为 `true` 时，隐式模式可以使用所有可能的选项。设为 `false`（默认）时，隐式模式仅使用有限的保守选项，其中最保守的一条是**默认不改写 nonce 前缀**（隐式生成的 nonce 类型为 `NONCE_TYPE_RANDOM`），从而避免在连接最开始的固定位置出现可被直接识别的可打印字节序列。
3. 【可选】`tcpFragment` - 配置 TCP 分片的对象。它不影响 UDP 代理协议。
4. 【可选】`nonce` - 配置 Nonce 前缀操纵的对象。
5. 【可选】`padding` - 配置网络数据段填充长度限制的对象。
6. 【可选】`lowEntropy` - 使用低熵位模式扩展加密数据正文的对象。

## TCP 分片

TCP 分片功能将某些 TCP 数据包拆分为更小的分片，使流量更难被分析。`tcpFragment` 对象支持以下字段：

1. 【可选】`enable` - 布尔值，启用或禁用 TCP 分片。默认为 `false`。
2. 【可选】`maxSleepMs` - 整数，指定发送两个分片之间的最大休眠时间（毫秒）。值必须在 0 到 100 之间。较高的值会增加分片之间的延迟，可能更有效地规避分析，但会降低性能。

启用 TCP 分片可能会增加网络延迟。

示例：

```js
"tcpFragment": {
    "enable": true,
    "maxSleepMs": 10
}
```

## Nonce 模式

Nonce 模式功能操纵加密数据包中的 Nonce 前缀。`nonce` 对象支持以下字段：

1. 【可选】`type` - Nonce 操纵策略。可选值为：
   - `NONCE_TYPE_RANDOM` - 不修改原始随机 Nonce。这是默认值。
   - `NONCE_TYPE_PRINTABLE` - 使用可打印的 ASCII 字符（0x20 到 0x7E）。
   - `NONCE_TYPE_PRINTABLE_SUBSET` - 使用预定义的可打印 ASCII 字符子集。
   - `NONCE_TYPE_FIXED` - 使用 `customHexStrings` 中的自定义 Nonce 前缀。如果未设置 `customHexStrings`，行为与 `NONCE_TYPE_RANDOM` 相同。
2. 【可选】`applyToAllUDPPacket` - 布尔值。设为 `true` 时，模式应用于每个 UDP 数据包。设为 `false`（默认）时，模式仅应用于第一个 UDP 数据包。
3. 【可选】`minLen` - 要操纵的最小字节数。值必须在 0 到 12 之间。当 `type` 为 `NONCE_TYPE_RANDOM` 或 `NONCE_TYPE_FIXED` 时，此字段将被忽略。
4. 【可选】`maxLen` - 要操纵的最大字节数。值必须在 0 到 12 之间。当 `type` 为 `NONCE_TYPE_RANDOM` 或 `NONCE_TYPE_FIXED` 时，此字段将被忽略。
5. 【可选】`customHexStrings` - 十六进制字符串列表（不含 `0x` 前缀），表示自定义 Nonce 前缀。例如，字符串 `"00010203"` 表示 4 字节的 Nonce 前缀 `[0, 1, 2, 3]`。每个 Nonce 前缀不能超过 12 字节。提供多个字符串时，每次随机选择一个使用。此字段仅在 `type` 为 `NONCE_TYPE_FIXED` 时生效。

> **AES-GCM nonce 规则（重要）：** 线路 nonce 恒为 24 字节，但 AES-GCM 套件（`CIPHER_SUITE_AES_256_GCM` / `CIPHER_SUITE_AES_128_GCM`）的 AEAD nonce 只取最后 12 字节 `wireNonce[12:24]`。因此 traffic pattern **最多只能操纵前 12 字节**（`minLen` / `maxLen` / 每个 `customHexStrings` 均 ≤ 12）；把前 12 字节改写成确定性常量不会进入 AES-GCM 的 nonce。绝不可改用 `wireNonce[0:12]` 作为 GCM nonce：同一密钥下重复的 GCM nonce 会直接摧毁机密性与认证能力。详见 `rust/docs/protocol-v0.2.md` §2.3。

> **风险提示：** 只配置**一个**固定前缀时，该前缀会在同一用户的所有连接上重复出现，观察者可以据此把多个会话关联到同一个用户；一旦这份样本泄露或被识别，整个前缀就会被加入封锁名单，全网的所有连接都会失效。提供多个字符串（实现会在发送时随机挑选一个）可以缓解这两个问题，但并不能完全消除；`NONCE_TYPE_FIXED` 仍然是最容易被识别的选项，除非确有需要，否则不建议使用。

使用可打印 Nonce 的示例：

```js
"nonce": {
    "type": "NONCE_TYPE_PRINTABLE",
    "applyToAllUDPPacket": true,
    "minLen": 6,
    "maxLen": 8
}
```

使用固定 Nonce 前缀的示例：

```js
"nonce": {
    "type": "NONCE_TYPE_FIXED",
    "customHexStrings": ["00010203", "04050607"]
}
```

## 填充模式

填充模式功能控制 shadowlemon 会向网络数据段添加多少填充字节。`padding` 对象支持以下字段：

1. 【可选】`maxMiddlePaddingLen` - 网络数据段中间填充字节数的最大值。取值必须在 0 到 255 之间。设为 `0` 可禁用中间填充。
2. 【可选】`maxEndPaddingLen` - 网络数据段末尾填充字节数的最大值。取值必须在 0 到 255 之间。设为 `0` 可禁用末尾填充。

这些字段设置的是上限。实际填充长度可能因为随机选择、MTU 限制、数据包开销和负载大小而更小。如果未设置某个字段，shadowlemon 会使用隐式模式生成来选择一个值：隐式生成的 `maxMiddlePaddingLen` 在 `[0, 127]` 内均匀取值（不再偏向 0），`maxEndPaddingLen` 在保守模式下取 255、在 `unlockAll` 为 `true` 时在 `[0, 255]` 内均匀取值。

示例：

```js
"padding": {
    "maxMiddlePaddingLen": 64,
    "maxEndPaddingLen": 128
}
```

## 低熵模式

> **V0.2 的低熵扩展在 Rust 中是 feature-gated 的，默认关闭（default OFF）。** 只有启用对应编译特性且配置 `trafficPattern.lowEntropy.mode ≠ LOW_ENTROPY_MODE_OFF` 时才会产生/接受低熵数据段；`embedded` feature 会裁掉该支持。完整算法见 `rust/docs/protocol-v0.2.md` §7。

低熵模式会扩展加密数据正文，使每个 64 位（8 字节）编码块中只有部分位承载密文，其余为填充位。TCP 和 UDP 代理传输均支持此功能。`lowEntropy` 对象包含以下字段：

1. 【可选】`mode` - 选择编码块标称承载的源数据量：
   - `LOW_ENTROPY_MODE_OFF` - 禁用低熵发送（默认）。
   - `LOW_ENTROPY_MODE_32` - 每个 8 字节块承载 4 字节数据。
   - `LOW_ENTROPY_MODE_40` - 每个 8 字节块承载 5 字节数据。
   - `LOW_ENTROPY_MODE_48` - 每个 8 字节块承载 6 字节数据。
   - `LOW_ENTROPY_MODE_56` - 每个 8 字节块承载 7 字节数据。
2. 【可选】`maskRotation` - 控制相邻 64 位数据块之间载荷位置的移动方式。`LOW_ENTROPY_MASK_NO_ROTATION` 保持掩码不变；`LOW_ENTROPY_MASK_ROTATE_RIGHT_1` 至 `_15` 将掩码向右旋转；`LOW_ENTROPY_MASK_ROTATE_LEFT_1` 至 `_15` 将掩码向左旋转。配置值在编码为线字节 `R` 时统一落入 `[0, 63]`（左移 k 等价于右移 64−k）。

示例：

```js
"lowEntropy": {
    "mode": "LOW_ENTROPY_MODE_32",
    "maskRotation": "LOW_ENTROPY_MASK_ROTATE_RIGHT_7"
}
```

### V0.2 简化算法

V0.2 采用「模式固定步长 + 掩码 popcount 固定 + 单字节旋转」，没有步长家族或「由掩码反推步长」的歧义，实现只需少量状态（见 `rust/docs/protocol-v0.2.md` §7.1–§7.5）：

- 每种模式有**固定步长** `C`：模式 32/40/48/56 分别为 4/5/6/7 字节，不再逐消息在标称值上下浮动。
- 发送端随机生成一个 32 位半掩码，要求其 1 的位数**恰好**为 `4·C`；重复成 64 位掩码后，每个 8 字节块恰有 `8C` 个数据位、`64−8C` 个填充位。因为 `C ≤ 7`，每块至少留 8 个填充位，不存在「无填充位」特例。
- 每个后续块把初始掩码循环右移 `(i · R) mod 64` 位，其中 `R ∈ [0, 63]` 由 `maskRotation` 映射得到；`R = 0` 表示所有块共用同一掩码。
- 填充位携带逐消息随机的极性 `p ∈ {0,1}`：整条消息的所有填充位统一为 0 或统一为 1，接收端从首块推断并要求后续块一致。最后一个不完整块中未被使用的「数据位」也按 `p` 填充。
- 认证标签在编码**之前**由 AEAD 产生，放在编码正文之后，**不参与**低熵变换，也不计入编码后正文长度。
- 接收端在解密元数据后校验：模式合法、掩码 popcount 精确等于 `4·C`、`R ≤ 63`、编码长度等于 `ceil(extractedPayloadLen / C) · 8`、填充极性一致等；任一不满足即丢弃该数据段。

客户端和服务端配置的控制方向不同：

- 客户端配置控制客户端到服务端的应用数据。
- 服务端配置使服务端到客户端的数据具备使用低熵模式的条件。只有在同一会话中认证通过一个低熵请求后，服务端才会启用该模式。服务端使用自己的模式与旋转设置，它们可以与客户端不同。
- 接收行为不依赖本地的发送设置。当前版本的接收端既接受普通数据，也接受所有有效的低熵模式（掩码 popcount 精确匹配该模式的 `4·C` 即被接受）。

低熵模式只作用于加密后的应用数据正文。它不会变换 Nonce、加密元数据、AEAD 认证标签、会话控制载荷、纯 ACK 数据段，也不会变换由 `padding` 配置的独立中间填充和末尾填充。

模式 32、40、48 和 56 的完整数据块正文扩展倍数依次约为 2.0、1.6、1.34 和 1.15。最后一个不完整数据块始终占用 8 字节，因此短数据分片的扩展比例可能更高。启用低熵模式后，TCP 单个应用分片的上限为 `min(32768, 8191·C)`：模式 32 为 **32764** 字节，模式 40/48/56 为 **32768** 字节；更大的写入会被安全拆分。使用 UDP 时，shadowlemon 会缩小明文分片，使扩展后的正文、认证标签、元数据、Nonce 和可选填充仍处于配置的 MTU 之内。因此，启用此功能会增加带宽与处理开销，并可能降低有效 UDP 载荷大小。

> **注意：** 低熵模式的掩码、旋转与填充规则是协议语义的一部分，**两端必须使用同一版本**，否则使用低熵模式的数据段会被对端拒绝。这些规则不改变任何线格式长度，也不改变 AEAD 语义。详见 `rust/docs/protocol-v0.2.md` §7 与 §11。

## 隐式模式生成

配置流量模式后，shadowlemon 会自动为未显式设置的字段生成值，这称为隐式模式生成。

`seed` 字段控制生成过程。如果提供了 `seed`，生成的模式保持稳定，同一份配置在每次启动时得到相同的结果。如果未提供 `seed`，每次启动都会生成一份不同的隐式模式，而且这份模式与主机名、shadowlemon 版本无关，因此第三方无法离线枚举出你实际使用的取值。

`unlockAll` 字段控制生成值的范围。默认的 `false` 采用保守取值：隐式生成的 nonce 类型为 `NONCE_TYPE_RANDOM`（不改写 nonce 前缀），中间填充上限在 `[0, 127]` 内均匀取值，低熵模式关闭。

显式设置的字段不会受到隐式生成的影响。例如，如果你将 `tcpFragment.enable` 设为 `true`，无论 `seed` 和 `unlockAll` 的设置如何，它都将保持 `true`。

## 配置生效方式

修改流量模式后，需要用 `shadowlemon server stop` + `shadowlemon server start`（服务端）或 `shadowlemon client stop` + `shadowlemon client start`（客户端）重启程序，新的流量模式才会生效。
