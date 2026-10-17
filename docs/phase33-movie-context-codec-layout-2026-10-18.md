# 第33阶段：区分 Recorder 输入、活跃模板、录像上下文中的 Codec 字段（2026-10-18）

> **本阶段新发现**：X-S10 原厂 3.11 / X-T4 原厂 2.12 的活跃 Codec/Format 字节，经过已核对的主模板或备份模板复制，出现在更下游录像上下文 **+0x9D8/+0x9D9**（X-S10）和 **+0x9DC/+0x9DD**（X-T4）。两机的一个录像参数构造器检查 Codec 字节是否为 1，并选用 **0x10004 / 0x10005** 两种输出参数；另有 Format 字节选择原厂字符串 **MP4 / MOV**。**但 GUI MovieCodec → Recorder 当前输入 +0x5B0 的首次赋值仍未找到；不能证明 Main10 或 4K60 解锁。**

安全范围：仅用用户授权 Ubuntu 上已存在的原厂 X-S10 3.11、X-T4 2.12 X6 Section1/2 与 Ghidra 12.1.4 只读结果。用户此前报告的实机 X-S10 版本为 2.10；绝不能将本阶段研究地址直接刷入该机。没有相机 USB/FF80 命令、RAM/Flash 读写、修改 DAT 或可刷补丁。原始固件及反编译日志仅保留在 Git 忽略的私有 output/。

## 1. 不能把三个对象的 +0x5B0 认作同一个 Codec 字段

| 对象 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| Recorder **当前输入**结构中的 Codec | 输入指针 +0x5B0 | 同左 |
| Recorder **活跃模板**基址 | 0x01C24DD8 | 0x01B83540 |
| 活跃模板 Codec / Format 偏移 | **+0x430/+0x431** | **+0x434/+0x435** |
| 活跃 Codec / Format 绝对字节 | 0x01C25208 / 0x01C25209 | 0x01B83974 / 0x01B83975 |
| **录像上下文**模板复制目标起点 | 上下文 +0x5A8 | 同左 |
| **录像上下文** Codec / Format 偏移 | **+0x9D8/+0x9D9** | **+0x9DC/+0x9DD** |
| 录像上下文 +0x5B0 实际对应 | 活跃模板 **+0x08** | 活跃模板 **+0x08** |

两机有确定的字段位置恒等式：

~~~text
X-S10: 录像上下文 Codec = 0x5A8 + 0x430 = +0x9D8
X-T4 : 录像上下文 Codec = 0x5A8 + 0x434 = +0x9DC

录像上下文 +0x5B0 = 模板 +(0x5B0-0x5A8) = 模板 +0x08，
并非模板 Codec +0x430 / +0x434。
~~~

因此不能把某个函数写上下文 +0x5B0 认作写 Recorder 输入 +0x5B0。它们是结构类型不同、基址不同的两个字段。

## 2. 原厂两条整块复制：活跃模板和第二备份模板

| 功能 | X-S10 | X-T4 |
|---|---|---|
| 主活跃模板 → 录像上下文 | FUN_012BD150 | FUN_012957C0 |
| 主模板起始 | 0x01C24DD8 | 0x01B83540 |
| 备份模板 → 录像上下文 | FUN_012C1EF4 | FUN_0129A6DC |
| 备份模板起始 | **0x01C25498** | **0x01B83C00** |
| 主模板与备份距离 | +0x6C0 | +0x6C0 |
| 目标 / 长度 | param_1+0x5A8 / 0x478 | param_1+0x5A8 / 0x47C |
| 拷贝包装函数 | FUN_012A9148 | FUN_01281848 |

备份模板来源不只来自 Ghidra 名称：X-S10 原始 Section1 的常量地址 0x012C1F60 含数值 0x01C25498；X-T4 的 0x0129A748 含数值 0x01B83C00。恰好与第32阶段活跃模板第二备份复制源头一致。

~~~text
X-S10: 0x01C24DD8 +0x6C0 = 0x01C25498
X-T4 : 0x01B83540 +0x6C0 = 0x01B83C00
~~~

两机主/备合计四条路径都还有如下**条件规范化**（通过原厂 A32 LDRB、CMP、MOVEQ、STRBEQ 及 Ghidra C 双重核对）：

~~~c
if (source_template[8] == 0x25) {
    movie_context[0x5B0] = 0x21;
}
~~~

此处理的是活跃/备份模板 **+8**，**不是活跃 Codec +0x430/+0x434**。不能推论它是在关闭 H.265、限制 10-bit 或过滤 4K60。

## 3. 找到 Codec 字节的录像参数消费者

| 证据 | X-S10 | X-T4 |
|---|---|---|
| 录像参数构造函数 | FUN_022B6230 | FUN_02222A00 |
| 已识别的一处实际 BL 上游调用点 | 0x022DFAA8 | 0x0224C208 |
| 从录像上下文读取字段 | 0x022B6784, LDRB [R4,#0x9D8] | 0x02222F44, LDRB [R4,#0x9DC] |
| 条件 | 值是否为 1 | 同左 |
| 参数写出 | output +0x220 | 同左 |

双机原始 ARM 的连续六条指令实现以下逻辑：

~~~c
uint32_t n = (movie_context[codec_offset] == 1) ? 4 : 5;
*(uint32_t *)(output + 0x220) = 0x10000 | n;
// n=4 => 0x10004; n=5 => 0x10005
~~~

这证明**录像参数构造代码根据此配置字节选择不同输出参数**。但尚未追踪该参数的最终驱动消费者，不能将 0x10004 或 0x10005 擅自标为 H.264/H.265 profile、10-bit bit depth、Main10 或 4K60 能力位；运行时值亦未读取。

## 4. Format 字节明确选择 MOV / MP4 字符串

| 项目 | X-S10 | X-T4 |
|---|---|---|
| 静态存在的格式字符串选择函数 | FUN_022CF30C | FUN_0223B8FC |
| 从上下文读取 Format | +0x9D9 | +0x9DD |
| 原始 LDRB | 0x022CF318 | 0x0223B908 |
| Format == 1 | **MP4** ROM 0x02697240 | **MP4** ROM 0x025F5F74 |
| 其他 Format 值 | **MOV** ROM 0x0269723C | **MOV** ROM 0x025F5F70 |

本轮直接从原厂 Section2 检查了两个四字节字符串 MOV 和 MP4（包括 NUL 结束字节），还核对选择器 A32 条件 MOVW/MOVT 的目标数值。注意：两机上述 Format 字符串函数在当前 Ghidra 工程中没有直接调用 xref，可能通过间接表调用，也可能未实际使用；能够证明代码和映射存在，**不是**实机确实选择此路径的运行证据。

## 5. GUI 缓存状态是独立于录像上下文的 16-bit 组合

| 项目 | X-S10 | X-T4 |
|---|---|---|
| GUI MovieCodec 缓存 | 0x01B88650 | 0x01AF2DB8 |
| 相邻 GUI MovieFormat 缓存 | 0x01B88651 | 0x01AF2DB9 |
| GUI 读取函数 | FUN_01182820 | FUN_0115663C |
| Codec 设置服务 ID（旧证据） | 0x3FC | 0x3E5 |
| Format 设置服务 ID（旧证据） | 0x3FB | 0x3E4 |

两台固件的 GUI 函数都把相邻 Codec+Format 缓存当作 16-bit 状态，并按同样四种值填充 UI 输出 param_1[0xA1]：

| 16-bit GUI 状态 | UI 索引 |
|---|---:|
| 0x0001 | 0 |
| 0x0000 | 1 |
| 0x0101 | 2 |
| 0x0100 | 3 |

这说明 GUI 确有多个编码/文件格式组合状态，**但 UI 索引不是经确认的 Recorder 内部 codec/profile/bitdepth 枚举**，也不能直接把两个模块各自取值为 1 的字段视作同一全局变量。

## 6. 为什么全面检索偏移 +0x5B0 仍不能当成赋值链

本轮仅扫描原厂 Section1/2 内机器字编码中的 A32 immediate-offset 写入，得到以下**候选数**：

| 原始 Section 类别 | X-S10 STRB/STR 候选 | X-T4 STRB/STR 候选 |
|---|---:|---:|
| Section1 | 7 / 1 | 6 / 1 |
| Section2 | 9 / 11 | 39 / 7 |

固件 Section 中混有真实 ARM 代码与数据，有少量候选并未被 Ghidra 识别为指令。即使确实是 STRB，它们也可能修改 UI 缓存、视频上下文、图像参数或其他结构。**X-T4 候选数量较多并不构成解锁 H.265 Main10 的证据**；没有基本指针类型与来源，不能把 +0x5B0 算成 Recorder Codec。

## 7. 本轮工具与验证

新增原创公开代码：

- tools/audit_movie_context_codec_identity_stage33.py —— 本地离线核验原始 Section1/2、Ghidra C、第32阶段基线。每机审计 **26 个 ROM A32/指针常量字及 2 个 ROM 字符串**，覆盖主/备模板复制、0x25→0x21 条件改写、上下文 Codec 偏移、下游参数映射、MOV/MP4 字符串及 GUI 组合状态。所有尚未证实能力明确为 False/UNKNOWN。
- tests/test_audit_movie_context_codec_identity_stage33.py —— **52 项完全合成的正反 ARM 测试**（无任何富士原厂二进制字节、无相机数据）。

私有研究只留在 Ubuntu 的 output/（被 Git 忽略），包含 xs10/xt4_stage33_gui_readers_decomp.log、xs10/xt4_stage33_all_direct_5b0_sites_decomp.log、xs10/xt4_stage33_movie_context_fields_consumers.log、xs10_stage33_codec_default_validator.log、xt4_stage33_context_copy_sources.log、xs10/xt4_stage33_movie_context_codec_format_refs.log、xs10/xt4_stage33_movie_packet_codec_caller.log、stage33_movie_context_audit_result.jsonlog。

复验命令（在用户授权 Ubuntu 中，需保留私有 ROM 和 Ghidra 日志）：

~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/audit_movie_context_codec_identity_stage33.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

## 8. 下阶段重点

第34阶段应沿录像参数构造的 **output+0x220** 继续下游追踪至编码器/容器驱动，确认 0x10004/0x10005 真正含义；另外继续逆向追究 **GUI MovieCodec → Recorder 当前输入 +0x5B0** 的首次初始化数据生产者，包括动态模式 0x200 记录和设置重建。

相机没有操作；v3.11 的静态地址不能用于实机 v2.10。HEVC Main10 的真实 SPS/bit-depth、4K60 传感器/ISP/VPU/持续写卡链仍未证实。**本阶段的成果是静态配置数据流和字段语义定位，不是可刷 10-bit 或 4K60 解锁。**
