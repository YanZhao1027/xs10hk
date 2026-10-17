# 第32阶段：Recorder 输入 Codec → 活跃 Codec 的正向静态赋值链（2026-10-18）

> **阶段重大结果**：基于 Ubuntu 本地 X-S10 原厂 3.11 与 X-T4 原厂 2.12，已找到并逐跳核对“当前配置缓冲区 +0x5B0/+0x5B1 → 固定中间配置 → Recorder 活跃 Codec/Format”的原厂 ARM 数据流。中间模板复制目标的字节地址与第30/31阶段独立确定的活跃 Codec/Format 全局字节**完全重合**。但是：仍不知道 GUI MovieCodec 如何填充当前输入缓冲区最初的 +0x5B0；没有恢复实时值、外部复制引擎代码或 Main10/4K60 的实际录制能力。

全部操作只针对用户授权 Ubuntu 已有原厂 X6 Section1/2 和 Ghidra 12.1.4 只读项目。此前用户报告的真实 X-S10 是 2.10；本阶段研究的 X-S10 是 3.11。没有 USB/FF80 相机命令、机身 RAM/Flash、修改 DAT、可刷补丁。原厂固件和反编译日志仅留本地被 Git 忽略的 output/。

## 一、真正的 Codec 输入→活跃数据边

X-S10 3.11：

~~~text
当前描述符 0x02D987E8
  [+0x10] 即 0x02D987F8 = 运行时配置缓冲区指针 P
        |
        v
[P +0x5B0] Codec / [P +0x5B1] Format
        |   FUN_012C9500：原始 ARM LDRB / STRB
        v
固定中间结构 0x02D9CC60
  [+0x430] = 0x02D9D090 Codec
  [+0x431] = 0x02D9D091 Format
        |   FUN_02214738 后续调用 FUN_012C1CE8
        |   后者传中间结构首地址给 FUN_012BD110
        |   复制 0x478 字节到活跃模板 0x01C24DD8
        v
Recorder 活跃模板 0x01C24DD8
  [+0x430] = 0x01C25208 Codec
  [+0x431] = 0x01C25209 Format
        |
        |   第30/31阶段另有向外序列化
        v
独立导出指针指向的 +0x5B0 / +0x5B1
~~~

X-T4 的对应实现：

| 数据源/功能 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 主指针描述符字段 | 0x02D987F8 | 0x02D0BF58 |
| 初始化配置处理函数 | FUN_02214738 | FUN_02180D0C |
| 字段重排函数 | FUN_012C9500 | FUN_012A313C |
| 原厂 PC 常量中间结构基址 | 0x02D9CC60 | 0x02D103B0 |
| 中间 Codec 字节 | **0x02D9D090** | **0x02D107E4** |
| 中间 Format 字节 | 0x02D9D091 | 0x02D107E5 |
| 中间偏移 | 0x430 / 0x431 | 0x434 / 0x435 |
| 配置后续更新函数 | FUN_012C1CE8 | FUN_0129A4D0 |
| 复制包装函数 | FUN_012BD110 | FUN_01295780 |
| 复制目标活跃模板基址 | 0x01C24DD8 | 0x01B83540 |
| 原厂复制长度 | **0x478** | **0x47C** |
| 活跃 Codec/Format | **0x01C25208 / 0x01C25209** | **0x01B83974 / 0x01B83975** |

身份恒等式直接成立：

~~~text
X-S10: 0x01C24DD8 + 0x430 = 0x01C25208
X-T4 : 0x01B83540 + 0x434 = 0x01B83974
~~~

## 二、8条原始 Codec/Format ARM 字节传递证据

| 数据边 | X-S10 A32 地址与指令 | X-T4 A32 地址与指令 |
|---|---|---|
| 读取输入 Codec | 0x012C9A40 LDRB R3,[R5,#0x5B0] | 0x012A3690 LDRB R3,[R5,#0x5B0] |
| 写中间 Codec | **0x012C9A44 STRB R3,[R4,#0x430]** | **0x012A3694 STRB R3,[R4,#0x434]** |
| 读取输入 Format | 0x012C9A48 LDRB R3,[R5,#0x5B1] | 0x012A3698 LDRB R3,[R5,#0x5B1] |
| 写中间 Format | 0x012C9A4C STRB R3,[R4,#0x431] | 0x012A369C STRB R3,[R4,#0x435] |

Ghidra 对应反编译明确显示：

~~~c
// X-S10
*(uint8_t *)(param_1 + 0x430) = param_2[0x5B0];
*(uint8_t *)(param_1 + 0x431) = param_2[0x5B1];

// X-T4
*(uint8_t *)(param_1 + 0x434) = param_2[0x5B0];
*(uint8_t *)(param_1 + 0x435) = param_2[0x5B1];
~~~

中间结构基址来自原始 Section2 literal 而不是猜测：X-S10 原厂 0x02214CA4 的32位常量是 0x02D9CC60；X-T4 原厂 0x02181278 常量是 0x02D103B0。

## 三、跨函数正向代码路径：实际 BL 与模板复制

同一个配置初始化器先读取当前描述符 +0x10 所保存的动态指针，再以该指针为源执行字段重排。后续（经过其他函数）将同一个固定中间结构首地址传给模板更新器。

| 静态 BL 边 | X-S10 | X-T4 |
|---|---|---|
| 初始化器 → 字段重排 | 0x022147AC → FUN_012C9500 | 0x02180D80 → FUN_012A313C |
| 初始化器 → 模板更新器 | 0x022148C8 → FUN_012C1CE8 | 0x02180EA8 → FUN_0129A4D0 |
| 模板更新器 → 块复制包装器 | 0x012C1D28 → FUN_012BD110 | 0x0129A510 → FUN_01295780 |
| 包装器 → 复制引擎 | 0x012BD138 → 0x00059328 | 0x012957A8 → 0x00059108 |

复制包装器原始 A32 MOVW/MOVT 设置目标模板基址、MOVW 设置复制长度、R0=目标/R1=固定中间源/R2=长度，并执行 BL。还有第二次以目标+0x6C0 为目的地的同长度复制。该范围包含 +0x430/+0x431 或 +0x434/+0x435 Codec/Format 字节。

**重要限制**：外部复制引擎 0x00059328 / 0x00059108 不在本次已加载的 X6 二进制映像中，尚未独立反编译其实现；已直接核验的是原厂参数传递、BL 目标、调用者 Ghidra C 的复制语义以及各字段地址算术。完整运行态执行和间隔中修改同一个中间字段的可能性尚未排除，不应声称已采集相机的 Codec 值。

此前活跃 Codec 地址的直接 Ghidra xref 分别只有2个 READ、0个直接 WRITE；**此次证明为什么直接 WRITE 为0不能排除存在赋值**：某个字段可以先写到别的结构，再经整块复制传入活跃配置。

## 四、额外确认：描述符初始化时的 0x44 字节长度

| 原厂初始化项 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 函数 | FUN_021B8344 | FUN_02120C20 |
| 描述符头基址 | 0x02D987E8 | 0x02D0BF48 |
| 原始6个指令字地址 | 0x021B84C0–D4 | 0x02120D9C–B0 |
| 描述符+0x04长度写入 | **0x44** | **0x44** |
| 描述符+0x08载荷地址 | 指向描述符自身+0x0C | 同左 |

在这条初始化路径中，头长度足以完整包含描述符+0x10的四字节主缓冲区指针。但是随后选中的模式记录可能重新覆盖长度：**不能把此初始化长度默认判成所有0x206/0x207记录的运行时长度**。

必须区分三个不同概念：描述符+0x08是载荷地址；描述符+0x10是主输入缓冲区的**指针值字段**；只有指针指向的另一块运行时数据结构才有+0x5B0 Codec字段。

## 五、外部来源候选与尚未得到的证明

另追到 FUN_012BD150（X-S10）/ FUN_012957C0（X-T4）将 Codec 模板数据复制到**其他**大型录像结构 +0x5B0，并在源为0x25时把目的字节规范化成0x21。这些是确实存在的写入，但相关调用者的缓冲区身份尚未证明与本阶段的主输入指针相同，不能凭偏移相同就当作 GUI 的初始赋值者。

真正仍然缺失：

- X-S10 GUI MovieCodec 设置服务 ID 0x3FC → GUI 缓存 0x01B88650：此前已确认。但 **GUI 缓存或同源设置服务 → 主配置输入缓冲区 +0x5B0 的首次/模式切换生产者仍未知**。
- 真实运行时主缓冲区的四字节指针数值与内容；复制引擎具体实现；间隔内的别名或动态修改。
- 原厂内录 HEVC Main10 profile/bit depth、4K60 传感器/ISP/VPU/写卡链路的真正启用能力。GUI枚举0/1和Recorder内部可能的0x21/0x22等值绝不可混同。
- 此次 X-S10 3.11 的代码地址绝不能应用于先前报告的实机2.10。

## 六、工具、自动化测试、可复验数据隔离

新增原创公开文件：

- tools/audit_recorder_codec_forward_stage32.py：只读取私有Section1/2及Ghidra日志，逐机交叉核验**6条描述符初始化、4条字段字节加载/存储、11条模板复制与4条BL，共每机25处原厂ARM位置**（两机共50处），包括 ROM 中间结构常量、参数身份、调用次序、复制区域覆盖与活跃全局地址恒等式。所有未验证解锁状态明确为False。
- tests/test_audit_recorder_codec_forward_stage32.py：**60项完全合成的 ARM 正/反单元测试通过**，涵盖错误方向、地址、指令、调用目标、长度、模板区间、编码字段混淆与不当运行态断言。没有厂商固件字节。

仅保存于 Ubuntu 被Git忽略的 output/：各机 stage32_descriptor_header_len_writer、stage32_current_to_active_parent、stage32_current_to_template_adapter、stage32_template_update_callers、stage32_template_copy_init、stage32_bridge_field_xrefs、stage32_forward_bridge_bl_refs 等私有日志，以及 stage32_codec_forward_audit_result.jsonlog。

复验（须在已有私有原厂镜像/日志的用户机器）：

~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/audit_recorder_codec_forward_stage32.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

下一步应专注于**最初谁写 Recorder 输入 +0x5B0**。在未取得完整 HEVC Main10 和4K60编码器证据、签名与救砖路径之前，不能生成可刷写补丁或宣布解锁。本阶段没有修改任何相机或原厂固件。
