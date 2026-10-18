# 第36阶段：VPU 内部 bit_depth 归一化、帧描述符条件码及消息队列传递（2026-10-18）

> 核心静态实证：在 X-S10 原厂 3.11 和 X-T4 原厂 2.12 中，从第35阶段已确认的 Recorder 活跃 Codec → VPU 初始化枚举，进一步追到了 VPU 初始化参数组装器、归一化后的位深/Codec 字段、被编码和解码设置共用的帧描述符构造器，以及长度 0x48、消息号 0xBB9 的环形消息队列写入。两机原厂 204 字节帧描述符构造函数，共 51 条 ARM，39 条机器码完全相同，余下 12 条差异全部是构造各自 RAM 地址的 MOVW/MOVT 常量。此证据不提供“enum0/enum1 等于真实 8/10bit”映射，不证明 Main10 SPS、运行时成功编码、内部4K60或硬件功能解锁。

## 1. 授权范围、版本和证据类别

仅使用用户授权 Ubuntu /home/zyubuntu/xs10hk 的原厂 X-S10 **3.11**、X-T4 **2.12** 已解压 X6 Section1/2 与既有 Ghidra 12.1.4 只读项目（-process section-1.bin -noanalysis -readOnly）。原厂二进制及Ghidra生成的私有日志只存在被 Git 忽略的 output/。

用户先前报告的实际 X-S10 机身固件为 **2.10**，下文 3.11 原始 ARM 地址绝对不可移植到实机。无相机、无 USB/FF80、无机身 RAM/Flash 读写、无 DAT 编辑、签名绕过、刷机或可刷补丁。

本文的“已确认”专指原厂固件静态指令级数据流、条件或调用关系；不意味着真实机身发生过该次调用、参数在所有录像模式中都不被修改、VPU 固件接受该参数或有最终录像文件。报告仅用于继续离线研究。

## 2. 两机相同的 VPU 参数拷贝和归一化

第35阶段的静态结果：

~~~text
Recorder Active Codec 字节（第32、35阶段）
      ↓
Movie Context +0xADDA
      ↓
VPU Init 参数字段 +0x188（video_codec）
Active Codec == 1 → codec_enum = 0
Active Codec != 1 → codec_enum = 1

两机同一路录像初始化函数：
VPU Init 参数字段 +0x0C（bit_depth 内部枚举）← 常数1
      ↓
驱动 FUN_011F97DC（X-S10）/ FUN_011CCE88（X-T4）
原厂参数验证、拷贝400字节到驱动私有缓存
      ↓
驱动状态事件 == 1 时，执行第36阶段找到的 VPU 初始化参数组装
      ↓
动态 VPU 初始化参数块：
  +0x0C = (codec_enum == 0) ? cached_bit_depth : 1
  +0x190 = cached_video_codec
      ↓
稍后的编码/解码参数设置中，帧描述符依据 参数块 +0x0C 分支
  == 0 → 描述符 ushort +0x18 = 0x201
  != 0 → 描述符 ushort +0x18 = 0x121
      ↓
相关软件环形消息队列通过命令 0xBB9 搬运 0x48 字节描述符
      ↓
【尚无实际 VPU 硬件消费/成功录制/HEVC Main10 码流证据】
~~~

准确性提醒：VPU 初始化参数块通过 RAM **指针槽**间接取得，指针槽不等于实际运行时指向的缓冲区地址。上表展示的是静态程序流程；不同状态事件中的先后与值一致性，需要真实执行证据才可最终确定。

### 关键地址

| 对象 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 驱动缓存初始化结构基址 | 0x01C25970 | 0x01B840D8 |
| 缓存的 bit_depth 枚举（+0x0C） | **0x01C2597C** | **0x01B840E4** |
| 缓存的 video_codec 枚举（+0x188） | **0x01C25AF8** | **0x01B84260** |
| 动态 VPU 初始化参数指针槽 | **0x01C8573C** | **0x01BE5808** |
| VPU 初始化参数组装器 | **FUN_011F8460** | **FUN_011CBB0C** |
| 驱动状态分派函数 | FUN_011F93DC | FUN_011CCA88 |
| 状态1 → 组装器原始 BL | **0x011F944C** | **0x011CCAF8** |
| 初始化参数块清零范围 | **0x298 字节** | **0x298 字节** |

组装器 Ghidra C 明确记录如下语义，两机一致：

~~~c
// cached_bit_depth = 驱动先前按原厂接口复制来的 init +0x0C
// cached_codec = 同一个缓存结构 +0x188

uint32_t eff_depth = cached_bit_depth;
if (cached_codec != 0)
    eff_depth = 1;

vpu_init_block[3] = eff_depth;     // byte +0x0C
vpu_init_block[100] = cached_codec; // byte +0x190
~~~

该函数还清空并初始化 0x298 字节的其他固件、工作缓冲区、码流、帧缓冲区和上下文字段，因此绝不能孤立改写某个比特就预期安全录像。

### 原始 ARM 静态校验

| 行为 | X-S10 A32 地址 | X-T4 A32 地址 |
|---|---|---|
| LDR 缓存 video_codec +0x188 | **0x011F8598** | **0x011CBC44** |
| CMP codec,#0 | 0x011F859C | 0x011CBC48 |
| codec==0: 有条件读取缓存 bit_depth +0x0C | **0x011F85A8** | **0x011CBC54** |
| codec!=0: MOVNE 位深枚举1 | **0x011F85AC** | **0x011CBC58** |
| 写 VPU 初始化参数块 +0x0C | **0x011F85B0** | **0x011CBC5C** |
| 缓存 codec → 参数块 +0x190：LDR | 0x011F87A4 | 0x011CBE50 |
| 缓存 codec → 参数块 +0x190：STR | **0x011F87A8** | **0x011CBE54** |

上述连续7条位深归一化指令中的 **6/7 条机器码完全相同**；第3条只是 MOVWEQ 指向不同机型缓存低半地址（0x5970/0x40D8）。另两条传入 codec 字段的 LDR/STR 机器码也一致。经原厂 Section1 little-endian 读取，不仅依赖反编译的字段名。

## 3. 真正分成 0x201 / 0x121 两种帧描述符

| 对象 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 帧描述符构造器 | **FUN_011FAB58** | **FUN_011CE204** |
| 动态帧描述符指针槽 | 0x01B8809C | 0x01AF2804 |
| 写入前的清零大小 | 0x48 = 72 字节 | 同左 |
| 上游分支依据 | VPU 参数块[3]（+0x0C）的32bit枚举值 | 同左 |
| enum==0 描述符 ushort[+0x18] | **0x201** | **0x201** |
| enum!=0 描述符 ushort[+0x18] | **0x121** | **0x121** |

具体 C 字段流：

~~~c
if (vpu_init_block[3] == 0) {
    *(uint16_t *)(frame_desc + 0x18) = 0x201;
    *(uint32_t *)(frame_desc + 0x34) = vpu_init_block[2];
    *(uint32_t *)(frame_desc + 0x38) = vpu_init_block[2];
} else {
    *(uint16_t *)(frame_desc + 0x18) = 0x121;
    *(uint32_t *)(frame_desc + 0x34) = vpu_init_block[2] << 2;
}
~~~

上面是**两种不同的帧缓冲描述符布局/步幅计算方式**，但 0x201/0x121 是驱动内部字段值，不能单凭整数给出公开像素格式名称（NV12/P010 等），更不能断言它们分别对应物理8/10bit。

主要 ARM 观察点：

| 条件/动作 | X-S10 | X-T4 |
|---|---|---|
| 取 init block +0x0C | 0x011FAB84 | 0x011CE230 |
| CMP,#0 | 0x011FAB88 | 0x011CE234 |
| BNE → enum非零分支 | **0x011FAB8C → 0x011FABF0** | **0x011CE238 → 0x011CE29C** |
| MOVW code0=0x201 | **0x011FAB9C** | **0x011CE248** |
| STRH 到 frame+0x18 | 0x011FABA0 | 0x011CE24C |
| MOVW code非零=0x121 | **0x011FABFC** | **0x011CE2A8** |
| STRH 到 frame+0x18 | 0x011FAC00 | 0x011CE2AC |
| 非零分支：stride <<2 | **0x011FAC18** | **0x011CE2C4** |
| 非零分支：STR frame+0x34 | 0x011FAC1C | 0x011CE2C8 |

已独立验证原厂 BNE 跳转符号位移、MOVW立即数、STRH 目标偏移以及每个分支的 LDR/STR/移位机器字。

### 强对照：完整204字节函数指令指纹

分别比较 X-S10 FUN_011FAB58、X-T4 FUN_011CE204 的整个 204B / 51条 ARM 指令：

- **39条完全相同的32-bit机器码**。
- **12条不同**：函数相对偏移 +0x08、+0x0C、+0x20、+0x24、+0x38、+0x3C、+0x6C、+0x70、+0x78、+0x7C、+0x98、+0x9C。
- 这12条**全部**通过额外原始 ARM 解码，证明是由6组 MOVW/MOVT 构造两机不同的参数块指针槽、帧描述符指针槽的地址常量；不是 codec 条件、format 数值、移位计算或调用语义变化。
- 因此，可严谨称**两机此函数的非地址操作完全同构**。不能推广到独立VPU微码/驱动运行时状态、机型能力和 Main10输出。

## 4. 通过编码/解码设置复用，并交给 0xBB9 软件消息队列

| 对象 | X-S10 | X-T4 |
|---|---|---|
| 编码参数设置内部函数 | FUN_011F8914 | FUN_011CBFC0 |
| 编码参数函数 → 帧描述符构造 BL | **0x011F898C** | **0x011CC038** |
| 解码参数设置内部函数 | FUN_011F89F0 | FUN_011CC09C |
| 解码参数函数 → 帧描述符构造 BL | **0x011F8A50** | **0x011CC0FC** |
| 使用同一帧描述符指针的传输构造函数 | FUN_011FAC24 | FUN_011CE2D0 |
| 编码侧消息队列函数 | FUN_011FA714 | FUN_011CDDC0 |
| 解码侧消息队列函数 | FUN_011FA844 | FUN_011CDEF0 |
| 软件消息编号及拷贝大小 | **0xBB9 / 0x48** | **0xBB9 / 0x48** |

静态链显示，驱动事件状态等于2时执行编码参数设置函数，等于3时执行解码参数设置函数；对应的设置函数分别调用相同的帧描述符构造函数。后续帧缓冲消息函数则使用 **同一个动态帧描述符对象**及编号0xBB9，通过不同方向的队列函数发送0x48字节的数据。两个独立软件发送函数依赖环形数据结构，使用按0x3FC取模的索引和参数字拷贝。

原厂ARM核验点：编码/解码两处构造器BL、状态1构造器BL、两个0xBB9队列发送函数BL，各自两机均核对原始签名和目标地址。

**边界**：证明的是向软件消息队列写入指定载荷的代码路径，不代表真实外设读取到它、更不代表写出的比特流是Main10或10-bit。这套驱动同时包含解码路径，内部“H265”错误字符串不意味这两组值专属于HEVC Main10编码模式。

## 5. 一个重要的、带明确前提的静态不变量

将第35阶段已经找到的录像初始化赋值，代入本阶段数据流：

~~~text
第35阶段录像参数构造路径：bit_depth 内部枚举 = 1

Active Codec == 1 → VPU codec enum 0 → 归一化后depth=1 → descriptor=0x121
Active Codec != 1 → VPU codec enum 1 → 强制depth=1    → descriptor=0x121

驱动确实存在 depth==0 → descriptor=0x201 的代码，
但仅靠上述原厂录像初始化赋值，不会将depth设为0。
~~~

这不是对所有实机模式的可达性/不可达性证明：上述三个阶段在不同状态事件和可能的跨模块条件下执行；存在其它调用者、间接写入者、DMA或固件事件后处理的可能。严格结论应为：**在使用已定位的录像参数构造路径、没有中途覆写的条件下，两机都将选择depth=1及descriptor=0x121。**

**关键警示：无法根据此推断 X-T4 的已知10-bit能力是通过哪一个ROM层级实现，更无法判断 X-S10 是否具备同等硬件能力。** 若 X-T4 的实际 Main10 沿另一模式/像素格式/码流层或另一个微码路径启用，这份共同的控制分支本身不能揭示它。

## 6. 未知、否定与下阶段精确任务

目前仍没有：

1. **bit_depth enum 0/1 → 真实8/10-bit及对应像素格式**的可信原厂映射；
2. frame descriptor 的 **0x201/0x121 → 公共像素格式/FourCC/Profile** 的可信映射；
3. VPU微码端解读 +0x0C / +0x190 和接收0xBB9消息的完整证据；没有 HEVC Main10 SPS（SPS bit_depth_luma_minus8/chroma）或真实10-bit录像文件；
4. GUI MovieCodec 设置地址 → Recorder 最初输入缓冲区 +0x5B0 Codec 字节的首次赋值者；
5. 机身 X-S10 的内部4K60 sensor/ISP/VPU/连续写卡能力及安全固件改写机制。

因此下一阶段应优先：

- 沿 **0xBB9消息的消费者、帧描述符里的0x201/0x121值以及VPU init块[3]** 寻找独立的像素格式语义，同时不向相机发送任何消息；
- 检查是否存在正常/其它录像构造路径会向 bit_depth +0x0C 写除1之外的值；无需修改二进制；
- 与 XT4 录像模式上下文和可能的 VPU微码版本比较，识别已证实的X-T4 Main10专属条件（不是把两机相同机器码误判成支持能力）；
- 继续上游 GUI → Recorder输入 +0x5B0 初值赋值追踪；4K60单独开展。

## 7. 原创审计脚本、纯合成测试、私有日志隔离

新增可公开的原创文件：

- tools/audit_vpu_bitdepth_packet_stage36.py：仅本机离线读取原厂 Section1/Ghidra日志及第35阶段审计基线，逐条检查缓存字段、状态分派、VPU参数块 +0x0C/+0x190、真实 A32 MOVWEQ/LDREQ/MOVNE/STR、帧描述符分支、frame+0x18值、stride转换、BL/环形消息调用，并对 **整个204B函数**作机器码指纹校验。所有 Main10/4K60/实体设备状态仍明确为 UNKNOWN/False。
- tests/test_audit_vpu_bitdepth_packet_stage36.py：**104项完全合成的正反测试**，覆盖 ARM 直接/条件BL、分支位移、指针字段错位、描述符常数、stride、状态事件错误、消息号/拷贝长度、完整函数指纹及错误硬件映射声明；不含用户机身数据、厂商ROM或Flash内容。
- docs/phase36-vpu-bitdepth-frame-packet-2026-10-18.md：本报告。

下列私有日志都只保存在 Git 忽略的 output/，未上传：

- xs10/xt4_stage36_vpu_init_fields_xrefs.log
- xs10/xt4_stage36_vpu_field_consumers_trace.log
- xs10/xt4_stage36_vpu_event_init_and_packet_transport.log
- xs10/xt4_stage36_vpu_bitdepth_packet_consumers.log
- xs10/xt4_stage36_frame_packet_bitdepth_branch.log
- xs10/xt4_stage36_vpu_frame_desc_send_callsite.log
- xs10/xt4_stage36_frame_descriptor_transport_refs.log
- stage36_vpu_bitdepth_packet_audit.jsonlog
- 私有Ghidra帮助脚本 AuditVpuBitdepthPacketReaders.java

在用户Ubuntu本机复验，需原厂ROM/私有Ghidra日志：

~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/audit_vpu_bitdepth_packet_stage36.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

**已实际通过：** Phase26—Phase36 全部双机原厂ROM离线审计；Stage36新增 **104项合成测试**；仓库追踪 tests/ 91项 + Git忽略 output/ 累计859项 = **950项离线测试通过**。独立复制成 public-only 工具与测试布局后，104项单测仍全部通过。之前的FF80测试只打印“USB service not detected, No command sent”，没有设备通讯。

**本阶段结论：定位了 bit_depth 有条件归一化、两种帧缓冲描述符和软件传输边界；没有发现 X-S10 特有的此段驱动限制，也没有解锁10-bit或4K60。**
