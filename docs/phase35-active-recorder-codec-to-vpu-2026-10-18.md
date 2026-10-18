# 第35阶段：Recorder 活跃 Codec → H.265/VPU 初始化参数的正向赋值链（2026-10-18）

> **重大静态数据流突破**：X-S10 原厂 3.11 与 X-T4 原厂 2.12，均已确认 Recorder 活跃 Codec 字节 → Movie Context +0xADDA → VPU/H.265 初始化参数 +0x188（原厂错误提示名为 video_codec）的真实 ARM + Ghidra 调用路径。录像程序向同一初始化结构 +0x0C（原厂称 bit_depth）写入内部枚举 1，之后通过直接 BL 进入 VPU 驱动初始化与编码参数设置包装器。两机有 7 条连续**逐字一致**的驱动 Codec/Bitdepth 验证 A32 指令。本发现说明软件端存在直接的 VPU 参数选择通道，但**枚举1的真实物理位深、运行中执行成功、Main10 SPS/10-bit 内录、4K60 内录仍完全未证明**。GUI Codec → Recorder 原始输入 +0x5B0 的首次赋值者依然未知。

## 一、安全范围和版本

- 只在用户授权的 Ubuntu /home/zyubuntu/xs10hk 上，对已存在的 X-S10 **3.11**、X-T4 **2.12** 原厂 Section1/2 和 Ghidra 12.1.4 只读项目进行离线核验（-noanalysis -readOnly）。
- 用户此前报告的 X-S10 **实机是2.10**；本文针对3.11的代码绝对地址、行为或补丁**不可直接用于实机**。
- **没有** USB/FF80、接入相机、运行态机身 RAM/Flash 读写、修改 DAT、刷机/绕签名、创建可刷固件。本地原厂 ROM、Ghidra 日志和数据库只保存在被 Git 忽略的 output/，GitHub 只接收原创分析工具、合成单测、解释报告。

## 二、从 Recorder 输入到两个视频分支

~~~text
                  第32阶段已确认的静态数据流
Recorder 当前输入 [P+0x5B0] → Recorder 活跃 Codec
 XS10  0x01C25208  = 0x01C24DD8 +0x430
 XT4   0x01B83974  = 0x01B83540 +0x434
                               |
                     ┌─────────┴───────────┐
                     |                     |
             第33/34阶段已有         第35阶段新增
                     |                     |
   活跃模板复制到 context+0x5A8    GetActiveCodec()从活跃全局读字节
                     |                     |
         context+0x9D8/0x9DC      context+0xADDA
                     |                     |
   数值选择 0x10004/0x10005   VPU 初始化 video_codec enum
                     |               ActiveByte==1 → 0
       注册 main+0x37F8            其他值 → 1
       到 backend+0x3D00                 |
                              VPU Init参数结构+0x188
                                        |
                              驱动接口读取和合法性检查
                              （非实机成功录像证明）
~~~

上下文 +0x9D8/+0x9DC 和 +0xADDA 是**两个不同的字节字段**；它们各自的静态生产者指向同一活跃 Codec，但不能证明运行时始终相等，更不能把 0x10004/5 的意义从枚举0/1推出。

## 三、活跃 Codec getter + context STRB，原厂机器字和函数链

| 项目 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 活跃 Codec 全局字节 | **0x01C25208** | **0x01B83974** |
| Getter | **FUN_012C048C** | **FUN_01298C18** |
| Getter 的字节 LDRB | 0x012C049C；基址0x01C24DD8 +0x430 | 0x01298C28；基址0x01B83540 +0x434 |
| Movie Context 构造器 | **FUN_022D5FEC** | **FUN_022425BC** |
| 先复制活跃模板到上下文 | 0x022D61AC→FUN_012BD150 | 0x0224277C→FUN_012957C0 |
| 随后调用 Getter | **0x022D62A4** | **0x02242874** |
| 将 R0 写入 Context+0xADDA | **STRB at 0x022D62A8** | **STRB at 0x02242878** |

关键 STRB 的原厂地址形成：ADD R5,R4,#0xA000；STRB R0,[R5,#0xDDA]，实际目标为 context +0xADDA。两个 Getter 使用 MOVW/MOVT 构造活跃模板基址，再以 LDRB 读取 Codec 字节。Ghidra C 还证明模板复制在 Getter/STRB **之前**。

上面提供的是正向的**静态代码路径**，中间仍可能存在其他调用、模式修改；实际相机未执行此实验。

## 四、录像初始化直接转换为 VPU 参数字段

| 参数/函数 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 录像 VPU Setup 父函数 | **FUN_022DEE64** | **FUN_0224B65C** |
| 传给驱动的 init 结构基址 | **0x02945A08** | **0x028A5150** |
| bit_depth 的结构偏移 | +0x0C | +0x0C |
| 此阶段查到的 bit_depth enum | **1** | **1** |
| video_codec 的结构偏移 | +0x188 | +0x188 |
| Active Codec byte==1 时 | **video_codec enum 0** | **enum 0** |
| Active Codec byte !=1 时 | **video_codec enum 1** | **enum 1** |
| 初始化结构包含配置复制长度 | 400字节 | 400字节 |

两机伪代码（bit_depth 数字语义未知）：

~~~c
params.bit_depth_enum = 1;
params.video_codec_enum = (ctx[0xADDA] == 1) ? 0 : 1;
init_vpu_driver(/* mode */0, &params, init_callback);
~~~

具体 A32 地址：

| 事件 | X-S10 | X-T4 |
|---|---|---|
| bit_depth字段写常数1 | **0x022DEF50** | **0x0224B748** |
| 读取 ctx+0xADDA | **0x022DEF58** | **0x0224B750** |
| CMP #1 | 0x022DEF5C | 0x0224B754 |
| BEQ 到 enum0 分支 | 0x022DEF60 → 0x022DF154 | 0x0224B758 → 0x0224B94C |
| !=1: video_codec ← 1 | **0x022DEF70** | **0x0224B768** |
| ==1: video_codec ← 0 | **0x022DF160** | **0x0224B958** |

原厂 ROM 的 MOVW/MOVT 及分支 signed offset 均独立解码核验；并验证 Ghidra C 的生产者、调用先后、参数身份与地址。

## 五、真正调用到 VPU 驱动，而非只提交参数指针

| 调用边 / 原厂 BL | X-S10 | X-T4 |
|---|---|---|
| Movie Setup → VPU Init API wrapper | **0x022DF0F8 → FUN_011F7190** | **0x0224B8F0 → FUN_011CA83C** |
| VPU Init wrapper → driver | **0x011F7330 → FUN_011F97DC** | **0x011CA9DC → FUN_011CCE88** |
| Movie Setup → 编码参数 wrapper | **0x022DF508 → FUN_011F745C** | **0x0224BC90 → FUN_011CAB08** |
| 编码参数 wrapper → driver | **0x011F7464 → FUN_011F9B84** | **0x011CAB10 → FUN_011CD230** |

以上四组边（每机4处）与两个 Movie Context Getter/copy BL（每机另2处）均有真实 ROM 指令目标校验，并在反编译调用者/原厂引用中得到交叉验证。

Init driver 验证输入结构中的 bit_depth/video_codec、固件/参考帧/工作缓冲区地址与长度、回调及队列状态等，再通过封装复制函数将400字节 init 参数拷贝到自身配置存储。Set Encoder Param driver 对15个 uint32 参数字保存到私有RAM后触发自身事件。因此确实存在 H.265 驱动 API 路径，**但没有获得设备固件执行、编码成功或Main10的运行时证明**。

## 六、7条完全同构的原厂位深/Codec验证指令

| 机器字及语义 | X-S10 0x011F97FC起 | X-T4 0x011CCEA8起 |
|---|---|---|
| LDR [init,#0x188]，video_codec enum | 0xE5913188 | 同一机器字 |
| CMP video_codec, #0 | 0xE3530000 | 同一机器字 |
| BNE 跳过相应位深检查 | 0x1A000002 | 同一机器字 |
| LDR [init,#0x0C]，bit_depth enum | 0xE591200C | 同一机器字 |
| CMP bit_depth, #1 | 0xE3520001 | 同一机器字 |
| BHI 跳转 bit_depth error | 0x8A000067 | 同一机器字 |
| LDRD 继续检查初始化地址 | 0xE1C141D0 | 同一机器字 |

原厂 Section1 字符串来源独立校验：
- X-S10: #init bit_depth ERROR @ 0x015B62A8；#init video_codec ERROR @ 0x015B6478；
- X-T4: #init bit_depth ERROR @ 0x0158DB68；#init video_codec ERROR @ 0x0158DD38。

Ghidra C 展示的检查逻辑：

~~~c
if (init.video_codec_enum == 0 && init.bit_depth_enum > 1)
    report_bit_depth_error_and_return();
if (init.video_codec_enum > 1)
    report_video_codec_error_and_return();
~~~

**不应倒推：内部 bit_depth 枚举1 == 10-bit。** 验证的是条件门控、合法值范围和赋值方向；缺少内部像素格式映射、VPU encoder profile/hvcC 或 bitstream SPS 证据。驱动名含 h265 也不能推断该机型运行时可内录 Main10。

## 七、保留的重要未解环节

1. **GUI MovieCodec 设置服务 → Recorder 输入大结构 +0x5B0 的初始赋值者未找到**。先前已验证输入→活跃，但源头仍缺。
2. 本阶段确认编码器控制参数结构的内部字段与调用，不等于真实机身上的驱动返回成功、HEVC Main10 bitstream或10-bit像素数据被VPU接受。
3. 驱动 video_codec enum 0/1 与 H.264/H.265 的确切标准映射尚未独立核实；不能凭相似值混用不同结构。
4. 第34阶段 backend +0x3D00 以指针引用的 0x10004/5 结构属于**另一条并行控制通道**，尚未与真实VPU硬件API消费字段建立等价关系。
5. **4K60** 的 sensor读出、ISP、VPU、存储带宽均未测得。
6. X-S10原厂3.11地址与此前实际相机2.10的内存布局不可安全互换。

## 八、本阶段原创工具、合成测试与隔离

- tools/audit_recorder_codec_to_vpu_stage35.py：读取原厂Section1/2与本地Ghidra日志、第32/33/34阶段审计结果，检查两个模型的 Getter、Context STRB、VPU初始化 +0x0C/+0x188赋值、4条驱动BL边、另外2条构造器BL、7条驱动A32 gate以及原始字符串、400字节init拷贝、15字编码参数拷贝。未知物理位深和编码功能均在输出标注为 UNKNOWN/False。
- tests/test_audit_recorder_codec_to_vpu_stage35.py：**81项原创纯合成正反 ARM 测试**，覆盖错误字段、源/目的地址、指令、条件分支、调用目标与反编译语义，原厂数据和相机数据未包含。
- docs/phase35-active-recorder-codec-to-vpu-2026-10-18.md：本报告。

原厂私有二进制与Ghidra日志只在 Ubuntu 的 output/，特别是 xs10/xt4_stage35_video_codec_context_writer.log、stage35_h265_vpu_init_decomp.log、stage35_h265_vpu_parent_callers.log、stage35_context_codec_getter.log、stage35_h265_api_wrapper.log，以及 stage35_codec_to_vpu_audit_result.jsonlog。

复验（需要本机私有原厂 sections / Ghidra 日志）：

~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/audit_recorder_codec_to_vpu_stage35.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

实测 **第26—35阶段所有原厂双机ROM审计通过**；第35阶段新81项合成测试通过；仓库追踪 91 项 + 本地忽略研究测试755项，累计**846项离线测试通过**。这仅是对审计的准确性验证，**不是相机功能解锁或拍摄性能测试**。

## 九、第36阶段研究优先级

先确定实际 VPU 初始化 bit_depth enum 0/1/2 对像素位深的真正对应关系与行为（必要时从驱动消费者和编码 SPS 结构定位，不改 ROM）；其次继续追真实 H.265 Encoder param 15字段和 VPU事件发送的数据布局，再对照 X-T4。与此同时返回 GUI服务/模式记录追 Recorder 当前输入 +0x5B0 的真正写入者。4K60传感器/ISP/VPU仍须独立实证。

**结论：已静态证明 Recorder活跃Codec → H.265/VPU init枚举与真实API调用链；Main10/10-bit和4K60没有实机或码流证明，仍未解锁。**
