# 第38阶段：VPU软件队列TX → 固定控制区写入，排除Section3假阳性（2026-10-18）

**突破摘要。** 原厂 X-S10 3.11与X-T4 2.12的Section1 ARM+Ghidra均已验证：软件H.265队列TX函数先组装/更新消息数据，然后执行将整数1写到 base + channel × 0x40 + 0x220 的32位寄存器样地址的代码。ROM中的base初始化为0xFFE00000。其邻近+0x20C、+0x218、+0x214被H.265 MapSession与其它会话管理路径读写，具有等待/超时控制流。这是Stage37软件环形队列之后实质性的原始代码证据，但没有官方硬件寄存器定义或另一核成功接收证据，不可认定它必然是VPU门铃，也不能证明Main10/10bit或4K60已解锁。

**误线索纠正。** X-T4第三解压段的两个MOVW低16位为0x0BB9，实际上和MOVT #0xFF00组成0xFF000BB9，传给不同的应用事件/显示例程，并非Stage37已找到的32位消息命令0x00000BB9。X-S10相应代码使用完整常量0xFF000C91。仅凭低16位搜索会造成假阳性。

## 0. 严格安全与版本

仅研究授权Ubuntu /home/zyubuntu/xs10hk 上已有的X-S10原厂3.11、X-T4原厂2.12 X6 Section1/2/3；X-T3仅用于相同HEVC模块字节对照。实际机身X-S10此前报告是2.10，不得将3.11 ROM地址直接应用于实际设备。Ghidra 12.1.4使用本地只读、临时Section3私有映像项目；从未接触相机、USB/FF80、机身RAM/Flash、DAT编辑、补丁制作、绕过签名、刷写或可刷固件。全部原厂ROM/Ghidra数据库及日志仅在git忽略的output/。本文的证明仅指静态ARM与反编译数据流，不指实际机身执行/编码成功/真实HEVC SPS。

## 1. 贯通Stage35—38的静态数据流边界

~~~text
Recorder Codec输入，最初GUI +0x5B0写入者未知
    → Recorder Active Codec byte
      X-S10 0x01C25208，X-T4 0x01B83974
    → MovieContext+0xADDA
    → VPU init video_codec+0x188
      Movie Setup将内部bit_depth enum=1写到init+0x0C
    → H.265/VPU初始化接口、400B缓存配置
    → 0x298字节VPU初始化包
      +0x0C条件归一化depth，+0x190记录codec
    → 72B帧描述符
      effective_depth==0: descriptor+0x18=0x201
      effective_depth!=0: descriptor+0x18=0x121
    → 软件TX环形队列，命令0x0BB9、payload 0x48字节
      队列数据W+0x92010或W+0x94010，消息头(len<<16)|cmd
    → 更新队列索引
    → 【Stage38新证据】CPU代码写1：
      *(u32*)(0xFFE00000 + runtime_channel*0x40 + 0x220)
    → 【尚无硬件实证】寄存器的官方功能、另一核的
       TX队列消费者、Main10 SPS或真实10bit录像
~~~

runtime_channel是由ROM全局指针槽再指向运行态RAM标量，值未知。静态公式成立不代表机身真实选用哪个channel。

## 2. 两个发送函数的ARM地址、控制指针赋值

| 证据 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 控制区域base的全局指针槽 | 0x01B4A12C | 0x01AB212C |
| base初始化值 | **0xFFE00000** | **0xFFE00000** |
| channel标量指针的全局槽 | 0x01C09B68 | 0x01B682A8 |
| channel标量RAM地址 | 0x01C8B7B0 | 0x01BEB868 |
| 第一组TX发送函数 | FUN_011FA714 | FUN_011CDDC0 |
| 第二组TX发送函数 | FUN_011FA844 | FUN_011CDEF0 |
| 第一组最终STR写1位置 | **0x011FA77C** | **0x011CDE28** |
| 第二组最终STR写1位置 | **0x011FA8AC** | **0x011CDF58** |

每个发送函数有十个连续真实A32字经过独立检查，包含：
- MOVW/MOVT生成控制base的全局槽，LDR取得初始化值；
- MOVW/MOVT生成channel标量指针全局槽，两个LDR分别读取指针和值；
- ADD R3,R3,R2,LSL #6，等效+channel×0x40；
- MOV R1,#1；STR R1,[R3,#0x220]。

第一发送者的关键点，X-S10 0x011FA758起、X-T4 0x011CDE04起。第二发送者的完整连续片段，X-S10 0x011FA888—0x011FA8AC、X-T4 0x011CDF34—0x011CDF58。两机的ADD、MOV和STR机器字在相应位置完全一致，绝非按字符串猜测。

初始化追溯：
- XS10 FUN_011FC4E8：原始STR@0x011FC500将selector全局指针槽初始化指向0x01C8B7B0，STR@0x011FC514将控制基址初始化为0xFFE00000。另一初始化路径 FUN_011F95D4 也在0x011F95F0重写base。
- XT4 FUN_011CFB94：STR@0x011CFBAC登记selector指针0x01BEB868，STR@0x011CFBC0写base。另一 FUN_011CCC80 在0x011CCC9C重复写base。
- 原厂ROM原始MOVW/MOVT、MOV R2,#0及MOVT R2,#0xFFE0、STR机器字独立核验，全部直接写入Ghidra xref也再次对上。每机控制base指针槽62个直接refs其中2处WRITE；selector指针槽64个refs其中1处WRITE；VPU动态包指针槽55 refs其中1处WRITE。不能由直接xref数量排除间接/别名/另一处理器操作。

**严格边界：** 目前只有原始CPU代码对该地址的写入计算及写入指令，没有得到实际芯片寄存器手册、VPU固件另一侧的响应或执行追踪。0xFFE00220+channel×0x40应称作设备寄存器通知候选。

## 3. 同一区域的MapSession/UnmapSession可读写与有限轮询

| 软件函数 | X-S10 | X-T4 |
|---|---|---|
| h265_MapSession | FUN_011FC820 | FUN_011CFECC |
| 检查+0x20C的Unmap/等待 | FUN_011FC958 | FUN_011D0004 |
| 另一Unmap/等待路径 | FUN_011FCA3C | FUN_011D00E8 |

软件静态流程：
- 向同一base+channel×0x40的+0x20C写1、+0x218写1、+0x230/+0x234/+0x238分别写0x33、+0x23C写0x23。
- 在最多24000次的循环中读取+0x218，期望它变为0；其它条件路径会清+0x220、写+0x214等字段。
- 另一软件路径读取+0x20C判断session状态、将+0x214置0、+0x218置1，最终清+0x20C；包含0x4B0次的有限等待及超时处理。
- 这只是H.265驱动的软件寄存器访问逻辑，不是运行时观察到芯片握手完成。

重要7组逐机原厂ARM对照：

| 指令 | X-S10地址 | X-T4地址 | 同一机器字 |
|---|---|---|---|
| ADD base+channel<<6 | 0x011FC854 | 0x011CFF00 | E0813303 |
| MOV R2,#1 | 0x011FC858 | 0x011CFF04 | E3A02001 |
| STR+0x20C | 0x011FC85C | 0x011CFF08 | E583220C |
| STR+0x218 | 0x011FC868 | 0x011CFF14 | E5832218 |
| LDR+0x20C | 0x011FC980 | 0x011D002C | E593320C |
| CMP #0 | 0x011FC984 | 0x011D0030 | E3530000 |
| STR+0x214清零 | 0x011FC9D4 | 0x011D0080 | E582C214 |

因此控制区+0x20C/+0x218/+0x214与+0x220并非孤立的无意义数据项；原厂软件有读、写、等待关系。但硬件端怎样解释这些字段依旧需要新的独立证据。

## 4. 第三个解压段的假阳性：实际是完整0xFF000BB9

这次首次把Section3分别导入独立临时Ghidra ARM项目，按原厂Section3 SHA256、入口ARM prologue以及原始BL目标核验，再成功只读反编译两机相应应用代码：

| 检查项 | X-S10 | X-T4 |
|---|---|---|
| Section3长度 | 10027008B | 10240000B |
| 候选映射基址 | 0x038F7DE8 | 0x0398A118 |
| ARM入口候选 | 0x038F7DF0 | 0x0398A120 |
| 相似的应用函数 | FUN_0390F03C | FUN_039A16D0 |
| 两处MOVW低半 | 0x0C91 | 0x0BB9 |
| 后续MOVT高半 | **0xFF00** | **0xFF00** |
| 完整32位实际参数 | **0xFF000C91** | **0xFF000BB9** |
| 接收参数的函数 | FUN_03928E84 | FUN_039BB34C |
| 原始BL两个调用 | 0x0390F0B4 / 0x0390F134 | 0x039A1748 / 0x039A17C8 |

随后服务例程涉及坐标缩放 (param_1-1)*0x14、(param_2-1)*0x18 等应用绘制/事件处理，**没有**证据表明它读取0xBB9软件队列。

对Section1/2/3做严格有界的对齐、无条件ARM MOVW低半立即数0x0BB9筛选：X-S10命中数4/0/0；X-T4为4/0/2；XT4第三段的两处均是上面的完整0xFF000BB9。此法不是全ISA/间接取常数/多核控制流穷举，不能证明另一核没有消息接收者。

## 5. 三机H.265模块字节相同是对照，不是Main10能力证明

私有原厂payload中三台机型相同的模块均带有H.265 MP Encoder描述头，长度425984B（0x68000）：
- XS10 payload偏移0x02DA0000；
- XT4 payload偏移0x02C40000；
- XT3对照payload偏移0x02C60000。

完整SHA256一致：

~~~text
9d986c77d71a57ceefbd6b0bde2668f1a057f6892daff3be0fb4a4a3c5f4441c
~~~

模块内各有17处非对齐的连续B9 0B字节组合，但完整little-endian 32bit 0x00000BB9和0x00480BB9均未直接匹配。这不是对专有指令集、数据重定位/动态解码的完整逆向；模块相同也不能证明机型的内存带宽、像素输入/bitdepth配置、硬件Main10支持一致。

## 6. 区分真实控制区写入和只负责日志的函数

X-S10 FUN_011FDA28、X-T4 FUN_011D10D4实为CPU侧调试文本环形缓冲区写入函数；XS10 FUN_011FDAEC、XT4 FUN_011D1198把数值拆成十六进制字符写入文本缓冲。二者Ghidra反编译均证实不是硬件队列通知。发送者中真正需要继续追的硬件访问是原始A32 STR [base + channel<<6 +0x220]，不能把后续打印例程误称为VPU中断处理。

## 7. 依然未知的功能与下一步

1. 0xFFE00000+channel×0x40控制区的官方芯片寄存器定义、+0x220真正的触发对象以及接收中断的处理器；
2. W+0x92010/+0x94010中的0xBB9请求是否被另一核心取走/反序列化，如何解释72B帧描述符、+0x18值0x121/0x201；
3. 驱动bit_depth内部enum的真实8/10-bit映射，HEVC真实Main10 SPS/profile/hvcC或编码成功数据；
4. GUI MovieCodec setter→Recorder最初输入+0x5B0的赋值者；
5. 真实机身2.10与本次离线3.11之间的差异、4K60传感器/ISP/编码器/录卡持续条件。

下阶段应优先离线追原厂SoC/MMIO定义及可用VPU端固件，对比0x20C/0x218/0x220硬件语义和消费者。**现无内录10-bit、Main10或4K60已解锁的证据，绝不进行设备操作或刷写。**

## 8. 原创审计、纯合成测试及复验

拟公开的文件：
- tools/audit_stage38_third_section_vpu_candidates.py：原厂X6 Section3 SHA/ARM Ghidra验证、MOVW/MOVT完整立即数、BL调用及三机HEVC模块hash、原始候选排除。
- tests/test_audit_stage38_third_section_vpu_candidates.py：76项纯合成正反ARM/模块测试。
- tools/audit_stage38_vpu_mmio_notify.py：两机TX各2组10字ARM、控制基址及selector来源、原厂所有直接xref、MapSession/UnmapSession相关7条ARM及Ghidra，以及日志器身份排除。
- tests/test_audit_stage38_vpu_mmio_notify.py：90项纯合成正反测试。
- docs/phase38-vpu-mmio-third-section-2026-10-18.md：本报告。

全部原厂Section/payload、Ghidra项目和私有分析日志留在Ubuntu忽略output/。本机只读复验：

~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/audit_stage38_third_section_vpu_candidates.py --output output
python3 tools/audit_stage38_vpu_mmio_notify.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

**实测**：Phase26—38的原厂离线审计全部通过（Stage38双机ROM+三机HEVC模块）；Stage38新增76+90=166项纯合成测试在独立public-only目录运行通过；仓库追踪91项+本机忽略研究测试1140项=**1231项离线自动化测试全部通过**。原项目FF80检测明确提示USB服务不存在、No command sent。Ubuntu本地main工作树保持未改变。

**阶段结论：打通了原厂ARM中的软件TX→可计算控制寄存器写1的静态路径，证实相同寄存器区另有会话管理和轮询；排除了第三段0xBB9低半字假阳性；硬件端、Main10/10-bit与4K60仍未证实或解锁。**
