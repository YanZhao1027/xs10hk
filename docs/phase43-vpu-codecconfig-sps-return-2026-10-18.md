# 第43阶段：MVE 40字节 BITSTREAM 返回描述符、CODECCONFIG 与序列参数通知（2026-10-18）

> **核心结果**：上一阶段（Draft PR #20）已确认两机原厂 MovieCodec==1 选 HEVC Encoder、VPU video_codec=0，而视频codec enum=1 选 H.264 Encoder；已找到的输出8/8位深 SET_OPTION 仅位于条件性 H.264 分支。第43阶段沿真正编码输出方向追查：X-S10原厂3.11与X-T4原厂2.12的ARM确实发送40字节的BITSTREAM描述符、使用0xBBA作为消息类型，并在0x7D6 OUTPUT分支恢复该描述符，检查 CODECCONFIG 标志0x80，再从返回描述符的地址、偏移和有效长度找到软件端可用数据范围。这个路径是寻找真实HEVC VPS/SPS/PPS并验证Main10的正确位置，但本阶段并未获取任何真实编码视频、SPS、实际硬件返回数据。另一处重要更正：0x7DF是8字节SEQUENCE_PARAMETERS元数据通知，不是视频SPS码流。两机在该分支发送0x3EC OUTPUT_FLUSH请求。没有任何解锁结论。

## 0. 原厂版本、离线与权限边界

- 分析的是授权Ubuntu /home/zyubuntu/xs10hk 已有的X-S10原厂3.11和X-T4原厂2.12 Section1原始ROM，以及Ghidra 12.1.4只读解码日志。此前用户报告实际X-S10机身版本为2.10，研究地址不适用于其实体机。
- 只读原厂文件和公开ABI，没有接触物理相机、发送USB/FF80指令、读写设备RAM/Flash、修改ROM/DAT、破解固件签名、制作补丁、刷写或产生可刷镜像。本机原厂固件、V61字节、Ghidra DB与调试日志只留在git忽略的 output/ 里，不提交到GitHub。
- 公开接口定义来源：
  - Kendryte K230 MVE v2: https://github.com/kendryte/k230_sdk/blob/main/src/little/linux/drivers/media/platform/canaan-vpu/mve_protocol_def_v2.h
  - Kendryte K230 MVE v3: https://github.com/kendryte/k230_sdk/blob/main/src/little/linux/drivers/media/platform/canaan-vpu/mve_protocol_def_v3.h
  - Kendryte K230 VPU host driver: https://github.com/kendryte/k230_sdk/blob/main/src/little/linux/drivers/media/platform/canaan-vpu/mvx_firmware_v2.c
  - CIX公开MVE v2: https://github.com/cixtech/cix_opensource__vpu_driver/blob/cix_p1_k6.6_master/driver/external/fw_v2/mve_protocol_def.h
- 以上为其他SoC厂商公开协议，不是富士指定芯片的官方寄存器手册。跨ABI与原厂A32一致构成强关联，但不证明设备真实运行成功。

## 1. 绝不能混淆两个不同的+0x18字段

CPU输入的MVE_FRAME消息编号0xBB9，payload为72字节，其中 frame+0x18 是uint16像素格式（0x201=NV12 8bit，0x121=Y0L2 10bit），已经在第41阶段双机原厂ARM验证。

编码输出使用另一结构：MVE_BUFFER_CODE_BITSTREAM=3002=0xBBA，payload为40字节。独立以Python ctypes重新计算公开mve_buffer_bitstream布局：

| 字段 | 相对偏移 | 含义 |
|---|---:|---|
| host_handle / user_data_tag | +0x00 / +0x08 | 输出缓冲标识与相关标签（均uint64） |
| bitstream_flags | +0x10 | uint32标记 |
| bitstream_alloc_bytes | +0x14 | 分配容量 |
| bitstream_offset | +0x18 | **码流有效字节起点**，不是输入帧pixel format |
| bitstream_filled_len | +0x1C | 实际可用字节数 |
| bitstream_buf_addr | +0x20 | 数据缓冲虚拟/工作地址 |
| frame_type / src_transform | +0x24 / +0x25 | 帧类型/变换 |

对本次返回数据有意义的公开bitstream_flags包括CODECCONFIG=0x80、ENDOFFRAME=0x10、EOS=0x1。特别是CODECCONFIG，意味着编码器可能把参数集等配置数据标记为配置输出，但**不能只因为软件存在0x80测试，就断言任何一次实机已经返回配置码流**。

## 2. 双机真实原始ARM：发送0xBBA/40B描述符

| 原始操作 | X-S10 3.11 | X-T4 2.12 | A32机器字 |
|---|---|---|---|
| 软件发送函数 | FUN_011FB3B8 | FUN_011CEA64 | 独立原厂函数 |
| 清 flags+0x10 | 0x011FB414 | 0x011CEAC0 | E5821010 |
| 清 offset+0x18 | 0x011FB424 | 0x011CEAD0 | E5821018 |
| 设置分配容量0x1000 (4096) | MOV 0x011FB428 / STR 0x011FB42C | MOV 0x011CEAD4 / STR 0x011CEAD8 | E3A01A01 / E5821014 |
| 写filled_len+0x1C | 0x011FB484 | 0x011CEB30 | E580701C |
| 写buf_addr+0x20 | 0x011FB488 | 0x011CEB34 | E5805020 |
| 第一条0xBBA消息与BL | MOVW 0x011FB490，BL 0x011FB494→FUN_011FA844 | MOVW 0x011CEB3C，BL 0x011CEB40→FUN_011CDEF0 | E3001BBA / EBFFFCEA |
| 第二条0xBBA消息与BL | MOVW 0x011FB564，BL 0x011FB568→FUN_011FA714 | MOVW 0x011CEC10，BL 0x011CEC14→FUN_011CDDC0 | E3001BBA / EBFFFC69 |

原始A32逐字读取和独立Ghidra反编译都通过。输出缓冲描述符长度0x28=40字节，每条描述符的分配字节初始为0x1000=4096。第42阶段另外证实HEVC enum0创建三个此类bitstream header记录，H.264 enum1创建两个；这与HEVC的VPS/SPS/PPS及H264的SPS/PPS参数集数量一致，**不是实际获取到这些NAL的证据**。

## 3. CPU真正接收0x7D6 OUTPUT并消费BITSTREAM

| 软件返回路径 | X-S10 | X-T4 |
|---|---|---|
| CPU响应分派主函数 | FUN_011FCBC4 | FUN_011D0270 |
| 软件响应RX-ring读取器 | FUN_011FAA68 | FUN_011CE114 |
| 返回BITSTREAM描述符RAM首址 | 0x019E55F8 | 0x01955538 |
| bitstream_flags(+0x10) | 0x019E5608 | 0x01955548 |
| bitstream_offset(+0x18) | 0x019E5610 | 0x01955550 |
| bitstream_filled_len(+0x1C) | 0x019E5614 | 0x01955554 |
| bitstream_buf_addr(+0x20) | 0x019E5618 | 0x01955558 |
| 原始TST flags 0x80 | 0x011FD234、0x011FD404 | 0x011D08E0、0x011D0AB0 |
| LDR +0x20 (buf_addr) | 0x011FD414 | 0x011D0AC0 |
| LDR +0x18 (offset) | 0x011FD418 | 0x011D0AC4 |
| LDR +0x1C (filled_len) | 0x011FD45C | 0x011D0B08 |
| 运行时页表地址映射 | FUN_011FC2E4 | FUN_011CF990 |

原始ARM TST r3,#0x80为E3130080，两机对应机器字一致；读取buf_addr/offset/filled_len分别是E5992020、E5993018、E599E01C。Ghidra接收控制流包括RX-ring拷贝到上述描述符RAM，测试CODECCONFIG标志、结合数据地址与offset、读取filled_len。第37阶段已核实0x3FC软件响应队列及长度取自消息头高16位。

地址映射函数按参数右移12位获取页号，通过动态RAM映射表计算目标地址，并保持低12位页内偏移。因此这里是运行时RAM/缓冲地址，**不能误当ROM文件偏移或相机固定物理地址**。没有动态页表、实际缓冲返回数据或任何真实Main10 SPS/hvcC可供检查。

## 4. 将三个容易误解的响应严格分开

| 消息 | 公开MVE协议身份 | X-S10原始A32 | X-T4原始A32 |
|---|---|---|---|
| 0x7D3 / 2003 | SET_OPTION_CONFIRM | MOVW@0x011FCC44 | MOVW@0x011D02F0 |
| 0x7E1 / 2017 | SET_OPTION_FAIL | MOVW@0x011FD014 | MOVW@0x011D06C0 |
| 0x7DF / 2015 | SEQUENCE_PARAMETERS | MOVW@0x011FCFC4 | MOVW@0x011D0670 |
| 0x3EC / 1004 | OUTPUT_FLUSH请求 | MOV@0x011FD8BC，BL@0x011FD8C0→FUN_011FA530 | MOV@0x011D0F68，BL@0x011D0F6C→FUN_011CDBDC |

两机的0x7DF SEQUENCE_PARAMETERS分支进行软件事件通知，然后发0x3EC OUTPUT_FLUSH，后续通知控制寄存器；请求MOV真实字均是E3A00FFB。公开mve_response_sequence_parameters只有8字节元数据：interlace、chroma_format、bitdepth_luma(+2)、bitdepth_chroma(+3)、所需缓冲数量等。**这不是HEVC码流中的VPS/SPS/PPS，不能从该响应的存在推断已经输出Main10。**

SET_OPTION_CONFIRM和FAIL处理分支只表明原厂CPU端存在判断、递减待确认数及失败通知逻辑，不证明真实硬件曾收到或接受Main10配置。0x7D6 OUTPUT返回的CODECCONFIG描述符才是以后应检查VPS/SPS/PPS数据的位置，且必须持有真正字节才能根据SPS profile与bit_depth_luma_minus8判定Main10。

## 5. 与第41、42阶段的关键上下游关系

- 第41阶段确定CPU输入frame+0x18写Y0L2/10bit或NV12/8bit，输入数据消息0xBB9/72B。输入像素格式与编码输出bitstream不是同一件事。
- 第42阶段确定Codec enum0确实选择独立HEVC Encoder固件源、enum1选H264；条件性SET_OPTION index38 (8/8)只在H264 enum1路径中识别，没有证据说X-S10的HEVC被这个选项强制成8bit。
- 第42阶段有界11条直接send-message调用、SndSetOption五条index为1、16、38、1、5，没有直接SET_OPTION index3 PROFILE_LEVEL；不能据此断定其他间接路径或V61默认profile不存在，更不能宣称HEVC Main10已自动开启。
- 本轮第43阶段找到了编码BITSTREAM描述符发送、返回、CODECCONFIG和有效数据定位的独立双机ROM路径，但仍未解出V61专有ISA、真正0xBB9消费者、真实HEVC Main10 SPS，也没有任何X-S10持续4K60内录证据。

## 6. 离线审计、测试与复现

公开原创文件仅三份：
- tools/audit_stage43_mve_bitstream_return.py：重建公开40B bitstream、8B sequence_params ABI；核对Stage42边界、两机原始ARM/Ghidra的0xBBA/0x28发送、两个BL、0x7D6接收、flags0x80、buf_addr+offset及filled_len、CPU动态地址转换、SET_OPTION反馈、SEQ_PARAMS与OUTPUT_FLUSH，所有输入ROM均SHA固定。
- tests/test_audit_stage43_mve_bitstream_return.py：109项纯合成正/反测试；A32字和Ghidra短文本完全人工构造，逐个变异字段和响应，源代码中没有任何Fuji原厂ROM或V61微码字节。
- docs/phase43-vpu-codecconfig-sps-return-2026-10-18.md：本报告。

在已有原厂素材的授权Ubuntu本机离线复现：

    cd /home/zyubuntu/xs10hk
    python3 tools/audit_stage43_mve_bitstream_return.py --output output
    PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
    PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q

**实际运行结果**：Stage43原始Section1双机SHA/ARM/Ghidra审计PASS，Phase26—43所有历史原厂只读审计PASS；新增109项纯合成测试在完全隔离的public-only目录PASS；本地追踪91项加Git忽略研究1717项，合计**1808项离线测试全部通过**。本地main仍保持clean，原厂payload/ROM从未修改或上传。

**阶段判断**：编码数据输出的CPU侧返回路径已经定位，SEQUENCE_PARAMETERS元数据通知与真正BITSTREAM CODECCONFIG数据已区分。要判定HEVC Main10，必须获得真实输出并解析VPS/SPS/PPS；仍未证明X-S10内录10bit/Main10或4K60已实现。
