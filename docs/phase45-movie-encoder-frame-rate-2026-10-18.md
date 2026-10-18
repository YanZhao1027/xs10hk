# 第45阶段：原厂MovieSetup→V61编码参数→59.94fps与NALU赋值闭环（2026-10-18）

> **核心突破**：从X-S10原厂3.11、X-T4原厂2.12 Section2 的MovieSetup直接BL，跨到Section1真正的编码器接口，再到15个32位参数的RAM保存器、编码器状态2装载器、真实SET_OPTION/B UFFER_PARAM发送者，打通此前不确定的编码路径。两机MovieSetup都将编码参数param[1]固定写成0x10（公开MVE协议的4-byte NALU长度格式），并将param[2]从视频配置转换为6个真实Q16 fps常量（23.98、24、25、29.97、50、59.94），最后作为MVE BUFFER_CODE_PARAM type9 FRAME_RATE提交。这是静态软件赋值链，不是实机VPU接受或4K60/Main10录制成功的证据。

## 0. 授权范围、版本与边界

仅离线只读分析授权Ubuntu /home/zyubuntu/xs10hk 内X-S10原厂3.11和X-T4原厂2.12 Section1、Section2、已存在只读Ghidra 12.1.4工程和日志。实体X-S10之前报告版本为2.10，不能把本地原厂3.11的地址用作硬件寄存器或刷写地址。没有接触或指挥物理相机、没有发送USB/FF80、没有RAM/Flash访问或写入、没有改写原厂ROM/DAT、没有补丁、破解签名、可刷文件或实机录像试验。所有厂商固件、V61微码、Ghidra数据库和原始审计日志只留在git忽略的 output/；GitHub仅提交原创审计器、人工合成测试和本报告。

公开Host↔MVE ABI（不是富士硬件能力的直接证明）：
- https://github.com/kendryte/k230_sdk/blob/main/src/little/linux/drivers/media/platform/canaan-vpu/mve_protocol_def_v2.h
- https://github.com/kendryte/k230_sdk/blob/main/src/little/linux/drivers/media/platform/canaan-vpu/mve_protocol_def_v3.h
- https://github.com/cixtech/cix_opensource__vpu_driver/blob/cix_p1_k6.6_master/driver/external/fw_v2/mve_protocol_def.h

核验的完整原始Section1/2 SHA256：

| ROM样本 | Section1 SHA256 | Section2 SHA256 |
|---|---|---|
| X-S10 3.11 | c86c9446a15a39e6e761c4ca96383e943cdb3a09cab6e609b85b3e48f3e91aff | f0c4db782031a81c620d764317ebf0219d10bb4b52eb4fd5998b9ce39c3afb8c |
| X-T4 2.12 | 0b5b0fb0ee5fe6b109dae9964b5cddfe18edab46b4a0c195f9da194448906eeb | e1ef8b30903d3078fde103cdd134fca7bfc4337d67bcaf55c3080ffd5fd93b13 |

## 1. 真正MovieSetup→Encoder的跨段直接CALL，区分此前dec_param

| 证据节点 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| Section2 MovieSetup | FUN_022DEE64 | FUN_0224B65C |
| 60字节(0x3C)编码参数块RAM起点 | 0x029459CC | 0x028A5114 |
| Section2→Section1原始直接BL | 0x022DF508→FUN_011F745C | 0x0224BC90→FUN_011CAB08 |
| 编码器接口包装器→真正保存器BL | 0x011F7464→FUN_011F9B84 | 0x011CAB10→FUN_011CD230 |
| 真正encoder 15-word参数RAM | 0x019FB67C | 0x0196B6D0 |
| 原始首两条STMIA | 0x011F9C20 / 0x011F9C28 | 0x011CD2CC / 0x011CD2D4 |
| 编码器事件状态2→加载器 | FUN_011F93DC→FUN_011F8914 | FUN_011CCA88→FUN_011CBFC0 |
| 解码器事件状态3→另一加载器 | FUN_011F89F0 | FUN_011CC09C |
| Encoder装载器→SET_OPTION | 0x011F89B8→FUN_011FB758 | 0x011CC064→FUN_011CEE04 |
| Encoder装载器→BUFFER_PARAM | 0x011F89C0→FUN_011FAFB0 | 0x011CC06C→FUN_011CE65C |

两个跨段BL的原始A32字分别EBBC5FD3、EBBDFB9C，有符号PC-relative地址回算与Ghidra UNCONDITIONAL_CALL指向上表编码接口一致。随后包装器第二个BL机器字均EB0009C6。真正编码器保存器前两条STMIA机器字均E8AE000F，Ghidra显示从param[0]到param[14]总共15个u32连续存入保存RAM；状态设置为2，与dec_param的状态3明确区分。状态分派函数随后调用各自encoder专用缓存加载器、SET_OPTION和BUFFER_PARAM。Ghidra前5个RAM保存字段各有一处直接WRITE和一处直接READ引用；这不排除间接/别名访问。

## 2. MovieSetup真正确定NALU=16及六档帧率

MovieSetup用清零长度0x3C构建参数；两机都将param[1]直接赋常量0x10（X-S10 A32 STR在0x022DF1C4，X-T4在0x0224B9BC；原始机器字均E5832004），通过原始跨段调用向真Encoder端提交。

| 字段 | X-S10参数块地址 | X-T4参数块地址 | 来源 |
|---|---|---|---|
| param[0] | 0x029459CC | 0x028A5114 | 条件来源：当前配置参数+0x9B9和模式字段+0x60F |
| **param[1]** | **0x029459D0** | **0x028A5118** | **两机直接写0x10，4字节NAL长度前缀** |
| **param[2]** | **0x029459D4** | **0x028A511C** | **根据当前帧率枚举转换为Q16 fps** |
| param[3..4] | +0xC / +0x10 | +0xC / +0x10 | Rate Control相关字段，值来自录像模式 |
| param[5..14] | 后40字节 | 后40字节 | 其它可选编码器参数字段 |

帧率枚举按 MovieSetup 参数+0x6018 指向的运行时模式对象的+0x5F5选择从主对象+0x5C6还是+0x5C7读取，然后执行case1..6；两机原厂反编译中所有常量相同：

| FPS枚举 | 原始Q16 | 除以65536的帧率 |
|---:|---|---:|
| 1 | 0x17FAE1 | 23.979995728 fps |
| 2 | 0x180000 | 24.000000000 fps |
| 3 | 0x190000 | 25.000000000 fps |
| 4 | 0x1DF851 | 29.969985962 fps |
| 5 | 0x320000 | 50.000000000 fps |
| 6 | **0x3BF0A3** | **59.939987183 fps** |

每机六处写入param[2]的原始A32 STR均通过SHA固定Section2逐字核验。X-S10的六个STR地址为0x022DF224、0x022DF2E8、0x022DF300、0x022DF314、0x022DF328、0x022DF340；X-T4的六处为0x0224BA1C、0x0224BAA0、0x0224BAB8、0x0224BACC、0x0224BAE0、0x0224BAF8。两机原始机器字分别恒为E581E008、E582C008；只读Ghidra也各找到六处WRITE引用。**这些是具体的编译后写入指令，而不是只看到六段字符串。**

**宽/高有另一条来源**：MovieSetup分别从当前动态模式对象+0x600、+0x602读取height/width，写入VPU初始化参数块。H.265/H.264选择又来自当前Codec字节+0xADDA（==1使用独立HEVC Encoder固件源0xCA0000，其他值用H264源0xD08000，已在Stage42完整核对）。因此三条静态路径同时存在不等于X-S10有合法的3840×2160+59.94fps+HEVC联合运行状态；要证明4K59.94必须独立追相机模式准入、ISP、总线、VPU能力及实际持续输出，不能从FPS选项独立存在推导。

## 3. 映射为真实MVE NALU、P帧和帧率报文

编码保存器的前5个参数依次加载到动态cache[5]、cache[6]、cache[4]、cache[2]、cache[3]，然后传给真正的Sender：

| Encoder参数 | 实际CPU缓存 | 公开MVE消息字段 |
|---|---|---|
| param[0] | cache[5] /+0x14 | SET_OPTION 0x3F2 index16 = ENC_P_FRAMES |
| **param[1]=0x10** | **cache[6] /+0x18** | **SET_OPTION index1 = NALU_FORMAT，value16=FOUR_BYTE_LENGTH_FIELD** |
| **param[2]=Q16 fps** | cache[4] /+0x10 | **BUFFER_CODE_PARAM 0xBBB type9 = FRAME_RATE (Q16 fps)** |
| param[3] | cache[2] /+0x08 | BUFFER_PARAM type10 RATE_CONTROL第一个参数字 |
| param[4] | cache[3] /+0x0C | BUFFER_PARAM type10 RATE_CONTROL第二个参数字 |
| 部分param[5..14] | 保存RAM后续字段 | 条件性BUFFER_PARAM type23 HRD_BUFFER_SIZE、type15 COLOUR_DESCRIPTION、type21 RATE_CONTROL_QP_RANGE |

两个缓存加载函数都经原始A32核对相应五条LDR：X-S10 0x011F8964、896C、895C、894C、8954；X-T4 0x011CC010、C018、C008、BFF8、C000；对应A32原始字依次E5930000、E5933004、E5930008、E593000C、E5930010。Ghidra函数明确把这些源字段复制进上述缓存索引。

两机Encoder SndSetOption确实对index1使用cache[6]、对index16使用cache[5]；在另一条编码BUFFER_PARAM消息路径使用type9，从cache[4]读取Q16帧率，然后使用type10从cache[2/3]取rate参数。BUFFER_PARAM的底层消息号为0xBBB，SET_OPTION为0x3F2，消息类型不可混同；同理SET_OPTION index9不是BUFFER_PARAM type9。BufferParam type10原厂实际发送长度0x0C，公开v2 struct rate_control完整成员数量不一定与原厂短消息完全一致，因此本阶段只识别type10的消息身份和两源字，**不冒充已还原其它隐藏码率字段**。SndSetOption/B UFFER_PARAM还存在运行条件（包括初始化参数+0x194），这条软件传参静态结论不代表硬件已确认参数。

## 4. Main10和4K60仍未确定

上面列出的实际encoder参数集合包含NALU格式、P帧数量、帧率、码率控制、色彩、QP、HRD等，但没有看到明确的HEVC PROFILE_LEVEL index3。Phase42有界枚举了每机11条直接底层消息发送BL，五条现有SET_OPTION index分别为1、16、38(仅H264相关条件)、1、5；本阶段补上MovieSetup上游实值和BUFFER_PARAM type9等，不可将“当前有界软件调用集合中没找到profile3”提升成“整个固件或V61内部一定没有Main10 Profile”。

公开Host-MVE协议Main10 option enum是4，真正编码HEVC SPS Main10的general_profile_idc为2；10bit Y0L2输入帧只是原厂CPU软件选择的像素缓冲格式，不能代替实际VPU成功编码证据。实体X-S10的Main10、4K60硬件能力、录制码流和60fps+4K组合仍**未证明，也未解锁**。

## 5. 后续目标：联合宽高+fps+codec准入而不是继续数值撞车

建议Stage46沿MovieSetup的三个不同源字段回溯配置表与合法模式组合：
- 分辨率：动态Movie模式对象+0x600/+0x602；
- 帧率枚举：MovieSetup主对象+0x5C6/+0x5C7，由动态模式对象+0x5F5切换；
- HEVC/H264选择：MovieSetup主对象+0xADDA。

要找到的不是三种单独合法值，而是**X-S10是否存在一条可到达的原厂调用路径，允许3840×2160、fps enum6、HEVC同时进入该编码会话**。若这种组合没有静态准入，还要识别究竟是UI、配置表、传感器/ISP还是编码运行时限制；不做固件修改或实机测试。

## 6. 审计工具与离线测试

新增原创文件：
- tools/audit_stage45_movie_encoder_fps_chain.py：对两台原厂Section1和Section2进行完整SHA和原始A32机器字验证（跨段BL、15字段来源STMIA、前5字段LDR、0x10 Store、六条fps STR）＋ Ghidra MovieSetup/encoder编码状态2与解码状态3/真实SET_OPTION/BUFFER_PARAM，对比公开MVE枚举，同时维持Main10/4K60未知标记。
- tests/test_audit_stage45_movie_encoder_fps_chain.py：**115项纯人工模拟正反测试**，模拟ARM字、Ghidra函数和xref，再逐点扰动条件、原始BL目标、参数和协议源，绝不包含实际ROM或私有Ghidra程序内容。
- docs/phase45-movie-encoder-frame-rate-2026-10-18.md：本报告。

复验命令（原厂审计只在授权Ubuntu上拥有gitignored原厂文件时运行；合成测试与ROM独立）：

    cd /home/zyubuntu/xs10hk
    python3 tools/audit_stage45_movie_encoder_fps_chain.py --output output
    PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
    PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q

**实际完成**：两机原厂Section1+2 SHA固定只读审计PASS；Phase26—45原厂离线审计全部PASS；115项新增合成测试在独立不带原厂ROM的public-only布局PASS；本机累计**91 tracked + 2004 ignored research = 2095项离线单测PASS**。原仓库FF80服务检查仅提示USB设备没有连接、No command sent。local main保持clean。没有原厂BIN/ROM、V61机器码或Ghidra日志上传GitHub。

**最终结论：** 已由MovieSetup真实机器码贯通X-S10和X-T4的编码器48/60字节来源、NALU16和六档帧率赋值至MVE类型9/选项1；证据强于Stage44仅局部dec_param探索，但无法据此认定X-S10原厂可内录HEVC Main10或4K60。
