# 第42阶段：HEVC / H.264 的 V61 固件源选路及 Main10 Profile 赋值边界（2026-10-18）

> **关键突破：** X-S10 原厂 3.11 和 X-T4 原厂 2.12 的 ARM MovieSetup 同时赋值 Codec 枚举与 VPU 编码器固件源指针。Movie Codec 字节为 1 时，选择 codec enum0、0x00CA0000，实际对应三机各自独立的 HEVC Encoder V61 映像；否则选择 enum1、0x00D08000，对应 H.264 Encoder。由此推翻先前把 SET_OPTION index38、luma/chroma=8/8 误以为 HEVC 8-bit 限制的可能性：这个选项只属于 H.264（enum1）的条件分支。**仍未找到 HEVC Profile=Main10 的实际发送/接受、真实 Main10 SPS 或 4K60 内录证据。**

## 0. 范围、来源、安全

使用用户授权 Ubuntu /home/zyubuntu/xs10hk 内的原厂 X-S10 3.11、X-T4 2.12 X6 Section1/2，X-T3 5.11 仅作原厂 V61 头部/哈希正对照，Ghidra 12.1.4 对已存在项目只读处理。真实 X-S10 此前报告的版本为 **2.10**，与本研究的 3.11 样本不同。文中 ARM 地址与固件源数值不得作为机身访问、Patch 或烧录地址。无 USB/FF80、实体相机 RAM/Flash 访问、固件修改、绕签名、刷写或生成可刷文件。原厂 ROM、V61 机器码、Ghidra 私有日志都留在 Git 忽略的 output/；公开内容只有独立原创的审计器、合成单测、中文研究说明。

公开外部协议正对照沿用第41阶段 Kendryte K230 MVE v2/v3 与 CIX VPU v2：
https://github.com/kendryte/k230_sdk/blob/main/src/little/linux/drivers/media/platform/canaan-vpu/mve_protocol_def_v2.h
https://github.com/kendryte/k230_sdk/blob/main/src/little/linux/drivers/media/platform/canaan-vpu/mve_protocol_def_v3.h
https://github.com/cixtech/cix_opensource__vpu_driver/blob/cix_p1_k6.6_master/driver/external/fw_v2/mve_protocol_def.h

## 1. Movie Codec → VPU 真实赋值链：两机同构，原始机器指令独立核验

MovieSetup X-S10 FUN_022DEE64、X-T4 FUN_0224B65C 均位于 **原厂 Section2**。两个分支共享一个原厂 Movie Context 字节 at +0xADDA：

| 操作 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| LDRB 读取 Context+0xADDA | 0x022DEF58 | 0x0224B750 |
| CMP 与 1 | 0x022DEF5C | 0x0224B754 |
| BEQ 字节==1 → HEVC 选择 | 0x022DEF60 → 0x022DF154 | 0x0224B758 → 0x0224B94C |
| 其它值：VPU init+0x188 codec=1 | 0x022DEF70 | 0x0224B768 |
| 其它值：选择 0xD08000 并写 init+0x10 | 0x022DEF74/78/7C | 0x0224B76C/70/74 |
| 等于 1：VPU init+0x188 codec=0 | 0x022DF160 | 0x0224B958 |
| 等于 1：选择 0xCA0000 并写 init+0x10 | 0x022DF164/68/6C | 0x0224B95C/60/64 |
| 使用选择的源地址，长度 0x39000，flags9 交区域服务 | 0x022DF078 → FUN_012A8514 | 0x0224B870 → FUN_01280C14 |
| Init 参数结构基址（RAM） | 0x02945A08 | 0x028A5150 |

两机原厂 A32 模式字节相同：LDRB 0xE5D33DDA、CMP 0xE1530002、BEQ 0x0A00007B；BEQ 有符号跳转目标单独计算验证；HEVC 分支 codec0、源地址 0xCA0000；H.264 分支 codec1、源地址 0xD08000。STR 指令写同一 Init 结构不同字段 +0x188/+0x10，已对真实 Section2 文件 SHA256、MOVW/MOVT/STR、BL 目标、Ghidra 伪 C 严格比对。

X-S10 Section2 SHA256：f0c4db782031a81c620d764317ebf0219d10bb4b52eb4fd5998b9ce39c3afb8c。
X-T4 Section2 SHA256：e1ef8b30903d3078fde103cdd134fca7bfc4337d67bcaf55c3080ffd5fd93b13。

**注意**：系统区域服务 FUN_012A8514/FUN_01280C14 调用低层 func_0x00058600，未独立证明它就是 memcpy 或完整的 VPU 微码装载过程。因此当前确定的是**软件端原厂固件源指针选路及所请求的范围长度**，不是运行中编码器肯定执行成功。

## 2. 用三机原厂独立 V61 映像标定源地址，而非根据数字猜 Codec

第40阶段分别核验了三机 V61 子映像独立头部、名称和完整 SHA256：
- HEVC Encoder：H.265 MP Encoder，字节数 0x39000，SHA256 = 37b04b1a4b2a97ce7d77200eadb2164be949b0fbd7390c241af00a82ba750880
- H.264 Encoder：H.264 BP/MP/HP Encoder，字节数 0x39000，SHA256 = 3baf997561ea106e831bd9107acb7476997492a36df886dedfe275fb31c74243
- 两编码器中间还有一个 HEVC Decoder，大小 0x2F000。因此相邻编码器起点相距 0x39000 + 0x2F000 = 0x68000，正好等于 0xD08000 - 0xCA0000。

| 原厂样本 | HEVC Encoder payload 文件偏移 | H.264 Encoder payload 文件偏移 | 各自减去 0xCA0000 / 0xD08000 的一致偏移 |
|---|---|---|---|
| X-S10 3.11 | 0x02DA0000 | 0x02E08000 | 0x02100000 |
| X-T4 2.12 | 0x02C40000 | 0x02CA8000 | 0x01FA0000 |
| X-T3 5.11 | 0x02C60000 | 0x02CC8000 | 0x01FC0000 |

两份**独立命名且 SHA 相互不同**的 0x39000 编码器、与两个运行源指针间相同的 0x68000 位移，再与两机 ROM 真实条件分支吻合，构成强映像源身份依据。这个相同位移仅对**两份已核验原厂映像**有效；没有证明完整 payload→运行虚拟地址映射。

## 3. 第二条独立软件交叉证据：bitstream header 2 与 3

X-S10 的 FUN_011FB3B8、X-T4 的 FUN_011CEA64 中，各有两处条件性头部提交：
- 读取 init 结构 +0x190 内部 video_codec 枚举，比较 1。
- codec=1 → MOVEQ 选择 2 份 header 记录；codec≠1 → MOVNE 选择 3 份。
- 每份 0x28=40 字节，消息 0xBBA=3002，公开 MVE 名为 MVE_BUFFER_CODE_BITSTREAM。
- 双机原厂 ARM 使用完全对应的 LDR、CMP、MOVEQ、MOVNE 和消息 MOVW，再经过确切 BL 发往软件 ring，全部原始机器字独立验证。

通常 H.264 参数集为 SPS/PPS 两类，HEVC 参数集为 VPS/SPS/PPS 三类，故该选路与已经确立的编码器独立映像身份吻合。但只证实**软件 header 个数条件与消息类型**，没有真正捕获相机所产生的 SPS/PPS/VPS，不能从条数推断 Main10 已编码成功。

## 4. 所以 Stage41 的 8/8 位深选项其实属于 H.264，不是 HEVC

第41阶段从公开 MVE ABI 得知：
- SET_OPTION 请求号 0x3F2，ENC_STREAM_BITDEPTH index38/0x26，8B 数据包含 luma_bitdepth=u16和chroma_bitdepth=u16；
- 原厂的 SndSetOption 只有在 init+0x194==0 并且 video_codec enum==1 时才发送该选项，两个值都是 8。
- **第42阶段证明 enum1 指向 H.264 Encoder，enum0 指向 HEVC Encoder**。所以这个已找到的 **8/8 选项是有条件的 H.264 输出位深设置，不能解释成 X-S10 HEVC Main10 被8bit强制限制**。

必须把三层区分：
1. CPU input-frame u16 format +0x18：0x201=8bit NV12、0x121=10bit Y0L2（第41阶段公开协议+两机原厂 ARM证据）。
2. SET_OPTION index38：编码器**输出码流目标位深**，当前原厂发送者对 H.264 enum1 设 8/8。
3. SET_OPTION index3：公开 MVE 的 PROFILE_LEVEL；公开 HEVC Main10 的枚举数值是 4，**Fuji是否曾在HEVC分支真实提交 profile4 未证明**。

CPU 构造10bit Y0L2帧输入消息，不等于 MVE 内核实际接受了数据、输出SPS Main10、或者实机具备4K60内录能力。

## 5. 有界追踪 Profile index3：两机11条直接BL枚举，五项选项都不是3

本阶段只读自编 Java Ghidra 脚本枚举泛用发送函数的全部静态直接引用：X-S10 FUN_011FA530、X-T4 FUN_011CDBDC 各 11 条 Ghidra UNCONDITIONAL_CALL，且逐条核验原始 Section1 BL 目标与Ghidra一致。其中每机各有5条来自 SndSetOption：
- index 顺序 **1、16、38（仅codec1且条件满足）、1、5**；
- **没有** public PROFILE_LEVEL index3 的直接发送；
- 其它直接调用分属 JOB、GO/STOP、DUMP、刷新或响应路径等，不把协议编号与局部数值搞混。

特别核对了另一个看似诱人的数值4：X-S10 FUN_011FB590、X-T4 FUN_011CEC3C 的 local_10=4、local_c=0，发消息 0x3F1、size8。公开 MVE 对应 MVE_REQUEST_CODE_JOB (1009)，载荷包括 cores(u16)、frames(u16)、flags(u32)，故此处是**作业 cores=4**，不是 HEVC Main10 Profile4。该 JOB 的原厂 MOVW 和 BL 也已验证。

**有界否定的边界**：5条现有 SndSetOption 编译消息中无 PROFILE_LEVEL=3，不证明所有可能间接调用、备用队列、其它参数路径或V61内部默认profile都没有此配置，更不证明硬件能自动用 Main10。此范围的“不存在”不能夸大成整个固件必然不包含。

## 6. 验证方法与 Stage43 继续研究方向

新原创只读审计器检查：
- Section1的原始选项发送BL、Section2源指针选择与BEQ、SHA一致性；
- 第40阶段三份完整原厂payload中四个独立V61模块头、哈希和尺寸；
- 第41阶段 MVE ABI、10bit/8bit格式及另一路 H.264 8/8位深条件；
- 两机SndBitStreamHeader的两套计数器分支与0xBBA消息；
- SndSetOption直接11引用、实际五条选项及 JOB4反假阳性；
- 未知Main10 SPS、V61内部ISA、硬件回调及4K60仍必须标为未知/False。

纯合成测试只用自制空白缓冲、人工指令字和虚构Ghidra文本，不携带ROM/微码/机器反编译内容；包括独立 public-only 运行，无需原厂文件。

Stage43首选：继续在 HEVC codec enum0 的真实初始化分支里跟随 Profile 选项 index3与微码默认选择；必要时从公开 MVE header bitstream buffer 消息 0xBBA、sequence parameter response 0x7DF 的CPU处理继续找生成SPS的有效路径。若仍找不到CPU profile4，可定位V61内部 option decoder，但在拥有可靠 ISA反汇编前不宣称已破解。与X-T4 Main10正对照比较静态代码，不用其公开产品规格作为X-S10能力的实证。4K60传感器/ISP/存储链路另行验证。

本阶段拟公开：
- tools/audit_stage42_vpu_codec_firmware_source_profile.py
- tests/test_audit_stage42_vpu_codec_firmware_source_profile.py
- docs/phase42-hevc-firmware-selector-main10-profile-2026-10-18.md

离线复验命令（只读）：

    cd /home/zyubuntu/xs10hk
    python3 tools/audit_stage42_vpu_codec_firmware_source_profile.py --output output
    PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
    PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q

**最后结论**：Stage42确定两个机型HEVC enum0/H264 enum1的原厂V61编码器固件源选路并纠正8/8选项的归属；没有找到直接PROFILE_LEVEL index3，真实 Main10输出和4K60内录仍未获得证明。实体相机和原厂固件均未被修改。
