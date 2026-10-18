# 第41阶段：V61 MVE公开协议与原厂ARM对接，解出10-bit Y0L2、72B帧及位深选项（2026-10-18）

> **第41阶段是主机↔VPU协议的突破，而非声称破解了私有V61微码ISA。** 我们从三个不同的公开Mali Video MVE协议头找到了消息号、帧字段位置、像素格式bitfield及码流位深选项的精确定义；再逐字重检 X-S10原厂3.11、X-T4原厂2.12 的ROM Section1和Ghidra调用路径。结论：此前CPU帧+0x18所写的0x201是NV12/8bit，0x121是Y0L2/10bit（并非P010）；0xBB9是FRAME消息；72B结构与+0x18、+0x34、+0x38偏移逐项符合公开MVE ABI。原厂还存在真实发送SET_OPTION (0x3F2)，选项index=38(0x26)，8B数据的两个码流位深值=8和8的条件性ARM指令链。**这不证明X-S10编码出HEVC Main10，也不证明谁是VPU微码的实际0xBB9消费者。**

## 0. 原厂范围与安全边界

只读研究用户授权Ubuntu /home/zyubuntu/xs10hk 已合法获得并解码的X-S10原厂3.11、X-T4原厂2.12 Section1及其只读Ghidra日志，X-T3原厂5.11作V61模块对照。用户先前报告**真实X-S10实机版本2.10**，而非本次3.11；本报告中的原厂ARM地址严禁套用于真实设备。全阶段未连接相机、发送USB/FF80、读取或修改实体RAM/Flash、编辑ROM/DAT、绕过签名、刷写、生成patch或可刷固件。私有原厂ROM、V61代码字节和Ghidra数据库都留在git忽略output/；只提交原创研究文字、审计脚本和纯合成测试。

外部公开资料已在GitHub代码搜索和逐文件读取中核对，**这些是其他SoC厂商公开的协议头，不是Fuji指定硬件的官方寄存器手册**：

| 来源 | 链接 | 审计所见Git Blob |
|---|---|---|
| Kendryte K230 MVE v2 | https://github.com/kendryte/k230_sdk/blob/main/src/little/linux/drivers/media/platform/canaan-vpu/mve_protocol_def_v2.h | 7888514a3ba4ace1ea62da324a9ced5534e3c45e |
| Kendryte K230 MVE v3 | https://github.com/kendryte/k230_sdk/blob/main/src/little/linux/drivers/media/platform/canaan-vpu/mve_protocol_def_v3.h | 9c79991f0c43e27cc78642a73bd8c98aa87d573f |
| CIX官方VPU驱动 MVE v2 | https://github.com/cixtech/cix_opensource__vpu_driver/blob/cix_p1_k6.6_master/driver/external/fw_v2/mve_protocol_def.h | f5c7eddebcf97fa9dcd992a316c675b7fec5f904 |

上面三个文件的Frame定义、相关格式枚举和关键Request/Response值互相吻合；不会因这个事实直接认为Fuji实际固件所有接口字段或版本绝对相同。本报告的Python实现由字段公式独立重建，未搬运厂商源码到本仓库。

## 1. 消息码终于有了明确定义

| MVE公开协议 | 十进制 | 十六进制 | 先前真实富士ARM静态数据 |
|---|---:|---|---|
| MVE_BUFFER_CODE_FRAME | 3001 | **0xBB9** | Stage36-37向VPU软件TX环形队列发送72B帧描述符 |
| MVE_RESPONSE_CODE_INPUT | 2005 | **0x7D5** | Stage39 CPU响应收回INPUT缓冲区 |
| MVE_RESPONSE_CODE_OUTPUT | 2006 | **0x7D6** | 公开协议值；此阶段未建立Fuji调用链 |
| MVE_RESPONSE_CODE_INPUT_FLUSHED | 2007 | **0x7D7** | 公开协议值 |
| MVE_RESPONSE_CODE_OUTPUT_FLUSHED | 2008 | **0x7D8** | Stage39 CPU响应该码且状态槽[0xC]==1时会条件性发下一帧 |
| MVE_REQUEST_CODE_SET_OPTION | 1010 | **0x3F2** | 本阶段从两机真实SndSetOption识别出 |

MVE消息头包含两个依次排列的little-endian u16：code与size，合计4B。Stage37原厂软件写入的32bit字为(size << 16)|code，Frame 72B => (0x48<<16)|0xBB9=**0x00480BB9**，little-endian为B9 0B 48 00。这是6个以上独立吻合点之一。

注意纠正第39阶段：**0x7D8是OUTPUT_FLUSHED，不是通常意义下的OUTPUT/“帧编码完成”**；后者的MVE消息编号实际为0x7D6。以前原厂A32条件调用下一帧的事实没有被推翻，但不能据此声明收到了真实硬件的特定成功帧应答，更不能从0x7D8推导Main10码流已输出。

## 2. 72字节帧描述符完整结构，与ARM字段逐个吻合

依K230/CIX公开结构重建MVE帧格式，字段从缓冲起点开始：
- host_handle: u64 at+0x0；user_data_tag: u64 at+0x8；
- frame_flags: u32 at+0x10；
- visible_frame_height: u16 at+0x14；visible_frame_width: u16 at+0x16；
- **format: u16 at+0x18**；
- frame_type及flags_ext各1字节，at+0x1A/+0x1B；
- 共用planar/AFBC数据union从+0x1C起；
- planar前面3个u32 top-plane地址，3个u32 bottom-plane地址，再是3个int32 stride；
- **stride[0]: +0x34**，**stride[1]: +0x38**，stride[2]:+0x3C；
- 尾部mini-frame y start/end字段，frame**总长72B=0x48**。

本轮原创ctypes独立实测公共结构sizeof(Planar)=40B、sizeof(AFBC)=28B、sizeof(union)=40B、sizeof(Frame)=**72B**；format.offset=**0x18**，stride0=**0x34**，stride1=**0x38**。

真正的富士A32已经在Stage36两机证实格式写入为STRH at+0x18（32位MOVW常量0x201或0x121），两个跨度的STR在+0x34/+0x38，72B发送作为0xBB9。Stage41又从两机原始Section1分别重检MOVW+STRH机器字及文件SHA256，核对前阶段原厂审计记录。**字段宽度、位置、消息号、包长与stride共同吻合，是独立且相当强的协议识别证据。**

## 3. 0x201与0x121的bitfield意义明确；不应把Y0L2叫作P010

公开V61/MVE协议format是u16 bitfield，位分组：
- bit 0..2：chroma subsampling，YUV420=1；
- bit 4..7：存储max_bitdepth_minus_8；
- bit 8..9：plane数量；
- bit 12..13：格式variant；
- bit 15：AFBC。

本轮独立编码和反向拆码：

| u16值 | 公开MVE定义 | 位深及布局 | 等式 |
|---|---|---|---|
| **0x201** | MVE_FORMAT_YUV420_NV12 | **8bit**、两平面 | 1 + (8-8)×16 +2×256 |
| **0x121** | MVE_FORMAT_YUV420_Y0L2 | **10bit**、一平面打包格式 | 1 +(10-8)×16 +1×256 |
| **0x281** | MVE_FORMAT_YUV420_P010 | **10bit像素存入16bit容器**、两平面 | 1 +(16-8)×16 +2×256 |
| 0x221 | MVE_FORMAT_YUV420_2P_10 | 10bit、两平面非P010 | 1 +(10-8)×16 +2×256 |

Stage36的原厂ARM定义“effective_depth==0 => format=0x201；否则=>0x121”从此可以标注为**8bit NV12 / 10bit Y0L2像素缓冲格式**。此前录像MovieSetup内部depth=1的静态路径如果没有中途写者会构造10bit Y0L2帧描述符，但**这只是CPU软件数据结构，不是实机VPU确实接受了10bit数据**，更不等于输出编码SPS profile_main10、bits_per_sample=10。

Stage40原厂V61编码器静态提示“hardware does not support MVE_FORMAT_YUV420_P010”专指公开协议的**0x281**，不能用这个P010提示推断原厂CPU真正填写的**0x121 Y0L2**也被拒绝。两者是不同输入格式。

## 4. 原厂发送了一个真正的编码码流位深选项：条件性8/8

Kendryte/CIX公开协议明确有：
- REQUEST SET_OPTION code **1010 / 0x3F2**；
- INDEX ENC_STREAM_BITDEPTH **38 / 0x26**；
- SET_OPTION payload有uint32 index、uint16 luma_bitdepth、uint16 chroma_bitdepth，总长8B；
- 另有INDEX PROFILE_LEVEL **3**、公开枚举H265 MAIN10 Profile **4**；这是协议允许的值，并非已证实Fuji发送Profile4。

原始富士A32与Ghidra精确双机镜像如下：

| 静态事件 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| Sender主函数 | FUN_011FB758 | FUN_011CEE04 |
| 检查init_packet+0x194==0 | LDR 0x011FB780 / CMP 0x011FB784 / BNE 0x011FB788 | 0x011CEE2C /0x011CEE30 /0x011CEE34 |
| 检查init_packet+0x190==1 | LDR 0x011FB804 / CMP 0x011FB808 / BNE 0x011FB80C | 0x011CEEB0 /0x011CEEB4 /0x011CEEB8 |
| MOV index38及STR | **0x011FB810/14** | **0x011CEEBC/C0** |
| 两个STRH写depth=8 | **0x011FB81C、0x011FB820** | **0x011CEEC8、0x011CEECC** |
| MOVW request#0x3F2 + BL发送8B | **0x011FB828/2C→FUN_011FA530** | **0x011CEED4/D8→FUN_011CDBDC** |

真实ARM核验：
- 读取init+0x194原始A32字E5933194，CMP0字E3530000，BNE字1A00002D；
- 读取init+0x190原始A32字E5933190，CMP1字E3530001，BNE字1A00001B；
- MOV index38字E3A03026；STR局部index字E50B3054；
- MOV r1,#8字E3A01008；两次STRH字E14B15B0 / E14B14BE；
- MOVW code0x3F2字E30003F2；其后真BL的ARM相对地址解码得到对应MVE软件队列发送函数。

原厂Ghidra C在两个模型均给出条件顺序：外层检查packet+0x194==0，内层检查packet+0x190==1，然后 local_58=0x26；local_54=0x00080008；FUN_XXXX(0x3F2,8,&local_58)。这意味着**在两个条件都满足的场景，软件发送“输出码流位深Luma=8/Chroma=8”协议命令**，不是仅有拒绝提示字符串。

**决定性未知**：还没有证实原厂video_codec enum1与HEVC/H264哪一个标准对应，且X-T4原厂有同构代码却能10bit内录。因此**不能**据此宣称“X-S10独有一个强制8bit HEVC限制开关”。也没找到富士实际将public协议中PROFILE_LEVEL index3和MAIN10 profile=4提交并由VPU接受的完整数据流。真实Main10仍无确认码流/SPS。

## 5. 真正V61微码ISA还没破解

第40阶段已分离原厂相同的V61独立HEVC Encoder和Decoder子映像。第41阶段找到的是**host↔firmware通信ABI的源码/结构**，并非V61专有微码反汇编器/正确地址重定位器。目前不可以从原始HEVC编码器中的2字节碰巧相等、Profile错误文字或P010拒绝文字猜测V61端的分支地址。真正另一核消费0xBB9帧描述符的函数、对Y0L2的输入校验、支持的Main10 Profile范围、是否真执行都未证明。外界关于Mali-V61系列支持HEVC Main10的通用介绍不等于X-S10机型实装硬件许可/片上带宽或4K60录像能力。

### Stage42应该直接追的赋值点

先从原厂ARM**SET_OPTION index3 PROFILE_LEVEL**的真实发送者出发，查发出的HEVC profile字段是否有值4（Main10），和同一函数中的codec enum、session和初始化条件建立可回放的静态因果链。先用X-T4支持Main10的正对照收敛profile4写者，再追X-S10是否调用同一条路径。与此同时确认enum1=HEVC还是H264，甄别刚证实的8/8选项究竟作用于哪种录像模式；最后找微码消费者及真实SPS证据。仍不碰机身固件或USB/FF80。

## 6. 本轮原创代码、真实审计和纯合成测试

新增公开原创文件：
- tools/audit_stage41_mve_v61_protocol_abi.py：从公开协议独立重建ctypes Frame72/字段偏移、NV12/Y0L2/P010/2P10bitfield、FRAME与INPUT/OUTPUT_FLUSHED消息号、SET_OPTION index38与PROFILE_LEVEL index3；对两机原厂A32、Ghidra真SET_OPTION发送、Stage36/37/39/40证据边界做fail-closed一致性审核。
- tests/test_audit_stage41_mve_v61_protocol_abi.py：**90项纯合成测试**，A32字和反编译风格fixture全部人工构造，涵盖前置条件、STRH值、BL回算、消息类型、格式位深、10bit与P010区别、禁止把OUTPUT_FLUSHED当普通帧完成。
- docs/phase41-mve-v61-protocol-abi-2026-10-18.md：本报告。

私有复现，只读：
~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/audit_stage41_mve_v61_protocol_abi.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

Stage41两机原厂ROM+Ghidra协议审计PASS，Stage26—41历史原厂离线审计回归PASS；90项新增纯合成单测于本机私有测试树和独立public-only目录均PASS；仓库追踪91项＋本机忽略研究1484项=**1575项离线测试全部通过**。项目原有FF80存在检查明确显示“No command sent”。本地main工作树仍未修改；ROM、V61微码和私有日志从未上传GitHub。

**结论：V61的消息协议、0x121/0x201像素格式和真实编码输出bitdepth选项已有多来源公开ABI×双机原厂ARM的强关联证据；实际V61微码ISA、X-S10 Main10码流及4K60并未破解或解锁。**
