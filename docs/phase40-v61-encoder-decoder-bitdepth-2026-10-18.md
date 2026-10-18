# 第40阶段：V61 HEVC编码/解码映像拆分与位深、Profile、P010诊断归属（2026-10-18）

> **核心成果**：过去第13/38阶段统称为“H.265 encoder 0x68000”的三个相同固件片段，实际上各包含**两个完整、独立的V61子映像**：HEVC Encoder（0x39000字节）和HEVC Decoder（0x2F000字节）。它们分别有自己的V61映像签名、版本文字和独立头部信息。三机四个模块各自的SHA256均通过原厂字节校验，旧的合并0x68000 SHA本身仍正确，但不能把其中decoder的10-bit和SPS信息归到encoder。本阶段确认encoder内部的HEVC Profile、stream bitdepth、10-bit输入格式、P010、协议消息的诊断静态文字；没有V61指令级反汇编，不证明这些诊断运行时被触发，也没有Main10编码成功或4K60证明。

## 0. 安全范围和版本

只读研究授权Ubuntu /home/zyubuntu/xs10hk 的原厂 X-T3 **5.11**、X-T4 **2.12**、X-S10 **3.11** 解码payload，以及此前的原始ARM/只读Ghidra第39阶段证据。本阶段无网络、无下载、无物理相机、USB/FF80命令、机身RAM/Flash访问、DAT/ROM更改、签名绕过、固件patch、刷写或可刷文件。用户以前报告**真实X-S10机身运行2.10**，本文3.11的文件偏移绝不可用作2.10实机访问地址。所有Fuji原厂字节和Ghidra日志仅存放在Git忽略的Ubuntu output/；本报告与原创审计/纯合成单测才可公开。

## 1. 原厂片段的确切边界：更正此前将解码器误包含在编码器内的命名

过去的三机HEVC片段（0x68000字节）没有字节错误，错误只是把内部两个子映像误认作一个编码器。原有 module_inventory.py 使用 H.26x 前缀匹配模块名称，因而漏掉名字以 HEVC Decoder 开头的另一模块头；第40阶段在原厂字节偏移+0x39060定位并核验了独立的HEVC Decoder模块签名。

| 原厂文件 | HEVC Encoder 独立映像（含起止） | HEVC Decoder 独立映像（含起止） | 紧接的H.264 Encoder |
|---|---|---|---|
| X-T3 5.11 | 0x02C60000—0x02C98FFF | 0x02C99000—0x02CC7FFF | 0x02CC8000 |
| X-T4 2.12 | 0x02C40000—0x02C78FFF | 0x02C79000—0x02CA7FFF | 0x02CA8000 |
| X-S10 3.11 | 0x02DA0000—0x02DD8FFF | 0x02DD9000—0x02E07FFF | 0x02E08000 |

两机内存地址不同，表中**全部是解码payload的文件偏移**，不是可执行虚拟地址/用户机身地址。

每个独立V61映像的局部偏移+0x60都含16字节特征码 5E EB 00 00 04 02 00 00 35 36 36 31 30 30 30 32；局部+0x70分别标记 H.265 MP Encoder 和 HEVC Decoder；局部+0xC0/+0xC4/+0xC8/+0xCC各有**不同的四个原始u32元数据字**：

| 独立V61映像 | C0 | C4 | C8 | CC |
|---|---|---|---|---|
| HEVC Encoder | 0x00038080 | 0x0003A000 | 0x00000012 | 0x0003FBF9 |
| HEVC Decoder | 0x0002EA00 | 0x00030000 | 0x00000039 | 0xFFFFF7FF |

没有官方映像格式说明，不能把这些字擅自解释为硬件编码器工作模式或codec能力位图。本阶段还用相邻H.264 Encoder和H.264 Decoder的独立签名/元数据作正向边界检查。四个相邻子映像以区域内0x00000、0x39000、0x68000、0xA1000、0xB5000作4KiB对齐切分。

### 分开算SHA-256，三机完全一致

| 子映像 | 大小 | X-T3、X-T4、X-S10三机一致的SHA256 |
|---|---:|---|
| **HEVC Encoder** | **233472B = 0x39000** | 37b04b1a4b2a97ce7d77200eadb2164be949b0fbd7390c241af00a82ba750880 |
| **HEVC Decoder** | **192512B = 0x2F000** | 1e7f6bcfa080f1ec70a52319ef559d7efd5c4c0df935bd31db45c99dd05e563e |
| HEVC合并片段（旧第13/38阶段） | 425984B = 0x68000 | 9d986c77d71a57ceefbd6b0bde2668f1a057f6892daff3be0fb4a4a3c5f4441c |
| H.264 Encoder边界对照 | 233472B | 3baf997561ea106e831bd9107acb7476997492a36df886dedfe275fb31c74243 |
| H.264 Decoder边界对照 | 81920B | 58ec013d91c20f673f55131fc43840d8a65d8c72fb63dff76f9846547bac9508 |

两个HEVC映像分别一致，意味着X-S10已包含与两个10-bit正对照机型相同的编码器程序**字节副本**，但无法由此保证它使用相同硬件能力、驱动参数、sensor/ISP配置或可以内录10-bit/4K60。

## 2. 静态诊断真正属于HEVC Encoder的部分

下表偏移均是**HEVC Encoder独立映像内部**，对X-S10原厂payload需加0x02DA0000（其它两机换其各自起点）。

| 编码器内部文件偏移 | 原厂ASCII静态诊断 | 当前可靠结论 |
|---|---|---|
| **+0xE0C7** | set-opt different stream bitdepths not supported | 存在流间位深组合不支持的诊断，触发条件未知 |
| **+0xE0F8** | set-opt encode stream bitdepth: unsupported value | 存在编码位深错误提示，实际枚举对应关系未确认 |
| **+0xF1E4** | set-opt: Unsupported HEVC profile | 存在HEVC Profile错误提示，允许哪些Profile仍未知 |
| +0xF206 | set-opt: Unsupported HEVC level | HEVC Level的错误提示 |
| **+0xFCFA** | encoding not supported of this 10-bit input format | 有某些10bit输入格式不支持的诊断，不能推断所有10bit都被拒 |
| **+0xFD2D** | hardware does not support MVE_FORMAT_YUV420_P010 | P010输入硬件不支持的提示，不能推断实体X-S10实际触发 |
| +0xE395 | hardware does not support encoding | 编码能力检查相关的错误文字 |
| +0xE3B8 | hardware does not support hevc | HEVC能力检查的错误文字 |
| +0xE2ED | Firmware version does not match hardware! | 映像/硬件版本兼容诊断 |
| +0xF0D1 | Recieved SET_OPTION data_size | 编码器的选项消息诊断 |
| +0xFBCA | Unsupported message code. | 编码器的未知消息码诊断 |
| +0xF579 | format 0x%04x visible %ux%u | 报告帧格式和尺寸的诊断模板 |
| +0xFD5E | MVE_BUFFER_FRAME_FLAG_INTERLACE set: | 帧标记与输入检查文字 |
| +0xEE7C | Unsupported encode param in MVE_COMM_BUF_INQ_ADDR. | 编码器入队参数限制诊断 |

全部内容逐项由三份原厂文件对相应子映像作精确偏移和唯一出现次数审核。文字可能存在于共享库里，**不是已证明执行的分支，不能由错误字符串猜出Main10禁用地址**。

### 关键对照：HEVC Decoder内部也有10bit/SPS文字，但含义不同

下表使用旧0x68000合并区域的相对文件偏移，均位于HEVC Decoder内部：

| 合并区域相对偏移 | 原厂decoder诊断 | 不能偷换的解释 |
|---|---|---|
| **+0x4B5B1** | Bitdepth of AFBC output buffer must be 10-bit because of decoded stream. | **解码输出缓冲区要求10bit**，绝非编码器能输出Main10的证据 |
| **+0x4B5FA** | Bitdepth of AFBC output buffer must be 8-bit because of decoded stream. | 解码器对应的8bit输出要求 |
| +0x4BE0E | stream bitdepth not supported by hardware | 解码侧码流位深的硬件限制报错 |
| **+0x4BE9B** | SPS: Warning: Stream uses more reference frames than profile permits | **解码输入SPS检查**，不是X-S10真实编码出的SPS |
| +0x4B506 | hardware does not support MVE_FORMAT_YUV420_P010 | 同类P010诊断也出现在decoder |

相邻H.264 Encoder同样包含 encoding not supported of this 10-bit input format 与 hardware does not support MVE_FORMAT_YUV420_P010；H.264 Decoder也有10-bit输出错误信息。这说明部分诊断接口跨编解码器共享，不能拿它直接作X-S10独有硬件拒绝或Main10允许的证明。新工具严格防止把HEVC Decoder的SPS/10bit输出文字错归到HEVC Encoder。

## 3. 与真正的CPU 0xBB9、0x121/0x201之间仍然缺少V61代码解码

第36—39阶段已经静态证明双机A32软件：
- VPU参数中bit_depth内部枚举0与非0分别使frame+0x18的ushort选择0x201/0x121，**未证明真实8bit/10bit映射**；
- 72B描述符由CPU作为消息号0x0BB9写软件共享TX队列；CPU软件随后写控制寄存器通知候选；
- H.265 CPU中断回调读取控制区+0x18 bit0、清+0x21C、通知RTOS事件、唤醒VpuReceive，CPU侧软件分派响应。
- **仍缺真正V61消费TX队列的指令及其对frame+0x18字段的解释**。没有原厂V61 ISA/重定位/可执行区边界的可信反汇编，绝不将任意2字节碰巧相等提升为程序xref。

本阶段有界原始字节检查：
- HEVC Encoder中对齐16位值 0x121有**13**个命中、0x201有**12**个、0x0BB9有**5**个；HEVC Decoder分别**6/6/3**。这些只是原始字段与指令数据混合区域中的数值碰撞，**并非已证实的V61格式判断或命令派发地址**。
- 两子映像中均没有完整4字节little-endian字节串（0x48<<16）|0x0BB9=0x00480BB9；也不能据此宣称微码不处理消息，消息码很可能由不同指令方式加载或从队列动态读取。
- encoder中字符串 set-opt encode stream bitdepth: unsupported value 起点+0xE0F8，其低16bit原始数值在前部有界窗口+0x7DCE、+0x7E66各出现一次，后续的raw-u16为0x81CD与0x21CD。另一个nalu format Unknown format文字起点+0xE00D，对应+0x73B8和+0x742C，后续数值0x81CD/0x01CD。这类编码位置值得将来用正确V61 ISA做交叉引用，但有其它同类常量，因此**目前明确标记为“有界字节候选，不是确认的指令引用”**。

## 4. 对X-S10 Main10与4K60的阶段性评估

| 问题 | 已证明的内容 | 未知部分 |
|---|---|---|
| 三机的HEVC编解码固件是否字节一致 | **独立Encoder与Decoder各自SHA都完全一致** | 模块真实运行时是否被不同硬件/权限条件限制 |
| HEVC Encoder是否有10bit/Profile校验文本 | **是，编码器独立映像中存在** | 真正V61校验分支、允许值、能否发Main10的码流 |
| HEVC Decoder有10bit和SPS信息 | **是** | 与X-S10编码成功无直接关系，禁止据此推断 |
| CPU frame+0x18的0x121/0x201 | 双机A32数据流已验证 | V61端对这两个值的格式/位深解释 |
| CPU发送0xBB9与响应事件链 | 双机A32已验证 | V61另一核消费者、真实IRQ/消息接收 |
| GUI MovieCodec最初写Recorder输入+0x5B0 | 尚未找到 | 赋值者、实际模式限制 |
| 4K60持续内录 | 未得到证据 | 传感器/ISP/VPU/录卡全链路 |
| X-S10内录HEVC Main10 | 未得到实机码流证据 | SPS profile和位深、真实硬件接受 |

**关键结论：仍不能宣称解锁10bit/Main10或4K60。**

## 5. 第41阶段离线目标

最有效的下一步是**先确定V61微码ISA/地址布局/重定位表的可解码证据**，然后回到编码器+0xE0F8/+0xF1E4/+0xFCFA/+0xFD2D处的实际校验分支。若能找到接收0xBB9的软件队列消费者，进而验证+0x18格式值的解释和可能的Main10 Profile选择器，才可判断限制是驱动、固件选项还是物理硬件。GPU/ISP/传感器4K60资源单独跟踪。仍不做实机调试与刷写。

## 6. 原创审计与全量回归

Stage40公开仅新增三份原创文件：
- tools/audit_stage40_v61_hevc_image_boundaries.py：三机原厂映像边界、四个独立V61头部元数据和SHA256、两个HEVC独立子模块编码/解码位深、Profile、P010、SPS静态诊断与H.264对照、有限2字节字面碰撞/前阶段证据边界fail-closed检查。
- tests/test_audit_stage40_v61_hevc_image_boundaries.py：**109项纯合成正/反测试**，所有模拟模块由零字节及自制假的描述符和文本/机器字样数据构成，不携带原厂ROM/Ghidra/实体机数据。
- docs/phase40-v61-encoder-decoder-bitdepth-2026-10-18.md：本文。

本机复验（需要已有私有原厂payload，只读执行）：

~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/audit_stage40_v61_hevc_image_boundaries.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

本轮Stage40三机原厂文件审计PASS，第26—40阶段所有历史原厂审计PASS，109项合成测试在本地及隔离public-only目录PASS；仓库追踪91项+本地研究1394项=**1,485项离线测试全部通过**。项目中既有FF80服务探测仅输出No command sent。Git本地main保持clean，原厂固件/私有研究产物仍在忽略的output/，不上传。

**本阶段结论：明确分离了真实HEVC编码器与解码器，防止错把解码器的10bit/SPS信息作为Main10编码支持证据；编码器含独立位深、Profile、P010、协议与硬件拒绝诊断，但实际V61分支与编码能力仍待指令级研究。**
