# 第27阶段：Recorder 当前配置指针的描述符来源（2026-10-15）

> **本轮实证**：X-S10 原厂 3.11 的当前 Recorder 配置缓冲区指针槽 0x02D9C2AC，在 FUN_02214738 中，从上游描述符 0x02D987F8 直接赋值得到。X-T4 2.12 的对应 FUN_02180D0C 则从 0x02D0BF58 赋值到 0x02D0FA0C。两机这对函数的前 21 条 A32 指令中，16 条机器码完全相同，另 5 条仅涉及原始描述符地址或出错调用。**这证实了指针的传递，不代表动态缓冲区里的 Codec 值已确认，更不证明 10-bit/4K60 可用。**

安全：本轮仅分析已授权 Ubuntu 中 X-S10 3.11、X-T4 2.12 原厂解压 X6 和已有 Ghidra 12.1.4 项目，均为只读。用户实机先前报告的 X-S10 版本为 2.10。无 FF80、无 USB、无机身 RAM/闪存写入、无改 DAT、无可刷补丁。

## 1. 新确认的描述符和指针槽

| 对象 | X-S10 3.11 | X-T4 2.12 |
| --- | --- | --- |
| 初始化描述符头基址 | **0x02D987E8** | **0x02D0BF48** |
| 头部期望 Magic | **0x0200** | **0x0200** |
| 头部 +0x0C 原始对象指针字段 | 0x02D987F4 | 0x02D0BF54 |
| **头部 +0x10 当前缓冲区指针字段** | **0x02D987F8** | **0x02D0BF58** |
| 头部 +0x14 辅助缓冲区指针字段 | 0x02D987FC | 0x02D0BF5C |
| 初始化函数 | FUN_02214738 | FUN_02180D0C |
| 运行时主配置指针槽（+0xAC4） | **0x02D9C2AC** | **0x02D0FA0C** |
| 运行时辅助指针槽（+0xAC8） | 0x02D9C2B0 | 0x02D0FA10 |
| Recorder 源快照 Codec 字节（第26阶段） | 0x02D9D834 | 0x02D10F84 |
| GUI MovieCodec 独立全局字节 | 0x01B88650 | 0x01AF2DB8 |

X-S10 的已验证指针值传递链：

~~~text
描述符头 0x02D987E8
   +0x0C → [0x02D987F4] → 写到 0x02D9C2A8  (对象槽 +0xAC0)
   +0x10 → [0x02D987F8] → 写到 0x02D9C2AC  (当前配置指针槽 +0xAC4)
   +0x14 → [0x02D987FC] → 写到 0x02D9C2B0  (辅助配置指针槽 +0xAC8)

*(uint32_t*)0x02D9C2AC → 指向某个当前配置缓冲区（运行时指针值未知）
                                |
                    第26阶段已证明的整块复制
                                v
Recorder 源快照 0x02D9D284
   +0x5B0 → Codec 字节 0x02D9D834 （当前内容值未知）
   +0x5B1 → Format 字节 0x02D9D835（当前内容值未知）
~~~

第二条缓存来源只是动态**指针值**，不是把 GUI Codec byte 写入目标指针。第26阶段另一个入口 FUN_022069D0 通过调用参数提供输入，不保证使用该 +0xAC4 槽位。

## 2. 完全复核原始 A32 地址关系与事件上游

X-S10 初始化函数 FUN_02214738 关键指令：

- 0x02214744/48：MOVW/MOVT R3 构建描述符 0x02D987E8。
- 0x0221474C/50：LDRH R1,[R3] 和 CMP R1,#0x200 验证描述符标记。
- 0x02214754：BEQ 0x02214764。若标记不符则进入报错事件 0x901C + 自环，此处**不是**编码格式的选择条件。
- 0x02214764/68：再次构造同一描述符基址。
- 0x0221476C/70/74：LDR [R3,#0x0C] → ADD R2,R3,#0x3000 → STR [R2,#0xAC0]。
- **0x02214778/7C：LDR R1,[R3,#0x10] → STR R1,[R2,#0xAC4]**；最终目的地正是 0x02D9C2AC。
- 0x02214780/84：头部 +0x14 → 运行时辅助指针槽 +0xAC8。

X-T4 匹配的 FUN_02180D0C 在 0x02180D18/1C 构造描述符 0x02D0BF48、0x02180D20/24 验证同一 0x200 magic，0x02180D28 BEQ。其最重要的**0x02180D4C/50** 同样把头部 +0x10 复制到 R2+0xAC4，X-T4 的目的地为 0x02D0FA0C；头部 +0x14 由 0x02180D54/58 送入辅助 +0xAC8 槽位。

这两段函数原始 Section2 的前 **0x54 字节 = 21 个 A32 指令字**，实测仅偏移 **+0x0C、+0x10、+0x24、+0x2C、+0x30** 的机器码不同（两组描述符 MOVW/MOVT 立即数、一个错误处理 BL）；其余 **16 条完全相同**。因此不能把 10-bit 限制直接归因于上述指针槽初始化本身。

已复验两条上游初始化事件：

- X-S10：FUN_021DA63C 的 0x021DA66C，以及 FUN_021E842C 的 0x021E844C，都指向 FUN_02214738。
- X-T4：FUN_02143EE4 的 0x02143F14，以及 FUN_021529B8 的 0x021529D8，都指向 FUN_02180D0C。

四个 A32 BL 均直接从原始 Section2 指令位移推导，并对照本地 Ghidra CALL xrefs 和反编译正文。

## 3. 没找到动态 Codec 值生产者，不能把其他 +0x5B0 错判成 Recorder 写入

针对完整 X6 静态地址引用：

| 目标 RAM 字段 | Ghidra 静态引用总数 | 直接 WRITE xref |
|---|---: |---:|
| X-S10 当前配置指针槽 0x02D9C2AC | 521 | **1**（0x0221477C） |
| X-T4 当前配置指针槽 0x02D0FA0C | 555 | **1**（0x02180D50） |
| X-S10 原始头字段 0x02D987F8 | 111 | **0** |
| X-T4 原始头字段 0x02D0BF58 | 111 | **0** |

头字段 0 个直接 WRITE xref 并不等于它没有写入者：可能通过整块结构复制、别名指针、其他处理器传输等生成。此前第26阶段已经证实了一个反例：Recorder 源基址零个直接 WRITE xref，但确实存在原始 memcpy 写入路径。因此此处只限定为**已选 Ghidra 映像中的直接静态引用**，并不推断没有运行时写入。

在原厂 Section2 中用 ARM opcode 语义而不是纯字符串查找带立即数的 STRB [Rn,#0x5B0]：X-S10 9 个，X-T4 39 个。对主要候选反编译后，这些偏移有的是独立的菜单数据、局部或大尺寸对象，不足以把任意 Rn 寄存器与当前 Recorder 主指针等同。**这两个数量不代表支持的编码格式或能力。**

还发现一个容易混淆的地方：X-T4 初始化器调用 FUN_022235A0 时存在 iVar5 +0x5B0，但 iVar5 是从对象**+0xAC8 辅助指针槽**读取，而不是 Recorder 主要源配置所用的 **+0xAC4 当前指针槽**；X-S10 匹配函数的辅助指针处理则使用 +0x344/+0x34C 等偏移。这是不同辅助结构的差异，不能仅凭相同 +0x5B0 偏移就声称 X-T4 存在可移植的 Main10 开关。

## 4. 离线复验脚本与单元测试

原创可公开文件：

- tools/audit_profile_pointer_origin_stage27.py —— 原始 Section2 中直接复核 MOVW/MOVT、LDRH/CMP、BEQ、自环、三组 LDR/STR、+0x3000 ADD、四条上游 BL 和地址计算；比对两机前 21 个 A32 机器字、读取 Ghidra 直接 WRITE/READ xref 基线，输出未知状态和原始立即数字节写入候选数量。
- tests/test_audit_profile_pointer_origin_stage27.py —— **51 项完全合成的正反测试通过**，包括误把 +0xAC8 当主槽、错误寄存器、描述符标记失效、原始字节分叉、错误事件 BL、静态 xref 缺失/新增等。合成测试不包含原厂固件。

留在 Ubuntu 忽略的 output/ 下的**私有、不上传**日志：

- xs10/xt4_stage27_buffer_slot_access.log
- xs10/xt4_stage27_profile_header_xrefs.log
- xs10/xt4_stage27_initializer_helpers.log
- xs10/xt4_stage27_pointer_init_callers.log
- xs10/xt4_stage27_pointer_init_callsite_context.log
- xs10/xt4_stage27_strb_5b0_candidates.log

使用 Ghidra 12.1.4 的 analyzeHeadless：-process section-1.bin -noanalysis -readOnly。私有扫描 Java 文件 ProbeRecorderBufferSlotAccess.java 和 AuditOffsetStoreSites.java 没有上传，原厂固件、Ghidra 项目、反编译日志也不上传。

复验：

~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/audit_profile_pointer_origin_stage27.py --output output
python3 tools/audit_snapshot_bulk_writers_stage26.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

原厂 X-S10 3.11、X-T4 2.12 审计已通过；新增 **51** 项，之前已有的公开 91 项 + 私有目录旧有 220 项（含第26阶段 48 项），现在总计 **91+271=362 项离线单元测试通过**。测试和静态路径不能替代真实 Main10 SPS、10-bit 文件、4K60 Sensor/ISP 与持续写卡能力。

## 5. 下一轮精确目标

下一阶段应追查 X-S10 描述符 0x02D987F8 的**初始缓冲区指针来源**，及实际缓冲区 +0x5B0/+0x5B1 的写入/规范化代码，优先寻找整块初始化、消息反序列化、其他模块共享结构与真实指针别名，必须经过原始指令和 Ghidra 数据链复核。X-T4 的对应源 0x02D0BF58 是有用的正对照。

当前没有 GUI MovieCodec (0x01B88650) → 动态当前配置缓冲区 Codec 字节的证明，无法提出安全可刷的补丁；10-bit、4K60 仍未解锁。继续只读离线研究。
