# 第26阶段：找到了 Recorder 原始配置 Codec 字节的整块写入者（2026-10-15）

> 新发现：离线确认在 X-S10 原厂 3.11 中至少有 **3 条**，在 X-T4 原厂 2.12 中至少有 **1 条**真实的整块内存复制调用，会向 Recorder 的原始配置快照写数据，而且复制范围确实覆盖 Codec (+0x5B0) 与 Format (+0x5B1)。这解释了为何之前查单独 STRB 和静态 WRITE xref 没找到源字节写入者。**仍不知道配置输入缓冲区 Codec 值由谁填写、是否来自 GUI MovieCodec，不能断言内录 Main10 或 4K60 可行。**

安全和版本：只分析获授权的 Ubuntu 上已有的原厂解压 X6 和 Ghidra 12.1.4 工程，均为只读。用户实机历史 X-S10 是 2.10，而静态地址基于 3.11。未发送 FF80 指令、没有相机 RAM/闪存读写、没有 DAT 修改、没有可刷补丁。

## 1. 已验证的 Recorder 源快照覆盖路径

| 结构 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| Recorder 源快照基址 | 0x02D9D284 | 0x02D109D4 |
| 源 Codec 字节 | 0x02D9D834 | 0x02D10F84 |
| 源 Format 字节 | 0x02D9D835 | 0x02D10F85 |
| 当前配置缓冲区指针所在的 RAM 槽位 | 0x02D9C2AC | 0x02D0FA0C |
| 当前配置管理对象基址 | 0x02D9B7E8 | 0x02D0EF48 |
| 该对象中的缓冲区指针偏移 | +0xAC4 | +0xAC4 |
| 复制例程 | FUN_012A9148 | FUN_01281848 |
| 已确认的完整快照写入路径 | 3 条，每条 0x5DC B | 1 条，0x5D8 B |

这些是已找到的写入路径，不是全部路径的上界。这里的写入目标**不是**第23阶段的 GUI Codec 全局（X-S10 0x01B88650 / X-T4 0x01AF2DB8）。

X-S10 原始固件中，目的地指针常量地址 0x02216B28、0x02206A7C、0x0221239C 均直接包含 0x02D9D284。X-T4 的目标常量地址 0x02184FD4 直接包含 0x02D109D4。

复制例程 FUN_012A9148 / FUN_01281848 自身已经反编译验证：从第二参数逐字节或逐字读取，写入第一参数。不是仅仅根据函数名称猜测 memcpy。

## 2. X-S10 的三条已确认写入

| 函数 | 原始 A32 复制 BL 地址 | 复制输入 | 原始字节数 |
|---|---|---|---|
| FUN_02216AD8 | 0x02216B1C | *(uint32_t*)0x02D9C2AC 指向的当前配置缓冲区 | 0x5DC |
| FUN_022069D0 | 0x022069E8 | 调用方传入且非空的缓冲区指针 | 0x5DC |
| FUN_02212304 | 0x02212338 | *(uint32_t*)0x02D9C2AC 指向的当前配置缓冲区 | 0x5DC |

前两条分别由 0x021E29C0 → FUN_02216AD8 和 0x0220626C → FUN_022069D0 触发。第三条由 FUN_021DA508 中的两条条件调用 0x021DA584、0x021DA5D4 触发。

第一条从 0x02216B24 的 A32 PC 相对 LDR 取到管理对象地址 0x02D9B7E8，然后执行 LDR R1,[R3,#0xAC4] 读取源配置指针。第三条经 MOVW/MOVT 和 ADD +0x3000 重构相同管理对象地址，再读相同 +0xAC4 指针槽位。因此这两条函数**共享同一个 RAM 指针槽位**：0x02D9B7E8 + 0xAC4 = 0x02D9C2AC。

FUN_022069D0 的源是传入参数。已由原始 SUBS R1,R0,#0 与 BEQ 0x02206A74 确认：源指针为零时绕过复制。还不能把这条输入指针也归因于 GUI 或同一配置缓冲区。

## 3. X-T4 的对照

X-T4 的 FUN_02184F00 在 0x02184F34 BL 到 FUN_01281848。原始 MOVW/MOVT/ADD 指令推导：

~~~text
MOVW/MOVT R4 = 0x02D0BF48
ADD R3,R4,#0x3000 → 0x02D0EF48
LDR R1,[R3,#0xAC4] → 读取位于 0x02D0FA0C 的配置缓冲区指针
LDR R0,[PC,...] → 0x02D109D4 （Recorder 源快照）
MOVW R2,#0x5D8
BL 0x01281848
~~~

此路径由两个上游函数 FUN_02139B58、FUN_02139CC0 的分支分别通过 0x02139C80、0x02139DE8 进入，具体执行要满足上游条件，不能声称无条件写入。

两机复制长度都覆盖 +0x5B0/+0x5B1，但 X-T4 和 X-S10 的路径、复制长度和事件触发条件不同；这些差异本身不证明 Main10 机型限制。

## 4. 为什么此前零个 WRITE xref 却仍存在真实写入

对**精确的源快照基址**做 Ghidra 静态引用统计：

| 类型 | X-S10 | X-T4 |
|---|---:|---:|
| 总引用数 | 113 | 119 |
| 涉及函数数 | 51 | 53 |
| PARAM | 93 | 99 |
| READ | 13 | 13 |
| DATA | 7 | 7 |
| WRITE | 0 | 0 |

本阶段却恢复了通过参数指针进行的整块内存复制。**单个 RAM 字节或基址的 WRITE xref 为空，不意味着该 RAM 没有写入者。** 还可能通过 memcpy、未恢复的别名、指针容器、DMA 等方法发生写入。

合计核验了 **4 条复制 BL + 6 条上游事件调用 BL = 10 个原始 ARM 调用目标**；此外复核了 PC 相对指针常量、LDR 源间接寻址、MOVW/MOVT、ADD 旋转立即数与真实 memcpy 参数方向。

## 5. 真正没有追通的一段

~~~text
X-S10 GUI eModeMovieCodec: 0x01B88650
                   │
                   └── 目前仍未找到有证据的赋值/序列化边
                                    ↓
当前配置缓冲区指针槽位: 0x02D9C2AC
缓冲区中 +0x5B0 / +0x5B1 的实际值: 未知
                                    │
                      整块复制（本阶段已证实）
                                    ↓
Recorder 源 Codec/Format: 0x02D9D834 / 0x02D9D835
                                    │
                          第20/25阶段已验证
                                    ↓
Recorder active Codec/Format: 0x01C25208 / 0x01C25209
~~~

为继续找上游，本轮还将 Ghidra 反编译扫描扩展到配置缓冲区指针槽位：X-S10 0x02D9C2AC 有 521 个 xrefs，涉及可反编译的 325 个函数；X-T4 0x02D0FA0C 有 555 个 xrefs，涉及 343 个函数。只搜索反编译文本中的字面 +0x5B0/+0x5B1 与设置 ID：X-S10 0 处直接匹配，X-T4 1 处匹配，但 X-T4 所在函数 FUN_02180D0C 使用的是另一个结构指针槽 +0xAC8，不足以证明当前配置缓冲区 +0xAC4 的 codec 被写入。

**这是有界的静态字符串/字面扫描，绝不等于排除了间接写入或复制。** 运行时缓冲区指针的具体值未知，+0x5B0 的实际值也未知。

## 6. 本轮原创代码、测试和离线证据

公开原创文件：

- tools/audit_snapshot_bulk_writers_stage26.py：离线检查原始 Section2 指令字和目标地址常量、调用 BL、PC LDR、MOVW/MOVT、ADD、+0xAC4 指针寻址、复制长度及 helper 方向，并报告所有未证实能力。
- tests/test_audit_snapshot_bulk_writers_stage26.py：**48 项合成单元测试通过**，覆盖错误的原始 A32 操作、目的地、尺寸、来源、分支、上游 xrefs、复制方向和静态扫描误判等。合成代码不含厂商固件数据。

仅保存在授权 Ubuntu、未上传 GitHub 的私有 output/ 日志：

- xs10/xt4_stage26_source_base_writer_candidates.log
- xs10/xt4_stage26_source_holder_functions.log
- xs10/xt4_stage26_memcpy_source_ops.log
- xs10/xt4_stage26_writer_upstream_refs.log
- xs10/xt4_stage26_bulk_writer_callers.log
- xs10/xt4_stage26_live_buffer_codec_field_scan.log

Ghidra 12.1.4 analyzeHeadless 使用 -process section-1.bin -noanalysis -readOnly，利用已有 TraceX6Function.java、ProbeX6Refs.java 和仅本地保存的 SnapshotWriterCandidates.java、AuditLiveConfigBufferFields.java 完成。

复验命令：

~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/audit_snapshot_bulk_writers_stage26.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

实际两机原始固件审计均通过。旧有 91 项仓库测试 + 172 项忽略目录测试 + 第26阶段新增 48 项 = **311 项离线测试全部通过**。测试不代表实机编码能力。

## 7. 下一轮目标与实机边界

优先回溯 X-S10 当前配置缓冲区指针槽位 0x02D9C2AC 的**具体实例与 +0x5B0 字节写入点**，判断 GUI MovieCodec 是否参与，以及是否有机型过滤/强制 H.264 的分支。X-T4 0x02D0FA0C 做同类正对照。

在证明可从菜单到 Recorder 缓冲区写入有效 Codec 值，进一步拿到 HEVC Main10 编码参数和实际 10-bit bitstream 证据之前，不能宣称 10-bit 已经能内录。4K60 仍需另查 Sensor/ISP/VPU/持续写卡链。**没有安全可刷的固件、没有独立救砖保障；继续保持离线分析。**
