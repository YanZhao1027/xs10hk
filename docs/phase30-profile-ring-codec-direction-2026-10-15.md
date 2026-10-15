# 第30阶段：追回配置指针缓存写入，并明确 Codec 字节的实际赋值方向（2026-10-15）

> **本轮最重要的新发现**：X-S10 3.11 和 X-T4 2.12 的 0x206 动态配置记录，确实可以**从当前描述符复制进一组由计数器管理的记录**；注册表读取同一动态数组时使用 (count−1) 作为最近记录下标。但是**0x206 / 子选项 0x8C 的普通保存入口，与其 0x8C 读取入口并不落在同一条数据记录上**。另一方面，原始 ARM 的 LDRB/STRB 已验证，Codec/Format +0x5B0/+0x5B1 的一条明确赋值链为 **Recorder 活跃配置 → 独立输出指针槽指向的缓冲区**，不是菜单或当前输入缓冲区 → Recorder。至此“记录字段赋值方向”更加明确，但**尚未找到 GUI MovieCodec → Recorder 当前输入缓冲区 +0x5B0 的代码证明**。

范围：只读处理用户 Ubuntu 中现成的 X-S10 **3.11**、X-T4 **2.12** 原始已解压 X6 及 Ghidra 12.1.4 项目；机主上次描述的真实 X-S10 版本为 **2.10**。全程没有向相机发送 FF80/USB 指令、没有机身 RAM/闪存读写、没有修改 DAT 或生成可刷固件。所有固件/Ghidra 原始日志只存在本地被忽略的 output/，不提交 GitHub。

## 1. 找到配置记录的实际写入：描述符 → 类型 0x206 动态记录

| 对象 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 当前描述符头 | 0x02D987E8 | 0x02D0BF48 |
| 描述符 +0x0C 载荷 | 0x02D987F4 | 0x02D0BF54 |
| 描述符 +0x10 主缓冲区指针字段 | **0x02D987F8** | **0x02D0BF58** |
| 将描述符保存到记录的分派函数 | **FUN_021F8100** | **FUN_0216417C** |
| 类型 0x206 动态记录头部数组基址 | **0x02D98A68** | **0x02D0C1C8** |
| 动态记录载荷数组基址 | **0x02D98A74** | **0x02D0C1D4** |
| 动态记录计数变量 | **0x02D9C2A4** | **0x02D0FA04** |
| 条目步长 | **0x50 字节** | **0x50 字节** |
| 记录头部 / 名义载荷 | 0x0C / 0x44 字节 | 0x0C / 0x44 字节 |

Ghidra 保存函数均在描述符类型为 **0x206**、特定子选项为 **0x11B 或 0x11E** 时执行：

~~~text
idx = count
target_header = RING_HEADER + idx * 0x50
target_payload = RING_PAYLOAD + idx * 0x50
count = count + 1

memcpy(target_header, CURRENT_DESCRIPTOR, 0x0C)
memcpy(target_payload, CURRENT_DESCRIPTOR + 0x0C,
       *(uint32_t *)(CURRENT_DESCRIPTOR + 0x04))
~~~

**这是真实固件里的条件式赋值机制，不是证明它已经在实机执行。** 上述载荷复制长度来自描述符 +0x04 的运行时字段。描述符主配置指针位于载荷起点相对 +4，只有长度 >=8 才完整覆盖四字节主缓冲区指针。

第29阶段已经验证的 **0x206 / 子选项 0x8C** 注册表读取链：

~~~text
last_index = count − 1
selected_header = RING_HEADER + last_index * 0x50
selected_payload = RING_PAYLOAD + last_index * 0x50

memcpy(CURRENT_DESCRIPTOR, selected_header, 0x0C)
memcpy(CURRENT_DESCRIPTOR + 0x0C, selected_payload,
       *(uint32_t *)(selected_header + 0x04))
~~~

最后这条链为**注册表 → 当前描述符**，保存链则是**当前描述符 → 注册表**。它们在代码层面使用同一个 0x206 动态数组和计数器；但没有证明运行时的执行顺序、计数器值、拷贝长度、条目有效性或真实的四字节指针。

**严重要避免的误判**：FUN_021F8100/FUN_0216417C 在类型 0x206 且**普通子选项 0x8C** 的**保存**分支会使用另一块固定内存：

| 数据方向 | X-S10 | X-T4 |
|---|---|---|
| 0x206/0x8C **普通保存**载荷目的地 | **0x02D9B314** | **0x02D0EA74** |
| 0x206/0x8C **读取（param_3=1）**源载荷 | **0x02D98A74 + (count−1)×0x50** | **0x02D0C1D4 + (count−1)×0x50** |

上面这两处**不是同一块缓冲区**。不能误把 0x8C 保存直接视为最近动态记录的生产者。特殊 0x11B/0x11E 才有已找到的动态插入代码。尚未证明哪些事件真的把当前描述符设为这些特殊子选项并运行保存。

类型 **0x207** 与此不同：已确认普通保存和对应注册表读取都使用同一组固定记录，X-S10 头部/载荷分别是 **0x02D9B358 / 0x02D9B364**，X-T4 是 **0x02D0EAB8 / 0x02D0EAC4**。这只说明复制位置一致，并没有读取到实际 Codec 内容。

## 2. 0x206 记录不是 Codec 数据本体，计数器也不是只增不减

两机 0x206 动态记录以 **0x50 字节**为步长，包含一个 0x0C 字节头部和约 0x44 字节的管理载荷（清理例程使用 0x44）。这个结构**不可能直接按自身 +0x5B0 偏移容纳完整 Recorder Codec 字段**；相关的是载荷中的**四字节指针**，它指向另一份运行时配置结构。在当前没有指针真实值与对象分配来源时，不能凭相同地址偏移推定 codec producer。

对计数变量的原始 Ghidra 静态引用分析：

| 对象 | X-S10 | X-T4 |
|---|---:|---:|
| 计数器 Ghidra xrefs | **34** | **38** |
| 直接 WRITE xrefs | **5** | **5** |
| 保存代码中递增计数的 ARM STR 指令 | **0x021F8474** | **0x021644F0** |
| 清理/撤销最近记录 | FUN_021F921C | FUN_02165298 |
| 压缩记录、移动后续条目 | FUN_021FB3F8 | FUN_021674C8 |
| 按条目标识删除/移动记录 | FUN_021FB77C | FUN_0216784C |

这些函数对条目进行 0x44 字节清理、0x0C/0x18 字节结构复制、0x50 字节跨条目移动和计数递减。因此**不能将 count 永远看作单调增长的“录像配置保存次数”**。这里没有实机计数上限、边界防护和运行时一致性的证明；静态直接 WRITE xrefs 的数量也不排除间接写入。

注意：这组 **0x50 字节的类型 0x206 动态记录**不是第28阶段找到的**16 个每条 0x54 字节的描述符缓存记录**，二者结构、入口和用途不同，不能混为一谈。

## 3. 原始 A32：明确识别“向外导出 Codec”的反向赋值

在本轮所有 X-S10 / X-T4 带 +0x5B0 字节写入的候选中，最容易被误以为是 Recorder 输入 Codec setter 的一对函数，其真实方向如下。

| 项目 | X-S10 | X-T4 |
|---|---|---|
| 输出序列化函数 | **FUN_012BE684** | **FUN_01296D38** |
| Codec **来源**：Recorder 活跃全局字节 | **0x01C25208** | **0x01B83974** |
| Format **来源**：活跃全局字节 | **0x01C25209** | **0x01B83975** |
| Codec **输出** | 传入指针 param_1 的 +0x5B0 | 同左 |
| Format **输出** | 传入指针 param_1 的 +0x5B1 | 同左 |
| 传入输出指针的 RAM 槽位 | **0x035BD868** | **0x03672078** |
| 调用者 | FUN_0221D1BC | FUN_02189BD4 |
| 序列化调用原始 ARM BL 位置 | **0x0221D298** | **0x02189CB0** |

独立读取原厂 Section1 的连续四个 A32 指令字：

- X-S10 **0x012BEB8C**：LDRB R3,[R5,#0x430]；**0x012BEB90**：STRB R3,[R4,#0x5B0]；
- X-S10 **0x012BEB94**：LDRB R3,[R5,#0x431]；**0x012BEB98**：STRB R3,[R4,#0x5B1]；
- X-T4 **0x01297250**：LDRB R3,[R5,#0x434]；**0x01297254**：STRB R3,[R4,#0x5B0]；
- X-T4 **0x01297258**：LDRB R3,[R5,#0x435]；**0x0129725C**：STRB R3,[R4,#0x5B1]。

Ghidra 原始反编译独立显示相同含义：param_1[0x5b0] = DAT_ACTIVE_CODEC; param_1[0x5b1] = DAT_ACTIVE_FORMAT。上游 caller 则从各自的 **0x035BD868 / 0x03672078 指针槽位**取得 param_1 再调用。

**确定的赋值方向是 Recorder 活跃 Codec/Format → 输出序列化缓冲区，而不是 GUI Codec → 当前主配置缓冲区。** 输出指针槽位与主配置输入指针槽位（X-S10 **0x02D9C2AC** / X-T4 **0x02D0FA0C**）地址不同；但我们也**不能静态证明运行时两个槽位中的指针值必然不同**。因此只是“没有证明与输入缓冲区是同一对象”，并非“已经排除所有运行时别名”。

还有其它 +0x5B0 同偏移函数，如 X-S10 FUN_012BD150、FUN_012C1EF4、FUN_0227AE8C、FUN_022C904C、FUN_020D7CC4 等。部分操作的是具有 +0x613、+0x9B5、+0x3FB3、+0xADDC 等高偏移字段的更大结构，部分是 Recorder 状态导出或布尔字段；并**无**经原始指针链验证的“它们就是当前主录像输入缓冲区”的证据。单凭偏移数值相同，不可移植地视为解锁入口。

## 4. 有界三目标交集筛查：没有同函数直接 xref，但不代表没有间接数据流

新增的 Ghidra 私有只读脚本对三类全局精确字节/槽位做函数级静态 xref 交集：

| 静态目标 | X-S10 | X-T4 |
|---|---:|---:|
| GUI eModeMovieCodec 字节 | **0x01B88650**（6 xrefs） | **0x01AF2DB8**（7 xrefs） |
| Recorder 活跃 Codec 字节 | **0x01C25208**（2 xrefs） | **0x01B83974**（2 xrefs） |
| 当前配置输入指针槽 | **0x02D9C2AC**（521 xrefs） | **0x02D0FA0C**（555 xrefs） |
| 三组两两共享直接引用的同一函数数 | **均为 0** | **均为 0** |

这里是**静态 Ghidra xref 交集**，只筛查“单函数直接同时引用两个精确符号”；通过调用链、参数、结构体别名、动态偏移、配置消息和 memcpy 跨多个函数的数据流都不会被完整覆盖。**绝不能把这三个零解释成不存在赋值者**：第26阶段已经证明 Ghidra WRITE xref 为零的源码区域也有真实 memcpy 写入。

对 FUN_021F8100 与 FUN_0216417C 的调用者反编译另做了有界扫描：X-S10 93 个静态调用引用涉及 92 个成功反编译的函数，X-T4 100 引用、99 个成功反编译函数。该保存函数没有函数参数，读取的是当前全局描述符，因此仅靠调用 C 文本无法给出 “一定以 0x206/0x11B 成功插入” 的运行时结论。

## 5. 原始二进制、工具与测试校验

本轮原创、可公开的审计工具：

- tools/audit_profile_ring_codec_direction_stage30.py：仅读取 Ubuntu 私有原厂 Section1/Section2 和此前生成的 Ghidra 日志；逐条验证描述符 → 保存记录的 memcpy、动态保存/恢复分叉、计数器与删除、静态 0x207 相同存储、原始 ARM Codec/Format 导出字节、调用者输出指针槽位，并显式将所有未证实解锁状态设为 False。
- tests/test_audit_profile_ring_codec_direction_stage30.py：**53 项完全合成**的 ARM 正/反测试。包含原始目的地反转、指针不一致、错误分支、错误读写偏移、错误 copy length、错误 count、假阳性 GUI→Codec xref 等。没有原厂固件、用户内存或相机密钥。

只保留在 Ubuntu 被 Git 忽略 output/ 的私有证据（不提交）：

- xs10/xt4_stage30_registry_record_field_refs.log
- xs10/xt4_stage30_profile_ring_push_callers.log
- xs10/xt4_stage30_registry_ring_counter_xrefs.log
- xs10/xt4_stage30_dynamic_ring_counter_writers.log
- xs10/xt4_stage30_serializer_entrycallers.log
- xs10/xt4_stage30_direct_5b0_writer_contexts.log 或其 XT4 已存在的偏移扫描日志
- xs10/xt4_stage30_codec_triad_xrefs.log
- xs10/xt4_stage30_remaining_byte_writer_calls.log
- xs10/xt4_stage30_remaining_byte_writer_callers.log
- stage30_ring_codec_direction_result.jsonlog

Ghidra 12.1.4 analyzeHeadless 使用 -process section-1.bin -noanalysis -readOnly。Java 辅助扫描脚本只在本地 output/ 下。

重现命令：

~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/audit_profile_ring_codec_direction_stage30.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

**实际通过**：新53项合成测试，原有91项仓库测试与448项本地测试（含此次新增）= 累计 **539 项离线单元测试通过**（91+448）。另第26—29阶段原厂二进制审计全部重新通过。每项合成测试只验证审计代码的正确性，不代表真实相机可录 10-bit/4K60。

## 6. 下一步剩余“真正的 Codec 输入赋值”问题

当前可以表示为：

~~~text
GUI eModeMovieCodec 0x01B88650
        |
        | [尚未找到跨设置服务的真实前向赋值/序列化]
        v
某个实际 Recorder 输入缓冲区的 [+0x5B0/+0x5B1]  ← 具体运行时指针及值仍未知
        |
        | [第26阶段已证明当前指针读取及整块复制]
        v
Recorder 源快照 Codec 0x02D9D834
        |
        v
Recorder 活跃 Codec 0x01C25208
        |
        | [第30阶段已验证的反向输出序列化]
        v
另一指针槽 0x035BD868 指向的输出缓冲区 +0x5B0
~~~

另有独立的模式记录/当前描述符来源链：

~~~text
类型206 的动态记录 [header 0x02D98A68 + n*0x50]
     ↑ 特殊子选项11B/11E保存当前描述符，动态长度条件
     ↓ 类型206/0x8C从(count-1)最近记录读到当前描述符，动态长度条件
描述符 0x02D987E8 / 主指针字段 0x02D987F8
     ↓ [第27阶段的指针复制到对象+0xAC4]
当前输入指针槽 0x02D9C2AC
     ↓
输入缓冲区（内部 Codec 值来源未证明）
~~~

**优先研究主指针 +0x10 的真实初始化来源、选中记录的运行时载荷长度，以及输入缓冲区的真实分配/字段填充函数；不要再把相同的 +0x5B0 偏移当成源地址身份。** 如无安全救砖和完整固件重签名路径，不进行实机补丁。HEVC Main10 的真正内录需要实际编码比特流/SPS 证据，4K60 还需 Sensor/ISP/VPU/写卡链路独立核实。本阶段均未解锁。
