# 第31阶段：Recorder 输入指针与输出指针之间的真实赋值（2026-10-16）

> **本轮的新证据**：在 X-S10 原厂 3.11 与 X-T4 原厂 2.12 中，确认存在对 Recorder 当前输入配置缓冲区的**指针值复制**：从当前输入指针槽读取 32-bit 地址，写入导出配置指针槽。随后同一个上层函数的成功路径中，会调用 Recorder 状态序列化函数，后者将活跃 Codec / Format 写入导出缓冲区 +0x5B0 / +0x5B1。这个发现建立了“Recorder 活跃状态 → 可能是当前输入缓冲区的导出目标”的**有条件反馈路径**，但没有证明两槽位在序列化执行时仍保存同一指针值，更没有证明 GUI MovieCodec 如何为 Recorder 设置最初的 Codec 值。

安全范围：本轮仅在获授权 Ubuntu 中对已有原厂 X-S10 v3.11、X-T4 v2.12 解压 X6 与 Ghidra 12.1.4 read-only 工程分析。机主此前报告的实机 X-S10 是 v2.10；不同固件地址不能直接套用。没有相机 USB/FF80 指令、机身 RAM/闪存读写、DAT 修改、固件补丁或刷机。私有原厂解压文件和 Ghidra 日志保持在 Git 忽略的 output/ 目录，不上传。

## 1. 指针槽的两个方向必须分清

| 结构 / 地址 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 描述符头基址 | 0x02D987E8 | 0x02D0BF48 |
| 描述符内当前指针字段 +0x10 | 0x02D987F8 | 0x02D0BF58 |
| **Recorder 当前输入指针槽** | **0x02D9C2AC** | **0x02D0FA0C** |
| **Recorder 导出指针槽** | **0x035BD868** | **0x03672078** |
| 指针值复制函数 | FUN_0221C934 | FUN_02189348 |
| 成功门控的上层调用者 | FUN_021CDF80 | FUN_0213754C |
| Recorder 配置序列化 | FUN_0221D1BC | FUN_02189BD4 |
| 活跃 Codec/Format 导出函数 | FUN_012BE684 | FUN_01296D38 |
| 活跃 Codec 字节地址 | 0x01C25208 | 0x01B83974 |
| 活跃 Format 字节地址 | 0x01C25209 | 0x01B83975 |

原厂代码的真正**赋值方向**为：

~~~c
// X-S10 FUN_0221C934
*(uint32_t *)0x035BD868 = *(uint32_t *)0x02D9C2AC;

// X-T4 FUN_02189348
*(uint32_t *)0x03672078 = *(uint32_t *)0x02D0FA0C;
~~~

这些表达式的左、右是**不同的 RAM 指针槽位**，而它们内部保存的**指针值在赋值指令刚执行完时相同**。这项原始 ARM 硬证据解释了之前两个不同地址的导出与输入缓冲区为何可能指向同一数据对象。

## 2. 已复核的原始 A32 指令，而非名称相似的猜测

X-S10 的指针赋值函数 FUN_0221C934：

- 0x0221C93C / 0x0221C940：MOVW/MOVT R2 = 0x035BD860；
- 0x0221C944 / 0x0221C948：MOVW/MOVT R3 = 0x02D987E8；
- 0x0221C94C：ADD R1,R3,#0x3000；
- **0x0221C950：LDR R1,[R1,#0xAC4] → 读取槽 0x02D9C2AC 的内容**；
- **0x0221C954：STR R1,[R2,#8] → 写入槽 0x035BD868**。

X-T4 的对应实现 FUN_02189348：

- 0x02189350 / 0x02189354：MOVW/MOVT R2 = 0x03672070；
- 0x02189358 / 0x0218935C：MOVW/MOVT R3 = 0x02D0BF48；
- 0x02189360：ADD R1,R3,#0x3000；
- **0x02189364：LDR R1,[R1,#0xAC4] → 槽 0x02D0FA0C**；
- **0x02189368：STR R1,[R2,#8] → 槽 0x03672078**。

两个模型各 7 条地址构建与加载/存储指令，共核验 14 个原厂 A32 指令字。Ghidra C 独立反编译显示：X-S10 的 _DAT_035bd868 = _DAT_02d9c2ac;，X-T4 的 _DAT_03672078 = _DAT_02d0fa0c;，与机器码方向一致。

## 3. 上层门控流程：初始化指针在先，导出 Codec 在后

X-S10 FUN_021CDF80 中：

~~~text
FUN_021F8100()              配置记录保存（此前阶段）
    ↓
FUN_0221C934()              导出指针槽 = 当前指针槽的值
  BL at 0x021CDF8C
    ↓
若干操作、四轮成功性判断
    ├─ 任一失败则返回 0
    └─ 成功路径：
           FUN_0221D1BC()
             BL at 0x021CE0F4
                  ↓
           FUN_012BE684(iVar3)
             BL at 0x0221D298
             iVar3 取自输出指针槽 0x035BD868
                  ↓
           输出缓冲区 +0x5B0 = 活跃 Recorder Codec
           输出缓冲区 +0x5B1 = 活跃 Recorder Format
~~~

X-T4 上层 FUN_0213754C 中同构的顺序为：0x02137558 BL→FUN_02189348，随后有条件的 0x021376C0 BL→FUN_02189BD4，再由 0x02189CB0 BL→FUN_01296D38。

从两份原始 Section1 读取 4 个关键 LDRB/STRB 字节操作：

| 功能 | X-S10 | X-T4 |
|---|---|---|
| Codec 从 active 读出 | 0x012BEB8C：LDRB [R5,#0x430] | 0x01297250：LDRB [R5,#0x434] |
| Codec 向输出写入 | **0x012BEB90：STRB [R4,#0x5B0]** | **0x01297254：STRB [R4,#0x5B0]** |
| Format 从 active 读出 | 0x012BEB94 | 0x01297258 |
| Format 向输出写入 | 0x012BEB98：STRB [R4,#0x5B1] | 0x0129725C：STRB [R4,#0x5B1] |

**严谨边界**：在初始化指针值复制与后续序列化之间，可能存在其他操作或通过别名修改任一指针值。我们尚未穷尽这些间接修改，也无法静态确认完整路径在实机上的执行情形。因此只能推论：**若指针值维持相等，该输出配置序列化会把活跃 Codec 写回当前输入配置缓冲区**。既不能把它写成无条件完成的实机操作，也不能倒置方向，声称它会从菜单产生 Recorder 输入初值。

## 4. GUI MovieCodec 缓存是另一路已证实的赋值

本阶段再次沿原始 GUI setter 的调用方向追查：

| GUI 相关项 | X-S10 | X-T4 |
|---|---|---|
| 设置服务编号 | **0x3FC** | **0x3E5** |
| 从设置服务读取该编号的函数 | FUN_01179DC0 | FUN_0114DAB4 |
| 写入 GUI 缓存的函数 | FUN_0115B578 | FUN_0112FD80 |
| GUI 缓存全局字节地址 | **0x01B88650** | **0x01AF2DB8** |
| GUI 缓存 STRB | 0x0115B5D4 | 0x0112FDDC |

这里确证的是：设置服务的返回值进入 **GUI MovieCodec 缓存**。但上述 GUI 缓存字节不等于 Recorder 活跃 Codec 字节，也不等于指针槽位。**尚未找到将 GUI 选择值正向写入 Recorder 当前缓冲区 +0x5B0 的赋值者。**

同偏移数字在固件里用于不同结构（菜单缓存、Recorder 结构、其他大型状态对象）。仅凭偏移相同不构成别名/赋值证据。

## 5. 为什么仍无法报出配置指针的实际数值

新编写的只读 Ghidra 内存映射检查证明：两机描述符主指针字段、当前输入指针槽、输出指针槽及 GUI 全局字节均不属于本次已载入 X6 静态固件内存块：Ghidra 报告为 UNMAPPED。这个术语仅描述当前 Ghidra 工程映射，**不意味着真实相机运行时没有这些 RAM 地址**。静态指令仍能验证如何计算并访问它们，但读不出机身 RAM 的运行时内容。

xref 审计显示当前输入指针槽与输出指针槽在现有 Ghidra 映像中各有 1 条直接 WRITE 记录，对应先前已审计的初始化写入与本轮新增指针复制写入。但第26阶段已证明：即使某个 RAM 目标缺少直接 WRITE xref，也可能经 memcpy、参数或别名被更新。不能把直接 xref=1 解释为“全局只存在这一处修改”。

## 6. 原创可复验工具、测试与隐私边界

新增可公开原创代码：

- tools/audit_recorder_input_export_alias_stage31.py：读取两台机型私有原厂 Section1/Section2 机器码及本地 Ghidra 日志；检验 14 条指针构建与数据搬运原始 ARM 指令、每机 4 条关键 BL、每机 4 条 Codec/Format LDRB/STRB、GUI 缓存 STRB、函数调用先后和 RAM 映射边界。把“赋值后立即相等”和“序列化时仍相等”设为不同断言，后者仍为未证实。
- tests/test_audit_recorder_input_export_alias_stage31.py：**49 项独立合成测试**全部通过，覆盖误认目标、指针赋值方向、BL 错误、字节字段读写、GUI 缓存 ID、运行时指针相等过度断言等，不包含厂商固件或任何实机数据。

私有日志仅保存在用户 Ubuntu 的 gitignored output/ 目录，不上传：
- xs10 / xt4_stage31_export_pointer_slot_initializer.log
- xs10 / xt4_stage31_export_pointer_slot_refs.log
- xs10 / xt4_stage31_alias_producer_order_callers.log
- xs10 / xt4_stage31_dynamic_ram_mapping.log
- xs10 / xt4_stage31_gui_codec_setter_pipeline.log
- xs10 / xt4_stage31_gui_setter_caller_context.log
- xs10 / xt4_stage31_codec_setting_id_sites.log
- stage31_alias_audit_result.jsonlog

Ghidra 12.1.4 的所有查询都使用 read-only 项目、-noanalysis -readOnly；相机本体没有受到操作。

复验（须具备本机私有原厂 sections 和 Ghidra 日志）：

~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/audit_recorder_input_export_alias_stage31.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

本轮原厂 ROM 证据审计 X-S10、X-T4 都通过；**49 项新增合成单元测试通过**；完整回归：仓库 tests/ **91 项**、本地研究 output/ **497 项**，累计 **588 项通过**。第26至30阶段的独立原厂审计也全部重新通过。此数量不能代表相机录制能力。

## 7. 剩余的 Codec 输入赋值环节

目前从 GUI 到 Recorder 的两段相互独立：

~~~text
设置服务 X-S10 ID 0x3FC
           ↓
GUI 缓存 0x01B88650
           ↓
[此处 GUI 值 → Recorder 当前配置字段尚未找到生产/转换函数]
           ↓
Recorder 当前缓冲区 [+0x5B0 / +0x5B1]（运行时值未知）
           ↓  第26阶段的已证实整块复制
Recorder 源 Codec 0x02D9D834
           ↓  第20/25阶段的活跃配置提交
Recorder 活跃 Codec 0x01C25208
           ↓  本阶段验证的条件式反向序列化
配置输出缓冲区 [+0x5B0]（可与输入对象有指针别名）
~~~

下一阶段应该优先查 GUI Codec 设置服务到 Recorder 初始 +0x5B0 的前向数据变换、配置快照写入与位深参数映射，并将动态指针别名/模式切换条件一并检查。对 4K60 还需独立验证传感器读取、ISP/VPU 和写卡持续带宽；当前仍无 HEVC Main10 SPS 或真实 4K60 内录证明。

**结论：两个指针槽的实际赋值链已找到，活动 Codec 的条件式反馈路径已建立为可验证假设；GUI→Recorder 初始赋值、Main10/4K60 内录解锁仍未证实。**
