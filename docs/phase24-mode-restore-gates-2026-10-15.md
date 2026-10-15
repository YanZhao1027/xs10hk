# 第24阶段：X-T4 与 X-S10 模式恢复代码的真实 A32 分叉（2026-10-15）

> **本阶段新增证据**：在 X-T4 2.12 与 X-S10 3.11 的 Section2 原厂固件中找到一对完全相同的 16 字节 A32 指令前缀，且**每份 Section2 各只出现一次**。从该唯一锚点追回实际跳转可见：X-T4 直接调用一个额外的 MovieFormat / MovieCodec 重载器；X-S10 则根据是否处于视频拍摄模式选择另一条间接重新初始化路径。这是真实控制流差异，**不是已发现 10-bit/4K60 内录解锁键**。
>
> 本轮仅操作已获授权的 Ubuntu 上的私人原厂解压固件和 Ghidra 工程；机身历史版本 2.10，研究地址来自 X-S10 3.11，不能用于现有机身。无 FF80、无 USB、无 RAM/闪存读写、无 DAT 补丁和刷机。

## 1. 一对有二进制指纹的模式恢复函数

| 角色 | X-T4 2.12 | X-S10 3.11 |
|---|---|---|
| Section2 模式恢复函数 | FUN_02043AB4 | FUN_020EB5F4 |
| 唯一的 16B 指令指纹位置 | **0x02043AF4** | **0x020EB638** |
| CMP R3,#0x2D | 0x02043AF8 | 0x020EB63C |
| EQ/NE 状态字节读取偏移 | +0x832 / +0x831 | +0x582 / +0x581 |
| 主模式切换函数 | FUN_0115E9C8 | FUN_0118B280 |
| 共同功能的 Codec/Format 初始化 | FUN_0114DAB4 | FUN_01179DC0 |

完整 ARM 小端二进制指纹为：

~~~text
0030d4e5 2d0053e3 0020a0e3 0810a0e3
~~~

分别对应 LDRB R3,[R4,#0]、CMP R3,#0x2D、MOV R2,#0、MOV R1,#8。脚本在每份原厂 Section2 中全量扫描，**均只发现一处**；不是按地址推测代码等价。

## 2. X-T4：两个独立上下文都能够触发额外的 Codec/Format 重载

XT4 原始 A32 已验证如下两条直接 BL：

- **0x02043B14 → FUN_0115B234**：来自 Section2 的 FUN_02043AB4，发生在恢复设置值之后；
- **0x0115F2D0 → FUN_0115B234**：来自 Section1 的模式切换总控 FUN_0115E9C8；反编译确定在状态 DAT_0115F340+0x834 为 1 时调用。

FUN_0115B234 会读取配置项 **0x3E4（MovieFormat）** 与 **0x3E5（MovieCodec）**，并分别调用 FUN_0112FE18 和 FUN_0112FD80 写入 GUI 设置字段。两处 BL 的目标均通过原厂 A32 位移解码计算，并经 Ghidra xref 对照验证。

但它只说明“设置值重新加载”，没有静态证据表明能直接启动 HEVC Main10 视频编码。

## 3. X-S10：该恢复事件走条件分流与模式总控，而非直接等价重载

匹配的 X-S10 函数 FUN_020EB5F4 在相同指纹后的真实机器码中：

1. **0x020EB668 BEQ 0x020EB688**：若 GUI 当前拍摄模式为 0x2D（录像），跳过这一额外辅助支路。
2. 若模式 **不等于 0x2D**，从 **0x020EB67C BL 0x02058368** 进入辅助函数。
3. FUN_02058368 在 **0x020583AC** 调用 FUN_0118B280(DAT_01B880A0,0x23)，即 X-S10 模式总控。
4. FUN_0118B280 在 **0x0118B79C** 调用 FUN_01179DC0，它可从菜单配置加载 X-S10 MovieFormat 0x3FB 和 MovieCodec 0x3FC。

这里的 0x23 是模式总控的一个参数，**不是 HEVC 开关**。FUN_02058368 还有 **71 条静态 xref**，表明它是广泛使用的模式管理函数，而非视频编码专用函数。

X-S10 在此匹配函数里没有 X-T4 那个直接的 FUN_0115B234 调用，但**仍有间接处理与其他调用者**；不能将其表述为“X-S10 不会初始化 Codec”或“只补一个 BL 就能实现 10-bit”。

## 4. 对 10-bit / 4K60 的实际意义与未解决的问题

相比第23阶段的 setter 引用数量对比，本阶段证明了额外的 X-T4 参数重载在主模式总控和 Section2 模式恢复两个事件路径里如何到达，并恢复了 X-S10 的匹配实现与条件分支。

尚缺以下决定性证据：

- **GUI → Recorder**：X-S10 上层 MovieCodec 位于 0x01B88650，录像器源快照 codec 位于 0x02D9D834。两个变量不同；未恢复从前者到后者的真实赋值/序列化代码，也未证明是否存在强制回写 0。
- **Main10**：原厂内部 10-bit 编码器是否可从 X-S10 正常 UI、Sensor/ISP 处理链到达并输出有效 HEVC SPS（Main10、10-bit）尚未证实。
- **4K60**：仍缺独立的 Sensor 4K59.94 读出、ISP、持续 VPU 负载和 SD 写入链。HDMI 的 4K60 EDID 数据不是内部录制许可。
- **版本和刷机**：机主 2.10 与研究 3.11 地址不兼容，且未有字节一致的 X6 修改回封、完整性机制验证及独立救砖方案。禁止将离线研究视为可刷补丁。

## 5. 复验脚本、测试与本地证据

新增原创公开代码：

- [tools/audit_mode_restore_gates_stage24.py](../tools/audit_mode_restore_gates_stage24.py)：扫描两台相机 Section2 16B 唯一指纹、解码 A32 带条件 LDRB 与 B/BL 位移、验证实际目标、比对原有 Ghidra 私有反编译日志与 xrefs，刻意不把尚未证实的 Recorder 通路判成成功。
- [tests/test_audit_mode_restore_gates_stage24.py](../tests/test_audit_mode_restore_gates_stage24.py)：**32 项全部通过**的纯合成 A32、条件和 xref 正反例，完全不含原厂固件数据。

Ghidra 12.1.4 analyzeHeadless 使用 -process section-1.bin -noanalysis -readOnly 导出以下**仅保存在 Ubuntu 的 output/** 日志：

- xs10_stage24_mode_switch_callers.log 与 xt4_stage24_mode_switch_callers.log
- xs10_stage24_analog_section2_mode_switch.log
- xs10_stage24_alt_mode_handlers.log
- xs10_stage24_mode_restore_xrefs.log 与 xt4_stage24_mode_restore_xrefs.log

可在当前授权 Ubuntu 验证：

~~~bash
cd /home/zyubuntu/xs10hk
PYTHONPATH=tools:output python3 tools/audit_mode_restore_gates_stage24.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

本轮实际对原厂固件审计 **X-S10 / X-T4 均通过**；旧有 91 项公开测试 + 106 项本地受忽略测试 + 32 项本轮测试 = **229 项离线单元测试通过**。这些测试并不测试相机实机性能。

**下一关**：优先追踪 GUI Byte/Format → Recorder 源快照的具体数据边，另外确认 X-T4 专属重载的 0x834 状态位在 XS10 是否存在等价条件，而不是试图在机主 2.10 上套用 3.11 地址。
