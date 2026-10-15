# 第25阶段：验证 Recorder 配置字节的双向回环；GUI 到源快照仍存在缺口（2026-10-15）

> **新增证据**：这次在原始 X-S10 3.11 与 X-T4 2.12 的 X6 ARM 二进制及对应 Ghidra 反编译中，恢复了两机同构的 Recorder **配置数据回环**：原始快照 (+0x5B0/+0x5B1) → 临时工作结构 → Recorder 活跃配置字节 → 单独导出到另一份输出配置结构 (+0x5B0/+0x5B1)。特别确认组装函数对两字节相邻的原始源数据采用了跳过方式：先由活跃 Recorder 配置填入 +0x5B0/+0x5B1，随后直接搬运源结构的 +0x5AC（4B）和 +0x5B2（3B）。这不是证明菜单允许 H.265，也不是 Main10 码流或 4K60 成功。

**安全与版本**：所有代码只读分析用户 Ubuntu 中已有的 X-S10 3.11、X-T4 2.12 原厂解压数据与私有 Ghidra 日志。历史 X-S10 实机版本 2.10；地址不能直接套用。无 USB 连接、无 FF80、无相机 RAM/闪存操作、无 DAT 修改、无刷机。

## 1. 实际数据边（不是四处相同偏移就推断相连）

| 结构与偏移 | X-S10 3.11 | X-T4 2.12 |
| --- | --- | --- |
| GUI eModeMovieCodec 字节（尚未接通） | 0x01B88650 | 0x01AF2DB8 |
| Recorder **源**配置结构基址 | 0x02D9D284 | 0x02D109D4 |
| 源 codec / format | 0x02D9D834 / 0x02D9D835 | 0x02D10F84 / 0x02D10F85 |
| 源结构转换器 | FUN_012C9500 | FUN_012A313C |
| 转换后工作结构 codec / format 偏移 | +0x430 / +0x431 | +0x434 / +0x435 |
| 提交原始 Codec 配置字段到运行时的函数链 | FUN_012C0878 → FUN_012BD110 | FUN_01299004 → FUN_01295780 |
| Recorder 活跃 codec / format 配置字节 | 0x01C25208 / 0x01C25209 | 0x01B83974 / 0x01B83975 |
| Recorder CONFIG 反向导出函数 | FUN_012BE684 | FUN_01296D38 |
| 组装整个输出结构的函数 | FUN_0221D1BC | FUN_02189BD4 |
| 输出结构中两字节偏移 | +0x5B0 / +0x5B1 | +0x5B0 / +0x5B1 |

这是 **Recorder 配置结构** 的读写，尚不能保证 VPU 接受 Main10 或录下有效 H.265 文件。

前向从源配置复制到活跃配置在历史第20阶段已经被验证。这次最大的补充是：在**同一个**全局输出组装函数中发现有序的三个 ARM BL：

- X-S10 FUN_0221D1BC：0x0221D210 → FUN_012C9500；0x0221D22C → FUN_012C0878；0x0221D298 → FUN_012BE684。
- X-T4 FUN_02189BD4：0x02189C28 → FUN_012A313C；0x02189C44 → FUN_01299004；0x02189CB0 → FUN_01296D38。

三条顺序均由 Section2 **原始 A32 BL 位移解码**确认，不只是信任 Ghidra 函数名或文档。

每台机器还分别检查了 Section1 **8 个 A32 LDRB/STRB**：前向配置读取 +0x5B0/+0x5B1 并写入工作结构 codec/format；反向从 Recorder 活跃配置地址写回另一输出结构 +0x5B0/+0x5B1。共 **16 个原始字节操作点、6 个 BL 目标**得到重验。

## 2. 反向导出单独处理 +0x5B0 和 +0x5B1

X-S10 的 FUN_012BE684：

~~~text
输出[+0x5B0] = RAM[0x01C25208]
输出[+0x5B1] = RAM[0x01C25209]
~~~

X-T4 的 FUN_01296D38：

~~~text
输出[+0x5B0] = RAM[0x01B83974]
输出[+0x5B1] = RAM[0x01B83975]
~~~

其中 X-S10 的原始指令地址 0x012BEB8C、0x012BEB90、0x012BEB94、0x012BEB98 分别是两组 LDRB/STRB；X-T4 对应地址为 0x01297250、0x01297254、0x01297258、0x0129725C。

两台机器的上层组装函数都是**先调用反向导出函数**，再进行其余字段的拼装。这两个已证实的相邻拷贝范围为：

- 输出 +0x5AC 开始，共 4 字节：覆盖 +0x5AC..+0x5AF；
- 输出 +0x5B2 开始，共 3 字节：覆盖 +0x5B2..+0x5B4。

它们**不会**覆盖由反向导出填写的 +0x5B0 / +0x5B1。脚本只对这些可见的拷贝与直接赋值作有界断言，不排除任何其他子调用、间接别名可能影响相同字段。

## 3. 更明确的“尚未打通”位置

当前确认三组不同的 Codec 字节：

~~~text
GUI:               X-S10 0x01B88650
                               [未知写入者]
Recorder 源快照:    X-S10 0x02D9D834
                               |
                               v
Recorder 活跃配置:  X-S10 0x01C25208
                               |
                               v
输出配置结构:       +0x5B0（专用反向序列化）
~~~

第 23/24 阶段证明 GUI 和模式切换里存在 MovieCodec 设置加载。第 20 阶段证明 Recorder 源 → 活跃配置。第25阶段串联有序的 Recorder 源 → 活跃配置 → 反向导出，并证明输出端有特例字段写入。

**最大未证实边仍是 GUI → Recorder 源快照**。静态二进制中的原始 32 位 little-endian 常量搜索：两份原厂固件中都没有发现直接包含 Recorder 源 codec **绝对地址** 的 4 字节字面量（X-S10 0x02D9D834、X-T4 0x02D10F84）；然而 Recorder **源基址**确有多处引用，因此可能由源基址加偏移、局部指针、复制、DMA 或间接调用写入。**常量未出现不能用来证明某个写入路径不存在**。

针对 Section2 的有限 ARM STRB 偏移扫描，X-S10 有 9 个 +0x5B0 静态写入站点、X-T4 有 39 个；这些多属于各式 GUI、模式或其他结构，不等于找到对 Recorder 源字节的写入目标。+0x5B1 立即数写入站点为零也不排除块复制、半字写或寄存器寻址写入。

## 4. 离线复验工具与当前结论

公开新增：

- tools/audit_codec_roundtrip_stage25.py：读取原厂 X6 section、两机原始 A32 指令、Ghidra 私有只读日志，验证 8+8 个字节操作、3+3 个 BL 目标、源 → active → export 调用先后、专用反向输出、相邻拷贝不覆盖、运行时 getter 与缓冲区分离。报告明确将 Main10、4K60、GUI → Recorder 源边标为未证实。
- tests/test_audit_codec_roundtrip_stage25.py：**34 项纯合成单元测试通过**，包括错误编码、相对分支误指、跨越两字节的相邻拷贝、重排函数调用、伪造反向导出、不匹配的工作状态 memcpy、误把 GUI 变量当活跃态等负例。

Ghidra 12.1.4 read-only 分析日志保留在 Ubuntu 忽略的 output/ 目录（不上传）：xs10/xt4_stage25_snapshot_producer_candidates.log、xs10/xt4_stage25_snapshot_populate_pipeline.log。上一阶段已有的 runtime_430_write_sites_stage20.log、runtime_config_state_commit_funcs_stage20.log、actual_movie_codec_selection_at_context.log 也参与审计。

复验：

~~~bash
cd /home/zyubuntu/xs10hk
PYTHONPATH=tools:output python3 tools/audit_codec_roundtrip_stage25.py --output output
PYTHONPATH=tools:output python3 output/audit_codec_snapshot_commit.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

此次原始固件审计已通过；原有 **91 项跟踪测试 + 138 项本地受忽略测试 + 34 项第25阶段新测试 = 263 项通过**。单元测试和记录器配置回环证明都**不能替代真实 HEVC Main10 SPS、10-bit 画面或 Sensor/ISP 4K60 帧流**。

## 5. 下一轮精准目标

优先查 Recorder 源基址 0x02D9D284 的上游指针与写入/复制来源；将候选路径严格和 GUI Codec byte 0x01B88650 的 setter/事件分派相联系，尤其排查通过整体结构 memcpy、状态对象别名或根据录像模式复制的路径。最终要求“真实数据流或原始指令中的可验证地址链”，而不是依靠 +0x5B0 相同、菜单字符串或额外 X-T4 模式调用推断。

**仍无安全、可恢复的可刷固件，不能向机主 X-S10 写入任何补丁。**
