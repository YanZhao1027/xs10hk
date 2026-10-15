# 第23阶段：MovieCodec / MovieFormat 相邻字段、复合状态及 X-T4 额外重载路径（2026-10-15）

> **结论摘要**：在 X-S10 3.11 与 X-T4 2.12 已解压 X6 固件中，通过只读 Ghidra + 原始 A32 指令验证，确认 eModeMovieCodec 与 eModeMovieFormat 是相邻的两个独立字节；一个 UI 状态组装函数把这两个字节组成四种复合状态。X-T4 还存在一个由特定模式切换触发的双字段重载函数，X-S10 当前已识别的直接 setter 调用没有对应的额外路径。**仍未恢复这套 GUI/菜单状态如何写入 Recorder 原始快照的赋值链，不能声称可内录 Main10 或 4K60。**
>
> **安全边界**：仅访问用户 Ubuntu 里已有的原厂离线固件和本地 Ghidra 工程。没有 USB 相机通信、FF80、相机 RAM/闪存访问、修改 DAT、重新封包或刷机。固件地址仅对应 X-S10 **3.11**；历史实机版本 **2.10**，不得混用。

## 1. 两个独立字节，不能把整个复合值当作 HEVC 标志

| 角色 | X-S10 3.11 | X-T4 2.12 |
| --- | --- | --- |
| GUI 设置结构基址 | 0x01B880A0 | 0x01AF2808 |
| GUI eModeMovieCodec，+0x5B0 | 0x01B88650 | 0x01AF2DB8 |
| GUI eModeMovieFormat，+0x5B1 | 0x01B88651 | 0x01AF2DB9 |
| Codec 字节 setter | FUN_0115B578 | FUN_0112FD80 |
| Format 字节 setter | FUN_0115B610 | FUN_0112FE18 |
| 菜单初始化（加载成对 codec/format 字节） | FUN_01179DC0 | FUN_0114DAB4 |
| Codec setting ID | 0x3FC | 0x3E5 |
| Format setting ID | 0x3FB | 0x3E4 |
| UI 状态组装函数 | FUN_01182820 | FUN_0115663C |

两机分别真实包含 eModeMovieCodec 以及 eModeMovieFormat 的调试标签（**同属固件调试字符串，不是可见菜单项的证据**）。对应 setter 在 A32 中分别向 +0x5B0、+0x5B1 执行 STRB；不是一次整体写 16 位枚举。

X-S10 FUN_01179DC0 从 0x3FB（format）和 0x3FC（codec）读取配置、转换并做有效性处理，再分别调用两套 setter。X-T4 FUN_0114DAB4 有相同的成对配置初始化形态，setting ID 分别为 0x3E4、0x3E5。

## 2. 新恢复：GUI 导出函数将两个字节折叠为四类

X-S10 FUN_01182820 从 DAT_01B88650 获取低字节，调用设置转换器处理 0x3FA，写入其输出结构 param_1[0x90]；X-T4 FUN_0115663C 对应 setting ID 为 0x3E3。

该函数另用 **16 位组合值**（从 +0x5B0 同址读取两个相邻字节）为 param_1[0xA1] 写入类别：

| 原组合字 | 输出 UI 类别 |
| --- | ---: |
| 0x0001 | 0 |
| 0x0000 | 1 |
| 0x0101 | 2 |
| 0x0100 | 3 |

两机对应分支完全匹配。低字节对应 codec，次高字节对应 format；**这证明 UI 状态能表达组合，不证明四种组合都能由 X-S10 正常菜单选择，也不证明这些组合会写进编码器配置**。特别注意 0x3FA/0x3E3 是此导出字段的转换 ID，**不是**低字节初始化的 codec ID 0x3FC/0x3E5。

## 3. 值得进一步研究的非对称：X-T4 的模式切换加载分支

X-T4 的 FUN_0115B234 根据当前模式设置类别 0x2D 或 0x21，依次读取多个设置，其中包括 0x3E4 (format)、0x3E5 (codec)，之后会分别调用 setter 并同步设置转换值。它被实际两个直接 BL 引用（0x0115F2D0 和 0x02043B14）。

Ghidra 对已识别 setter 的直接调用引用计数：

| setter | X-S10 3.11 | X-T4 2.12 |
| --- | ---: | ---: |
| MovieCodec | 3 | 4 |
| MovieFormat | 2 | 3 |

X-S10 已有的两个字段初始化函数、Section2 菜单输入分支均有真实 BL。但在当前静态 xref 结果中没有发现 X-T4 FUN_0115B234 所对应的额外双字段重载调用；该非对称是一项**可供调查的差异**，而不是“X-S10 缺失整个功能”的证明。可能存在未识别函数体、调用表、间接分派或不同菜单生命周期。

## 4. A32 二进制交叉确认（非仅字符串匹配）

原创只读脚本 [audit_codec_format_pair_stage23.py](../tools/audit_codec_format_pair_stage23.py) 对两个原厂解压 section 的 **10 个** A32 指令站点逐字解码，验证是正确的正偏移立即数 LDRB/STRB、目标寄存器和 0x5B0/0x5B1 偏移。其中每机包括：codec 写、format 写、format 读、GUI 组装函数的 codec 读，以及 Section2 菜单支路的 codec 读。然后同时审计私人 Ghidra 反编译输出中对应 setter、成对初始化、复合分类与 xref 计数。

每机实际验证结果：a32_byte_sites_verified = 5、composite_ui_cases 为 0x0→1, 0x1→0, 0x100→3, 0x101→2。两机 GUI 地址 **都不等于** Recorder 源快照字节地址：

- X-S10 Recorder 输入快照中的 codec 0x02D9D284 + 0x5B0 = 0x02D9D834
- X-T4 Recorder 输入快照中的 codec 0x02D109D4 + 0x5B0 = 0x02D10F84

二者结构恰好都有 +0x5B0 不能视为已打通的引用关系。更下游的 Recorder active byte（X-S10 0x01C25208）已由第20阶段记录，本阶段**未找到新的从 GUI 到 Recorder source 的直接边**。

## 5. 本机已复验与可重复步骤

本轮在授权 Ubuntu 的受忽略 output/ 目录新增并保留：

- output/xs10_stage23_codec_ui_readers.log、output/xt4_stage23_codec_ui_readers.log；
- output/xs10_stage23_codec_highbyte.log、output/xt4_stage23_codec_highbyte.log；
- output/xs10_stage23_codec_ui_reader_callers.log、output/xt4_stage23_codec_ui_reader_callers.log；
- output/xs10_stage23_pair_call_xrefs.log、output/xt4_stage23_pair_call_xrefs.log。

这些日志通过 Ghidra 12.1.4 的 analyzeHeadless、-process section-1.bin -noanalysis -readOnly 配合原有 TraceX6Function.java / ProbeX6Refs.java 产生。原固件、日志和 Ghidra 工程**不上传 GitHub**。留存地址可以重跑上述 Ghidra 分析。

~~~bash
cd /home/zyubuntu/xs10hk
PYTHONPATH=tools:output python3 tools/audit_codec_format_pair_stage23.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

原创 [合成测试](../tests/test_audit_codec_format_pair_stage23.py) **20项通过**，覆盖 A32 解码、越界、寄存器/立即数错位、误把 caller 当函数定义、误用 0x3FC 当 UI 导出 ID、损坏四类组合、丢失双字段初始化与 X-T4 额外加载等负例。包含原仓库 91 项、私有此前 86 项与本次 20 项，总计 **197 项离线测试全部通过**；原始硬件能力不由单元测试决定。

## 6. 下一关的判定准则

1. 以 X-T4 FUN_0115B234 的上游直接调用者 0x0115F2D0、0x02043B14 为正对照，比较 X-S10 模式切换中是否裁剪了 MovieCodec/MovieFormat 重新加载，或者存在不同的间接实现。
2. 从上述 GUI 对象及输出结构回追 **到 Recorder 原始快照的实际写入者**，寻找可证实的 setter/serializer/memcpy 链，而不是强迫两份不同的 +0x5B0 等同。
3. Main10 需实际 HEVC SPS/位深证据；4K60 则独立需要 Sensor/ISP 60fps 原始帧流、录像启动和持续写卡证据。X-S10 不存在经过验证的可刷补丁及独立救砖方案。

**阶段结论**：复合 UI 状态及额外 X-T4 模式重载路径已经用原始指令、Ghidra 和反例测试交叉确认；真正阻断 10-bit 内录的机型条件和 GUI→Recorder 数据边仍未被证明，故不作实机修改。
