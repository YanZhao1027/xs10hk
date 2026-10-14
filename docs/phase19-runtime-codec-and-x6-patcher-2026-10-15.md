


> **第 20 阶段勘误/重大更新（2026-10-15）：** 本阶段发现的“32B 独立 setter 没有直接 ARM BL 调用者”是事实，但**不能再把它当成录像 Codec 当前配置缺少写入者的证据**。已经找到实际存在的另一条 `设置快照+0x5B0 → 工作状态+0x430/0x434 → 双份整块 memcpy → 当前运行时 Codec 字节` 完整执行路径，并在 X-S10 3.11 与 X-T4 2.12 两机离线验证。详见 [第 20 阶段完整批量配置提交路径](phase20-codec-snapshot-commit-2026-10-15.md)。真正尚未查明的是**X-S10 原始配置快照是否能从正常 UI 得到 H.265 枚举 1**，以及 Main10/4K60 实际录制能力。


> **第 20 阶段勘误/重大更新（2026-10-15）：** 本阶段发现的“32B 独立 setter 没有直接 ARM BL 调用者”是事实，但**不能再把它当成录像 Codec 当前配置缺少写入者的证据**。已经找到实际存在的另一条 `设置快照+0x5B0 → 工作状态+0x430/0x434 → 双份整块 memcpy → 当前运行时 Codec 字节` 完整执行路径，并在 X-S10 3.11 与 X-T4 2.12 两机离线验证。详见 [第 20 阶段完整批量配置提交路径](phase20-codec-snapshot-commit-2026-10-15.md)。真正尚未查明的是**X-S10 原始配置快照是否能从正常 UI 得到 H.265 枚举 1**，以及 Main10/4K60 实际录制能力。
# 第十九阶段：从真实录像 codec 运行时状态追到 VPU 初始化；评估 X6 刷机封装风险（2026-10-15）

> **两项经过原厂固件离线验证的新结果：**
>
> 1. X-T4 与 X-S10 都有成对的 **32 字节运行时 codec getter/setter**；录像环境初始化实际读取该状态，将取值存入录像上下文偏移 `+0xADDA`，再由 H.265 初始化业务转成 VPU 结构偏移 `+0x188` 的 codec 类型：**运行模式值 1 时 VPU codec 字段为 0，否则为 1**。独立的位深参数 `+0x0C` 在两机均写入 **1**。因此 X-S10 主程序不仅有通用驱动，而且有确切的**上游配置值至 H.265 初始化参数**的数据依赖关系。
> 2. 开源 FujiHack 补丁器解析 OS header 6 并不意味着它会自动重压缩原厂 X6 固件。我们在 X-S10 3.11 与 X-T4 2.12 **原厂 .DAT** 中均验证到四个独立的 X6 LZ77 packed section；FujiHack 公共 patcher 当前源码的补丁注入核心是**原文件中的直接取反字节替换及 checksum 增量更新**。对我们的**解压后的 Ghidra ARM 地址**不能直接采用这种原始 DAT 字节注入方法，尚无 X6 回封、端到端校验/签名与救砖证明。

**没有编译、生成或刷入任何修改版固件；没有访问 USB 及 FF80。** X-S10 机身 2.10 与离线 DAT 3.11 仍不匹配。

## 1. 代码级：找到真实的两机 runtime codec getter 和 setter

之前只是从编码设置 ID / 通用允许值表出发，而这次在 Section 2 的**录像上下文创建函数**中看到：

~~~c
mode = movie_codec_runtime_get();
recorder_context[0xADDA] = mode;
~~~

具体不是“疑似共用字符串”，而是经 Ghidra ARM 函数反编译确认的调用点：

| 角色 | X-T4 2.12 | X-S10 3.11 |
| --- | --- | --- |
| 运行时 mode 存储字节 | `DAT_01B83974` | `DAT_01C25208` |
| 只读 getter，32 字节 | `FUN_01298C18` | `FUN_012C048C` |
| 配对 setter，32 字节 | `0x01298C38` | `0x012C04AC` |
| Recorder 主流程写入的上下文字节 | `+0xADDA` | `+0xADDA` |
| 调用 getter 的上层准备函数所在本地 Ghidra 记录 | `output/xt4_codec_field_setters.log` | `output/xs10_codec_field_setters.log` |

两个 32 字节 setter **在现有 Ghidra 项目中最初未被自动标识为函数**。本轮只在本地私人 Ghidra 项目里，以位于 `output/ProbeARMSetter.java` 的一次性分析脚本显式反汇编其起始地址并创建研究函数。新识别的 ARM/C 行为是：

~~~c
// X-T4，ResearchSetter_01298c38
DAT_01B83974 = parameter;

// X-S10，ResearchSetter_012c04ac
DAT_01C25208 = parameter;
~~~

这证实这两个内存字节有简单直接的 getter/setter 配对；**没有**证实目前已开放的正常用户菜单可以调用该 setter 或写入值 1。

### 独立 BL 调用扫描所给的反证边界

新增脚本 `tools/audit_movie_codec_gate.py --scan-bl` 将 X-T4 与 X-S10 的解压 `section-1/2/3.bin` 按已推导的候选基址遍历所有 32bit ARM BL，求出实际跳转目标。针对上述两个 setter，结果都是：

- X-T4 直接 A32 `BL` 调用点：**0**；
- X-S10 直接 A32 `BL` 调用点：**0**。

**这绝不意味着代码不可达。** 相机设置系统可能通过回调、函数指针、表分派或整块配置数据复制修改状态；目前仍需要补齐这里的运行时写入调用链。静态扫描也不覆盖所有 Thumb/间接分派或 Ghidra overlay。

## 2. 两机录像初始化实际使用了这个 mode

实际录像编码器的 H.265 参数构建函数：

| 组件 | X-T4 2.12 | X-S10 3.11 |
| --- | --- | --- |
| Recorder 构建 H.265/VPU init | `FUN_0224B65C` | `FUN_022DEE64` |
| 400B 驱动 init 结构地址 | `0x028A5150` | `0x02945A08` |
| 独立位深 `init +0x0C` | **1** | **1** |
| 编码方式 `init +0x188` | `0x028A52D8` | `0x02945B90` |
| 初始化验证入口 | `FUN_011CCE88` | `FUN_011F97DC` |

两机均使用等价代码：

~~~c
bool selected_mode_one = (recorder_context[0xADDA] == 1);
init_params.video_codec = !selected_mode_one; // init + 0x188
init_params.bit_depth = 1;                    // init + 0x0C
~~~

因此，“某个可读 runtime mode byte” → “录像上下文” → “400B 驱动初始化 codec 字段”这一条依赖关系**已明确恢复**。

特别注意：`init.video_codec` 的值是 *1 的反转*，与第十七阶段通用设置里的 `eModeMovieCodec` 数值 **不能简单按相同标号代入**。我们**尚未直接验证** runtime byte 的来源最终与持久化用户菜单的 `eModeMovieCodec=1` 是同一项且肯定可达；避免声称“已经能通过用户菜单直接调用 HEVC Main10”。

相同的 936B 驱动函数进一步验证 `init.video_codec==0 && init.bit_depth>1` 时拒绝。它并没有按机型区分。此前第十八阶段还已经独立确认值 1 进入会话并影响 `0x0201/0x0121` 的描述符选择。

## 3. 4K60 表首项识别为录像类型/高速录像分支，而非 Main10 开关

沿第十五阶段 `96 × 64B LUT` 四键查表，追到确定它第一个键来源的 68B 函数：

| 函数 | X-T4 | X-S10 |
| --- | --- | --- |
| `recmvJudgeMovieTypeHSMovie` 分类函数 | `FUN_0223DCAC` | `FUN_022D171C` |
| 返回值 `0` | 输入类型码 1、4、5、6、7 | **相同** |
| 返回值 `1` | 输入类型码 2、3 | **相同** |

结合之前已反编译录像上下文准备逻辑：判断返回 0 时 **LUT 首项设为 0**；返回 1 时按输入类型码 3 → 首项 2，其它情况首项 1。

**因此 LUT 的第一匹配键主要用于将普通/高速录像相关的模式类型分类**，而非直接编码为“H.265 8/10bit Profile”。两机这一逻辑完全相同，所以无法解释 X-S10 缺少 4K60 内录，不能误将 `record[0]=0` 当成解锁 Main10 的魔法常数。

静态 LUT 包含 4K59.94 候选表项这一事实依然成立；上游 **(分辨率 × 帧率 × codec) 组合许可** 尚未找到实际允许 4K60 的条件。

## 4. FujiHack 固件补丁器：解析到 X6 版本号 ≠ 可以直接刷压缩后的 X6

本阶段独立核对开源第三方项目：

- [FujiHack 主仓库](https://github.com/fujihack/fujihack)：明确称已有 PTP USB debugger 主要移植到 **XF1 与 X-A2**，并警示非官方固件和救砖风险；
- [FujiHack 固件 patcher](https://github.com/fujihack/patcher)：支持 FUJI `OS/header ID 6` 的 metadata 解析，已有 legacy `unxor` 直接注入逻辑，且 README 一般性声称可 patch/repack；
- [FujiHack 支持机型说明](https://wiki.fujihack.org/supported/)特意说明列在机型表只代表使用同类 RTOS，**不等于该型号已能安全运行 FujiHack**。

我们没有对相机使用上述工具，只做了原厂固件只读解析，并比对公共 patcher 的实际源代码。Xi6 DAT 内主要 ARM 程序需要独立的 LZ77 解压才能得到，不能把 Ghidra 的 `0x011F...` ARM 地址简单线性映射成 `FWUP0025.DAT` 中的同偏移位置，再用原始字节取反注入。

新安全工具 [`tools/audit_x6_raw_patcher_compat.py`](../tools/audit_x6_raw_patcher_compat.py) 直接调用本项目已验证的只读 `fw_inspect.inspect` + `x6_decompress.find_sections`，从**本地原厂 DAT**校验：

| 原厂 DAT | firmware 版本（原厂字段按 hex 展示） | `os_id` | X6 LZ77 压缩段 | 可证明直接原始字节注入安全？ |
| --- | --- | --- | --- | --- |
| X-S10 `FWUP0025.DAT` | **3.11** | 6 | **4** | **否** |
| X-T4 `FWUP0024.DAT` | **2.12** | 6 | **4** | **否** |

对 X-S10 的四个段逐一恢复：

| 段 | Packed (byte) | Unpacked (byte) |
| --- | ---: | ---: |
| 1 | 3,914,256 | 8,012,912 |
| 2 | 5,298,316 | 9,449,472 |
| 3 | 4,563,800 | 10,027,008 |
| 4 | 3,480,732 | 6,763,104 |

**结论**：现成的 FujiHack 原始 XOR 字节补丁代码不能被认定为对 X-S10 的正确**解压编辑 → LZ77 重压缩 → 文件偏移/段头重建 → 供应商 checksum/签名完整性确认 → 独立救砖**流程。系统是闭源签名或校验情况未完全明了；若将来要尝试私人研究，请首先在电脑端实现**不改任何字节的解包→回封往返完全一致验证**，并必须另行确认救砖条件。现在没有可刷写的生成物。

代码本身是安全性评估，不应从中推导“X6 永远不能修改”或“FujiHack 全部型号均不支持”。这里只对**当前公开直改 XOR 字节方式**与这两份特定 X6 压缩固件的兼容性下结论。

## 5. 本轮提交与全部离线测试

公开仓库新增（只含原创分析脚本，**不含原厂 DAT 或厂商反编译代码**）：

- [`tools/audit_movie_codec_gate.py`](../tools/audit_movie_codec_gate.py)：检验运行时 byte getter/setter、录像上下文 `+0xADDA`、HEVC codec init `+0x188`、位深 `+0x0C`、分类函数，再对 X6 Sections 1–3 执行独立 ARM BL setter 调用点扫描；全部使用私人 Ghidra 输出目录；
- [`tests/test_audit_movie_codec_gate.py`](../tests/test_audit_movie_codec_gate.py)：**11** 项纯合成单元测试；
- [`tools/audit_x6_raw_patcher_compat.py`](../tools/audit_x6_raw_patcher_compat.py)：严格检测原厂 OS6 DAT 内四段 X6 LZ77，**绝不生成修改包**；
- [`tests/test_audit_x6_raw_patcher_compat.py`](../tests/test_audit_x6_raw_patcher_compat.py)：**4** 项纯合成单元测试。

Ubuntu 上复现命令：

~~~bash
cd /home/zyubuntu/xs10hk

PYTHONPATH=tools:output python3 output/audit_movie_codec_gate.py \
  --output output --scan-bl

PYTHONPATH=tools:output python3 output/audit_x6_raw_patcher_compat.py \
  /home/zyubuntu/Downloads/FWUP0025.DAT

PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

由于 Ubuntu 对 GitHub HTTPS 连接时断时续，最新脚本已通过 GitHub connector 创建、再由相同 connector 将完全相同的源代码写回 Ubuntu Git 忽略的 `output/` 路径做实际验证；原本 `tools/` 与 `tests/` Git 追踪目录尚未成功 pull 同步。

**截至本轮验证：原有 91 项 + 前五次离线新增 33 项 + 本次 11 + 4 = 共 139 项测试全部通过**。本地实际 X-S10 和 X-T4 Ghidra 反编译字符串均通过脚本校验，真实原厂 DAT 均识别到各自 4 个压缩 section。没有访问机身、USB、FF80、SD 卡或闪存。

## 6. 下一关：真正缺的证据

1. **追求最具体的 codec 菜单门控**：查运行时字节 `0x01C25208` 的**可靠写入来源和可达条件**。目前找到 32B setter，但没有找到静态直接 BL；可能需要重建间接调用表或配置块中的映射关系。
2. **上层模式组合过滤**：X-S10 要真正内录 4K60，必须证实进入 4K fps=6 与 codec=1 的配置组合，且 X-S10 的传感器/ISP/VPU/热和持续写卡均可完成。
3. **Main10 客观标准**：最终实际流中的 HEVC SPS 需要呈现 profile 2 (Main10)、bit_depth_luma_minus8/chroma_minus8 各为 2；当前没有 X-S10 机身 Main10 码流。
4. **刷机最小必要条件**：离线修改到回封 DAT 的无改动**byte-identical roundtrip**，合法完整性校验和**经验证的可用救砖机制**。另外我们的 X-S10 3.11 代码地址与用户机身 2.10 不同；不能拿这些地址直接写入旧版本。

**阶段结论**：本轮找到了运行时 codec→Recorder→VPU 初始化的真实数据链，并进一步排除了共用 LUT 的高速分类开关作为独有锁，同时识别出现成原始字节补丁器与 X6 压缩布局的关键差异。距离“可安全刷固件”仍有实质性工作，尚未开始写机。
