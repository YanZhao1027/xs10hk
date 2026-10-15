
# 第二十阶段：证实录像 Codec 是通过“设置快照 → 运行时结构整块复制”更新（2026-10-15）


> **第21阶段后续验证（2026-10-15）**：从 X-S10/X-T4 原厂 A32 指令已确认存在 `菜单 Codec 数值转换 → eModeMovieCodec setter` 的直接处理代码，两机七组数值转换表49/49相同，并保留 `1=H.265` 枚举。但这仍未证实 Recorder source snapshot `+0x5B0` **会从 UI 设置全局变量收到 1**；两者是不同的 RAM 状态。X-S10 还缺少 X-T4 专门的 H.265/4:2:0 10bit 菜单文案。应继续追实际菜单可见性与快照赋值，不应强行给相机 RAM 写入。详见 [第21阶段报告](phase21-menu-map-hevc-ui-gap-2026-10-15.md)。


> **核心突破：**前一阶段已经确认 X-S10 的录像任务从 `DAT_01C25208` 读取模式，向编码驱动初始化结构 `+0x188` 提交对应 codec 选择，但该运行时配置字节的简单 setter 没有直接 ARM BL 调用者。本阶段沿对应的设置结构及状态同步程序逆向，**找到了两台机型各自一条完整的、无需调用单字节 setter 的有效写入路径**：
>
> 1. 将设置快照的 `+0x5B0` 字节复制到一个工作状态结构；
> 2. 将**同一个工作结构指针**送入状态提交函数；
> 3. 用 `memcpy` 一次将 0x478（X-S10）或 0x47C（X-T4）字节写入**真正的当前运行时状态地址**，覆盖包含 Codec 模式的 `+0x430` 或 `+0x434` 字节；
> 4. 原有录像 getter 再从这一个运行时字节读取它，并送向录像初始化、VPU codec 字段。
>
> 这项证据说明：**没有发现独立 setter 的直接调用，不能推出 Codec 模式被锁死为 H.264**。X-S10 与 X-T4 在**这一段结构复制和提交路径**有高度一致的数据流。**但是我们仍未证明来源快照 `+0x5B0` 在 X-S10 的普通用户菜单中能够变成 H.265 对应的值 1。** 上游 UI/机型策略以及真实 Main10 编码能否启动，依然是后续需要证实的环节。
>
> 研究只使用 Ubuntu 上的**离线原厂固件及私人 Ghidra 反编译日志**，没有相机、USB、FF80、SD 或闪存操作。用户相机实际运行过的版本是 2.10，而此处分析的 X-S10 原厂 DAT 是 3.11，绝不可混用离线地址刷入机身。

## 1. 从一份设置快照找到精确的序列化字段

这次不再单纯凭 `STRB offset=0x5B0` 查找，因为不同类型的结构也可能有这个偏移——XT4 某些与视频完全无关的函数处理 `+0x5B0` 的 ASCII 字符，我们已经发现了假阳性。改为**只在真实配置同步函数内追踪来源与目标参数**。

| 符号和地址 | X-T4 2.12 | X-S10 3.11 |
| --- | --- | --- |
| 设置快照原始指针的 ROM literal 位置 | `0x0218A2FC` | `0x0221D8E4` |
| ROM literal 指向的设置快照 RAM 基址 | `0x02D109D4` | `0x02D9D284` |
| 快照中 Codec 模式字节 `+0x5B0` | **`0x02D10F84`** | **`0x02D9D834`** |
| 将快照转为工作状态的函数 | `FUN_012A313C`，1484 字节 | `FUN_012C9500`，1464 字节 |
| 工作状态指针的 ROM literal 位置 | `0x0218A300` | `0x0221D8E8` |
| 工作状态 RAM 基址 | `0x02D103B0` | `0x02D9CC60` |
| 工作结构中 Codec 字节相对偏移 | `+0x434` | `+0x430` |
| 工作结构中 Codec 字节地址 | **`0x02D107E4`** | **`0x02D9D090`** |

实际 Ghidra 反编译最后的逐字节赋值：

~~~c
// X-T4 2.12, FUN_012A313C:
working[0x434] = snapshot[0x5B0];

// X-S10 3.11, FUN_012C9500:
working[0x430] = snapshot[0x5B0];
~~~

两机的 Source offset 完全相同，Target offset 相差四字节；两机对应的工作结构前半部布局也系统性相差四字节。这里**没有做强制 H.264 的写入或 1→0 归零**，但不代表任何其它上游 / 下游函数没有模式过滤。

**指针值已从原厂解压 Section 2 对应的 ROM 32bit little-endian 字节独立读取并经脚本核验**，不是仅仅根据 Ghidra 自动符号显示推测。

## 2. 关键缺失环节已经补上：工作状态真正覆盖 Codec 当前全局值

前一阶段只找到 X-S10 32 字节 `FUN_012C04AC` 单字节 setter，缺少直接 `BL` 调用。现在找到了另外一条真实数据写入通路：

| 对应流程 | X-T4 | X-S10 |
| --- | --- | --- |
| 录像/设置状态提交的上层函数 | `FUN_02189BD4`，1832 字节 | `FUN_0221D1BC`，1832 字节 |
| 将工作状态送入提交 wrapper | `FUN_01299004` | `FUN_012C0878` |
| wrapper 内对 bulk copier 的 ARM `BL` | `0x01299020` | `0x012C0894` |
| 真正执行双份 `memcpy` 的函数 | `FUN_01295780`（64 字节） | `FUN_012BD110`（64 字节） |
| 当前运行时配置基址（第一份） | **`0x01B83540`** | **`0x01C24DD8`** |
| 备用镜像配置基址（第二份） | `0x01B83C00` | `0x01C25498` |
| 每次复制字节数 | **`0x47C`** | **`0x478`** |
| 当前配置中的 Codec 字节 | **`0x01B83974` = base+0x434** | **`0x01C25208` = base+0x430** |
| 同地址读取 Codec 的 getter | `FUN_01298C18` | `FUN_012C048C` |

已独立验证的原厂逻辑（只展示重建的结构，不复制整个厂商代码）：

~~~c
// X-T4:  FUN_01295780
if (working != NULL) {
    memcpy((void *)0x01B83540, working, 0x47C);
    memcpy((void *)0x01B83C00, working, 0x47C);
}

// X-S10: FUN_012BD110
if (working != NULL) {
    memcpy((void *)0x01C24DD8, working, 0x478);
    memcpy((void *)0x01C25498, working, 0x478);
}
~~~

两次 `memcpy` 的字节长度都覆盖对应的 codec 字节位置。即便独立 setter 没有被直接调用，**整块状态同步仍能修改相同的当前运行时字段**。

### Ghidra 参数恢复的一个重要陷阱

在 wrapper `FUN_01299004 / FUN_012C0878` 的 C 反编译中，Ghidra 把 `FUN_01295780 / FUN_012BD110` 的调用表现成**无参数函数**，这是不完整的调用约定推断。上游真实代码明确向 wrapper 传递工作指针；逐条 ARM 汇编核验显示，在 wrapper 的入口到 `BL memcpy` 之间**没有修改 R0，也没有另一个 BL**，因而该工作指针被原样交给真正的 bulk copier。

我们用一段独立、可复验的汇编日志检查此 R0 保留事实，而不是简单信赖 C 反编译的错误函数原型。测试也包含“wrapper 错误地覆盖 R0”的负例，要求分析失败。

### 实际上层调用完整顺序

X-S10 `FUN_0221D1BC` 的调用顺序：

~~~c
source  = *(uint32 *)0x0221D8E4;  // ROM literal: 0x02D9D284
working = *(uint32 *)0x0221D8E8;  // ROM literal: 0x02D9CC60
FUN_012C9500(working, source, ...);
// 其它独立配置准备；未看到这个路径强制归零 Codec 模式
FUN_012C0878(working);            // R0 保留，进而调用 FUN_012BD110
// 之后由 FUN_012BE684 从 active 全局再导出完整快照
~~~

X-T4 `FUN_02189BD4` 用 `FUN_012A313C→FUN_01299004→FUN_01295780`，结构一一对应。四个译码器直接调用 site 和另一个 config export 都有原厂 ARM BL 交叉引用；这条证明不依赖显示菜单字符串。

## 3. 还验证了相反方向的配置导出

全局配置不仅能从快照导入，另一份程序可以把当前 Codec byte 重新放回快照：

~~~c
// X-T4 FUN_01296D38:
snapshot[0x5B0] = DAT_01B83974;

// X-S10 FUN_012BE684:
snapshot[0x5B0] = DAT_01C25208;
~~~

这证明 `snapshot+0x5B0` 对应**具体运行时 Codec 字节**，而不是仅因为同一个数值偏移碰巧出现。两机都有成对的导入/导出、当前配置与镜像配置布局。

但这并不能解释 **source snapshot 的数据在菜单选择之前是怎样产生的**；这里只是找到了数据复制通路而非菜单赋值的全部上游。

## 4. 两套不同的运行时变量不能混淆

第十七阶段从设置系统解码出 **`eModeMovieCodec` 枚举**：0=H.264、1=H.265，X-S10 和 X-T4 均在录像类别 `0x2D` 的通用配置合法性检查中接受 1。

**它的底层储存地址却与本次的当前 Recorder 字节不同：**

| 概念 | X-T4 | X-S10 |
| --- | --- | --- |
| eModeMovieCodec GUI/通用设置运行变量 | `DAT_01AF2DB8`，setter `FUN_0112FD80` | `DAT_01B88650`，setter `FUN_0115B578` |
| 录像当前运行时 Codec 字节 | `DAT_01B83974` | `DAT_01C25208` |
| 已确认 Snapshot Codec byte | `snapshot +0x5B0` | `snapshot +0x5B0` |

**目前尚没有独立证据证明 `DAT_01B88650` 必然会进入 Source snapshot `0x02D9D834`；因此不能从上一阶段 GUI 设置“允许数值 1”，跳跃性推出本阶段 Source snapshot“实际可配置为 1”。**

这一层很可能就是下一步需要真正找清楚的**菜单/机型限制**。如果它被查明，还需独立证实相机能创建 Main10 VPU 会话并生成合法 HEVC SPS，而不只是静态程序“可以接受这些数字”。

## 5. 新增离线工具、原厂实测结果和不可逾越的刷机门槛

已在 GitHub 提交本阶段原创代码（不上传原厂固件、解压 ARM 段或大量反编译源码）：

- [`tools/audit_codec_snapshot_commit.py`](../tools/audit_codec_snapshot_commit.py)：分别从 X-T4/X-S10 的原厂解压 Section 2 读取两个 ROM pointer literal，并核验真正的 ARM 序列化赋值、相同工作指针从 parent 到 wrapper 的传递、wrapper 在 ARM 汇编里保留 `R0`、两个当前/镜像状态 `memcpy`、同一 active Codec byte 的 getter，以及反向导出；
- [`tests/test_audit_codec_snapshot_commit.py`](../tests/test_audit_codec_snapshot_commit.py)：**12 项完全人造数据/假 Ghidra 文本的单元测试**，包含源/目标地址错配、没有足额复制、编造不同指针、R0 被覆盖、反向回填错位、混淆 active byte 等故意失败的输入。

独立复现（需已存在本地、受 Git 忽略的 `output/` Ghidra 研究日志）：

~~~bash
PYTHONPATH=tools:output python3 tools/audit_codec_snapshot_commit.py --output output
~~~

真实 X-S10 固件输出：

~~~text
xs10.snapshot_pointer: 0x2d9d284
xs10.snapshot_mode_byte: 0x2d9d834
xs10.working_pointer: 0x2d9cc60
xs10.working_mode_byte: 0x2d9d090
xs10.active_state_base: 0x1c24dd8
xs10.active_mode_byte: 0x1c25208
xs10.mirror_state_base: 0x1c25498
xs10.bulk_copy_size: 0x478
xs10.snapshot_value_one_actual_UI_reachable: UNPROVEN
xs10.HEVC_Main10_recording_verified: False
~~~

相同工具亦在 XT4 固件上全部核验成功。第十九阶段共 **139 项**测试（91 项原有和 48 项累计新增）；本阶段另有 **12 项全部通过**，**151 项合计通过**。Ubuntu 因 GitHub HTTPS TLS 偶发中断，新增代码经 GitHub 连接器提交、再取出同字节源码放到本地受忽略的 `output/` 目录实际执行。

本次只读分析没有再通过 FF80 读取/调试实机；仍然没有可刷写补丁。X6 重压缩、厂商整体封装校验/潜在签名、机身当前 2.10 与离线 3.11 的差异和独立救砖路径依然未解决；**切勿把这个虚拟地址做现场内存写入或固件编辑。**

## 6. 下一步的严格研究目标

1. **优先追踪 X-S10 Source snapshot `0x02D9D834` 的写入来源**。Ghidra 对 `0x02D9D284` 基址已有 113 条交叉引用，但字段 `0x02D9D834` 本身没有静态直接交叉引用；说明必须结合间接指针、结构布局、菜单/配置回调与批量复制来恢复。X-T4 `0x02D109D4` 有 119 条基址引用，适合作正对照。
2. 把此 Source snapshot 的 `+0x5B0` 与 GUI/通用 eModeMovieCodec (`0x3FC`) 赋值过程连起来，查明“1”在哪个机型/模式选择条件被允许或拒绝；不要只找第一个数值 1 就写补丁。
3. Main10 继续需要真正 HEVC SPS/硬件 Profile 证据，4K60 还需验证 sensor/ISP/VPU/码流持续写入可用性。
4. 打包/刷机之前必须先在电脑端**完全无改动**的 X6 压缩/回封往返测试、完整性鉴定和独立救砖确认。**目前不制造刷写 DAT。**

**本阶段结论：缺失的“运行时 Codec 写入者”已查明是一条完整的 snapshot → working → active bulk-copy 提交路径，但真正的可配置能力仍取决于上游 snapshot 如何获得用户选择，不能把软件栈传递能力等同于 X-S10 已经支持内录 Main10。**
