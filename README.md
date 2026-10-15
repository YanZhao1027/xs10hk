# X-S10 Firmware Research / X-S10 固件研究

研究目标：评估富士 X-S10 的 **4K30 10-bit 机内录制** 和 **4K60** 是否受固件限制，区分视频菜单限制、硬件编码能力、传感器读取模式、HDMI 处理链与散热限制。

> 项目当前为 **只读研究阶段**。不刷写、不修改 SD 卡内容、不运行未经验证的相机端代码。尚无证据证明 X-S10 可以解锁 4K60 或 10-bit 内录。




## 第 21 阶段：H.265 菜单数字映射竟然 49/49 相同；差异指向 UI 资源（2026-10-15）

**新完成的原厂 ARM 指令与表数据双重校验：**X-S10 `0x02103A30` 通过数值转换器读取电影编码设置 `0x3FC`，再于 `0x02103A38` 直接调用 `FUN_0115B578` 更新 `eModeMovieCodec`；X-T4 的对应调用地址为 `0x02057E74`／`0x02057E7C`、设置项 `0x3E5`。全部真实 A32 BL 及 MOV 立即数由脚本独立计算验证。

两机共有七组成对录像设置的 **49 条完整 16B UI 数值转换记录，49/49 完全相同**；其中 codec 的四行映射都为 **`[1,0,1,0]`**（`eModeMovieCodec` 1=H.265、0=H.264）。此前又已证明两机的通用 codec 设置权限接受 H.265 枚举值1，因此**X-S10 并未在这些通用设置数值表内删去 HEVC。**

**新发现的机型差异反而在 UI 文案：**原厂 payload UTF-16LE `H.265` 文本 X-T4 有105处、X-T3有175处、**X-S10为0**；`4:2:0 10bit` X-T4有23处、X-T3有52处、**X-S10为0**。与此同时 X-S10/T4 底层均注册 `UI_MOVIE_CODEC_H265`，均有126项 `UI_MOVIE_MODE_*` 名称。X-T4 `MSG_ITEM_TITLE_FILEFORMAT_MOVH265` 等独立 MOVH265 菜单文案在 XS10 对应 Section1 中缺失。**优先继续追前端菜单可见性与 UI→Recorder 配置快照的桥接，而不是随便更改 HEVC 驱动代码。**

**重要界限：**现在证实的是**菜单转换处理分支存在**、映射表包含 H.265 值1，**不是 X-S10 正常可见菜单就能选择 H.265**；还没有证明 UI 全局变量 `0x01B88650` 能写入 Recorder 的 source snapshot `0x02D9D834`，更没有 Main10 SPS/4K60 实机录制证据。研究依然 **100%离线**，无 FF80 USB、固件打包或刷机。

**[第21阶段完整分析、49条映射表、ARM指令验证及源码](docs/phase21-menu-map-hevc-ui-gap-2026-10-15.md)**。新增 `tools/compare_codec_menu_mappings.py` 与12项全合成单元测试；目前 **163项离线测试全部通过**。

## 第二十阶段：找到真实的“录像 Codec 配置字节”批量写入者（2026-10-15）

**本阶段最重要的新增代码证据**：此前找到的 X-S10 运行时录像模式字节 `DAT_01C25208`（及 X-T4 对应 `DAT_01B83974`）**并不只能通过那个没有直接 BL 调用者的 32 字节 setter 更新**。两机还有能够逐层验证的**配置快照 → 工作状态 → 当前全局状态**数据路径：

| 真实数据流 | X-T4 2.12 | X-S10 3.11 |
| --- | --- | --- |
| 原始配置快照的 Codec 字节 | `0x02D10F84`（base+`0x5B0`） | **`0x02D9D834`**（base+`0x5B0`） |
| 经 ARM 配置翻译后的工作 Codec 字节 | `0x02D107E4`（+`0x434`） | **`0x02D9D090`**（+`0x430`） |
| 将工作结构提交到当前运行状态的 memcpy 函数 | `FUN_01295780` | **`FUN_012BD110`** |
| memcpy 字节数 | **`0x47C`** | **`0x478`** |
| 真正的当前运行时 Codec 字节 | `0x01B83974` | **`0x01C25208`** |
| 反向从当前运行时导出快照 | `FUN_01296D38` | `FUN_012BE684` |

具体实证：Ghidra 明确显示 `working[+offset] = snapshot[0x5B0]`；上层将**同一工作指针**送入 memcpy wrapper；直接 ARM 汇编证明 wrapper 保留 R0 给底层 memcpy；两机复制长度均覆盖 Codec 字节。其后上一阶段已确认的录像 getter 从当前运行时字节取值，并最终影响 VPU 初始化的 codec 字段。**因此 X-S10 的 Codec 模式并未在这一段批量提交中被硬编码成 0。**

**极重要区别：**另一个名为 `eModeMovieCodec` 的通用 UI 设置变量（X-S10 `DAT_01B88650`）**并不等于**这里的录像运行时字节（`DAT_01C25208`）。**下一关是找 Source snapshot `0x02D9D834` 怎样接收用户的 H.265 选择**。尚未证明正常菜单能把值 1 送进去，也未证明 Main10 SPS/4K60 硬件支持或具备安全的刷机包。

**[第 20 阶段完整离线 Ghidra 控制流、源码和测试](docs/phase20-codec-snapshot-commit-2026-10-15.md)**。新增 `tools/audit_codec_snapshot_commit.py` 和 12 项合成数据单元测试。**当前累计 151 项离线测试通过**；仍未向相机发送调试命令、写 RAM、做固件修改或刷机。

## 第十九阶段：运行时 codec 状态追踪到 VPU 初始化；明确 X6 刷机封装风险（2026-10-15）

**新增的真实控制流证据：**X-T4 与 X-S10 的录像程序不是把 H.264 写死，而是分别通过 32 字节 Getter 获取运行时配置字节，再写入录像上下文 `+0xADDA`，最后交给 H.265 驱动初始化函数。

| 组件 | X-T4 2.12 | X-S10 3.11 |
| --- | --- | --- |
| Codec 运行时配置字节 | `0x01B83974` | `0x01C25208` |
| Getter | `0x01298C18` | `0x012C048C` |
| Setter（新验证 ARM） | `0x01298C38` | `0x012C04AC` |
| Recorder 生成 HEVC init | `0x0224B65C` | `0x022DEE64` |
| VPU codec 字段 | 400B init 结构 `+0x188` | 400B init 结构 `+0x188` |
| Codec mode=1 时 | `video_codec=0` | `video_codec=0` |
| 独立位深字段 | `bit_depth=1` | `bit_depth=1` |

**更接近真正的 UI 解锁分歧了：**X-S10 确有具体的 codec 数据来源、配置字节及从 Recorder 到 VPU 的条件分支，但扫描三段 ARM 代码没有发现两个 setter 的直接 BL 调用点；仍需恢复菜单/配置块的**间接写入路径**，不能宣称已找到能直接刷写的开关。

**对刷机尤其重要的新结论：**检测了 X-S10 3.11 和 X-T4 2.12 原厂 DAT，虽然 FujiHack 的公共 patcher 能解析 OS ID `6` 的 header，但两机各自含 **4 个独立 X6 LZ77 压缩段**；当前公开的原始 XOR 字节直接注入方式**不是一个已验证的 X6 解压修改再重压缩安全工作流**，不能把 Ghidra 解压段 ARM 地址当作 DAT 文件偏移。不要盲用它给 X-S10 刷固件。

新增原创安全脚本 `tools/audit_x6_raw_patcher_compat.py` 只读原厂 DAT 并明确输出不能认定安全；`tools/audit_movie_codec_gate.py` 校验完整 codec 数据路径。**本阶段新增 15 项合成测试，累计 139 项全部通过**。

**[第十九阶段完整报告：codec 实际源数据、setter ARM 调用和刷机 X6 压缩风险](docs/phase19-runtime-codec-and-x6-patcher-2026-10-15.md)**。仍是纯 Ubuntu 离线研究，**没有相机通信、修改版固件或刷机测试**。

## 第十八阶段：真正 H.265 位深参数贯通录像程序与驱动（2026-10-15）

**最接近 Main10 的新证据：**从三机实际 H.265 驱动的错误日志 `#init bit_depth ERROR` 反向还原到了一个**独立的位深输入字段（400 字节 init 结构，偏移 `+0x0C`）**：

| 机型 | 录像初始化写入 | H.265 驱动 bit_depth 检查 | 会话格式输出 |
| --- | --- | --- | --- |
| X-T3 5.11 | `bit_depth=1` | 检查通过（codec=0 时拒绝 >1） | 非零→`0x0121` |
| X-T4 2.12 | `bit_depth=1` | **同样** | 非零→`0x0121` |
| **X-S10 3.11** | **`bit_depth=1`** | **同样** | **非零→`0x0121`** |

已验证三机各自的 **936 字节驱动输入检查函数**、400 字节结构复制、运行时会话 DWORD`[3]` 赋值和对该字段的**两个真正分支：零值时 `0x0201`，非零时 `0x0121`**。这意味着 X-S10 H.265 初始化里的位深字段**不仅不是被硬编码成 0，而且进入了后续会话格式生成逻辑**。

此前 X-T3/X-T4 编码参数 `input[3]=1/3` 与这里的**驱动初始化 bit_depth=1** 是两套不同结构；前者已经追到 `0xBBB` 类别、`0x0A` 编码选项包，且与码率相关数据打包发送。**不能把那个 1/3 直接当作 Main10 开关。**

**[第十八阶段：三机位深判断、会话格式分支和编码参数下传的可复验证据](docs/phase18-h265-bitdepth-runtime-chain-2026-10-15.md)**。工具 `tools/audit_h265_bitdepth_chain.py`、8 项合成测试 `tests/test_audit_h265_bitdepth_chain.py`。

**界限：**尚未查明枚举 `1` 的官方含义，也未实际取得 X-S10 HEVC Main10 SPS 证明；UI/传感器/存储端的许可仍未突破。以上地址来自离线 X-S10 3.11，**不能用于机身现有 2.10 的 RAM 读写或刷固件**。这轮依然只有本地固件分析、没有相机操作。

## 第十七阶段：解出 H.265 设置允许值矩阵——X-S10 通过合法性检查（2026-10-15）

**新突破：在真正执行的设置校验代码及固件数据表中，X-S10 3.11 的 `eModeMovieCodec=1`（H.265）**对于录像类别 `0x2D` **通用验证结果为允许，与 X-T4 2.12 完全相同。**

| 参数 | X-T4 2.12 | X-S10 3.11 |
| --- | --- | --- |
| 编码设置项 ID | `0x3E5` | `0x3FC` |
| H.264 枚举 `0` | flag `2`，允许/优先默认 | flag `2`，允许/优先默认 |
| H.265 枚举 `1` | flag `1`，允许但非默认 | flag `1`，允许但非默认 |
| 录像 category ID | `0x2D` | `0x2D` |
| 设置表每选项行长度 | `16` 字节 | `28` 字节 |
| category 总数 | `9` | `24` |

ARM 反编译中的核心合法性条件为 `(uint8_t)(flag - 1) < 4`，所以 H.265 对应 flag1 在**两机都通过此项通用合法性检查**。该结果独立经过真实固件表项的离线逐字节解读与模拟单元测试验证，不是字符串搜索。两机 setter 也都能接受枚举 1（对应的 ARM 枚举名称函数明确返回 `MODE_MOVIE_CODEC_H265`）。

**重要限制：** 这不是“X-S10 已能内录 Main10”或“4K60 已解锁”。UI 是否提供选项、录像任务是否真正送出 HEVC 会话、VPU profile/10-bit 输入格式能否成功、热与写卡等均未得到实机证据。**绝不能简单移植 16 字节的 X-T4 表到 28 字节的 X-S10 表。**

**[第十七阶段：设置权限矩阵解析、Ghidra 代码证据及复现](docs/phase17-movie-codec-permissions-2026-10-15.md)**。离线工具：`tools/codec_setting_permissions.py`。

~~~bash
python3 tools/codec_setting_permissions.py \
  --xt4-section1 output/x6-xt4/section-1.bin \
  --xs10-section1 output/x6-xs10/section-1.bin
~~~


**进一步交叉验证：** 与 codec 配置相邻的另外四组录像相关设置也有一对一 ID 映射（X-T4 `0x3DD/0x3DF/0x3E2/0x3E4/0x3E5` 对应 X-S10 `0x3F4/0x3F6/0x3F9/0x3FB/0x3FC`）。两机录像类别的 **33 条有序 (设置数值, 权限 flag) 全部相同**；即使某些原厂表存在重复数字，新工具也能保留重复条目准确比较。其它三个设置项的精确语义还未确定，因此仍未证明 4K60 完全开放。

~~~bash
python3 tools/compare_movie_perm_groups.py \
  --xt4-section1 output/x6-xt4/section-1.bin \
  --xs10-section1 output/x6-xs10/section-1.bin
~~~

## 第十六阶段：恢复尚未分析的第 3 个 ARM 程序段（2026-10-15）

已验证 X-T4、X-S10 的 X6 LZ77 `section-3.bin` 均为 **包含真实 ARM 程序和混合数据**的二进制。通过文件首个函数指针、两个 ARM 函数序言、内部 BL 分支目标独立验证段地址，并将其加载进既有 Ghidra 联合项目，**两机均分析成功并已保存**。其中尚有区域落到非代码数据，完整运行时 overlay/重定位仍待确定，不能将任何地址范围内字节盲目改写。

**[第十六阶段：第三 ARM 段地址推导与 Ghidra 验证](docs/phase16-third-arm-section-2026-10-15.md)**。离线工具：`tools/x6_third_section_map.py`。

此前阶段新增的 8＋5＋8＋4 项测试，第十八阶段新增 8 项、第十九阶段新增 15 项第二十阶段新增12项、第21阶段新增12项，与原有91项合计 **163 项全部通过**（第21阶段新增12项菜单转换+ARM调用验证测试）。所有程序源码已提交 GitHub；Ubuntu 目前遇到 GitHub TLS 握手失败，本轮在本地 Git 忽略的 `output/` 目录采用 GitHub 同字节源码备份运行测试。**实机 USB 诊断仍暂停；无相机操作，也无修改固件。**

## 第十五阶段：4K60 真正录像参数表恢复（2026-10-14）

**最新突破不是又找到 4K60 的名字，而是恢复了 X-S10 与 X-T4 实际查表程序使用的 96×64 字节录制参数 LUT。** Ghidra 已确认函数 X-S10 `0x022E123C`、X-T4 `0x0224DB10` 按四项键选中记录，派生视频分辨率、码率和其它 VPU 配置值。两机**全部 96 条（6,144 字节）逐字节完全相同**，SHA256 均为 `43852b4bb7454ad54b1a9d018432250829abb334dec9961fb54e4862407199bc`。

**这份硬核代码证据显示：X-S10 LUT 中确实存在 4096×2160/59.94 的 3 条候选记录，以及 3840×2160/59.94 的 3 条候选记录（每台机器相同，共 6 条）。** 对应真正的 88 字节宽高转换函数返回 4096×2160 / 3840×2160 / 2048×1080 / 1920×1080；六档 fps 都被这张表覆盖。注意：**这些不是已经验证可实际启用的录像格式**；机身的上层模式许可、Main10 位深、传感器/ISP 性能和写卡链条仍未验证。

本轮还发现两机共用的 `recfCalcCorrect4kParam` 会临时将某些运行字段赋值为 `8`；这**不是 X-S10 独有的 8-bit 锁**。下一阶段应定位表前的四字段模式筛选，及表后的动态配置值，而不是盲改 `8`、`1` 或 `3`。

**[第十五阶段详细报告及真实 ARM 调用证据](docs/phase15-recorder-lut-4k60-2026-10-14.md)**

只读验证：

~~~bash
python3 tools/compare_recorder_tables.py \
  --xt4-section1 output/x6-xt4/section-1.bin \
  --xt4-section2 output/x6-xt4/section-2.bin \
  --xs10-section1 output/x6-xs10/section-1.bin \
  --xs10-section2 output/x6-xs10/section-2.bin
python3 -m unittest discover -s tests -q
~~~

离线测试现为 **99 项全部通过**（原仓库 91 项 + 新增 8 项；本轮 Ubuntu→GitHub HTTPS 暂时不可用，因此新增代码以已提交 GitHub 字节副本在本地忽略目录中完成验证）。没有 USB 实机操作，也没有生成刷写包。

## 第十四阶段：实际录像任务直通 H.265 驱动（2026-10-14）

**突破：把每台机身解压后的两段 ARM 程序放入同一个 Ghidra 项目，正式确认来自“录像初始化业务”到“HEVC 驱动参数设置”的直接 ARM BL 调用。**

| 机型 | 录像程序中的跨段 BL | H.265 参数包装函数 |
| --- | --- | --- |
| X-T3 5.11 | `0x01F03738` | `0x01096B44` |
| X-T4 2.12 | `0x0224BC90` | `0x011CAB08` |
| **X-S10 3.11** | **`0x022DF508`** | **`0x011F745C`** |

三机录像程序均会准备 60 字节 HEVC 编码参数结构并带回调传给驱动。`input[2]`（偏移 `+8`）已经被证实为 **Q16.16 帧率**，三机均有 `0x3BF0A3`（59.94 fps）的赋值分支。注意：**X-S10 能 FHD59.94，不能由此证明 4K59.94 可以使用**。

一个值得继续调查但**语义未验证**的差异：在当前录像初始化函数中，X-T3 与 X-T4 的参数 `input[3]` 可被设置为 `1` 或 `3`，X-S10 仅观察到 `3`。**绝不应未经证明就称其为 Main10/8-bit 开关或拿它刷机。**

两机上层视频初始化结构均从录制上下文中提取两个 16 位尺寸相关字段，并调用类似的 VPU 初始化参数校验函数（X-T3/X-T4/X-S10 都是 716 字节）。**X-S10 不只是有相同 H.265 编码模块，其录像任务实际上还存在明确的 H.265 初始化和编码参数提交调用点**；模式可达性、像素位深、4K60 同时满足仍未证明。

**[第十四阶段完整 ARM 调用链、Q16 帧率/尺寸参数和实测地址](docs/phase14-cross-segment-hevc-params-2026-10-14.md)**

电脑端全离线复现：

~~~bash
python3 tools/x6_cross_segment_calls.py --model xs10 \
  --section1 output/x6-xs10/section-1.bin \
  --section2 output/x6-xs10/section-2.bin
python3 tools/audit_hevc_recorder_builder.py \
  --xt3 output/xt3_recorder_hevc_init.c.txt \
  --xt4 output/xt4_recorder_hevc_init.c.txt \
  --xs10 output/xs10_recorder_hevc_init.c.txt
python3 -m unittest discover -s tests -q
~~~

截至当时项目累计 **91 项自动化测试通过**；第十五阶段新增 8 项后，现累计 99 项，无相机 USB 操作，没有生成或写入修改后的固件。

## 第十三阶段：X-T3 正对照确认三机共用 H.265 编码器（2026-10-14）

用户新增 X-T3 官方 5.11 文件 `FWUP0019.DAT`（本地 SHA-256 `9f2c75fd8a16a1d71b9218f6dbd3144b1f11820bcecd3a9608c8cda9f25f95a3`）。**已用原来的 X6 LZ77 解压器解出 2/2 个压缩段，并成功导入 Ghidra 的两个 ARM 入口。** X-T3 和 X-T4 都已知支持 H.265 4:2:0 10-bit / 4K60 内录，因此是 X-S10 的两个“正对照”。

**决定性新证据：三机的 H.265 encoder 425,984 字节、H.264 encoder 233,472 字节、H.264 decoder 81,920 字节，累计 741,376 字节，全部逐字节一致（0 字节差异）。** 不只是名字一样，原厂字节和 SHA-256 完全一致。X-T3 的 H.265 参数接收函数也跟 X-T4/X-S10 同为 368 字节，VPU 参数装载函数同为 220 字节，Session 映射函数同为 312 字节，事件分派函数同为 504 字节；已在 Ghidra 中恢复相似的真实 ARM 调用关系。

三机本地 DAT payload 中 UTF-16LE `4:2:0 10bit` 的出现次数：X-T3 **52**、X-T4 **23**、X-S10 **0**；`H.265` 分别 **175 / 105 / 0**。说明 UI/本地化资源层有区别，但**并不等于已定位 Main10 开关**。

另一个关键反例：已知支持 4K60 和 10-bit 的 X-T3，录像上下文步长 `0x3C0E8`，反而比 X-S10 的 `0x3C318` **小 560 字节**。**之前不能再把“X-S10 录像上下文比 X-T4 小”当作不能支持 Main10/4K60 的证据。**

**[第十三阶段完整代码证据、三机地址及研究报告](docs/phase13-xt3-three-way-positive-control-2026-10-14.md)**。

全程仅分析 Ubuntu 上已下载的原厂文件，不操作相机；全部厂家解压程序留在本地 `output/`，不会提交 GitHub。

~~~bash
python3 tools/three_way_codec_audit.py \
  --xt3 output/xt3-payload.bin \
  --xt4 output/xt4-payload.bin \
  --xs10 output/xs10-payload.bin
python3 -m unittest discover -s tests -q
~~~

当时共 80 项测试通过；第十四阶段新增测试后累计 91 项通过。尽管两台 Main10 正对照大大提高了研究信心，**X-S10 内录 10-bit / 4K60 的有效调用路径及刷机救援机制尚未确定**。

## 第十二阶段：HEVC 真实编码驱动与录像任务差异（2026-10-14）

**已用 Ghidra 自动分析 X-S10 3.11 与 X-T4 2.12 各自的前两段主程序，追踪到真实的 H.265 编码参数驱动函数，而不仅仅是字符串：**

- X-S10 `FUN_011F9B84` ↔ X-T4 `FUN_011CD230`：均约 368 字节，具有状态检查、复制 60 字节编码参数、登记回调、向 VPU 通知处理等结构；**H.265 驱动可执行代码确实存在**，但内部 Main10 激活路径还未打通。
- **126/126 个 `UI_MOVIE_MODE_*` 名称及 ID 在两机完全相同**，包含各 8 个 4K59.94/50 资源。它们是**共用资源注册表**，不能作为 X-S10 具备实际 4K60 能力的证据。
- X-T4 独有若干 H.265 MOV 文件格式菜单的标题/说明资源；上层文件格式处理存在差异。
- 录像帧等待与上下文初始化**存在真实代码差异**：X-S10 对一些状态使用 6/7 的基准值，X-T4 对应为 11/13/14；两机上下文结构步长分别为 `0x3C318` 和 `0x4B0A0`。这些数值的物理语义仍需进一步恢复，**不能直接照搬 X-T4 常量**。
- 重要：UI 资源 ID（H.265=0）和运行时 `eModeMovieCodec` 编码枚举（H.265=1）**并非同一数值体系**。

**[第十二阶段完整调用图与证据报告](docs/phase12-hevc-recorder-code-path-2026-10-14.md)**

电脑端复现：

~~~bash
python3 tools/compare_video_resources.py --xs10-dir output/x6-xs10 --xt4-dir output/x6-xt4
python3 -m unittest discover -s tests -q
~~~

Ghidra 可使用 `ghidra_scripts/ProbeX6Refs.java` 和 `TraceX6Function.java` 跟踪本文地址。全部实机诊断继续暂停；**仍未找到可安全解锁 10-bit/4K60 的确证开关**。

## 重大突破：已完整解压 X6 LZ77 主程序（2026-10-14）

**X6 压缩解码格式已独立还原：X-S10 3.11 和 X-T4 2.12 的 8/8 个压缩段均成功完整解压，输出长度严格匹配原厂包头。** 采用 `tools/x6_decompress.py`，已恢复共约 67.8 MB 的二进制程序与资源（仅保留在本机受 Git 忽略的 `output/x6-*/`）。**没有使用相机维修接口**。

更进一步，`tools/x6_load_hints.py` 识别出 X-S10 与 X-T4 各前两段的装载基址及 ARM 入口候选，**4/4 个入口都通过 Ghidra 12.1.4 的 ARM32 反汇编验证**。第十二阶段已正式开始编码驱动/录像资源的交叉引用与反编译比较。

**完整技术报告：[第十一阶段：X6 LZ77 完整解压与 Ghidra 验证](docs/phase11-x6-lz77-decompressed-2026-10-14.md)**。

离线复现（输出目录已有数据时，省略 `--output-dir` 只计算散列，不会覆盖原有文件）：

~~~bash
python3 tools/x6_decompress.py output/xs10-payload.bin
python3 tools/x6_decompress.py output/xt4-payload.bin
python3 tools/x6_load_hints.py output/x6-xs10/section-1.bin output/x6-xs10/section-2.bin
python3 -m unittest discover -s tests -q
~~~

**注意：成功解压 ≠ 可以安全刷写。** X6 重压缩、整个 DAT 的校验/签名、X-S10 2.10 与离线 3.11 的地址差异，以及独立救砖机制仍待解决。仍无证据证明 10-bit 机内录制或 4K60 已可启用。

## 重要安全状态：FF80 RAM 实机读取失败（2026-10-14）

> **请勿再在 X-S10 上运行 FF80 RAM 读取或 USB 调试配置修改。** 实验期间调试标记 `0xF7` 临时设为 `1` 并确认；随后仅 16 字节的 RAM 读取请求造成 FF80 超时，恢复标记的指令也超时，无法确认其值恢复。没有获取内存数据，没有调用 EEPROM 保存或固件更新。**机主已确认取出电池并重新装回后可正常开机；全部拍摄功能尚未逐项复核。**
>
> 为防止误用，`tools/ff80_ram_sample.py` 的主入口已强制禁用。现在已确认普通开机恢复正常；后续研究改为已解压的固件代码分析，不再尝试 FF80 内存读取或调试配置修改。详见 [第八阶段失败记录](docs/phase8-ff80-ram-timeout-2026-10-14.md)。

## 第二次 FF80 RAM 读取：离线审核结论

机主希望再次尝试读取 RAM，但本次离线审核后仍**不建议在当前 X-S10 上执行第二次 FF80 读取**：已确认上次的读命令封包与上游参考实现逐字节匹配，无法靠修正一个已知包格式错误降低实机风险；同时没有 X-S10 2.10 的可靠内存映射。**此次只新增离线协议测试，不访问相机**。

[第九阶段：第二次试读审核与必要安全条件](docs/phase9-ff80-second-read-review-2026-10-14.md)。可运行 `python3 -m unittest discover -s tests -v` 进行协议向量与其它离线测试；该阶段当时 43 项通过；项目随后已增加 X6 解压测试。未来若能确认可用 RAM 地址、验证错误恢复和独立固件救砖流程，再重新评估现场试读。`tools/ff80_ram_sample.py` 仍强制禁用。

## 第十阶段：固件压缩边界与恢复路径离线核查

**已在原厂 X-S10 3.11 与 X-T4 2.12 固件中验证 8/8 个压缩段候选尾部的全零对齐填充**，比先前更可靠地确定了压缩数据的文件范围。这是此前阶段的历史状态；目前已经解压成功，并获得四个高置信度装载与 ARM 入口候选（仍未做实机内存映射验证）。

与此同时，简单字节/字求和、取反、CRC32 等**均不能从这两份原厂文件直接复现头部 checksum 值**；公开工具的增量校验逻辑不能直接视为已适配 X6。官方 SD 卡恢复只涵盖部分更新失败情形，**未找到 X-S10 可独立于坏主固件启动的已验证救砖路径**。

详见 [第十阶段：压缩段边界、checksum 与恢复方案核查](docs/phase10-offline-map-recovery-2026-10-14.md)。电脑端可运行 `python3 tools/package_invariants.py /home/zyubuntu/Downloads/FWUP0025.DAT` 复现。全部操作只读且离线，**绝不向相机发维修指令**。

## 当前状态（2026-10-14）

- 研究主机：Ubuntu 24.04.5 LTS (x86_64)。
- 已重新连接并通过标准 PTP 通信确认 Fujifilm X-S10，VID:PID `04cb:02ea`。Ubuntu 的相机桌面挂载已恢复。
- **机身运行版本：2.10**（2026-10-14 从实际 USB 相机标准 PTP `GetDeviceInfo` 读取两次确认）。它不同于本地已下载的 X-S10 **3.11** 官方固件包；不能混淆地址/代码版本。
- 用户已从官方页面下载 `FWUP0025.DAT` 至 `/home/zyubuntu/Downloads/`；文件头读取出 Ver.3.11，SHA-256 记录如下，但**尚未验证厂家签名或校验和**。
- 已在 `output/xs10-payload.bin` 离线提取约 48.7 MiB 负载；标记扫描结果仅保留在 `output/video-markers.json`。
- 目前发现 HEVC/H.265 编码器相关诊断文本与 `4K_59_94P_400M_16` 模式名，**不能据此推断机身具备可用的编码或 4K60 功能**。
- 已记录 [第一阶段研究笔记](docs/findings-2026-10-14.md)、[第二阶段 Ghidra / 编码模块分析](docs/phase2-2026-10-14.md)。
- Ghidra 12.1.4 + JDK 25 已验证并安装在 `/home/zyubuntu/tools/`；本地项目放在被忽略的 `output/ghidra/`。
- 同一套签名发现 H.265 Encoder、H.264 Encoder、H.264 Decoder 三组描述符，但是否执行仍未证实。
- 通过比对大小字段与公开压缩率记录，已经在 X-S10 3.11 与 X-T4 2.12 两套 X6 固件中各找到 **4 组压缩段头候选记录**；现已在第十一阶段成功解压八段数据，并通过 Ghidra 核实前两段的入口映射候选。
- 注意：直接扁平导入**仍在压缩状态的原始负载**会把数据误解为代码；现在已按解压后的前两段候选装载地址成功导入 Ghidra。
- 仓库中的工具只用于电脑端检查和**离线、只读**文件分析。

## 当前重点：HDMI 10-bit 与机内 Main10 并非同一路径

官方 X-S10 说明书确认 HDMI 4:2:2 10-bit、SD 4:2:0 8-bit；X-T4 说明书则确认 SD 上的 H.265 4:2:0 10-bit。共享 HEVC 固件块不能证明 X-S10 已经具备机内 HEVC Main10 初始化能力。参见 [下一阶段研究路线与可选诊断模式的风险说明](docs/next-step-hdmi-and-diagnostic-2026-10-14.md)。

如果有 Atomos 外录样片，可以用 `bash tools/probe_recording.sh /path/to/clip.mov` 本地检查视频文件编解码元数据，但元数据不能独立证明 HDMI 输入位深。**由于历史 FF80 实验曾导致相机无响应，现在停止任何 FF80 实机操作，继续纯离线逆向。**

## USB 维修诊断研究（已进入，受限只读查询成功）

已在 X-S10 实机上成功进入并退出 `04cb:ff80` 维修模式（红灯、黑屏），验证普通开机能恢复；**受限 FF80 信息查询成功**：`product_name=X-S10`、`device_version=1.60`（含义待确认）、`device_type=CAMERA`、`framework=1.00`。普通 PTP 曾报告 `2.10`，两个字段不可混为一谈。在第七阶段只读查询固定配置字节 `0xF7` 得到 **`0x00`（USB 调试关闭）**。**其后第八阶段曾临时改动 RAM 调试配置并试读 16 字节，导致 FF80 无响应；取出电池后正常开机恢复，后续所有实机诊断暂停。**参见 [第七阶段实机 FF80 报告](docs/phase7-ff80-live-2026-10-14.md)，以及 [第六阶段入口测试](docs/phase6-ff80-constrained-probe-2026-10-14.md)。

## 历史 FF80 单字节调试状态检查（已停止现场操作）

~~~bash
python3 tools/ff80_debug_flag.py
~~~

此脚本**只读取**地址 `0xF7` 的 1 个配置字节，不会开启调试，也不读取 RAM/刷机。但鉴于第八阶段的相机不响应事件，**目前不要运行任何 FF80 现场检查**。详见 [第八阶段报告](docs/phase8-ff80-ram-timeout-2026-10-14.md)。

## USB 实机固件版本确认（安全只读）

~~~bash
bash scripts/ptp_device_info.sh
~~~

[完整实验记录](docs/phase5-ptp-current-firmware-2026-10-14.md)。该脚本仅通过标准 PTP 读取 DeviceInfo，必要时临时卸载并恢复 GNOME 的相机挂载；**不读取照片/RAM，不进入维修模式，不写入相机**。

## 从 USB 检查开始

在 Ubuntu 终端运行：

~~~bash
bash scripts/check_usb.sh
~~~

如未发现设备，使用支持数据的 USB-C 线，将相机设置为「USB 读卡器」，连接电脑后 **开机**，然后重跑脚本。无需安装驱动、无需 sudo。该脚本只读取 USB 枚举信息，不向相机写入数据。USB 读卡器模式不是读取相机固件的调试接口。

## 下载并检查原厂固件（需自行阅读并接受官方许可）

官方入口：https://www.fujifilm-x.com/global/support/download/firmware/cameras/x-s10/

官方公布的 Ver.3.11（2024-03-28）文件名为 **FWUP0025.DAT**。固件已下载到本机 Downloads，直接运行以下只读命令：

~~~bash
sha256sum /home/zyubuntu/Downloads/FWUP0025.DAT
python3 tools/fw_inspect.py /home/zyubuntu/Downloads/FWUP0025.DAT
~~~

若只读解析结果符合预期，且决定将原厂负载导出供后续静态分析，可执行：

~~~bash
python3 tools/fw_inspect.py /home/zyubuntu/Downloads/FWUP0025.DAT --extract output/xs10-payload.bin
~~~

首次提取已完成；重复执行会因目标文件已存在而停止，以免覆盖。分析脚本只读取 DAT 和写入指定的电脑本地输出文件；不会访问 USB 相机、不会生成可用于刷机的修改固件、也不校验厂家签名。**解析成功不代表固件安全或机型已被破解**。

## 扫描视频功能标记

~~~bash
python3 tools/video_markers.py output/xs10-payload.bin --json output/video-markers.json
~~~

此命令已运行过一次；再次输出 JSON 时请选择新路径，因为工具不会覆盖已有结果。字符串命中并不是功能可用的证据。

## 识别视频编解码模块描述符

~~~bash
python3 tools/module_inventory.py output/xs10-payload.bin
~~~

## 运行离线单元测试

~~~bash
python3 -m unittest discover -s tests -v
~~~

测试使用自造的合成字节数据；不包含富士原厂固件。

## 研究路线

1. USB 枚举与版本信息确认（不进行写入）。
2. 离线检查 X-S10 官方 DAT 包头及负载格式，记录 SHA-256。
3. 在合法且获得许可的前提下对比 X-S10 与 X-T4 的固件组件、视频模式表及编码器初始化。
4. 静态分析结果要与实际硬件能力分开记录；不能仅凭相同的 X-Processor 4 推断功能可解锁。
5. 在有可靠恢复手段、充分测试之前，不尝试补丁刷写。

## 安全与版权

- **禁止向本公开仓库提交** 原厂 \`.DAT\`、解包的 \`.bin\`、内存镜像、存储卡照片、含序列号的日志或其它可能属于第三方的受版权保护文件。
- 富士官方固件下载协议包含逆向工程限制，请自行查阅和考虑适用法律及使用许可。
- FujiHack 列出的「使用同类 RTOS 的机型」**不等于**针对该机型已有成熟补丁。
- 已有资料：[官方固件页面](https://www.fujifilm-x.com/global/support/download/firmware/cameras/x-s10/)、[FujiHack 固件格式](https://wiki.fujihack.org/firmware/)、[FujiHack 项目](https://github.com/fujihack/fujihack)、[FujiHack Patcher](https://github.com/fujihack/patcher)。
