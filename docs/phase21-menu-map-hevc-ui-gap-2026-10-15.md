# 第21阶段：破解菜单数值转换表，发现 X-S10 H.265 UI 资源缺口（2026-10-15）

> **新证据**：用 X-T4 2.12 作正对照，从实际 ARM 指令恢复了 X-S10 3.11 的“菜单输入 → 配置数值转换 → eModeMovieCodec setter”完整单次处理分支。两机**七组录像设置转换表共 49 条记录的全部四 DWORD 逐条完全相同**；其中 H.265 编码设置的四个行索引映射为 **1、0、1、0**。此外，X-S10 虽保留 codec/UI 代码资源注册，却**缺失 X-T4 中 H.265/4:2:0 10bit 专门菜单文案**。因此，菜单可见性及其配置快照传递路径比通用许可表、转换表更值得调查。
>
> **未证实**：X-S10 正常菜单真的可选择 H.265；通用菜单设置变量能向 Recorder 的设置快照传递 H.265 数值 1；实际 VPU 最终生成 Main10/4K60。全程**离线**，无相机 USB/FF80、无修改 DAT/刷机。机身过去确认为 2.10；以下地址仅对原厂 X-S10 3.11 适用。

## 1. X-S10 和 X-T4 真实菜单转换分支：逐条 A32 指令比对

X-S10 的 `FUN_0115B578` 是 `eModeMovieCodec` 的真正 setter，将参数截断为字节储存在 `DAT_01B88650`。此前看到它在 `0x021039F8` 和 `0x02103A38` 有两个 Section2 的直接 `BL` 调用，但它们不在 Ghidra 自动识别的函数体内，`TraceX6Function` 曾返回 `NOT_FOUND`。这不代表代码不存在。本轮用 Ghidra 单独读取实际已反汇编的指令，发现下列调用链（与 X-T4 一一对应）：

| 菜单设置流程 | X-T4 2.12 | X-S10 3.11 |
| --- | --- | --- |
| codec 配置项 | `0x3E5` | **`0x3FC`** |
| 准备 codec setting ID 的 MOV | `0x02057E70` | `0x02103A2C` |
| ARM BL 至数值转换器 | **`0x02057E74`** | **`0x02103A30`** |
| 数值转换器入口 | `FUN_01022F7C` | `FUN_0102300C` |
| 真正的 336B 转换器 | `FUN_01121F5C` | `FUN_0114DC2C` |
| `UXTB R0,R0` | `0x02057E78` | `0x02103A34` |
| ARM BL 至 `eModeMovieCodec` setter | **`0x02057E7C`** | **`0x02103A38`** |
| setter | `FUN_0112FD80` | `FUN_0115B578` |
| 目的 GUI/通用设置全局变量 | `0x01AF2DB8` | `0x01B88650` |

两机调用前的 A32 操作均为 `R3=3`、`R2=0`、`R1=R5`、`R0=各自 codec setting ID`。数值转换器返回后经 `UXTB` 再写入 setter。换成概念伪代码：

~~~c
uint value = map_movie_menu_value(codec_setting_id, menu_index, 0, 3);
set_eModeMovieCodec((uint8_t)value);
~~~

**这是实际二进制存在的控制流，不是单靠 H.265 字符串做出的猜测。** 但是，能发现这样一段调用，仍然**不能证明 X-S10 正常可见的菜单会把 H.265 行索引送到这个分支**。

## 2. 两机共有“配置项 ID → 16 字节×N 行”的数值映射器

两台机器 `FUN_0114DC2C/FUN_01121F5C` 里确切的转换方式是：按 `setting_id` 查询 4 字节指针索引，再在每条 16 字节（4 个 little-endian uint32）的行序列中搜索匹配的候选行，最终返回选定的某个 DWORD 列；尾项四个 DWORD 均为 `0xFFFF`。

| 映射器参数 | X-T4 | X-S10 |
| --- | --- | --- |
| 配置项索引表基址 | `0x01700694` | `0x01788E80` |
| 行宽 | 16 字节 | 16 字节 |
| Codec setting ID | `0x3E5` | `0x3FC` |
| 接受的输出字段序号 | `3`（返回行内 `record[2]`） | 相同 |

**注意这不是之前第17阶段的通用权限表。** 那张表在两机的单条宽度分别为16/28字节、用于检查是否允许设置候选值；此处两机均16字节，是**菜单数值转换关系**。二者原理、地址、功能各不相同。

原厂二进制逐字节解析七组 `X-S10 setting_id = X-T4 setting_id + 0x17` 的结果：

| X-T4 key | X-S10 key | 原始记录数量 | 两机所有四 DWORD 逐条比较 | 输出的 menu→数值序列 |
| --- | --- | ---: | --- | --- |
| `0x3DD` | `0x3F4` | 9 | 完全相同 | 7,7,6,6,4,5,9,10,11 |
| `0x3DF` | `0x3F6` | 15 | 完全相同 | 1–15 |
| `0x3E0` | `0x3F7` | 11 | 完全相同 | 1,2,3,4,5,6,7,10,11,14,15 |
| `0x3E2` | `0x3F9` | 4 | 完全相同 | 3,2,1,0 |
| `0x3E3` | `0x3FA` | 2 | 完全相同 | 1,0 |
| `0x3E4` | `0x3FB` | 4 | 完全相同 | 0,0,1,1 |
| **`0x3E5`** | **`0x3FC`** | **4** | **完全相同** | **1,0,1,0** |
| **总计** | | **49** | **49/49 相同** | |

Codec 对应的四条真实记录，在两份官方解压二进制中依次为：

~~~text
(1, 0x7FFFFFFE, 1, 0x7FFFFFFE)
(0, 0x7FFFFFFE, 0, 0x7FFFFFFE)
(3, 0x7FFFFFFE, 1, 0x7FFFFFFE)
(2, 0x7FFFFFFE, 0, 0x7FFFFFFE)
~~~

此前已经由独立的 `eModeMovieCodec` 名称函数证实：`1=H.265`、`0=H.264`。即 **X-S10 的此张静态菜单数值转换表不仅包含 H.265，而且与原厂 X-T4 一字不差**。更早第17阶段亦证明通用设置权限表在录像类别 `0x2D` 下允许 H.265 数值1。因此，“X-S10 在通用许可或菜单数字映射中简单删掉 HEVC”的假说排除得更彻底了。

## 3. 实际出现的重大差异：H.265/4:2:0 10bit 菜单资源被裁剪

这里必须区分 **资源代码标识存在** 和 **正常界面文案存在**。

既有的 [`compare_video_resources.py`](../tools/compare_video_resources.py) 对两机 X6 `section-1/2.bin` 的资源 ID 解析显示：

- X-T4、X-S10 均具有126项 `UI_MOVIE_MODE_*` 名称、8项带4K59.94的名称、8项带4K50.00的名称，ID 完全一致；
- 两机均注册 `UI_MOVIE_CODEC_H265`（资源 ID **0**）、`UI_MOVIE_CODEC_H264`（资源 ID **1**），以及MOV/MP4 H265注册名；
- **注意**上面的 UI resource ID `0=H265`，与 `eModeMovieCodec` 运行时 enum `1=H265` 是**不同命名空间**；不要直接当成逻辑错误。

但 X-T4 `section-1.bin` 有 `MSG_ITEM_TITLE_FILEFORMAT_MOVH265`、`MSG_VALS_TITLE_FILEFORMAT_MOVH265`、`MSG_COMMENT_FILEFORMAT_MOVH265`；**X-S10 的相同 section 中缺少上述三项**，存在的是不同的 H.264-only 命名，如 `MSG_COMMENT_FILEFORMAT_MOVH264IIII2`。此区别来自原厂资源二进制，而非假设。

再对**原厂 payload 本身**逐字节搜索特定 UTF-16LE 文本（每个重复语言版本也会被计入）：

| UTF-16LE 标记 | X-T3 5.11 | X-T4 2.12 | X-S10 3.11 |
| --- | ---: | ---: | ---: |
| `H.265` | 175 | **105** | **0** |
| `4:2:0 10bit` | 52 | **23** | **0** |
| `4:2:2 10bit` | 70 | 69 | 46 |

**这里只能严格说：X-S10 的这些特定界面文案资源缺失，而内核资源 ID、参数转换表仍在。** 用户界面资源层是值得优先追的差异，但没有证明“只改隐藏菜单就成功内录10bit/4K60”；X-S10 的 `4:2:2 10bit` 更可能来自外接 HDMI 输出，不能等同内录 Main10。字符串重复数量不等于功能数量。

## 4. 距离真正打通上游最后仍缺一个关键环节

第20阶段的录像状态提交路径已经完整：

~~~text
原始 Recorder 设置快照 X-S10: 0x02D9D834
    -> 工作结构字段:              0x02D9D090
    -> 双份 memcpy 更新活动状态:  0x01C25208
    -> Recorder context+0xADDA
    -> H.265/VPU init+0x188
~~~

这次找到的菜单 `eModeMovieCodec` 更新却只确认在 **`0x01B88650`** 发生，**还没有找出 `0x01B88650 -> 0x02D9D834` 的确切赋值/序列化关系**。X-T4 对应两个地址为 `0x01AF2DB8` 与 `0x02D10F84`，同样不应混淆。

Ghidra 静态 xref 实查：

| 查询 | X-T4 | X-S10 |
| --- | ---: | ---: |
| `getReferencesTo(snapshot +0x5B0)` | 0 | 0 |
| `getReferencesTo(snapshot 基址)` | 119 | 113 |
| 后者映射到的已定义 Ghidra 函数数 | 53 | 51 |

对根基址 xref 的函数逐一反编译检查，还没有恢复出对特定 `+0x5B0` 的确切直接写入语句。**零静态引用不是不可修改的证明**：真实修改可能来自计算偏移、间接指针、全结构解码、整块复制或 Ghidra 尚未解开的 overlay。

因此，需要先证明**正常 UI 选择/序列化实际上能更新 Recorder 这一独立快照**，而不是靠旧 3.11 地址去碰机身 2.10 的 RAM。

## 5. 可复验工具、测试与安全性

本阶段新公开的原创工具：

- [**`tools/compare_codec_menu_mappings.py`**](../tools/compare_codec_menu_mappings.py)：用纯 Python 解码 ROM 内七组菜单映射的所有DWORD和四字终止项；同时独立解码原厂 Section2 中 **R3/R2/R1/R0、ARM MOV旋转立即数/MOVW、BL跳转、有符号偏移、UXTB和 codec setter 第二条BL**，不依赖 Ghidra 的函数边界标注；
- [**`tests/test_compare_codec_menu_mappings.py`**](../tests/test_compare_codec_menu_mappings.py)：12 项**完全合成**映射数组/ARM 指令测试，覆盖正确 H265映射与错误 key/branch/指针/空表/UXTB/输入寄存器等负例，单元测试不含厂商固件。

真实官方离线段复验：

~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/compare_codec_menu_mappings.py \
  --xt4-section1 output/x6-xt4/section-1.bin \
  --xt4-section2 output/x6-xt4/section-2.bin \
  --xs10-section1 output/x6-xs10/section-1.bin \
  --xs10-section2 output/x6-xs10/section-2.bin
~~~

重要输出：

~~~text
all_equal: True
total_xt4_rows: 49
total_xs10_rows: 49
xs10_codec_row_to_enum: [1, 0, 1, 0]
normal_xs10_menu_displays_HEVC: UNVERIFIED
runtime_snapshot_codec_byte_from_UI: UNVERIFIED
main10_4k60_supported: UNVERIFIED
~~~

离线原仓库91项 + 忽略目录已累计新增72项（包括本阶段12项）＝**163项测试全部通过**。代码通过 GitHub 连接器提交，并用同字节源码副本在授权 Ubuntu 受忽略的 `output/` 运行，因 Ubuntu 对 GitHub HTTPS 偶有TLS断连，没有将新代码强行覆盖本地其他文件。**原厂 DAT、解压二进制、Ghidra 完整反编译源码均未上传到公共仓库。**

**绝无 FF80、相机 RAM 读取、固件刷写或任何改机操作。** 此轮所有 ROM 地址为 XS10 3.11/X-T4 2.12 静态地址；任何想刷机的方案都还需先通过压缩回封的 byte-identical 往返、完整性验证、版本兼容和独立救砖的门槛。

## 6. 下阶段的优先研究路径

1. **前端菜单装配/可见性**：从 X-T4 的 `MSG_ITEM_TITLE_FILEFORMAT_MOVH265`、`MSG_VALS_TITLE_FILEFORMAT_MOVH265` 真正的引用/选择逻辑入手，对比 X-S10 只有 H.264 菜单文案的结构，确定是否有机型条件或菜单项列表裁剪；
2. **快照写入者**：正向跟踪菜单更新，以及逆向跟踪 X-T4 `0x02D10F84`、X-S10 `0x02D9D834` 的整块输入/反序列化；最终必须看见 UI enum1 能抵达 snapshot offset+0x5B0；
3. **独立 4K60**：继续查分辨率×帧率×Sensor/ISP模式许可，而不是假设 HEVC codec 菜单开启后 4K60 自动可用；
4. **码流证明与刷机门槛**：Main10 要有真实 SPS profile与位深、文件录制成功；X6 DAT 修改必须有可靠回封/校验/独立救砖路径。

**本阶段边界清晰：后台共用的 UI 数值转换器与权限规则不构成已经发现的专属禁用，但 H.265/内录 10bit 的上层可见资源被 X-S10 裁剪。这给出了更明确的前端调查方向，而不构成可刷固件的证据。**
