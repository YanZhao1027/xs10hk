
# 第22阶段：HDMI 外录机 10-bit 与 X-S10 内录 HEVC／4K60 的真实限制边界（2026-10-15）

> **本阶段重要技术纠错**：用户猜测“连接外录机会启用 10-bit 菜单，4K60 需要另寻入口”。X-S10 官方确实支持 HDMI 外部输出 4:2:2 10-bit，但官方 SD 内录 H.264 4:2:0 8-bit、4K 最高 29.97p。我们进一步从两机真实 ARM 代码恢复出“4K60 许可”判断的**原始数据源是外部 HDMI 接收器 EDID**，而**不是本机 Sensor/ISP 4K60 白名单**：X-S10 从 HDMI DDC 寄存器 `0xFFF7B000` 读取 `0x80` 字节 EDID 基本块，使用标准 `0x7E` 扩展块数量字段，解析得到当前连接设备宣告的视频模式，再比较内部模式代码 `0xF0` 或 `0xF6`。
>
> **另一强证据**：X-S10 3.11 与 X-T4 2.12 的 HDMI 视频代码映射表共有 **36 条×16 字节＝576 字节，全部相同**，SHA-256 为 `9cb1963b5623ea2f869bbd4fe6c016d8c2e5055434966416ef092dc0532fb3d3`。它是**HDMI sink 支持模式的转换表**，不能与前一阶段录像内部的 96×64B LUT 混淆。
>
> **设备安全**：本次所有活动只读取受权 Ubuntu 内已存在的用户自行下载原厂固件和离线 Ghidra 项目，无 FF80、无 USB 相机通讯、无相机 RAM 或闪存操作，也没有制作/刷写修改版 DAT。机身先前运行 FW **2.10**，研究固件为 X-S10 **3.11**；以下地址不能用于现有机身。

## 1. 先验证 HDMI 10-bit 与 SD 内录完全不同

FUJIFILM 官方 X-S10 资料说明 HDMI OUTPUT INFO DISPLAY 设为 OFF 时，HDMI 外部输出可为 **4:2:2 10-bit**；原机 SD 卡 4K 内录为 **H.264、4:2:0 8-bit**，最大29.97p，FHD可选59.94p。参考：
- [官方 X-S10 Movie Setting](https://app.fujifilm-dsc.com/en-int/manual/x-s10/menu_shooting/movie_setting/index.html)
- [官方 X-S10 产品规格](https://fujifilm-x.com/global/products/cameras/x-s10/specifications/)

离线真实程序显示这三种状态有不同内存位置、不同 setter 与消费者：

| 状态 | X-S10 3.11 | X-T4 2.12 |
| --- | --- | --- |
| **eModeHdmiOutInfo**（HDMI 信息显示） | `0x01B88623`，setter `FUN_011595C4` | `0x01AF2D8B`，setter `FUN_0112DDCC` |
| **eModeMovieCodec**（菜单的H.264/H.265枚举） | `0x01B88650`，setter `FUN_0115B578` | `0x01AF2DB8`，setter `FUN_0112FD80` |
| **Recorder实际 codec 状态** | `0x01C25208` | `0x01B83974` |

HDMI 信息显示状态在 X-S10 `FUN_020501D4`、`FUN_0205B6C8` 等输出逻辑被读取；**未见其直接向 Recorder codec 状态写入值 1 的静态调用证据**。不排除其它尚未追到的间接路径，但用户不能由外录机启用4:2:2 10bit 推论“机内已开启HEVC Main10”。

## 2. 4K60 代码的真身：外部设备 EDID／DDC 能力协商

从 `FUN_02050094` 检查器正向/反向追回：
| 职责 | X-S10 3.11 | X-T4 2.12 |
| --- | --- | --- |
| 读取EDID/DDC并初始化外部视频模式 | **`FUN_0126B7E0`** | `FUN_012419F8` |
| 依据外部显示设备能力生成模式集合 | `FUN_01269B80` | `FUN_0123FD98` |
| 单个外部视频模式过滤器 | `FUN_012696E0` | `FUN_0123F8F8` |
| 辅助成员／位图查询 | `FUN_01269634` | `FUN_0123F84C` |
| Mode raw-code→内部 code | `FUN_012B99D8` | `FUN_01291F20` |
| 生成完整 `0x68` 字节动态 mode 列表 | `FUN_012BA020` | `FUN_01292568` |
| 读取并缓存当前外部视频模式列表 | **`FUN_01150B94`** | `FUN_01125190` |
| 4K类别＋fps编号→sink视频代码 membership 测试 | **`FUN_02050094`** | `FUN_01FAC60C` |
| 模式集合辅助 bitmask | `0x01C855E4` | `0x01BE56B0` |
| EDID 视频 code 缓存区 | `0x018177BC` | `0x01786BD0` |

关键反编译事实：

1. X-S10 `FUN_0126B7E0`／X-T4 `FUN_012419F8` 操作 `0xFFF7B000` 的 DDC/EDID 接口；读取 `0x80` B，**确实读取 EDID `+0x7E`**（扩展块数量）。证实当前处理的是**接收显示设备能力**，不是内部传感器时序寄存器。
2. X-S10 `FUN_01269B80` 收集外部代码后依据配置 `0x3840/0x3841` 和 `FUN_012696E0` 构建运行列表；`FUN_01269634` 校验外部名单成员和辅助模式分类 bitmask，**bitmap 不是独立的“机内录制解锁开关”**。
3. `FUN_012BA020` 将原始外部代码转换为 `0x68` 字节缓存；`FUN_012B99D8` 的编码表在原始输入 `0x11` 时返回 `0xF0`，原始 `0x17` 时返回 `0xF6`；XT4 一样。
4. `FUN_02050094` 在 4K 类别且 fps index=6 时测试动态外部模式表里是否包含 `0xF0` 或 `0xF6`，以决定当前 **HDMI sink 模式匹配**。**这不会提升相机 sensor readout 或开启本机 SD 的 H.265 Main10。**

要明确：`[943]4K_60fps_F60`、`[903]4K_2KOUT_60fps_F60` 等 Section2 字符串只是通用模式编号，里面甚至还有 4K240p，不能视为 X-S10 的 4K240p/60p 采集能力。真正运行时使用的 EDID 能力列表依赖外录机实际报告，不可从官方固件离线得知当前连接设备真实支持哪些模式。

## 3. 两机的 HDMI 模式转换原始 ROM 表 576 字节严格一致

两机的 36条×16B ROM 原始模式记录：

| 数据 | X-S10 3.11 | X-T4 2.12 |
| --- | --- | --- |
| Section1 视频代码表起点 | **`0x0162DE08`** | `0x01605D2C` |
| 条目数/字节数 | **36 / 576B** | **36 / 576B** |
| 二进制 SHA256 | `9cb1963b5623ea2f869bbd4fe6c016d8c2e5055434966416ef092dc0532fb3d3` | **相同** |
| 所有 DWORD／行的字节比较 | **完全一致** | **完全一致** |
| 涉及 `0x11` 和 `0x17` 的模式码映射 | 均有 | 均有 |

**它不属于第15阶段 96行×64B＝6144B 机内 Recorder LUT。** 本项目此前已经证实机内 Recorder LUT 在XS10与XT4中也相同，但 **HDMI sink 能力和 Recorder 候选 LUT 两项“相同”，都还不能证明 X-S10 实际能摄取 4K59.94 数据、让VPU持续编码或正常写卡**。

## 4. 用户“连接外录机后会出现 10bit 菜单”的可检验判断

| 用户设想 | 当前结论 |
| --- | --- |
| 外录机接入时启用 10bit 视频输出 | **官方支持 HDMI 4:2:2 10bit**，与 HDMI 输出设置有关 |
| 外录机改变 HDMI 视频模式列表 | **有真实 EDID 解析和外部接收端能力协商代码** |
| 外录机触发机内 SD 卡 H.265/Main10 | **尚未见证据；独立变量与设置路径** |
| 只修改 EDID 0xF0/0xF6 便能开启相机 4K60 录制 | **否：这些是外部 HDMI sink mode code** |
| 4K60 内录固件解锁可行 | **尚未证实 Sensor/ISP、内录 UI 请求、硬件吞吐、热/时钟和写卡能力** |

机主可以用正常 HDMI 设置连接外录机，在外录机上读取输入视频信号元数据、用实际外录视频分析色深及帧率；无须维修模式或刷机。这只能检验外录路径，不会验证 SD 卡 Main10。

## 5. 原创脚本、已通过的测试与安全条件

仅提交原创、只读离线源码：
- [`tools/audit_hdmi_edid_vs_recorder_4k60.py`](../tools/audit_hdmi_edid_vs_recorder_4k60.py)：检查 Ghidra 私有日志中两机 HDMI info setter、EDID 0x80B 和 +0x7E、sink mode 0x68B 缓存、video code 0x11/0x17→0xF0/0xF6，及基于原厂Section1的 36×16B ROM 原始记录比较；输出简要发现不上传厂商固件。
- [`tests/test_audit_hdmi_edid_vs_recorder_4k60.py`](../tests/test_audit_hdmi_edid_vs_recorder_4k60.py)：新增**14**项纯合成验证，含错误 EDID 字段、错误长度、错误 4K fps6、混淆 HDMI/Recorder 状态、伪造 bitmap、损坏 mode 表、越界等负例，测试不包括原厂内容。

真实验证命令（需本地已有私有X6和Ghidra输出）：

~~~bash
cd /home/zyubuntu/xs10hk
PYTHONPATH=tools:output python3 tools/audit_hdmi_edid_vs_recorder_4k60.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

Ubuntu 实际对原厂固件进行只读运行，输出：
`EDID_mode_conversion_equal: True`，
`HDMI_EDID_mode_record_count_each: 36`，
`contains_4K60_sink_mode_enum_0x11_and_0x17: True`，
`internal_4K60_sensor_capture_proven: False`。

原有本地 **91项**测试 + 隔离目录先前 **72项** + 本次 **14项**，当前总计 **177项离线单元测试全部通过**。本机 Git 主目录尚未拉取最新GitHub提交（本机直连GitHub曾有TLS错误）；本轮源码是GitHub connector写入，再回读字节到Git忽略 `output/` 目录实际验证。没有上传富士版权 DAT、程序解压二进制、反编译源代码，未访问相机。

## 6. 真正追查如何打开 4K60 的下一关

**不能从 HDMI EDID bitmap 开始改机。** 这只关乎接收设备模式，不决定本机采集速率。下一关应分别解决：

1. **摄取 Sensor/ISP 4K59.94**：以 X-T4/X-T3 的真实录制模式作正对照，查 sensor readout timing、ISP采样/裁切、时钟/接口配置；先证明 X-S10 的传感器和 ISP 可以产生 4K60 原始帧流。与接收显示器 EDID 无关。
2. **内录可达性**：从用户菜单选到分辨率×fps×codec，再到Recorder启动时调用96×64B LUT的输入键。X-S10 在上游哪一条件禁用 4K60 应从业务/机型权限分支发现，而不是把 LUT里共有模式当成UI支持。
3. **机内 Main10 单独证实**：继续追 `eModeMovieCodec` UI 变量 `0x01B88650` 到 Recorder Source snapshot `0x02D9D834` 的桥接；最终需实机真实 HEVC SPS证明 Main10 Profile、bitdepth_luma/chroma=10。
4. **刷机前提仍缺**：原始 X-S10 FW3.11地址与机主2.10不兼容；未有 X6 压缩无修改 byte-identical往返、厂商完整性机制和经验证救砖路线。以前FF80 RAM试验使相机死机，需要避免反复试探未知RAM。

**阶段结论**：连接外录机会影响HDMI EDID能力协商、HDMI输出本身支持10bit；但原本误以为能控制机内4K60的 `0xF0/0xF6` 实际是外部接收设备mode code。下一关回到真正的 Sensor/ISP 视频采样与内录上游模式许可。
