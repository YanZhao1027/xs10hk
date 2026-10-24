# 第60阶段：Codec `1`=H.265，X-T4附加重载会恢复默认H.264（2026-10-25）

在第59阶段**原厂逐模式ROM准入表**的基础上，本轮另外核验了直接的原始**枚举字符串映射**与**模式重载的上游调用关系**。它们能证明“X-S10/X-T4在电影模式允许H.265选项”，但**没有证明HEVC Main10/10-bit或4K60能被实际编码、输出或写卡**。

## 枚举真实名称（原厂Section1）

| Codec枚举值 | X-S10 v3.11 | X-T4 v2.12 | 明确含义 |
|---|---|---|---|
| `0` | `0x0144009C` | `0x01429D04` | 原厂字符串`MODE_MOVIE_CODEC_H264` |
| `1` | `0x014400B4` | `0x01429D1C` | **`MODE_MOVIE_CODEC_H265`** |
| `2` | `0x014400CC` | `0x01429D34` | `MODE_MOVIE_CODEC_NUM`，不是已证明的可用模式 |
| 映射函数 | `FUN_01034DC4` | `FUN_01035078` | 真实ROM原始字符串字节和Ghidra双重验证 |

枚举值`1`对应**H.265/HEVC codec选择**，绝不能等同“Main10 profile”或10bit位深。静态ROM原厂配置中**模式`0x2D`同时允许Codec 0/1**，其他模式只允许0；两机一致。表中Codec=0的默认标志为`2`，Codec=1仅在模式`0x2D`标志为`1`。两机**默认值解析器**都会优先选到`0`，但仍允许用户选择`1`（在合适的模式中）。

## 关键额外配置重载路径与误判风险

| 项目 | X-S10 | X-T4 |
|---|---|---|
| 直接Codec GUI setter | `FUN_0115B578` | `FUN_0112FD80` |
| 原始ROM上直接BL调用该setter的静态地址数 | **3** | **4** |
| 原厂初始化检查/默认回退 | `FUN_01179DC0`，参数`0x3FB/0x3FC` | `FUN_0114DAB4`，参数`0x3E4/0x3E5` |
| 额外集中式重载函数 | 尚未在**直接调用Codec setter的三个地址**中找到对应实现 | **`FUN_0115B234`** |

原厂X-T4 `FUN_0115B234`：根据GUI模式字节等于`0x2D`选择配置类别`0x2D`，否则选`0x21`；对录像格式/帧率/Codec等多个参数重新读取**默认值**，例如`FUN_01025514(mode,0x3E5)`，非哨兵值时直接调用`FUN_0112FD80`。在上述两个模式中默认Codec都为`0`，**所以这条重载路径一旦执行，可以把合法的H.265选择重设成H.264**。注意“存在恢复默认机制”并不证明它在真实录像过程中一定触发，也不证明H.265编码器不可用。

两处X-T4原始BL入口已独立核验：**`0x0115F2D0`** 和 **`0x02043B14`** → `FUN_0115B234`；内部**`0x0115B314`**→Codec setter。前者位于`FUN_0115E9C8`的受条件`*(char *)(DAT_0115F340+0x834)==1`控制区；后者在`FUN_02043AB4`内直接调用，但该外层函数的执行条件仍未回溯至实机事件。

X-S10相关初始化函数同样会通过`0x2D`分支的准入检查和默认值fallback写入H.265，`0x21`模式也有独立菜单流程。**直接调用xref只有三个不等于跨函数/间接重载彻底不存在**。两机Codec setter本身都无Main10能力检查；上游validator检查的是**ROM菜单允许性**，不是传感器/VPU能力。

## 审计、合成测试、可复验性

`tools/audit_stage60_h265_codec_reloader.py`对第59阶段及全部先前原始SHA/X6审计递归复验，然后核实真实枚举ROM字符串、两个模式的ROM默认值、直接Codec写入和X-T4 extra reloader的原始A32 BL、两个入口及Ghidra条件。**75项纯合成测试**独立篡改字符串、BL、xref、模式默认标志及各个可见的重载条件。无ROM二进制或私有日志上传。

Ubuntu私有日志为`output/{xs10,xt4}_stage59_GUI_setter_callers.log`、`*_stage59_flag_codec_origins.log`、`*_stage60_movie_mode_reload_boundaries.log`、`*_stage60_config_resolver_implementation.log`。其他指令/文件仍由上一阶段已有审计核验。

~~~bash
cd /home/zyubuntu/xs10hk
PYTHONPATH=tools:output python3 tools/audit_stage60_h265_codec_reloader.py --output output
~~~

**下一步重点**：根据第61阶段从Recorder构造VPU bitdepth/codec参数的真实代码，证明或否定`Main10 profile`及实际10bit码流；在此之前不进行相机USB/FF80、固件补丁/刷机，也不猜测某个eMode4kOut枚举等于4K60开关。