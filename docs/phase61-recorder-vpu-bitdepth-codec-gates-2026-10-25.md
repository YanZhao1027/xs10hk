# 第61阶段：Recorder → VPU bit_depth 与 Codec 类别校验（2026-10-25）

**研究对象：**X-S10 v3.11 / X-T4 v2.12 原厂 X6 Sections，Ubuntu 上的只读 Ghidra 静态分析。此前记录的实体 X-S10 固件为 v2.10，不能直接使用研究 ROM 地址。这里没有相机操作、USB/FF80、RAM/Flash 改写、固件补丁或刷写。

## 可由原厂 ARM 指令验证的路径

| 位置 | X-S10 v3.11 | X-T4 v2.12 |
|---|---|---|
| Recorder/VPU 配置构造 | `FUN_022DEE64` | `FUN_0224B65C` |
| VPU 输入配置基址 | `0x02945A08` | `0x028A5150` |
| bit_depth 数值字段 config+0x0C | `0x02945A14` | `0x028A515C` |
| 原厂 MOV R2,#1 / STR R2,[R3,#0xC] | `0x022DEF4C/50` | `0x0224B744/48` |
| 编码器类别字段 config+0x188 | `0x02945B90` | `0x028A52D8` |
| 类别1写入 | `0x022DEF6C/70` | `0x0224B764/68` |
| 类别0写入 | `0x022DF15C/60` | `0x0224B954/58` |
| VPU封装器 | `FUN_011F7190` | `FUN_011CA83C` |
| Recorder调用封装器 | `0x022DF0F8` | `0x0224B8F0` |
| VPU原厂驱动入口 | `FUN_011F97DC` | `FUN_011CCE88` |

在找到的这条静态构造路径，两机均对 config+0x0C **固定设置数字1**。编码器类别则由 Movie/Recorder 对象 `+0xADDA` 是否等于1判断：相等时类别0，否则类别1。**GUI MovieCodec 数值0/1不应未经证明地等同于VPU类别0/1，VPU bit_depth数字1也不能未经核验地称为8bit或10bit。**

底层驱动原始A32分别验证：

- 类别 config+0x188 为0 **且**位深代码 config+0x0C 大于1时，返回 `#init bit_depth ERROR`。
- 类别 config+0x188 大于1时，返回 `#init video_codec ERROR`。
- 还有内存地址与大小、帧/参考/码流缓冲区等其它必要检查，单一条件通过不代表驱动真正可录。

X-S10原始检查地址：`0x011F97FC`, `0x011F9808`, `0x011F980C`, `0x011F9810`, `0x011F991C`。X-T4：`0x011CCEA8`, `0x011CCEB4`, `0x011CCEB8`, `0x011CCEBC`, `0x011CCFC8`。原厂直接 Ghidra xref 对两个机型都识别了各一处 config+0x0C 写入、各两处 config+0x188 写入；直接xref覆盖范围内的计数不排除其它间接别名写者。

## 与已知 H.265/4K60 配置的关系

第59–60阶段ROM菜单表与原厂字符串已确认两机在电影模式 `0x2D` 可选 H.264（枚举0）或 H.265（枚举1）；**H.265 不等于 Main10**。原厂同时共享一些4K60剩余录制时间、HDMI 2160P/5994字符串；字符串也不是传感器/ISP编码器在 X-S10 上达到4K60的物理证据。

该阶段并未取得位深数字1的硬件10bit映射、实际HEVC Main10 SPS、机内完整录制文件、真实队列投递或4K60传感器链证明。**没有可安全用于实体机身的刷写补丁**。

## 离线审计和隔离

- `tools/audit_stage61_vpu_bitdepth_codec_builder.py`：先递归检查上一阶段和更早SHA固定原始ROM审计，再核验源结构数值1、类别0/1分支、ARM原始BL、VPU驱动拒绝条件和直接引用。
- `tests/test_audit_stage61_vpu_bitdepth_codec_builder.py`：74项纯合成ARM指令、故意破坏条件/字段/调用边的正反测试。
- 完整私有原厂Ghidra日志、ROM Section1/Section2及所有原厂审计运行输出继续仅保存在用户 Ubuntu 仓库 Git 忽略的 `output/` 中，不上传到GitHub。

在授权Ubuntu上原厂审计PASS，四阶段累计新增448个合成测试，全套离线 **91 tracked +3947 locally ignored=4038/4038 PASS**。**这些测试不是4K60或Main10功能验证。**
