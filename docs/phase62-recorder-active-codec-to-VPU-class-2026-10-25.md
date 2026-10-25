# 第62阶段：复验Phase47活动Codec来源，并与Phase61 VPU编码器类字段闭合（2026-10-25）

**准确的发现归属：**活动Recorder Codec → Movie状态对象`+0xADDA`这条路径此前在**Phase47已发现**；本轮以原厂X-S10 3.11 / X-T4 2.12 Section1/2 ARM再核验，并**首次将其接上Phase61已确认的VPU cfg+0x188类别选择与独立cfg+0x0C位深代码**。这是已知来源和新下游约束的端到端**有条件静态固件数据流**，不是实机录像成功证明，更不是一个10bit/4K60解锁方法。

## 原厂地址和指令

| 数据节点 | X-S10 | X-T4 |
|---|---|---|
| Phase49活动Codec RAM | `0x01C25208` | `0x01B83974` |
| 读取该活动字节的getter | `FUN_012C048C` | `FUN_01298C18` |
| 原厂getter的ROM基址MOVW/MOVT | `0x012C0494/98`→`0x01C24DD8` | `0x01298C20/24`→`0x01B83540` |
| 原厂`LDRB R0,[R3,#偏移]` | `0x012C049C`，偏移`0x430` | `0x01298C28`，偏移`0x434` |
| Recorder/Movie初始化函数 | `FUN_022D5FEC` | `FUN_022425BC` |
| **BL getter → STRB 到Movie `+0xADDA`** | `0x022D62A4` → `0x022D62A8` | `0x02242874` → `0x02242878` |
| Phase61后续VPU配置构造 | `FUN_022DEE64` | `FUN_0224B65C` |
| 构造器取Movie对象`+0xADDA` | `0x022DEF58` | `0x0224B750` |
| 构造器写VPU cfg`+0x188`类别0/1 | `0x02945B90` | `0x028A52D8` |
| 构造器另外写VPU cfg`+0x0C`**数字位深代码1** | `0x02945A14` | `0x028A515C` |

原厂Ghidra在两机均显示getter是直接`return DAT_活动Codec_RAM`；Movie对象初始化取该getter的返回值写入`+0xADDA`；随后VPU构造器根据`(Movie[+0xADDA]==1)`计算VPU类别`(uint)!predicate`。此层VPU类0和1**数值与GUI MovieCodec枚举值表面相反**（GUI 0=H264/1=H265），因此**不能默认两个结构使用相同的枚举数值定义**；在没有额外证据之前也不应把VPU类0直接等价于HEVC Main10。

**原厂是否真的支持10bit还没有答案**：该构造器对cfg+0x0C恒定写入数字`1`，既没有看到从GUI H.265枚举`1`到物理bitdepth=10的映射，也未观察到Main10 SPS/HEVC码流或4K60录制。VPU入口有多个其它失败保护（缓冲区地址/大小、编码器状态），本报告不会把单一类别检查“没拒绝”当作完整能力证明。

## 完整研究链与继续条件

~~~text
Phase59–60原厂GUI电影模式0x2D：MovieCodec可选0(H264)/1(H265)
  ↓ Phase58: 条件式 GUI全块copy → 独立0x200 Recorder输入P
  ↓ Phase57/54/32: 在成功队列接收和0x200初始化前提下进入活动配置
  ↓ Phase49: P+0x5B0 → Recorder活动Codec RAM
  ↓ Phase47 + 本轮Phase62 A32重新固定：getter → Movie对象+0xADDA
  ↓ Phase61: 判断该运行态字段 → VPU cfg+0x188类别0/1
             同时VPU cfg+0x0C固定写入位深数字代码1
  ↓ VPU wrapper/driver运行时成功仍未知
  【无Main10/10bit/4K60实机证据，也未识别能安全直接修改的配置】
~~~

外部IPC实际投递、配置对象别名、后续可能覆盖、VPU数字位深代码1的**物理8/10bit对应**、视频序列header、不同固件版本迁移风险和机身真实型号准入仍未排除。尤其以前实体X-S10 v2.10与研究ROM v3.11不一致，绝不能直接拿这些地址进行实机访问。

## 复验范围

原创`tools/audit_stage62_active_codec_to_vpu_class_bridge.py`先执行Phase61/60/59及之前全部原厂X6 SHA绑定审计，再验证Section1 getter MOVW/MOVT/LDRB到活动Codec精确地址、Section2 getter BL与紧随STRB到`+0xADDA`的ARM机器码、两机Movie/VPU构造器状态条件，保持所有未证实的硬件/运行时声明显式False。`tests/test_audit_stage62_active_codec_to_vpu_class_bridge.py`增加**37项完全人工构造的ARM和字段正/负测试**，不含富士厂商固件/私有日志。

私有原厂Ghidra日志仅存本地Git忽略`output/{xs10,xt4}_stage62_vpu_codec_runtime_flag_setter.log`、`*_stage62_codec_runtime_value_origin.log`和Phase61对应日志。无相机USB/FF80、设备RAM/Flash、厂商ROM/DAT改写、固件补丁、签名修改或刷写。完整源ROM、Ghidra项目及全文日志未向GitHub上传。