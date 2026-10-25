# 第64阶段：eMovieFps GUI参数到活动Recorder FPS的真实前向数据边（2026-10-25）

## 核心结论

**本轮使用X-S10原厂3.11 / X-T4原厂2.12 X6 Section1+2及只读Ghidra逐字确认**，在第63阶段已定位的真实`eMovieFps` GUI RAM字节`GUI+0x6E`之后，存在一条**两机同构且可从原厂A32静态复验**的下一步路径：

~~~text
  Phase63 GUI eMovieFps setter: XS10 GUI 0x01B8810E / XT4 GUI 0x01AF2876
     ↓ [Phase58条件式整结构GUI→P memcpy, 需要队列/状态事件条件]
  Recorder独立type=0x200配置输入P[+0x6E]
     ↓ [Phase32字段转换器，Phase64两种条件分支中相同LDRB/STRB指令]
  中间结构[+0x1E] XS10 0x02D9CC7E / XT4 0x02D103CE
     ↓ [Phase32已SHA/BL验证的活动模板 0x478/0x47C B复制，跨函数事件]
  活动Recorder FPS RAM XS10 0x01C24DF6 / XT4 0x01B8355E
     ↓ [Phase64独立ROM getter MOVW/MOVT/LDRB和3个BL调用点]
  原厂Movie模式构造器使用这个FPS枚举（包含值6的switch分支）
     ↓
  【Movie对象+0x5C6/0x5C7与活动值的所有状态等价性**尚未建立**】
  【4K59.94实际传感器/ISP/VPU联合准入及HEVC Main10输出仍未知】
~~~

这是一段有前置条件的**固件静态数据流**，并非实机USB读值、机内录制或可安全使用的“解锁补丁”。已有ROM包含`MODE_FPS_60`枚举且Movie模式允许这一菜单候选（Phase63），不能由此推出真实3840×2160@59.94Hz与10bit内录成功。

## 1. 原厂精确ARM：输入+0x6E → 中间+0x1E

| 原厂证据 | X-S10 v3.11 | X-T4 v2.12 |
|---|---|---|
| Phase32独立输入P转换器 | `FUN_012C9500` | `FUN_012A313C` |
| 原厂**第一**组LDRB R3,[R1,#0x6E]/STRB R3,[R0,#0x1E] | **`0x012C959C`/`0x012C95A0`** | **`0x012A31D8`/`0x012A31DC`** |
| 原厂**第二**组同编码LDRB/STRB（另一分支） | **`0x012C9A84`/`0x012C9A88`** | **`0x012A36D4`/`0x012A36D8`** |
| 两机原始机器字序列 | `E5D1306E` / `E5C0301E`，两次 | 完全相同，两次 |
| 固定中间结构起点（Phase32） | `0x02D9CC60` | `0x02D103B0` |
| 中间FPS字段`+0x1E` | `0x02D9CC7E` | `0x02D103CE` |
| 活动模板拷贝长度（Phase32） | `0x478` | `0x47C` |
| 活动模板起点（Phase32） | `0x01C24DD8` | `0x01B83540` |
| **活动FPS字节** | **`0x01C24DF6`** | **`0x01B8355E`** |

原始Ghidra转换器两机都包含**两次**精确赋值 `*(undefined1 *)(param_1 + 0x1e) = param_2[0x6e];`。虽然条件支路有其它不同字段处理，但两个明确的输入→中间FPS拷贝位置相同。Phase32验证模板实际复制长度远超0x1E，Phase49与Phase58验证该输入P身份和有条件的上游GUI传递链；**这不排除跨调用修改、别名/竞争或运行态未执行**。

## 2. 已存在的活动Getter、消费者与反向导出

| 原厂证据 | X-S10 | X-T4 |
|---|---|---|
| 活动FPS getter | `FUN_012BD550` | `FUN_01295BC4` |
| getter原始LDRB R0,[R3,#0x1E] | **`0x012BD560`** | **`0x01295BD4`** |
| 原始getter基址MOVW/MOVT | `0x012BD558/5C`→`0x01C24DD8` | `0x01295BCC/D0`→`0x01B83540` |
| 三处直接BL getter | `0x022D18AC`、`0x022D3FD8`、`0x022D41D0` | `0x0223DE3C`、`0x022405A0`、`0x02240798` |
| 使用该值的录像模式构造函数 | `FUN_022D1870`、`FUN_022D3E00` | `FUN_0223DE00`、`FUN_022403C8` |
| 原厂独立**反向**快照导出 | `FUN_012BE684` | `FUN_01296D38` |

构造器`FUN_022D3E00`/`FUN_022403C8`两机都**两次**调用活动FPS getter，并在一处`switch`中明确处理`case 6`。另一个构造函数将getter返回值作为参数传入配置计算函数；这证明活动FPS参与后续软件构造，不证明传感器和真实每帧编码接受。导出器反向执行`Q[+0x6E] = 活动RAM[FPS]`，**绝不可把这个导出方向冒充成最初写入P的来源**。

## 3. 专项反例：指令里的`#0x5C6`不一定是Movie+0x5C6

第47阶段旧的有界扫指令脚本在X-S10发现**一条**`STRBNE R0,[R3,#0x5C6]`（`0x021F6B44`），曾被归在`5c6/WRITE`。本轮反查原厂函数`FUN_021F6B2C`发现Ghidra正确计算最终目标其实是：

`*(int *)(DAT_021F6B54+0xAC8)`所指向的**另一个动态对象基址 + `0x15C6`**。

这是因为指令中`R3`已先在其它指令加了`0x1000`，所用机器字`0x15C305C6`的立即数`0x5C6`只是**基址拆分后的低部分**。在没有严格的指针身份链证明此动态对象与Movie配置对象一致之前，**不得将其当作Movie+0x5C6写者**。X-T4旧有界扫没有看到相同候选也不能据此断定没有其它真实写者，DMA、结构拷贝、间接地址和不同寄存器组合都可能遗漏。剩余真正缺失的边是“活动FPS/配置转换结果 → 不同上下文的Movie+0x5C6/+0x5C7”的原厂对象身份、条件与最后覆盖顺序。

## 4. 与Main10及4K60相关但不应偷换的已有证据

- Phase45–47：两机都有4K FPS6 (`0x3C=60`) 软件分支以及独立的96×0x40静态模式矩阵；在指定类别/变体/flag组合下，ROM可匹配4K分辨率。未证明真实XS10能进入所有组合，特别是活动4K flag `+0xA8E==1`还可能把mode low7改为6而改命中1080。
- Phase35–36/41：两机VPU启动路径的bitdepth数字代码1在适当状态下被转换为0x121 **10-bit Y0L2输入帧格式**（已由公开MVE ABI辨识）；是CPU侧帧描述符**不是**真实HEVC编码SPS/MAIN10 profile证据。
- Phase63：两机真正GUI eMovieFps菜单0x2D允许枚举6=`MODE_FPS_60`。本报告将菜单→活动FPS进一步连接，但**还缺活动FPS与实时帧率和分辨率联合准入之间所有条件的证据**。

X-S10研究ROM固件v3.11与此前实体机v2.10不一致，不能直接移用绝对地址。原厂V61硬件处理器指令、sensor/ISP真实制式、码流HEVC VPS/SPS profile及机内写卡稳定性均未取得直接证据；**本阶段绝不声称已经解锁任何硬件能力**。

## 5. 复验、合成测试与隐私隔离

原创 `tools/audit_stage64_real_movie_fps_active_recorder_bridge.py`首先重跑Stage63、Stage62及之前的全部SHA固定原厂ROM审计；随后逐机检查每一条A32复制指令、真正GUI偏移与活动模板基址恒等式、Getter MOVW/MOVT/LDRB、三处BL调用、Ghidra转换器与快照导出方向、旧指令低立即数伪写者。`tests/test_audit_stage64_real_movie_fps_active_recorder_bridge.py`新增**65项纯合成A32/模仿转换器与反向导出正反测试**（包括错误偏移、改变寄存器/BL、虚构指针同一性等），不使用任何原始富士固件字节或完整私有Ghidra。

仅用户授权Ubuntu执行原厂只读Ghidra `-noanalysis -readOnly`，私有日志 `output/{xs10,xt4}_stage64_*`及厂商原始Section1/2仍在Git忽略目录。GitHub只提交三项原创源码、合成测试和本报告；不上传原厂X6/V61、真实RAM dump、Ghidra项目/日志，不执行USB/FF80、实体相机读写、补丁或刷机。完整单元测试数以本轮CI/Ubuntu输出为准。