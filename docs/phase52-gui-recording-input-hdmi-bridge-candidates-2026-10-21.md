# 第52阶段：GUI录像输入结构与Recorder输入偏移重合，`P+0x581`直达HDMI连接状态（2026-10-21）

> **本轮发现的是很强的上游结构线索，而不是首次赋值的最终闭环**：X-S10原厂3.11、X-T4原厂2.12的 **`INPUT eMode4kOut` GUI字段均位于各自固定UI配置结构的 `+0x581`**，且 **`INPUT eModeMovieCodec` 均位于同一UI结构的 `+0x5B0`**；这与第49–51阶段已证实的Recorder动态输入缓冲区 `P[+0x581] / P[+0x5B0]` 完全对应。还有第三项跨机验证：两个GUI结构在原厂中均被按完整 **0x5DC（XS10）/0x5D8（XT4）字节**作为输入做只读内存比较，长度也与 Recorder 配置对象的典型快照复制范围一致。**同字段布局 ≠ 证明两个运行时指针相等，也 ≠ 证明GUI setter会改变当前P。**
>
> **另一项独立证实**：已有 Recorder 当前输入指针槽 `P` 真实通过原厂BL传到两机的 `FUN_021FC43C` / `FUN_02168510`，此函数读取 `P[+0x583]`、`P[+0x6C]`、**`P[+0x581]`** 后计算视频输出/HDMI连接相关状态，并在状态变化时发通知 `0x8043`。包含原厂调试标签 `RECCONT: HDMI CONECT NG`。**该消费者不是P的flag setter；业务语义还需独立确认，但已有证据强烈支持这是与HDMI/输出模式相关的字段，不能冒充“4K60解锁位”。**

## 1. 固件和隔离边界

仅使用用户授权 Ubuntu `/home/zyubuntu/xs10hk` 中保存的 **原厂 X-S10 v3.11 / X-T4 v2.12** X6 Section1、Section2 和既有 **Ghidra 12.1.4 `-noanalysis -readOnly`** 联合项目；历史实体机为 **X-S10 v2.10**，**ROM中的绝对地址不能用于该机身**。所有厂商固件、反编译全文、Ghidra工程和新生成的扫描日志均留在Git忽略的 `output/`，未上传至GitHub。无USB、FF80、实体相机RAM/Flash操作、ROM/DAT修改、固件补丁、刷机，亦未影响其它Ubuntu服务。

## 2. 两机同构的**GUI缓存地址**和对应Recorder输入**相对布局**

| 元素 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| GUI/INPUT状态结构基址（ROM的MOVW/MOVT确认） | `0x01B880A0` | `0x01AF2808` |
| `eMode4kOut`字段地址，正好 GUI基址`+0x581` | `0x01B88621` | `0x01AF2D89` |
| `eMode4kOut`原厂setter | `FUN_01159648` | `FUN_0112DE50` |
| `STRB R4,[R3,#0x581]`原始A32地址 | **`0x011596A4`** | **`0x0112DEAC`** |
| `eModeMovieCodec`字段地址，正好 GUI基址`+0x5B0` | `0x01B88650` | `0x01AF2DB8` |
| `eModeMovieCodec`原厂setter | `FUN_0115B578` | `FUN_0112FD80` |
| `STRB R4,[R3,#0x5B0]`原始A32地址 | **`0x0115B5D4`** | **`0x0112FDDC`** |
| 当前Recorder**动态输入指针所在的指针槽** | `0x02D9C2AC` | `0x02D0FA0C` |
| 当前Recorder实际`P`数值 | **未知** | **未知** |

本阶段每机两条UI写入指令的**完整A32 MOVW/MOVT→STRB R4** 均直接从原始Section1核验，配合Ghidra函数中的日志 `INPUT_eMode4kOut` / `INPUT_eModeMovieCodec` 和真实RAM字段赋值；不是只靠名字或“两个5xx偏移”猜测。GUI基址还在原厂Section2内存范围描述数据中以独立4B常量出现，但单凭内存块表不能推出当前Recorder P指针就是GUI基址。

**应严格区分三种不同东西**：GUI结构内的固定地址字节；动态Recorder输入 `P+同一偏移`；位于固定活动Recorder RAM的运行时flag/Codec值。第49阶段证明的是 `P → 活动RAM` 的有条件代码路径，**不负责**证明P最初来自哪个 GUI/IPC 配置生产者。

## 3. 更强的佐证：Recorder P 的真实值被传入HDMI连接状态消费者

| 原厂指令与函数 | X-S10 | X-T4 |
|---|---|---|
| 本轮新确认消费者 | `FUN_021FC43C` | `FUN_02168510` |
| 原厂初始化器用 `P` 调用它的BL | `0x022149B0` | `0x02180F9C` |
| 原厂序列化器用 `P` 调用它的BL | `0x0221D738` | `0x0218A14C` |
| `LDRB R3,[R0,#0x583]` | `0x021FC48C` | `0x02168560` |
| `LDRB R3,[R0,#0x6C]` | `0x021FC49C` | `0x02168570` |
| **`LDRB R3,[R0,#0x581]`** | **`0x021FC518`** | **`0x021685EC`** |
| 计算的输出/HDMI状态缓存（目标并非P字段） | 另一个配置管理对象`+0xAC8+0x1CE1` | 另一个对象`+0xAC8+0x1F45` |
| 变化后通知事件 | `0x8043` | 相同 |

以上原始A32 `LDRB/STRB`、实际BL位移目标均由Section2核验。前两条上层函数反编译均显示 `FUN_021FC43C(_DAT_02D9C2AC)` / `FUN_02168510(_DAT_02D0FA0C)`，因此这个 `+0x581` 确认就是**Recorder当前P的字段**而不是第50阶段发现的“另一个结构也有+0x581”。

该消费者包含一个与HDMI状态有关的分支：当源对象首字节、`+0x583`及类型条件满足后，若模式为7或8，会根据 `P[+0x581]==0` 选择内部状态1或2；其他模式分支也使用 `P+0x70`，无效组合走带 `RECCONT HDMI CONECT NG` 的调试路径。**状态数值不等于物理HDMI带宽，更不等于4K60/HEVC Main10合法性**。这个函数**读取**P中的flag，并更新**另一份状态缓存**，不是初始flag写入者。

## 4. 已核实相同大小的GUI全结构处理：仍没有出现“GUI → P”边

沿GUI结构基址真实Ghidra xrefs做只读反编译扫描，找包含复制助手、长结构长度等候选，识别出两组重要**伪阳性**：

| 结果 | X-S10 | X-T4 | 真正动作 |
|---|---|---|---|
| GUI全结构长度 | `0x5DC` = 1500 B | `0x5D8` = 1496 B | 与 Recorder 典型快照大小相同 |
| 全结构比较函数 | `FUN_02068184` | `FUN_01FC3578` | GUI结构与另一份固定GUI备份做**只读比较** |
| 比较调用原始ARM `BL` | `0x020684EC → FUN_012A9498` | `0x01FC38E0 → FUN_01281B98` | 原始ARM `R0=GUI,R1=GUI镜像,R2=len`，比较而不是复制 |
| GUI备份来源地址 | `0x01B55E10` | `0x01ABFD88` | 与Recorder P槽不是同一个地址；动态别名仍未知 |
| 带 `REC_INPUT` 标签的GUI访问 | `FUN_02128290` | `FUN_0207B750` | 接收GUI基址和全长，调用下面**打印调试数据**的函数 |
| 十六进制调试打印函数 | `FUN_0212814C` | `FUN_0207B60C` | 逐字节格式化输出，**并非配置写入** |

对比较调用附近的原始 `MOVW R2,len` / `MOV R1,R5` / `MOV R0,R4` / `BL` 共两机8个机器字做了核对；目标比较helper自身Ghidra实现逐字/逐字节检查相等，不含通过输入指针进行内存写入的逻辑。故不能因为看见 `&DAT_01B880A0,0x5DC` 或 `REC_INPUT`，就声称该调用把GUI数据灌进Recorder。

还复查了第51阶段已经筛出的 Recorder当前P相关复制调用：X-S10 `FUN_021FE318` / XT4 `FUN_0216A5BC`，若P非零，则调用复制引擎把 **P复制到独立诊断快照 `0x0290FDDC` / `0x0286F1DC`**；P为空时清空诊断快照。反向“GUI→P”的边并不在这两个例程中。它们与上面的GUI镜像地址也不同，不可混成同一条跨模块赋值路径。

## 5. bounded xref交集扫描与注册表类型身份边界

本轮另用只读Ghidra脚本交叉检查：

| 扫描对象 | X-S10 | X-T4 |
|---|---:|---:|
| GUI基址函数数 | 801 | 809 |
| 当前Recorder P槽引用函数数 | 325 | 343 |
| 当前描述符中P指针字段 `descriptor+0x10` 引用函数数 | 82 | 83 |
| GUI基址与当前P槽**直接引用函数交集** | **0** | **0** |
| GUI基址与描述符P字段**直接引用函数交集** | **0** | **0** |
| GUI基址范围内筛出包含广义拷贝调用的函数 | 18 | 11 |
| GUI基址范围内包含大长度字面量的函数 | 23 | 20 |

交集为0意味着**在该Ghidra静态直接xref覆盖范围内**没有出现“同一个函数既直接引用GUI基址又直接引用P槽”的简单桥接；**不等于全固件不存在函数传参、IPC、memcpy、结构体别名或间接数据拷贝**。大长度字面量也可能是完全无关的字段（包括`0x2000`和负数），不能视为确凿跨对象写入者。

同时本轮额外重新验证原第29阶段的配置选择：某些事件加载`0x206/0x207`记录到共享描述符；而真实 Recorder 活动配置初始化函数 X-S10 `FUN_02214738` / X-T4 `FUN_02180D0C`在 ARM `0x02214750` / `0x02180D24` **明确要求描述符当前`type==0x200`，否则报告异常后停在保护循环**。因此**不能直接把单独的 `0x206/0x207` 描述符载入当成同一次Recorder P初始化**：要么有其它上下文/后续记录恢复到0x200，要么它走的是另一个执行阶段。时序和真实载荷值尚未恢复。第29阶段的描述符复制长度仍是运行时值，完整覆盖指针字段须长度至少8，不能直接假设已覆盖。

## 6. 脚本、覆盖和本轮验证

这次新增**5份可发布的原创文件**（均不包含厂商固件或Ghidra全文）：

- `ghidra_scripts/ProbeStage52UiRecorderAliasIntersections.java`：读取GUI基址、Recorder当前P槽、当前描述符P字段的直接函数引用交集，明确不是跨函数数据流证明。
- `ghidra_scripts/ProbeStage52GuiBulkEgress.java`：只读扫描GUI直接xref函数中的可能整块比较/复制候选，保留静态不完备边界。
- `tools/audit_stage52_gui_recorder_hdmi_alias.py`：再次执行第29、31、32、48、49、50、51阶段原厂SHA/ARM审计，并本轮新核验 **4个GUI STRB + 8个其前置MOVW/MOVT、2×HDMI相关BL、10个HDMI字节读写点、2个GUI缓冲区比较BL和其原始实参准备、`0x200`保护及全部Ghidra/限定扫描统计**；针对所有未证实的状态输出False。
- `tests/test_audit_stage52_gui_recorder_hdmi_alias.py`：新增 **96项合成-only正反测试**，故意损坏A32字、混淆GUI和Recorder数据身份、丢失HDMI消费者、错判全量比较/十六进制dump等。
- `docs/phase52-gui-recording-input-hdmi-bridge-candidates-2026-10-21.md`：本报告。

完成 Ubuntu 原厂离线审计：`STAGE52 ORIGINAL GUI FLAG/CODEC OFFSETS, HDMI P READ AND GUI CMP PASS`。全套离线测试：**91项仓库现有跟踪测试 + 2786项Git忽略本地研究测试 = 2877项全部PASS**，其中新阶段新增96项。实际任何模式能否进入此路径、配置数据初值/写者、实时P指针、4K60传感器链、HEVC Main10 SPS或安全刷机仍没有取得证明。

复验需用户Ubuntu原厂数据和只读私有Ghidra日志：

~~~bash
cd /home/zyubuntu/xs10hk
PYTHONPATH=tools:output python3 tools/audit_stage52_gui_recorder_hdmi_alias.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

**第53阶段的最高价值问题**：从GUI固定结构 `0x01B880A0` / `0x01AF2808` 出发，追踪模块间配置发送/IPC消息载荷或非直接引用的运行时指针初始化链：究竟哪个函数复制 `+0x581/+0x5B0` 对应的GUI数据到Recorder动态`P`，或Recorder P与GUI结构是否指向同一地址？必须有跨函数真实参数和原始ARM写入/复制证据，不能从相同偏移、相同长度、HDMI字样或交集为0直接推论存在/不存在桥接。继续分别审计0x200启动记录/后续恢复与0x206/0x207分支时序。

**没有可刷补丁，不应通过USB/FF80对实机试探，也不能声称4K60或Main10已被解锁。**