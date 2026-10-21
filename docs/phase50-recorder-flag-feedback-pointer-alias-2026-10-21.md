# 第50阶段：`+0x581` 模式状态的候选写入者清查与 Recorder 条件回写路径（2026-10-21）

> **核心结果**：从已验证的第31阶段 `Recorder 当前输入配置指针P → 导出配置指针Q` 的原始 A32 赋值、第48阶段活动 Recorder 状态的逆向导出，以及第49阶段 `P[+0x581] → 活动状态 → 父对象+A8E` 的前向转换，恢复了一个可验证的 **条件式状态反馈回路**：只有在指针复制后 `Q` 的值保持与 `P` 相等、且上层成功条件允许调用序列化时，当前活动 flag 才会通过输出序列化写回 *同一个* 输入缓冲区的 `+0x581`。这是一条真实固件里存在的**条件化静态数据路径**，**不是首次初始化写入证据、运行时值观察或 4K60 解锁**。

另一成果是针对直接 `STRB [寄存器,#0x581]` 的只读 Ghidra 全区有界指令盘点：两机**各3处**，两台均是 2 处其他全局状态和1处 Recorder 反向导出。我们同时盘点能覆盖 `+0x581` 的整字 `STR [寄存器,#0x580]`：**X-S10 7处，X-T4 6处**，其中发现两组同构的 Movie 运行结构写入函数，但尚未证明该对象别名为 Recorder 输入 P。指令偏移盘点不包含 memcpy／DMA／寄存器动态偏移／未被反汇编的区域，不能当成全固件“仅有3个写入者”的穷举证明。

研究范围与安全：使用用户授权 Ubuntu `/home/zyubuntu/xs10hk` 现有未修改 X-S10 官方 **3.11**、X-T4 官方 **2.12** 原始已解包 X6 Section1/2、Ghidra 12.1.4 已有只读联合工程。机身此前为 X-S10 **2.10**；**不同固件地址绝不能用于实体机**。未向相机发 USB/FF80 命令，未操作实体 RAM/Flash、修改厂商 ROM/DAT、封装补丁、刷机。所有原厂/解压二进制、Ghidra数据库和全文私有日志保持本机 Git 忽略 `output/`，不提交 GitHub。

## 一、逐机确认配置输入 P 与输出 Q 的指针**值复制**

| 原始证据 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 当前输入主指针槽 P（保存指针值的 RAM） | `0x02D9C2AC` | `0x02D0FA0C` |
| 导出指针槽 Q（保存指针值的 RAM） | `0x035BD868` | `0x03672078` |
| 原始指针值复制函数 | `FUN_0221C934` | `FUN_02189348` |
| A32 读取 P 的指针值 | `0x0221C950` | `0x02189364` |
| A32 写入 Q 指针槽 | `0x0221C954` | `0x02189368` |
| 复制上层函数 | `FUN_021CDF80` | `FUN_0213754C` |
| 原始 BL 调用指针复制 | `0x021CDF8C` | `0x02137558` |
| 有条件地调用序列化 BL | `0x021CE0F4` | `0x021376C0` |
| 上层序列化函数 | `FUN_0221D1BC` | `FUN_02189BD4` |
| 序列化真正调用 Recorder 逆向导出 | `0x0221D298 → FUN_012BE684` | `0x02189CB0 → FUN_01296D38` |

本轮重新调用原第31阶段离线审计，并复查此前 ROM MOVW/MOVT、ADD、LDR、STR 和 BL 目标及 Ghidra 调用先后。**在执行 `Q=P` 的那条赋值结束时两指针值相等**。但随后其他调用、事件或间接写入仍可能改变任一槽内的指针；**尚未证明在序列化调用现场 Q==P，也未观测实体运行时路径或 RAM 内容**。

## 二、新核验活动 flag 到导出对象 `+0x581` 的 ARM 八字节搬运指令

与第49阶段的正向路径相反，本轮重新逐字读取两机原厂 **Section1**，对两机各4组 LDRB+STRB（**每机8条、共16条原始ARM指令字**）及对应 Ghidra C 表达式进行验证：

| 从活动 Recorder 读取，再写 Q | X-S10 LDRB / STRB | X-T4 LDRB / STRB |
|---|---|---|
| 活动 flag → `Q[+0x581]` | `0x012BEA70 / 0x012BEA74` | `0x01297134 / 0x01297138` |
| 活动 companion → `Q[+0x580]` | `0x012BEA78 / 0x012BEA7C` | `0x0129713C / 0x01297140` |
| 活动 flag+2 → `Q[+0x583]` | `0x012BEA80 / 0x012BEA84` | `0x01297144 / 0x01297148` |
| 活动 flag+3 → `Q[+0x582]` | `0x012BEA88 / 0x012BEA8C` | `0x0129714C / 0x01297150` |

X-S10 活动 flag 基址 `0x01C251D4`，X-T4 `0x01B83940`；四个相邻活动 RAM 字节按输入字段顺序**并非**升序 `+581/+580/+583/+582` 序列化。编码器活动 Codec 是独立的 `0x01C25208` / `0x01B83974`，高于 flag `+0x34`。同一个导出器也序列化 Codec/Format 至 `Q[+0x5B0/+0x5B1]`，但不意味着它为 Codec 或 flag 创造了一个初始值。

验证条件链：

    描述符 +0x10 → Recorder 输入 P → 第49阶段前向转换 → active flag
                                                         │
                                 第48阶段父对象+A8E getter（仅4K类）
                                                         │
    P ---已验指针值赋值 ---> Q --成功路径导出---> Q[+0x581] = active flag
                                                │
                      只有导出执行时 Q 仍等于 P │
                                                ▼
                                  输入 P[+0x581] 的条件式回写

**特别注意**：上面的回路既不证明第49阶段调用与第31阶段导出属于同一个实际事务，也不证明 Q==P 始终维持。它只说明这些对应条件下的静态数据流如何相接。

## 三、对直接写入 `+0x581` 的有界 Ghidra 指令盘点

读取现有已反汇编、已加载的 ARM 指令，限定内存地址区间 `0x01021000..0x028A0000`，按即时偏移与读/写指令筛选。**不是任意别名、运行时分配或固件所有代码的全程序证明。** 结果：

| 对象 / 类型 | X-S10 原厂 | X-T4 原厂 | 当前可证明的目标 |
|---|---|---|---|
| UI `eMode4kOut` 缓存 STRB `+0x581` | `0x011596A4` | `0x0112DEAC` | RAM `0x01B88621` / `0x01AF2D89`，不是 Recorder P 槽本身 |
| 其它状态 STRB `+0x581` | `0x0116BBF4` | `0x011F29A0` | RAM `0x01C1FBC1`（INFO_REC custom no）/ `0x01AC83BD`（另一条件状态），尚无 P 指针身份连接 |
| Recorder 实际导出 STRB `+0x581` | **`0x012BEA74`** | **`0x01297138`** | 运行时输出指针 Q，调用者读取专属 Q 指针槽 |

前两类使用原厂 MOVW/MOVT 或 PC-relative LDR 常量重构**真实绝对目标地址**，并与 Ghidra 反编译一并核验，绝不是看到 `#0x581` 就假定写同一数据对象。X-T4 `0x011F29A0` 原始 MOVW/MOVT 基址 `0x01AC7E3C`，所以写 `0x01AC83BD`；X-S10 `0x0116BBF4` 则由 ROM `0x0116BC2C` 常量 `0x01C1F640` 加 `0x581` 写 `0x01C1FBC1`。这些绝对地址均**不等于**已知输入指针槽、输出指针槽或活动 flag 地址；但输入指针 P 的真实数值未知，不能静态排除某个 RAM 对象的额外别名关系。

## 四、整字写入 `+0x580` 会覆盖 `+0x581`，不可忽略

两机 Ghidra 已加载指令内还有**12处**直接写 `+0x580`（含 byte/word）。其中可覆盖 `+0x581` 的 `STR` 4字节操作是：**X-S10 7处，X-T4 6处**。至少发现两组对照机完全同构的 Movie 运行结构函数：

| 结构函数 | X-S10 | X-T4 | Ghidra确认的行为 |
|---|---|---|---|
| Movie 结构初始化候选 | `FUN_02231498` | `FUN_0219E138` | `*(u32 *)(param_1+0x580)=1`（小端时 offset +581 为 0） |
| Movie 结构重算候选 | `FUN_022368A0` | `FUN_021A35AC` | `*(u32 *)(param_1+0x580)=*(u32 *)(param_2+0x18)` |
| 上层读取 Movie 动态对象 | `FUN_0227E1F0` 使用 `FUN_02283BB8()` 返回指针 | `FUN_021E2E74` 使用 `FUN_021F01B8()` 返回指针 | 同时访问较高 Movie/context 偏移（例如 `+0x5BE`、`+0xB7C` / `+0xB80`） |

这些是原始 Movie 结构的**合法写入候选**，不能因它们使用同一数值偏移就宣称它们写了 Recorder 的**当前输入缓冲区 P**。前述上层 Movie 对象 getter 尚未与配置描述符的 P 指针建立真实别名链，也没有证明执行时机。当前无法排除其他 `STRH`、memcpy、间接地址构造或暂未反汇编的代码覆盖 `P+0x581`。本轮审计将这些不确定性明确保留为未证实状态。

## 五、复验、原创代码与下一关

公开的原创代码（无厂商原始固件/全反编译文本）：

- `ghidra_scripts/ProbeStage50InputFlagWriters.java`：**只读**、有限偏移的 Ghidra 指令读写/函数拥有者盘点，输出可复核本机私有日志；不把偏移视为指针身份。
- `tools/audit_stage50_recorder_flag_feedback.py`：对原厂ROM及 Ghidra 结果逐字检查 16 条导出传递A32、6个直接 `STRB+581` 站点、4个其它全局基址重构、`+580` 整字候选数、两机Movie源码；重新执行第31阶段 alias 验证和第49阶段前向验证（第49阶段包括第32与第48及 SHA256 审计）。
- `tests/test_audit_stage50_recorder_flag_feedback.py`：**88项完全合成的正/负测试**（原始 ARM 损坏、字段误序、反向赋值、GUI目标地址伪证、false pointer equality、缺失库存项、4字节覆盖漏检等）。
- `docs/phase50-recorder-flag-feedback-pointer-alias-2026-10-21.md`：本报告。

本机实测原厂审计输出：`STAGE50 ORIGINAL A32 FLAG FEEDBACK + POINTER ALIAS INVENTORY PASS`。全回归结果为 **仓库已跟踪91项 + 本机Git忽略2588项 = 2679项全部通过**（其中本轮88项）。测试并不证明物理机 4K60/Main10 性能。

离线重现（只在机主已有私有ROM/Ghidra项目的Ubuntu；无需连接相机）：

~~~bash
cd /home/zyubuntu/xs10hk
# 生成当前Ghidra只读盘点（每个模型另选对应project）
/home/zyubuntu/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless output/ghidra_x6 xs10_merged_x6 -process section-1.bin -noanalysis -readOnly -scriptPath ghidra_scripts -postScript ProbeStage50InputFlagWriters.java > output/xs10_stage50_input_flag_immediate_writers.log 2>&1
/home/zyubuntu/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless output/ghidra_x6 xt4_merged_x6 -process section-1.bin -noanalysis -readOnly -scriptPath ghidra_scripts -postScript ProbeStage50InputFlagWriters.java > output/xt4_stage50_input_flag_immediate_writers.log 2>&1
PYTHONPATH=tools:output python3 tools/audit_stage50_recorder_flag_feedback.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

**下一关**：优先沿描述符 `+0x10` 的 P 指针，到 0x206/0x207 模式配置记录，追溯 `P[+0x580..583]` 的初始生成/块拷贝、当前 Movie 动态对象及整字 `+0x580` 写入者的指针身份证据；同时审计 Q=P 之后到序列化前是否存在能改指针值的别名写。需要原始 ARM 指令和实际传参链，不能从偏移相等或两个机型共有条件推出 X-S10 专有 4K59.94 锁。

**当前没有 HEVC Main10 SPS、真实10-bit内录、Sensor/ISP 4K59.94 输出，也无安全可用的刷写方案。**