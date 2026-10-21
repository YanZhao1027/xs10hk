# 第51阶段：Recorder 当前输入 `P+0x581` 的直接模式分支和两机相同的48×10字节查找表（2026-10-21）

> **新的静态实证**：除了第49阶段已证实的 `P+0x581 → 中间结构 → 活动Recorder flag → 父对象+A8E`，X-S10 原厂3.11和 X-T4 原厂2.12还各有至少两条**直接从当前输入配置 P 读取 `+0x581` 和 `+0x6C`、在 `P[0x581]==1 && P[0x6C]==7` 时将传入参数7改成6，然后调用同构模式索引查找器**的独立函数。两机对这段ARM逻辑都具备直接的RAM指针源身份链：PC相对ROM字面量 → Recorder配置对象基址 → `LDR [base,#0xAC4]` → `LDRB [P,#0x581]`，不是仅凭相同字段偏移推断别名。
>
> **另一项新结果**：该查找器使用一张 **48记录×10字节 = 480字节** 的原厂模式映射表；两机表**逐字节相同**（SHA256 `9aa3ab18a1604e9e4c9425d02dd042cce9b879dd4da349984035003516a7f9f0`）。原始ARM按4个输入字段查找，输入7→6可以在部分合成组合中改变命中索引，但对另一些组合产生**无匹配**并触发固件函数的死循环保护。**不能据此判断实体机执行过该分支、解锁了4K59.94、支持Main10或找到初始`P+0x581`写入者。**

## 1. 固件版本、范围与数据安全

本轮仅在用户授权 Ubuntu `/home/zyubuntu/xs10hk` 中离线读取**未修改**的 X-S10 v3.11 / X-T4 v2.12 Fujifilm X6 Section1、Section2 与本机已有 Ghidra 12.1.4 只读反汇编工程。研究的实际机身历史版本 X-S10 v2.10，与3.11的内部地址**不能混用**。无相机连接、USB/FF80操作、RAM/Flash访问、ROM/DAT修改、重签名或刷机。本地原厂固件、Ghidra数据库和私有完整日志都在 Git 忽略的 `output/` 中，**不上传**。

## 2. 原始ROM证明读取的就是 Recorder 当前输入指针 P

| 地址/函数 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| Recorder 当前输入描述符 | `0x02D987E8` | `0x02D0BF48` |
| 描述符管理者基址（`descriptor + 0x3000`） | `0x02D9B7E8` | `0x02D0EF48` |
| 当前输入指针槽（`manager + 0xAC4`） | `0x02D9C2AC` | `0x02D0FA0C` |
| 第一个直接模式读取器 | `FUN_022182EC` | `FUN_02184918` |
| 其PC相对ROM地址常量 | `0x02218408` → `0x02D9B7E8` | `0x02184A84` → `0x02D0EF48` |
| 第一组读取当前指针 P 的 `LDR [R3,#0xAC4]` | `0x02218300` | `0x0218492C` |
| 第一组 `LDRB [P,#0x6C]` / `[P,#0x581]` | `0x02218304 / 0x02218308` | `0x02184930 / 0x02184934` |
| 第二个直接模式读取器 | `FUN_02218464` | `FUN_02184AE0` |
| 其PC相对ROM地址常量 | `0x02218518` → `0x02D9B7E8` | `0x02184B94` → `0x02D0EF48` |
| 第二组 `LDR [R3,#0xAC4]` | `0x02218470` | `0x02184AEC` |
| 第二组 `LDRB [P,#0x6C]` / `[P,#0x581]` | `0x02218474 / 0x02218478` | `0x02184AF0 / 0x02184AF4` |

两机各两条路径的 PC LDR 原始 ARM立即数、PC+8位移、RAM管理对象基址及后续8条与条件相关的A32原始机器字均经审计。第一组两机连续机器码指令的**条件核心完全一致**：

~~~text
LDR   R1, [R3, #0xAC4]     ; P = 当前配置缓冲区指针
LDRB  R0, [R1, #0x6C]      ; 类型/原模式参数
LDRB  R2, [R1, #0x581]     ; 原flag值
CMP   R2, #1
CMPEQ R0, #7
MOVEQ R2, #1
MOVNE R2, #0
CMP   R2, #0
MOVNE R0, #6             ; 只有上述两条件同时成立
...
BL    原厂48记录查找包装函数
~~~

另一个功能相同的输入读取器由于编译器对中间变量安排不同，将 `MOVNE R0,#6` 置于另外三次 `LDRB` 之后，但同样先从相同 `+0xAC4` 指针读取`P[+0x6C]`和`P[+0x581]`、再经过两个 `CMP`、条件转换与 BL。不要把 Ghidra 输出中C字符串的 **`'\a'`** 误读成10：C里的 `\a` 是ASCII BEL，数值 **7**；原始ARM `CMPEQ R0,#7`（机器字`03500007`）已经直接验证。

这一变换发生在配置参数被映射到索引**之前**。它不同于第47阶段已证实的下游父对象 `+0xA8E` 条件重写；即使两者都可能给出参数6，也**不可假定是同一个函数、同一次调用或者相同执行条件**。

## 3. 进一步找到参数最终进入48×10记录的四条件原始查表器

| 查表函数 | X-S10 | X-T4 |
|---|---|---|
| 返回序号的扫描器 | `FUN_012C6ADC` | `FUN_012A0710` |
| 上层包装函数 | `FUN_012C6B48` | `FUN_012A077C` |
| 480字节原厂Section1表首地址 | `0x0171AC70` | `0x0168A858` |
| MOVW/MOVT取表首址（R12） | `0x012C6AE8 / 0x012C6AEC` | `0x012A071C / 0x012A0720` |
| 索引初始化 / 记录步长 / 最大记录数 | `R0=0 / +0x0A / 0x30` | 相同 |
| BL：第一组读取器→包装函数 | `0x02218334` | `0x02184960` |
| BL：第二组读取器→包装函数 | `0x022184A0` | `0x02184B1C` |

原始A32的四键选择规则与Ghidra交叉验证如下：

| 查找字段 | 原始输入来源 | 表中偏移 | 匹配规则 |
|---|---|---|---|
| Mode | 从 `P[0x6C]` 得到，经 `flag==1 && mode==7` 条件可变成6 | `row[0]` | 必须相等 |
| Key2 | `P[0x6E]` | `row[2]` | `0xFF`通配或相等 |
| Key3 | `P[0x6F]` | `row[4]` | `0xFF`通配或相等 |
| Key4 | `P[0x596]` | `row[6]` | 必须相等 |

扫描器每次向前跳10字节，最多48条，返回0..47范围内的索引。**必须注意**：Ghidra由于函数返回类型恢复不精确将扫描器标为`void`，但原始ARM清楚地以`R0`做索引计数并在匹配后从函数返回；包装函数也对`R0`与`0x2F`比较并在匹配不到时跳入无限循环。此结论来自**实际机器指令**，不依赖反编译器的`void`猜测。

两机同一张表中的记录类别分布：普通前36条包括18条`Mode=6`与18条`Mode=7`，后12条均是`Mode=6`的扩展记录，合计 **Mode6有30条、Mode7有18条**。**表数据、行数、四键规则和严格保护逻辑都相同**，无法由此定位X-S10专属的4K60禁用判断。

## 4. 用原厂表进行纯离线、反事实索引对照

以下仅是对**相同原厂表**喂入两个假定元组的**静态查表结果**，不是相机上拍摄到的录像或菜单选择。

| 输入参数 | 原始Mode=7 (`flag!=1`) | `flag=1`使Mode变成6 |
|---|---|---|
| Key2=6、Key3任意、Key4=2 | 命中行19 | 命中行3 |
| Key2=6、Key3任意、Key4=3 | 命中行18 | **无匹配**（返回48，包装函数有失败循环） |

“无匹配”并不证明实体机可能真的进入这条路径：上游GUI、参数校验或运行时组合有可能从不允许这个组合。反过来也不能把切换行号解读为`4K60→FHD`已实机触发，或相机具有任何可直接写入的安全解锁开关。该48×10索引表不同于第46阶段的**96×64字节分辨率/FPS记录表**；虽然存在其他下游关系，但本阶段没有证明两张表在实际录像状态下如何协同决定最终传感器/ISP参数。

## 5. 输入 `P+0x581` 真正初始写入者仍未找到

新 Ghidra 只读脚本按**直接引用当前输入指针槽**的函数做有界反编译索引：

| 统计 | X-S10 3.11 | X-T4 2.12 |
|---|---:|---:|
| 引用P指针槽的反编译函数 | 325 | 343 |
| 其中使用原厂通用复制helper的函数 | 16 | 18 |
| 命中相关复制/字段/长度筛查的候选函数 | 21 | 24 |
| 新发现的直接从P读取`+0x581`的模式判断者 | 至少3处 | 至少4处 |

除了两个主要模式分支，X-S10 `FUN_02218570` 与 X-T4 `FUN_02184B98/FUN_02184CAC` 也通过真实 `+0xAC4` 指针访问相同输入字节；另有两机同构的输入字段**导出**到另一参数结构的函数 `FUN_021F95F0` / `FUN_0216567C`（`param_2[+0x21] = param_1[+0x581]`），这同样**不是输入缓冲区初始写入**。本次有界同函数扫描未证明`P+0x581`首次赋值者；通过结构体别名、函数参数传递、`memcpy`及硬件DMA形成的写入仍无法穷尽。

同样，第50阶段的当前输入指针 P 值复制到导出指针 Q 后，序列化时是否仍保存相同指针值尚未得到实体运行态验证；该未证实问题不因本阶段新的直接读取而解决。

## 6. 公开原创研究文件与可复现验证

- `ghidra_scripts/ProbeStage51ConfigPointerBulkUses.java`：只读反编译直接引用P槽的函数，对涉及字段和拷贝的候选进行有界汇总，**不把同函数出现memcpy视为P目的地证明**。
- `tools/audit_stage51_direct_mode_flag_table.py`：重跑第50阶段、第31、32、48、49阶段的原厂SHA/ARM审计链后，核验本阶段4处ROM指针常量、两机四条P读取分支、4处BL、Section1 480字节表SHA、A32索引遍历与包装失败保护，独立模拟四键匹配。
- `tests/test_audit_stage51_direct_mode_flag_table.py`：本阶段 **102项完全人工合成** 正反测试，故意破坏原始指令、指针字面量、BL边、表字段、模式位和错误通配规则，**不含厂商原始表字节或反汇编数据集**。
- `docs/phase51-direct-input-flag-mode-map-2026-10-21.md`：本报告。

原厂原始Section1/2离线审计打印 `STAGE51 P+581 DIRECT MODE GATES AND IDENTICAL 48x10 TABLE ORIGINAL ARM PASS`。在Ubuntu完成全部回归：**91个仓库已跟踪测试 + 2690个本地忽略研究测试 = 2781项通过**，含新增102项合成测试。

离线复核（先生成本机Ghidra只读日志，其余私有原厂固件与辅助日志仍保留在`output/`）：

~~~bash
cd /home/zyubuntu/xs10hk
/home/zyubuntu/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless output/ghidra_x6 xs10_merged_x6 -process section-1.bin -noanalysis -readOnly -scriptPath ghidra_scripts -postScript ProbeStage51ConfigPointerBulkUses.java 02d9c2ac fun_012a9148 > output/xs10_stage51_config_pointer_copy_uses.log 2>&1
/home/zyubuntu/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless output/ghidra_x6 xt4_merged_x6 -process section-1.bin -noanalysis -readOnly -scriptPath ghidra_scripts -postScript ProbeStage51ConfigPointerBulkUses.java 02d0fa0c fun_01281848 > output/xt4_stage51_config_pointer_copy_uses.log 2>&1
PYTHONPATH=tools:output python3 tools/audit_stage51_direct_mode_flag_table.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

**后续最高优先级**：沿Recorder描述符`+0x10`指向的P，把0x206/0x207记录载荷、模式选择中来源的配置初始化与`P[+0x581]` 的**首次写入**接通；在各个通用复制调用中核验真目的地、源数据及长度，并从设置服务/机型权限检查取证。仍须另查4K59.94传感器/ISP/持续写卡、真实HEVC Main10 SPS，不应进行实机FF80、补丁或刷写。