# 第59阶段：两机原厂逐模式MovieFormat、MovieCodec与eMode4kOut准入表（2026-10-25）

**最重要的新证据**：从X-S10 v3.11、X-T4 v2.12原厂X6 Section1**真正的参数索引表/模式表/每模式枚举允许标志**，而不是从GUI名字猜测，独立恢复了两个固件的录像配置准入规则。**在MovieFormat、MovieCodec和`eMode4kOut`的ROM菜单准入层，两机在模式`0x2D`和`0x21`上相同，X-S10并没有缺少Codec枚举`1`。** 当前只证明静态ROM配置，不代表实机已走该模式、HEVC Main10 10bit SPS存在、传感器能输出4K60，亦不是补丁方案。

## 原厂索引与结构

| 已核验原始ROM字段 | X-S10 v3.11 | X-T4 v2.12 |
|---|---|---|
| 原厂模式字节数组起点 | `0x0141AE54` | `0x014090A0` |
| 模式数（之后以`0x2E`结束） | **24** | **9** |
| 参数ID/指针索引表 | `0x0141AE70` | `0x014090AC` |
| 索引项数，随后全0 | **252** | **254** |
| 单个候选值记录长度 | **28B（数值4B + 模式位24B）** | **16B（数值4B + 9模式位 + 填充）** |
| MovieFormat 参数ID/候选数据地址 | `0x3FB`/`0x01421C2C` | `0x3E4`/`0x0140D314` |
| MovieCodec 参数ID/候选数据地址 | `0x3FC`/`0x01421C80` | `0x3E5`/`0x0140D344` |
| `eMode4kOut` 参数ID/候选数据地址 | `0x58E`/`0x0141B6AC` | `0x574`/`0x014098D4` |
| 允许性测试函数的真实实现（入口还有thunk） | `FUN_0114DFAC` | `FUN_011222DC` |
| 不可用值的默认选择实现 | `FUN_0114E198` | `FUN_011224C8` |

两个ROM的参数索引均有9条高16位为1的其他类型记录，**不能**把索引表中的所有ID都当成简单`uint16`键；本阶段逐项校验允许的`0/1`类型上半字，以及三项目标参数是`0`类型。逐候选值的结束标志是原厂32位`0x7FFFFFFE`；找不到合适选择时调用者使用**不同的**`0x7FFFFFFF`表示不可用，不能混为一谈。逐模式标志`1..4`被原厂验证函数视为可选，`0`为不可选；类型0候选中的标志`2`是原厂默认选择实现偏好的值。

## 精确恢复结果

以下方括号是**实际被原厂允许检查返回可选的枚举值**，不是机器物理性能或bit depth：

| 参数 | X-S10/X-T4模式`0x2D` | X-S10/X-T4模式`0x21` | 两机在其它存在的模式 |
|---|---|---|---|
| MovieFormat | `[0,1]` | `[0]` | 只有`0` |
| MovieCodec | **`[0,1]`** | `[0]` | 只有`0` |
| `eMode4kOut` | **`[3,0,1,2]`** | `[3]` | 只有`3` |

全部四字节候选值及对应24/9个标志都以原厂ROM字节核验。两机都为MovieFormat/MovieCodec的`0`写入所有模式的`2`标志，仅在电影模式`0x2D`为`1`设置`1`标志。`eMode4kOut`中`3`是所有模式的标志`2`；`0,1,2`只在电影模式`0x2D`的标志是`1`。

**结论边界：**这里的`1`是什么Codec由第60阶段另行根据ROM原始字符串核验；就此阶段来说，X-S10和X-T4**至少在这一层相同**。原厂候选允许不等于录制稳定、4K60传感器/ISP读出、编码profile Main10准入、输出SPS/HEVC码流或安全的固件修改。

## 原厂审计与测试

`tools/audit_stage59_movie_menu_ROM_allowlist.py`先重新核验第58阶段及之前所有SHA固定的原始X6审计，再读取模式数组、**逐个参数ID指针**、所有目标候选记录、结束哨兵和允许标志，并与两个只读Ghidra校验/默认值函数交叉验证。`tests/test_audit_stage59_movie_menu_ROM_allowlist.py`共**262项纯人工合成ROM表**测试：故意扰乱模式、参数ID/指针、表长、候选枚举、全模式标志、默认标志、终结哨兵和Ghidra判定。无富士二进制、私有反编译片段或机身数据被纳入PR。

原始私有证据位于Ubuntu的Git忽略`output/x6-{xs10,xt4}/section-1.bin`，只读Ghidra原始日志为`output/{xs10,xt4}_stage60_config_resolver_implementation.log`及第59阶段GUI setter日志。运行：

~~~bash
cd /home/zyubuntu/xs10hk
PYTHONPATH=tools:output python3 tools/audit_stage59_movie_menu_ROM_allowlist.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
~~~

**安全隔离**：原厂ROM版本X-S10 3.11/X-T4 2.12；历史实机X-S10 2.10**地址不能直接套用**。本阶段未进行USB/FF80、相机RAM/Flash、ROM/DAT编辑、镜头/SD卡操作或固件刷写。所有厂商二进制和完整Ghidra/日志仍只在Ubuntu本地的忽略目录，GitHub仅发布原创审计、合成测试和本报告。