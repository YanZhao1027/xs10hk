# 第十四阶段：三机录像任务直达 H.265 驱动，解出帧率参数（2026-10-14）

> **本阶段重大突破：不再停留于 H.265 模块和驱动函数存在。** 已经把 X-T3 5.11、X-T4 2.12 和 X-S10 3.11 的**两段解压 ARM 代码装载到各自同一 Ghidra 地址空间**，并经独立 ARM BL 指令扫描 + Ghidra 反编译交叉验证，证实**三台机身各自的录像初始化函数，都直接调用了 H.265 参数封装函数，后者再调用与 VPU 相连的编码参数驱动**。
>
> **X-S10 的上层录像程序里确实存在 H.265 初始化与参数提交的可执行路径**。但是，这不证明这些路径可以由 X-S10 已开放的录像菜单实际触发，更不证明 H.265 Main10 / 4K60 能以机内方式运行。
>
> 本阶段只使用 Ubuntu 上的用户授权原厂固件**离线解压副本和 Ghidra 数据库**。无 USB/FF80 调试、无相机访问、无改写 DAT、无刷机。**机主实际 X-S10 版本为 2.10，而研究包是 3.11；这些离线地址不得在实机使用。**

## 一、为什么之前漏掉了真正的上层调用

前一阶段使用独立 Ghidra 项目导入 Section 1 与 Section 2。录像业务的程序在 **Section 2**；H.265 驱动在 **Section 1**。当 Ghidra 单独加载一个 Section 时，段外地址没有映射，程序反编译器会显示诸如 \`func_0x...\` 的外部调用，且无法在驱动函数上统计到来自另一段的引用。

本阶段先用独立 A32 指令解码器，对每个模型 Section 2 的 32 位对齐指令按 ARM **BL（branch with link）** 公式还原跳转地址，逐字节确认来自录像业务的跨段调用。又以 \`ghidra_scripts/AddX6SecondSegment.java\`，把 Section 2 按候选装载基址加入 **Section 1 所在的同一个 Ghidra 程序**，重跑 ARM 自动分析，重新查询 Ghidra xref。

结果：三机均得到 **相同作用、不同地址**的两层调用链。独立指令扫描与 Ghidra 自动识别相互印证。

## 二、三机完整跨段 H.265 初始化调用链

| 对象 | X-T3 5.11 | X-T4 2.12 | X-S10 3.11 |
| --- | --- | --- | --- |
| 上层录像参数构建函数（Section 2） | \`0x01F0318C\` | \`0x0224B65C\` | \`0x022DEE64\` |
| 真正的跨段 \`BL\` **调用位置** | \`0x01F03738\` | \`0x0224BC90\` | **\`0x022DF508\`** |
| H.265 参数封装（Section 1） | \`0x01096B44\` | \`0x011CAB08\` | **\`0x011F745C\`** |
| 驱动参数接收函数（Section 1） | \`0x01099274\` | \`0x011CD230\` | **\`0x011F9B84\`** |
| 编码参数事件接收后的 VPU 装载 | \`0x01098004\` | \`0x011CBFC0\` | \`0x011F8914\` |
| VPU 主循环编码事件分派 | \`0x01098ACC\` | \`0x011CCA88\` | \`0x011F93DC\` |
| 设备会话映射等待函数 | \`0x0109BF08\` | \`0x011CFECC\` | \`0x011FC820\` |

Ghidra 在三机相应入口均反汇编到确切的 \`bl\` 指令：

~~~asm
X-T3    01F03738  bl 0x01096B44
X-T4    0224BC90  bl 0x011CAB08
X-S10   022DF508  bl 0x011F745C
~~~

目标是**实际的 H.265 参数包装函数**，不是日志显示函数。包装函数进一步调用 368 字节的 \`h265_drv_set_enc_param\` 状态/参数处理逻辑，例如 X-S10 的 \`0x011F745C\` → \`0x011F9B84\`。

三个业务函数均已通过 Ghidra 成功反编译，并能看见它们分别传入**60 字节的内部参数结构及一个回调函数指针**：

| 模型 | 上层业务调用形式（结构信息，非完整固件源码） | 作为 \`input[0]\` 的全局结构起点 |
| --- | --- | --- |
| X-T3 | \`set_enc_param(&DAT_0246BF24, callback)\` | \`0x0246BF24\` |
| X-T4 | \`set_enc_param(&DAT_028A5114, callback)\` | \`0x028A5114\` |
| X-S10 | \`set_enc_param(&DAT_029459CC, callback)\` | \`0x029459CC\` |

**含义：** 三机都具备相应的软件**调用点**。并没有证明任何一个调用点在特定机身已经被允许的录像模式里一定可达、可成功返回；也没有证明所有输入有效。特别是不能由一次静态 \`bl\` 的存在推导出 X-S10 直接可以录制 Main10。

## 三、真实编码参数中的第一个已确认语义：帧率 Q16.16

三个上层录像函数在调用 H.265 参数包装函数前，会对其结构的 **DWORD \`input[2]\`（从结构开头偏移 \`+0x08\`）**按相机的 fps 枚举写入以下值。这些数值是 16.16 固定点，除以 \`65536\` 即为实际帧率：

| 帧率 | 原始值 | XT3 | XT4 | XS10 |
| --- | --- | --- | --- | --- |
| 23.98 fps | \`0x17FAE1\` | ✓ | ✓ | ✓ |
| 24 fps | \`0x180000\` | ✓ | ✓ | ✓ |
| 25 fps | \`0x190000\` | ✓ | ✓ | ✓ |
| 29.97 fps | \`0x1DF851\` | ✓ | ✓ | ✓ |
| 50 fps | \`0x320000\` | ✓ | ✓ | ✓ |
| **59.94 fps** | **\`0x3BF0A3\`** | ✓ | ✓ | **✓** |
| 120 fps | \`0x780000\` | ✓ | — | — |

这是很关键的**代码级**结果：X-S10 并不只是包含 \`4K59.94\` 的公共 UI 文字；它的**录像任务生成的 H.265 参数结构，也包含 59.94 fps 的赋值分支**。

**边界：X-S10 官方允许 FHD 59.94p，但不允许 4K 59.94p。** 因此这里只能说明参数生成逻辑支持 **59.94 这一帧率值**，**不能证明 H.265、10-bit、4K、59.94 fps 可以在 X-S10 上同时选用。** 真正的 4K60 可用性取决于独立的画面尺寸/格式筛选、ISP/传感器时序、编码与写卡资源。

## 四、另一个字段确实存在三机差异，但其含义还没有定论

在目前找到的业务初始化函数中，输入参数的 **DWORD \`input[3]\`（偏移 \`+0x0C\`）**具有以下常量赋值：

| 机型 | 该字段在目标录像参数构建函数中发现的常量 |
| --- | --- |
| X-T3 5.11 | **1 / 3**，受上层模式/状态条件影响 |
| X-T4 2.12 | **1 / 3**，受上层模式/状态条件影响 |
| X-S10 3.11 | **3**，在当前分析的该函数内仅看到 3 |

在三机 H.265 驱动的对应 **220 字节**参数装载函数中，已确认这个 \`input[3]\` 作为有效数据被复制进入 VPU 会话结构的 \`dst[2]\`；因此它不是纯显示资源。

但是**\`1\` 与 \`3\` 代表什么目前尚未知**。可能与压缩行为、封装格式、码率控制或其他模式有关。**绝不能凭常数不同就宣称 \`input[3]=1\` 是 Main10，或者认为把 X-S10 的 \`3\` 改成 \`1\` 就能解锁。** 本次没有生成任何 patch。

这条差异是下一轮研究价值很高的**可验证候选字段**，而不是已解密的激活开关。

## 五、初始化结构中还存在画面尺寸来源：4K60 需要联合分析

上述 60 字节 H.265 编码参数以外，三机录像代码在同一函数中还分别构造了**视频驱动初始化结构**，其中前两个 16 位值来自上游录制上下文。

| 模型 | 初始化结构（与 60 字节编码参数分离） | 初始化驱动函数 | 初始化逻辑大小 |
| --- | --- | --- | --- |
| X-T3 | \`0x0246BF60\` | \`0x01096878\` | 716 字节 |
| X-T4 | \`0x028A5150\` | \`0x011CA83C\` | 716 字节 |
| X-S10 | \`0x02945A08\` | \`0x011F7190\` | **716 字节** |

三机的初始化驱动函数均已成功反编译，检查了指针和多处 4 KiB 对齐约束，再处理初始化参数。它们的**代码结构高度相似**。

业务层读取上游的两个 16 位字段：

- X-T3：来自录像配置结构的 \`+0x5AC\` 与 \`+0x5AA\`；
- X-T4、X-S10：来自录像配置结构的 \`+0x602\` 与 \`+0x600\`。

**这些非常可能是视频初始化的宽高相关字段，但单位、方向与裁切后的含义还需要通过上下游验证。** 不能只看 fps 字段便宣称 4K60 有完整的初始化组合。

X-S10 的初始化路径并非纯 H.264：录像业务代码可以到达 H.265 驱动初始化接口，也能到达编码参数处理接口。**不过静态存在与模式可用之间仍有一道不可省略的业务能力检查。**

## 六、与两个正对照机型比较后，结论进一步收敛

X-T3/X-T4 的 H.265 编码器模块和相关驱动结构，已在[第十三阶段](phase13-xt3-three-way-positive-control-2026-10-14.md)证实与 X-S10 **741,376 字节的三种视频 codec 模块完全一致**。现在更进一步证实**上层录像任务也有对应调用代码**。

- **不再合理的说法：**“X-S10 根本没有 HEVC 编码器或主程序调用接口。”三机正对照和真实 ARM BL 已反驳这一过强断言。
- **仍可行但未验证的假说：** X-S10 的某些编码配置/菜单允许条件和参数生成逻辑被软件限制。
- **仍未排除的其它约束：** 传感器 4K60 读出时序、热预算/功耗、内存及 VPU 资源、文件容器/音视频混流、SD 卡吞吐、额外的机型/认证检查等。

X-T3 是有用的正对照，因为它能 4K60/10-bit 内录而没有 IBIS；而 X-S10 具有 IBIS，却可能为了功耗、产品定位或其它因素限制视频功能。**不能把 IBIS 的有无直接当成充分的能力解释。**

## 七、可重复检验脚本（都不会改写相机/固件）

本阶段新增脚本及模拟测试：

- \`ghidra_scripts/AddX6SecondSegment.java\`：将第 2 个解压段以独立 RAM 映射加到同一个**Ghidra 项目**。改变的是离线分析数据库，不是机身 RAM。
- \`tools/x6_cross_segment_calls.py\`：独立还原 A32 \`BL\` 的 PC 相对偏移，验证 Section 2 → H.265 封装函数的直接调用。
- \`tests/test_x6_cross_segment_calls.py\`：正/负相对分支、误识别抑制和文件头基址测试。
- \`tools/audit_hevc_recorder_builder.py\`：从**本地私有 Ghidra 反编译文本**提取 \`input[2]\` fps 常量和 \`input[3]\` 观察值；明示未知语义。
- \`tests/test_audit_hevc_recorder_builder.py\`：仅用合成 Ghidra 样本的验证。

在用户授权 Ubuntu：

~~~bash
cd /home/zyubuntu/xs10hk

python3 tools/x6_cross_segment_calls.py \\
    --model xt3 \\
    --section1 output/x6-xt3/section-1.bin \\
    --section2 output/x6-xt3/section-2.bin
python3 tools/x6_cross_segment_calls.py \\
    --model xt4 \\
    --section1 output/x6-xt4/section-1.bin \\
    --section2 output/x6-xt4/section-2.bin
python3 tools/x6_cross_segment_calls.py \\
    --model xs10 \\
    --section1 output/x6-xs10/section-1.bin \\
    --section2 output/x6-xs10/section-2.bin

python3 tools/audit_hevc_recorder_builder.py \\
    --xt3 output/xt3_recorder_hevc_init.c.txt \\
    --xt4 output/xt4_recorder_hevc_init.c.txt \\
    --xs10 output/xs10_recorder_hevc_init.c.txt

python3 -m unittest discover -s tests -q
~~~

本阶段**91 项离线测试全部通过**。本地私有 C 反编译全文、Ghidra 项目、原厂数据均保存在 Git 忽略的 \`output/\` 内，**不会把厂商反编译程序全文上传公共 GitHub**。公开仓库只保存分析工具、可复现的地址及简要结论。

为给他人重建跨段 Ghidra 程序提供思路，以下是某次**新建** X-T4 项目的示例（必须使用新项目名，不能重复已有项目导致映射冲突）：

~~~bash
/home/zyubuntu/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless \\
  output/ghidra_x6 xt4_merged_x6_example \\
  -import output/x6-xt4/section-1.bin \\
  -processor ARM:LE:32:v7 -cspec default \\
  -loader BinaryLoader -loader-baseAddr 0x01021000 \\
  -noanalysis -scriptPath ghidra_scripts \\
  -postScript AddX6SecondSegment.java \\
       /home/zyubuntu/xs10hk/output/x6-xt4/section-2.bin \\
       0x01E0F000 0x01E1DE60
~~~

完成映射后，可对同一项目执行 \`-process section-1.bin -scriptPath ghidra_scripts -postScript ProbeX6Refs.java 011cab08\` 让 Ghidra 将它与录像函数 \`0x0224BC90\` 连起来。

### 联合 Ghidra 自动分析结果

- X-T3 的 H.265 参数包装函数 \`0x01096B44\`：**1 条来自 Section 2 的 ARM BL**，位置 \`0x01F03738\`；
- X-T4 的包装函数 \`0x011CAB08\`：来自 \`0x0224BC90\`；
- X-S10 的包装函数 \`0x011F745C\`：来自 \`0x022DF508\`。
- **3/3** 的独立 ARM 指令解析与联合 Ghidra xref 结果完全一致；
- Ghidra 全部三个联合项目都完成自动分析（\`Analysis succeeded\`），私有项目保存在 \`output/ghidra_x6/*_merged_x6\`。

### 安全边界

富士 [X-T3 官方电影菜单](https://fujifilm-dsc.com/en/manual/x-t3/menu_shooting/movie_setting/index.html) 明确：H.265 可做 SD 卡 4:2:0 10-bit；[X-T4 官方电影菜单](https://fujifilm-dsc.com/en/manual/x-t4/menu_shooting/movie_setting/index.html) 同样列出 H.265 10-bit；[X-S10 官方电影菜单](https://fujifilm-dsc.com/en-int/manual/x-s10/menu_shooting/movie_setting/) 目前只列出卡内 H.264 4:2:0 8-bit、HDMI 4:2:2 10-bit。因此，对比 X-T3/X-T4 是可验证的正对照，但在此**尚不能生成保证可用的 X-S10 Main10 或 4K60 patch**。

过去 [FF80 16 字节 RAM 读取造成 X-S10 无法正常关机](phase8-ff80-ram-timeout-2026-10-14.md)，由机主取出电池恢复；该危险路线仍已禁用。下一步应仅继续离线定位 **有效录像模式筛选（codec × fps × resolution）** 和 \`input[3]\` 字段真实用途，并另行攻克 DAT 重压缩/校验及独立救砖方案。

**现阶段的最强结论是：X-S10 3.11 的真实录像程序确实生成 H.265 驱动参数并保留有效的跨段提交调用点，包括 59.94 fps 值；只是尚未证明这些静态代码在 X-S10 对外开放的录像模式下会实际运行。**
