# 第47阶段：4K模式键条件改写、1080/4K静态查表分叉及真正HEVC Codec来源（2026-10-19）

> **新突破**：沿第46阶段两机完全一致的96×0x40字节录像模式矩阵上游继续，首次定位了把原始配置字节Movie+0x5BD/+0x5BE复制成录像模式u16键Movie+0xADD8/+0xADD9的**原始A32写入指令**。当录像类型属于4K类（原厂分类器将类型4/5/6/7归为4K）且Recorder运行时父对象+0xA8E等于1时，第一字节被**条件性强制写为6**；否则从原始Movie+0x5BD复制。第二字节总是从Movie+0x5BE复制。与此同时，Movie+0xADDA的HEVC/H264 Codec选择字节是由独立BL调用读取**活动Recorder codec RAM**所得，不是静态模式矩阵的列。两机A32机器码、只读Ghidra C及查表结论三重一致。
>
> **严守能力边界**：这说明某个未识别含义的条件分支可让同一静态模式类别、相同帧率和品质落入不同像素尺寸的ROM表项；**并不证明实体X-S10实际触发了这个分支、进行了实际图像降采样、允许内录4K60、成功编出HEVC Main10或者存在可绕过的授权标志**。X-S10原厂离线样本版本3.11，过去用户报告实体机是2.10。

## 1. 只读ROM、原始ARM地址与两机对照

本阶段仍只读取授权Ubuntu /home/zyubuntu/xs10hk 内已有的两机原始X6 Section1+Section2及Ghidra离线只读项目。两机原始Section1/2全SHA固定为第45、46阶段审计值；此次原始A32逐条复核而非靠同名反编译文本推测。无相机、无USB/FF80、无RAM/Flash读写、无原始固件更改、无签名旁路、无补丁或刷机文件。厂商固件、V61微码、Ghidra DB与完整私有日志只留本机Git忽略output/。

| 关键节点 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| Recorder初始化函数 | FUN_022D5FEC | FUN_022425BC |
| 使用Movie类型判断4K的原厂分类器 | FUN_022D1674 | FUN_0223DC04 |
| 直接BL分类器（原厂Section2） | 0x022D625C | 0x0224282C |
| 比较运行时+A8E标志==1 | 0x022D6278 | 0x02242848 |
| 条件性MOV EQ low-key=6 | 0x022D6280 | 0x02242850 |
| 条件性STRBEQ写Movie+0xADD8=6 | **0x022D6284** | **0x02242854** |
| 常规LDRB Movie+0x5BD / STRB +0xADD8 | 0x022D6290 / 0x022D6294 | 0x02242860 / 0x02242864 |
| LDRB Movie+0x5BE / STRB +0xADD9 | 0x022D629C / 0x022D62A0 | 0x0224286C / 0x02242870 |
| BL读取活动Codec getter | **0x022D62A4** → FUN_012C048C | **0x02242874** → FUN_01298C18 |
| STRB getter返回值至Movie+0xADDA | **0x022D62A8** | **0x02242878** |
| getter返回的活动Recorder Codec RAM字节 | **0x01C25208** | **0x01B83974** |
| 下游MovieSetup使用+0xADDA选择HEVC/H264 | FUN_022DEE64 | FUN_0224B65C |

两机关键ARM机器字同构：
- 判断4K分类结果CMP r0,#0：E3500000；比较运行时标志==1：E3530001。
- 仅在条件成立时MOV EQ r2,#6：03A02006，STRB EQ至重定位后的+0xADD8：**05C32DD8**。
- 正常模式键低字节从+0x5BD读取：E5D425BD、写入+0xADD8：E5C32DD8。
- 高字节从+0x5BE读取：E5D435BE、写入+0xADD9：E5C53DD9。
- BL调用活动Codec getter的机器字分别EBBFA878/ EBC158E7，PC相对BL目标计算与Ghidra源码吻合；把返回R0存入+0xADDA：E5C50DDA。
- getter自身真正读取的活动Codec RAM原始ARM LDRB地址加偏移也验证：X-S10 MOVW E3043DD8 / MOVT E34031C2 / LDRB E5D30430，X-T4 MOVW E3033540 / MOVT E34031B8 / LDRB E5D30434。结合Ghidra getter返回值，确认为活动Recorder codec RAM而非猜测HEVC常量。

注意ARM需要先把Recorder基指针加0xA000，再以#0xDD8等立即数寻址；直接把其它函数中同为#0xDD8的任意ARM存储指令理解成相同语义是错误的。本阶段审计锁定的是上述Recorder函数内部、在分类器调用和活动codec getter之间的准确相邻指令序列。

## 2. 原始四条件ROM表查找：从4K记录分叉到1080记录

第46阶段已证明两机共同原始96条、0x40字节模式表必须同时满足：
- runtime class +0x5F5 == table[0]；
- u16 LE(Movie+0xADD8) == table[1:3]；
- fps枚举(Movie+0x5C6 或 +0x5C7) == table[3]；
- Movie variant X-S10 +0x9B8 / X-T4 +0x9BC == table[4]。

当前第47阶段定位了 **+0xADD8及+0xADD9在进入查表前的写入者**。当4K分类器返回1、运行时父对象+0xA8E==1时，**low mode key=6**而不是源Movie+0x5BD的值；否则复制源字段。高字节始终来自Movie+0x5BE。

在人工假设其余条件相同（class0、fps6、variant1、源Low7）时，两机**真实原厂ROM**解析结果：

| high-key | 原本low=7命中 | +A8E==1时强制low=6命中 |
|---|---|---|
| 2 | mode 0x0207 → **记录33: 3840×2160** | mode 0x0206 → **记录70: 1920×1080** |
| 7 | mode 0x0707 → **记录15: 4096×2160** | mode 0x0706 → **记录52: 2048×1080** |

这里的模式记录/宽高字是未经修改的原厂Section1+2，由SHA核验、并通过原厂Width/Height查表规则解出。它们证明**条件性地选择到不同的分辨率记录**；不是以任何实机实际画面证明ISP裁切/降采样。尤其，如果源Movie+0x5BD根本不是7，或者变体/FPS/类别没有匹配，相应4K记录仍然不可达。

条件+0xA8E的业务含义、取值写者、菜单/机型关联**尚未查明**。双机均有相同条件，故不得把该位直接称为“XS10 4K60锁”。

## 3. 真正Codec来源闭环：与模式矩阵独立

原厂Ghidra明确显示Movie+0xADDA的赋值来源：
- X-S10 FUN_022D5FEC：调用FUN_012C048C，返回DAT_01C25208，STRB至Movie+0xADDA；
- X-T4 FUN_022425BC：调用FUN_01298C18，返回DAT_01B83974，STRB至Movie+0xADDA；
- 这两个RAM字节在第32–45阶段已确认为活动Recorder Codec字段。第42阶段又已证明MovieSetup见Codec枚举1就选择HEVC Encoder V61源0xCA0000，否则选择H264 Encoder源0xD08000。

这比在模式表中找HEVC字面值更接近真正执行数据流：**同一个MovieSetup后来同时读取Recorder解析出的width/height/fps及前面复制的active codec选择字节**。但它们能否组成实体X-S10菜单/ISP/VPU准许的4K59.94 HEVC会话仍无证据；该模式表本身不把Codec作为直接第五个匹配条件。

## 4. 4K录像类型的fps6软件处理

同一个原厂Recorder初始化器在4K类型分支中，对fps枚举1..6采用case映射：
1/2→0x18，3→0x19，4→0x1E，5→0x32，**6→0x3C (60)**；两个机型对这段控制流一致。这说明第46阶段6条4K fps6静态记录之外，**上游Recorder初始化软件确实还包含一个可处理4K类别fps6的分支**。但“有处理分支”不等于合法菜单选择或真实硬件运行；不得把0x3C称为已实测4K60帧率。

## 5. 审计器、测试与复现

本PR原创三文件：
- tools/audit_stage47_mode_key_codec_ingress.py：双机原厂Section1+2完整SHA、精确原始A32/BL位点、getter原始MOVW/MOVT/LDRB、Ghidra两个4K分类器/条件覆盖/活动codec源、真实两机96记录与width/height的分支对照，失败即停止。
- tests/test_audit_stage47_mode_key_codec_ingress.py：**90项纯合成**参数/模式字/ARM指令/Mock Ghidra/分支篡改反例测试；完全没有原厂ROM片段、V61代码或实机录像。
- docs/phase47-mode-key-codec-ingress-2026-10-19.md：本报告。

**实际回归**：原厂只读审计Phase26—Phase47全部PASS；Stage46与Stage47的**263项**合成测试在完全不包含原厂BIN/ROM/Ghidra日志的隔离public-only目录PASS；本地仓库原有91项tracked + gitignored研究2267项 = **2358项离线单元测试全部PASS**。本地main clean，原仓库FF80状态检测仅显示未检测到USB设备、No command sent。原厂ROM、微码、Ghidra工程、私有指令日志不提交GitHub。

复现命令（需要已存在的授权离线原厂Section1/2文件与只读Ghidra日志）：

    cd /home/zyubuntu/xs10hk
    python3 tools/audit_stage47_mode_key_codec_ingress.py --output output
    PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
    PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q

## 6. 下阶段最有区分力的上游问题

应优先找Recorder父配置+0xA8E标志的**真实来源和代表的业务状态**，而不是修改值；追Movie+0x5BD/+0x5BE源字段、X-S10 +0x9B8/X-T4 +0x9BC变体与fps字段+0x5C6/+0x5C7的上游菜单/传感器条件，并确认两机差异实际出现在哪里。这里没有发现X-S10专属4K60禁用补丁点，也没有内录HEVC Main10真实SPS和4K60实机证据。

**结论**：ROM中的静态4K59.94记录并非孤立死字节，Recorder在其上游具有确定的条件性模式键重写和活动Codec拷贝路径；且双机原厂代码同构。物理能力和可选/可运行状态依然未知，绝不宣称已解锁。
