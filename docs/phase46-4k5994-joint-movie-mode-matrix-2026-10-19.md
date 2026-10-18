# 第46阶段：96×0x40 原厂录像模式矩阵、4K59.94 联合模式记录与宽高解码（2026-10-19）

> **关键突破：** X-S10 原厂 3.11 和 X-T4 原厂 2.12 各存在一张**逐字节完全相同**的 Recorder/Movie 模式记录表：96 条，每条 0x40 字节，最后第97条首字节0xFF为终止标志。实际 ROM 函数逐条匹配**模式类别、尺寸键、帧率枚举、模式变体四个字段**，然后从Section1原厂宽高 LUT 写入运行时影片宽高。其中包含明确的 3840×2160 + 59.94fps 和 4096×2160 + 59.94fps 候选记录。两机相同的是**编译后的软件静态超集**，并未证明 X-S10 UI 可以选择、HEVC能够和该组合同时通过上游许可、传感器/ISP/VPU可以运行，或4K60/Main10已经解锁。

## 0. 原始ROM与安全边界

只读授权Ubuntu /home/zyubuntu/xs10hk 中两机未修改的原厂X6 Section1/Section2和Ghidra 12.1.4只读项目。X-S10原厂**3.11**样本不等于用户此前报告的实体X-S10 **2.10**。本阶段无实体相机、FF80/USB通信、硬件RAM/Flash读写、原厂DAT/ROM修改、签名处理、V61微码改写、补丁或刷机文件；没有真实录像码流样本。地址全部为离线ROM虚拟地址，**不能当作设备可写地址**。厂商ROM、V61字节、Ghidra数据库及完整研究日志只在gitignored output中，GitHub仅提交原创源工具、合成测试和本报告。

原厂SHA256（本轮审计器每次独立重读，引用Stage45已经固定的两个分段身份）：

| 样本 | Section1 SHA256 | Section2 SHA256 |
|---|---|---|
| X-S10 3.11 | c86c9446a15a39e6e761c4ca96383e943cdb3a09cab6e609b85b3e48f3e91aff | f0c4db782031a81c620d764317ebf0219d10bb4b52eb4fd5998b9ce39c3afb8c |
| X-T4 2.12 | 0b5b0fb0ee5fe6b109dae9964b5cddfe18edab46b4a0c195f9da194448906eeb | e1ef8b30903d3078fde103cdd134fca7bfc4337d67bcaf55c3080ffd5fd93b13 |

## 1. 96×0x40静态RecordTable真实位置与调用链

| 字段 | X-S10 | X-T4 |
|---|---|---|
| Section2 模式记录表首地址 | **0x027A0DBC** | **0x026FDE5C** |
| 96条记录总长度 | **0x1800 = 6144 B** | **相同** |
| 终止符FF位于 | **0x027A25BC** | **0x026FF65C** |
| 真正按0x40步进遍历的函数 | **FUN_022E123C** | **FUN_0224DB10** |
| 主录像初始化调用此匹配函数的ARM BL | **0x022D6978** | **0x02242F48** |
| 初始化 / 运行时对象生产者 | FUN_022D5FEC | FUN_022425BC |
| 宽度解码函数 | FUN_012C9354 | FUN_012A2F90 |
| 高度解码函数 | FUN_012C941C | FUN_012A3058 |
| Section1 宽度 u32 LUT | 0x0171BF0C | 0x0168BAE4 |
| Section1 高度 u32 LUT | 0x0171C1F0 | 0x0168BDC8 |
| MovieSetup最终消费尺寸的函数 | FUN_022DEE64 | FUN_0224B65C |

96条真实原厂记录体按SHA256为：
**43852b4bb7454ad54b1a9d018432250829abb334dec9961fb54e4862407199bc**。
两机逐字节相同，连紧随其后的FF哨兵也一致；**并非是两份独立配置表的名称碰巧相似**。

两个宽高数组各740字节（37×5×uint32），两机同样相同：
- width LUT SHA256 **1487b8f22ce79a2255416db3c5610be42aa33305695b65944bb0bb63f57e395d**
- height LUT SHA256 **fc69ac54361cb78b51cae67a42bdd49d3f22d726fef6e4e49f9a496f5ef3949a**

全部真实ROM哈希、Section2的A32直接BL译码及Ghidra原始调用引用、两个Section1表实际解码公式均由审计器独立通过；不是扫描一串4K或60字面量的联想。

## 2. 真正的四重记录匹配：联合模式键，不等同于HEVC开关

原厂查表函数依次比较四个字段：
1. **record[0] == 当前运行时模式对象+0x5F5的帧类别**。主录像初始化对常规影片类别（含原厂4K分类函数列出的4/5/6/7）写入0；高速影片2/3以1/2分类。
2. **record[1..2]的小端uint16 == Movie主上下文+0xADD8的uint16尺寸/模式键**。
3. **record[3] == fps enum**。类别1/2来自Movie+0x5C7，其它类别来自Movie+0x5C6。随后Stage45的同源枚举送编码器Q16 FPS。
4. **record[4] == 模式variant**。X-S10来自Movie+0x9B8；X-T4来自Movie+0x9BC。该值不能未经验证改称为codec/Profile；本阶段仅以variant命名。

一旦匹配，两个宽高函数分别以 record[1]作为类别、record[2]映射成列0..4，计算 (record[1]×5+列)×4，在独立原厂Section1宽高表取uint32，再写入 (Movie+0x6018指向的运行时对象)+0x600/+0x602。这两个字段又确实在Stage45的MovieSetup被读取，作为VPU初始化宽高。

解码结果（两机逐字一致）：

| record[1] | record[2] → 列 | 真实宽 | 真实高 |
|---|---|---:|---:|
| 7 | 2 → 2 | **3840** | **2160** |
| 7 | 7 → 4 | **4096** | **2160** |
| 6 | 2 → 2 | 1920 | 1080 |
| 6 | 7 → 4 | 2048 | 1080 |

全部96条真实表项按解码后分辨率计数：**1920×1080：42条；2048×1080：18条；3840×2160：18条；4096×2160：18条**。fps枚举1—6，每档恰有**16条**。frame class计数0/1/2分别为72/18/6。

**注意：** +0xADD8的模式键是u16，而codec/HEVC选择字节在Movie上下文**+0xADDA**，不是同一个字段；查表函数**没有直接读取+0xADDA**。因此这个Recorder LUT是电影尺寸/帧率/变体的联合候选表，**不是HEVC许可矩阵**。

## 3. 六条4K59.94原厂联合表项逐条复核

表内fps枚举6，经第45阶段MovieSetup Q16换算为0x3BF0A3 / 65536 = **59.939987183fps**。零基索引：

| 行 | class | 小端模式键 | fps枚举 | variant | 解码宽高 |
|---|---:|---|---:|---:|---|
| 15 | 0 | 0x0707 | 6 | 1 | **4096×2160** |
| 16 | 0 | 0x0707 | 6 | 2 | **4096×2160** |
| 17 | 0 | 0x0707 | 6 | 3 | **4096×2160** |
| 33 | 0 | 0x0207 | 6 | 1 | **3840×2160** |
| 34 | 0 | 0x0207 | 6 | 2 | **3840×2160** |
| 35 | 0 | 0x0207 | 6 | 3 | **3840×2160** |

例如合成键 class0、尺寸模式0x0207、fps6、variant1，按真实四项比较唯一匹配记录33；class0、0x0707、fps6、variant2唯一匹配记录16；改为class1则不会命中4K这组。这个条件匹配是**代码数据层面的可满足条件**，**不是UI/机型可达到条件的实证**。原厂4K分类器虽已核对，但谁允许将Movie主上下文设成这些值、是否通过I/O制式/机型限制、是否允许HEVC与fps6和此尺寸并存，尚需继续研究。

## 4. 排除错误推断，寻找真正瓶颈

现可明确排除“原厂X-S10 3.11完全没有4K59.94模式记录”这一个假说：两机数据连字节级都相同。但不可由此推断“X-S10只是UI隐藏4K60”“强行选择相同行就能录制”“两机传感器/ISP等价”。两个机型可能复用整个底层Movie/Recorder LUT，却在前端UI、模式枚举准入、Sensor Readout/ISP、VPU物理吞吐、写卡链路或产品配置有不同限制。Stage22还识别了另一组仅代表**HDMI接收器EDID**支持的4K60代码，它与本阶段这张真正的Movie/Recorder查表完全不同，不能混淆。

当前软件静态关系已严密区分：

**Movie主对象+0xADD8（录像尺寸键）／+0x5C6或+0x5C7（帧率）／+0x9B8或+0x9BC（variant）→ 96×0x40 LUT→运行时width/height+0x600/+0x602→MovieSetup。**

与此同时**Movie主对象+0xADDA（HEVC编码选择）**进入另一个独立Codec/V61固件源分支。必须额外证明两条路径的**联合可达性**，才可讨论是否有合法X-S10的4K59.94+HEVC会话。HEVC Main10 Profile还是要有真正SPS general_profile_idc=2和亮度、色度10bit以及样本来源证据；本轮没有这样的文件，也没有对V61独立ISA或硬件实际运行的成功验证。

## 5. 第47阶段建议

优先从模式GUI与 Recorder 配置生成者回溯Movie+0xADD8、+0x5C6/+0x5C7以及X-S10 +0x9B8 / X-T4 +0x9BC的写者，做**联合值来源和机型分支差异**分析。然后单独核验传感器/ISP读出是否能实时提供3840×2160@59.94或4096×2160@59.94、硬件带宽和编码回调。如缺少上述证据，只能继续把4K59.94判为“底层原厂表存在的候选模式”，不是合法录制支持。

## 6. 公开文件与自动化复验

本阶段新增原创：
- tools/audit_stage46_joint_movie_mode_matrix.py：两机Section1/2完整SHA、原厂96×64 ROM表及双LUT哈希、A32原始CALL、只读Ghidra四键匹配/0x40步进/动态宽高赋值和Recorder MovieSetup消费者审计，严格报告未知实际硬件能力；
- tests/test_audit_stage46_joint_movie_mode_matrix.py：**173项合成测试**，从头构造独立的A5填充人工96记录以及人工37×5维度LUT，覆盖类/模式/帧率/变体、坏终止符、宽高越界、错用Codec字段、假Ghidra负向变异与96条逐行检验；不含原始固件、V61机器码或任何厂商反编译函数体；
- docs/phase46-4k5994-joint-movie-mode-matrix-2026-10-19.md：本报告。

离线复验（原厂ROM文件只在授权机器的gitignored output下存在）：

    cd /home/zyubuntu/xs10hk
    python3 tools/audit_stage46_joint_movie_mode_matrix.py --output output
    PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
    PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q

**实际结果：**
- 两机原厂Section1/Section2与记录表、宽高解码LUT和Ghidra/A32审计PASS；
- 原厂只读审计Phase26—Phase46全部PASS；
- 新增173项合成测试在不含任何Fuji ROM的独立public-only目录PASS；
- 累计**91 tracked + 2177 ignored research = 2268项离线测试PASS**，本地main仍clean；FF80设备未检测到，No command sent；
- 没有连接/修改实体相机或生成固件补丁，PR保持Draft并按研究阶段叠加。

**结论：** 原厂X-S10与X-T4共用完整96条影片配置超集，包含六条真实由宽高表解码成4K59.94的联合候选行；尚不能将其视为X-S10可正常使用的4K59.94+HEVC或Main10内录。
