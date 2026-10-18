# 第44阶段：NALU格式真实上游赋值链、四字节码流长度前缀及HEVC Main10 SPS纯离线验证（2026-10-18）

> **本轮实际突破**：X-S10原厂3.11与X-T4原厂2.12不仅有同构的 VPU SET_OPTION index1 / NALU_FORMAT 命令和输出端长度转换，而且找到它们的**源值保存函数**：一个从调用者读取48字节参数块的原厂函数，连续使用三条A32 STMIA复制12个uint32，其中第一个字即NALU格式模式；此第一个值在RAM中保存，随后由VPU参数组装器取出，写入动态配置指针所指向的对象+0x18，再交给 SndSetOption。若最终值等于公开MVE协议的16 / 0x10（四字节NALU长度字段），原厂CPU的输出分支会把 filled_len-4 写成**四字节大端长度**。两机原厂Section1原始机器字、Ghidra只读函数与RAM xref逐条复核通过。
>
> **能力边界必须保留**：源参数写入者的原厂错误诊断名含有 dec_param；尚未证实实体录像HEVC Session真的调用它、也未获取当时的param_1[0]实值。因此这项研究**是精确的静态赋值和条件性格式关系**，不是证明每段X-S10 HEVC影片都用Length-4封装，更不是Main10解锁。

## 0. 范围、版本、资料与操作安全

本阶段只读访问授权Ubuntu /home/zyubuntu/xs10hk 内的X-S10 3.11及X-T4 2.12原厂X6 Section1、之前建立的只读Ghidra日志及Stage41—43原厂SHA核验结果。用户以前报告实体X-S10是2.10，并非本地研究使用的3.11 ROM。因此本文ARM/RAM地址不能用于机身直接访问。全程未连接相机、没有USB/FF80命令、没有读取或写入实体RAM/Flash、没有ROM/DAT修改、绕签名、刷机、生成Patch或可刷镜像。原厂BIN、V61微码、Ghidra DB、其完整私有日志及原始ROM审计输出都在Git忽略output/，本Draft PR只包含原创审计工具、离线解析工具、纯合成测试和报告。

公开协议来源（仅作为Host↔MVE ABI的独立资料，不是富士硬件实测）：

- https://github.com/kendryte/k230_sdk/blob/main/src/little/linux/drivers/media/platform/canaan-vpu/mve_protocol_def_v2.h
- https://github.com/kendryte/k230_sdk/blob/main/src/little/linux/drivers/media/platform/canaan-vpu/mve_protocol_def_v3.h
- https://github.com/kendryte/k230_sdk/blob/main/src/little/linux/drivers/media/platform/canaan-vpu/mvx_firmware_v2.c
- https://github.com/cixtech/cix_opensource__vpu_driver/blob/cix_p1_k6.6_master/driver/external/fw_v2/mve_protocol_def.h

## 1. 公开MVE NALU_FORMAT枚举确切含义

| 公开名称 | SET_OPTION index | 选项参数 | 作用 |
|---|---:|---:|---|
| MVE_SET_OPT_INDEX_NALU_FORMAT | **1** | 见下 | 指定NALU格式，而不是Codec Profile或位深 |
| MVE_OPT_NALU_FORMAT_START_CODES | 1 | **1** | 使用HEVC/H264 NAL起始码 |
| MVE_OPT_NALU_FORMAT_ONE_NALU_PER_BUFFER | 1 | **2** | 一个缓冲区一个NALU |
| MVE_OPT_NALU_FORMAT_ONE_BYTE_LENGTH_FIELD | 1 | **4** | 一字节长度字段 |
| MVE_OPT_NALU_FORMAT_TWO_BYTE_LENGTH_FIELD | 1 | **8** | 两字节长度字段 |
| MVE_OPT_NALU_FORMAT_FOUR_BYTE_LENGTH_FIELD | 1 | **16=0x10** | **四字节NALU长度字段** |

数字16/0x10不是HEVC Main10位深值，更不是HEVC编码输出profile。公开MVE的PROFILE_LEVEL option编号为3，MVE的Main10 profile参数是4；这些都是不同维度。

## 2. RAM中的选项值来自哪里：两机的真实A32赋值表

| 真实软件事件 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| dec_param样式源参数写入函数 | **FUN_011F9CF4** | **FUN_011CD3A0** |
| 参数API转发包装器 | FUN_011F7494、调用点0x011F749C | FUN_011CAB40、调用点0x011CAB48 |
| 48字节参数块的第一条STMIA | **0x011F9E10** | **0x011CD4BC** |
| 第二、第三条STMIA | 0x011F9E18 / 0x011F9E20 | 0x011CD4C4 / 0x011CD4CC |
| 参数0x10比较指令 | **0x011F9E28** | **0x011CD4D4** |
| NALU模式参数首字的RAM保存处 | **0x01B55DE0** | **0x01ABFD58** |
| RAM模式值读取函数 | FUN_011F89F0 | FUN_011CC09C |
| 从上述RAM首字读取的原始LDR | **0x011F8A28** | **0x011CC0D4** |
| 写入VPU动态参数对象+0x18的原始STR | **0x011F8A2C** | **0x011CC0D8** |
| 下一步进入SndSetOption的直接BL | 0x011F8A44 → FUN_011FB758 | 0x011CC0F0 → FUN_011CEE04 |
| 下一步构造BITSTREAM头的BL | 0x011F8A54 → FUN_011FB3B8 | 0x011CC100 → FUN_011CEA64 |

原始A32同构字：
- 三个STMIA批量写12个32bit参数：E8AC000F、E8AC000F、E88C000F；按顺序覆盖前48字节，每个机型均逐字一致。
- 调用者第一项与0x10比较：E3530010。
- 最终LDR源值：E5933000；随后STR至当前配置对象+0x18：E5823018。
- 包装器及进入SndSetOption、BITSTREAM头部构造器的BL均由未经修改ROM机器字计算目标，并与Ghidra引用/函数同一性一致。

Ghidra C显示源参数的第0项保存至上述RAM首字、末项第11项保存至同一连续结构+0x2C，合计48字节。如果传入格式0x10，会走一个将NAL缓冲四字节头交换字节序并调整长度的条件性循环；HEVC/H264会分别按内部codec标识使用3/2个头记录（Stage42另有独立证据）。这只能证明函数实现了相关条件分支。输入参数的真实运行时值及这条名为dec_param的接口是否由录像Session调用**未查明**。

私有只读Ghidra对首字0x01B55DE0/0x01ABFD58均枚举到**2处直接静态引用**，其中一处WRITE来自上述首条STMIA、一处READ来自配置组装器LDR。这里的2不包括内存别名、间接函数或整体RAM块拷贝，不能推断没有其它写者。

## 3. 真正串到SET_OPTION index1及CPU编码输出数据

读取函数把源RAM首字装进当前VPU配置对象 +0x18（Ghidra显示为保存对象数组的[6]），之后调用：
- XS10：FUN_011FB758 → generic消息发送 FUN_011FA530；
- XT4：FUN_011CEE04 → FUN_011CDBDC。

两个SndSetOption的Ghidra C中，分别在编码/解码不同条件分支，都能看到 local index=1，local payload=上文配置对象[6]，真实请求代码0x3F2、总数据8字节。此前Stage42已核验全部五个直接选项index为1、16、38、1、5；其中index38与8/8码流位深针对H264 enum1的条件分支。index1跟位深无关。

Stage43已从公开MVE ABI×双机ARM定位0x7D6 OUTPUT返回的是40字节MVE_BUFFER_CODE_BITSTREAM描述符（flags+0x10、offset+0x18、filled_len+0x1C、buf_addr+0x20），且CODECCONFIG位为0x80。本阶段把同一CPU响应逻辑中的 **配置对象[6]==0x10** 进一步关联回来：两机Ghidra明确把原始filled_len减去4，再拆成四个字节，按**大端**写入实际码流缓冲区头部。验证器特别限制仅当运行时设置16才使用这项规则，不能把所有返回BITSTREAM都硬判为Length-4，也不能把输出描述符+0x18误当像素格式（输入72B帧+0x18才是NV12/Y0L2）。

原厂Ghidra代码中出现此0x10条件3处、相应CPU输出四字节长度重写片段2处；这属于不同分支共享同一设置参数的静态事实，具体事件是否会同时在录像过程中执行仍未知。

## 4. 另一个会误判Main10的数值：MVE Option Profile4与真实SPS Profile2

原厂仍没有直接确认HEVC Main10 Profile已被实际设置或成功输出（第42阶段仅有界查过11条直接send引用，未找到index3发送，间接路径和微码默认行为未知）。本阶段增加独立纯离线的HEVC SPS校验器，避免把协议里的数字直接解释成编码比特流：

| 名称空间 | 表示HEVC Main10时的数值 | 来源 |
|---|---:|---|
| Host-MVE SET_OPTION: MVE_OPT_PROFILE_H265_MAIN_10 | **4** | MVE协议的管理层枚举值 |
| 真正HEVC SPS: general_profile_idc | **2** | HEVC Profile-Tier-Level比特流字段 |
| SPS的实际像素位深 | bit_depth_luma=10、bit_depth_chroma=10 | 分别由两个Exp-Golomb减8字段得到 |

因此一个真实HEVC SPS如仅出现字段值4，不能因此判为Main10；也不能只根据输入Frame是Y0L2/10bit就推出已成功输出Main10。必须在正确的SPS结构中看到相应general_profile_idc、luma/chroma两个位深字段，且样本有可追溯的来源，才能把对应录像归属到实机模式。

工具 tools/inspect_hevc_sps_stage44.py 是完全原创的**纯离线原始码流**解析器：
- 支持 HEVC Annex B起始码或四字节大端NAL长度前缀（auto/annexb/len4）。
- 仅扫描真正NAL类型33 SPS，去除必要的emulation-prevention字节，按HEVC SPS语法解析profile_tier_level、chroma_format、width/height以及bitdepth字段。
- 保守报告所有解析到的SPS是否同时明确指向Profile2和10/10bit；零个SPS、截断字段、无效NAL、矛盾的SPS不会判成功；无论结果如何都不自动认定源自X-S10。
- **输入必须是已经存在的本地.raw HEVC elementary stream**（扩展名.h265/.hevc/.265），不是MOV/MP4容器，不访问摄像机和外部网络，也不改文件。
- 本轮**没有任何实体相机产生的视频样本提供给该工具**。工具只以纯合成码流完成测试；没有真的提取到X-S10的SPS。

示例命令（仅当日后已存在本地原始HEVC elementary stream时）：

    python3 tools/inspect_hevc_sps_stage44.py --input /path/to/existing-sample.hevc --mode auto

注意必须先把真正MOV/MP4容器中的HEVC NAL流正确地提取出来再用；不可把MOV字节直接喂给该脚本，也不可把测试器生成的人工SPS当成实际录制证据。

## 5. 重复性审计、测试与保护边界

本阶段新发布5项原创文件：
- tools/audit_stage44_nalu_format_provenance.py：读取已存在的原厂Section1、Stage43原厂审计和只读Ghidra日志，逐机重检SHA、三条STMIA/48B、CMP16、源RAM LDR与+0x18 STR、SET_OPTION index1两分支以及CPU返回四字节前缀改写。
- tools/inspect_hevc_sps_stage44.py：无第三方依赖的标准库HEVC原始码流SPS字段解析器。
- tests/test_audit_stage44_nalu_format_provenance.py：87项纯合成数据流与错误指令/分支/字节序反例。
- tests/test_inspect_hevc_sps_stage44.py：85项从零构造的人工SPS/NAL、错误profile/错误位深/不同包格式/错误边界反例。人工SPS没有任何原厂码流来源。
- docs/phase44-nalu-mode-source-sps-parser-2026-10-18.md：本研究文档。

两份新脚本在本机gitignored output/中以原厂文件和Ghidra日志作只读审计，另外将依赖脚本和两份合成测试复制到独立、不带任何Fuji ROM或私有Ghidra数据的public-only目录后重跑。这种隔离测试**172项全部PASS**。自第26至第44阶段历次原厂ROM只读审计全部PASS。现有tracked仓库91项+ignored研究1889项=**1980项离线测试全通过**（原仓库FF80检查只显示设备未被检测到、No command sent）；本地main仍clean。

复验需要原始ROM才能完成原厂A32检查，其他检查可脱离ROM完成：

    cd /home/zyubuntu/xs10hk
    python3 tools/audit_stage44_nalu_format_provenance.py --output output
    PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
    PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q

**当前结论**：真实静态NALU格式上游赋值者和条件性Length-4编码输出修改关系已找到，并提供纯离线HEVC SPS profile/位深判别工具。尚无实机选择NALU模式16、硬件接收Main10 Profile、HEVC Main10 SPS实际录制、4K60传感器/ISP/录卡可行性或V61专有ISA解码证据。绝不据此宣称已解锁内录Main10或4K60。
