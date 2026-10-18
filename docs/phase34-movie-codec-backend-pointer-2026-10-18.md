# 第34阶段：录像 Codec 控制字段被登记到后端运行时参数指针槽（2026-10-18）

> **结论**：本阶段继续追第33阶段录像上下文 Codec 所决定的 0x10004/0x10005 参数，确认**写入它们的整份控制参数结构**会被当前录像对象同时登记在两个指针槽中；其中第二个槽位于动态后端对象 +0x3D00。两台机型的参数登记器不仅逻辑同构，而且在原厂 Section2 中是**完整 152 字节、逐字节相同的 ARM 函数体**。这是下游**指针交接**证据，不是 HEVC/Main10/4K60 的硬件执行证据，也不是实机录像证明。

安全与版本：X-S10 原厂 **3.11**、X-T4 原厂 **2.12**；用户此前报告的实机 X-S10 **2.10**，不可混用绝对地址。整个阶段只在用户授权 Ubuntu 上离线读取 Section1/2、已有 Ghidra 12.1.4 只读数据库与私有日志，没有相机、USB/FF80、RAM/Flash 读写、修改 DAT 或可刷补丁。原厂固件和反编译日志保持在被 Git 忽略的 output/，GitHub 只上传原创分析脚本、纯合成测试与说明。

## 一、新的两级参数结构指针链

~~~text
ctx = 当前录像应用上下文 (运行时地址未知)
main = *(ctx + 0x601C)           // 主录像对象指针
backend = *(main + 0x124A8)     // 动态后端运行时对象指针

已在第33阶段验证：
  *(uint32_t *)(main + 0x37F8 + 0x220)
     = (ctx[CodecOffset] == 1) ? 0x10004 : 0x10005
  CodecOffset：X-S10 +0x9D8；X-T4 +0x9DC

本阶段新验证（同一有条件录像启动分支）：
  *(void **)(ctx + 0x5FF4)     = main + 0x37F8
  *(void **)(backend + 0x3D00) = main + 0x37F8

因此：
  主对象中的实际选择字段 = main + 0x3A18
  动态后端获得的参数结构指针 = main + 0x37F8
  （后端是否读取该字、真正下达什么驱动命令仍未知）
~~~

请注意，这里两个登记目标保存的是**指向整份参数结构的 32 位指针**，而不是把字值 0x10004/0x10005 直接写到后端 +0x3D00。

## 二、真实调用顺序与条件门控

| 原厂静态事实 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 录像主入口调用者 | FUN_022DF9EC | FUN_0224C14C |
| 判断主对象子模式 | main +0x122A0 | 同左 |
| 视频控制参数构造 | FUN_022B6230 | FUN_02222A00 |
| 入口→构造器的 BL | **0x022DFAA8** | **0x0224C208** |
| 参数块起点 | main +0x37F8 | 同左 |
| ctx 的备用参数指针槽 | +0x5FF4 | 同左 |
| 后端指针登记器 | FUN_022E3D5C | FUN_02250634 |
| 入口→登记器的 BL | **0x022DFAF8** | **0x0224C258** |
| 参数块第0x220字位置 | **main +0x3A18** | 同左 |

原厂 Ghidra 对调用者的伪代码（省略中间其他函数）：

~~~c
main = *(uint32_t *)(ctx + 0x601c);

if (*(uint8_t *)(main + 0x122a0) == 0) {
    // 另一种录像处理分支，本阶段不声称共享下面全部调用
} else {
    build_video_params(ctx,
        main, main + 0x3494, main + 0x37f8, main + 0x120d4);

    *(uint32_t *)(ctx + 0x5ff4) = main + 0x37f8;

    // 中间还有日志和其他配置构造调用
    register_video_param_pointers(ctx);
}
~~~

已在两机原厂 Section2 中逐个复核两个 BL 跳转目的地、同一个主指针来源、子模式分支及两个指针存储目标；并与第33阶段对 +0x9D8/+0x9DC 和 +0x220 的原始字节访问审计进行关联。

**不能忽略分支条件**：函数里存在该路径，不等于所有机型、所有拍摄模式或所有录像启动动作都会经过它。

## 三、真正的后端参数登记布局

两机后端登记器均从主录像对象内的 **+0x124A8** 取出后端对象的动态指针，然后写入如下字段：

| 后端目标字节偏移 | 写入的数值 |
|---|---|
| backend +0x3CF8 | main |
| backend +0x3CFC | main +0x3494 |
| **backend +0x3D00** | **main +0x37F8（包含 +0x220 Codec 选择字段的整个结构）** |
| backend +0x3D04 | main +0x120D4，或根据 ctx+0x3118 为零时填 NULL |
| backend +0x3D08/+0x3D0C | 相邻录像运行时元数据指针/数值，不能凭地址猜测语义 |

关键 ARM 指令，两机偏移一致：

| 登记器函数内的相对位置 | 原厂 ARM 语义 |
|---|---|
| +0x08 | ADD R12,R0,#0x6000 |
| +0x0C | LDR R2,[R12,#0x1C] → main |
| +0x10 | ADD R3,R2,#0x12000 |
| +0x14 | LDR R3,[R3,#0x4A8] → backend |
| +0x18 | ADD R1,R3,#0x3000 |
| +0x1C | STR R2,[R1,#0xCF8] → backend+0x3CF8 |
| +0x20～0x2C | 计算并写入 main+0x3494 → backend+0x3CFC |
| +0x30～0x38 | 计算 main+0x37C0+0x38 → main+0x37F8 |
| **+0x3C** | **STR R2,[R1,#0xD00] → backend+0x3D00** |

原始地址中，X-S10 的最后关键 STORE 位于 **0x022E3D98**，X-T4 位于 **0x02250670**；二者机器码均是 **0xE5812D00**。这不仅由反编译指示，还与 Section2 小端原始指令字完全匹配。

## 四、两机整段 152 字节函数完全相同

完整原厂 Section2 的以下两个函数体，按 Ghidra 定位的 152 字节长度逐字节比较：

- X-S10：**0x022E3D5C—0x022E3DF3**
- X-T4：**0x02250634—0x022506CB**

两机完整 152B SHA-256：

~~~text
b5d9d90e6316613bde4e99143d01fabd3048732c6182c0c004c8ecd70cd6c5ac
~~~

已证实相同的是**参数指针登记函数的原始代码及其内部参数结构 ABI**。不能由此推出主 SoC 所有传感器/ISP/VPU 固件相同、可录制码流相同，也不能推出 X-S10 的编码功能一定被 UI 人为关闭。

自动审计会在原始二进制不再一致时失败；不会把特定机型的版本地址套在另一版本的相机上。

## 五、后端消费点搜索结果：负面筛查的严格边界

为了进一步确定后端 backend+0x3D00 有没有直接读取者，本轮离线扫描两机原始 X6 Section1+Section2 中以下**受限的 A32 模式**：

- 指令先执行 ADD Rn,Rm,#0x3000；
- 之后 35 条指令内按相同基址寄存器、立即数 #0xD00 执行 LDR 或 STR；
- 计算位置可能是某结构的 +0x3D00，但不假设所有这种命中都是同一后端对象。

结果（仅此寻址模式）：

| 原始镜像范围 | 直接 READ 模式候选 | WRITE 模式候选 |
|---|---:|---:|
| X-S10 Section1 | 0 | 0 |
| X-S10 Section2 | **0** | 2 |
| X-T4 Section1 | 0 | 0 |
| X-T4 Section2 | **0** | 2 |

两机各有一个 WRITE 正是本阶段原厂 152B 登记器。另一组 WRITE 位于无关函数区域，**不能直接判为同一 backend 实例写入**。

**此筛查不完备**：真实消费者可能通过另一种寻址序列、偏移运算、指针转移、整块复制、跨模块/跨处理器数据交换或未加载镜像访问该槽。没有匹配的此类 LDR，**不能推论没有任何读取者，更不能说没有 H.265/Main10 硬件**。

## 六、GUI 初始源头和硬件功能，仍然缺失的证据

此前第32阶段已证明：
- 当前 Recorder 输入配置 +0x5B0/+0x5B1 → 中间结构 → Recorder 活跃 Codec/Format。

第33阶段已证明：
- 活跃 Codec/Format 在录像上下文的相对位置为 X-S10 +0x9D8/+0x9D9 和 X-T4 +0x9DC/+0x9DD；
- 若 Codec 配置字节为 1，输出一个 0x10004 字；其他字节值输出 0x10005；Format 的静态代码分支能选择 MOV/MP4 字符串。

本阶段新证明：
- **持有 0x10004/0x10005 的参数结构指针，被传到后端对象**。

仍不能证明：
1. GUI MovieCodec 设置服务如何**首次把值赋给 Recorder 输入配置 +0x5B0**。
2. 哪一个函数最后读取 backend+0x3D00 并解释参数块 +0x220；两整数真正的编码器/封装语义仍为 UNKNOWN。
3. 外部驱动/VPU 对应字段的含义，录制时到底经过什么 Profile/Main10/位深配置。
4. 真正的机内 HEVC Main10 SPS/bitdepth、传感器 4K60 读取/ISP/VPU/稳定码率和文件写卡链。
5. 上述静态条件分支在用户相机上实际执行，及其运行时字节的取值。

因此**没有**相机刷写、固件解锁或实际 H.265 10-bit/4K60 录制主张。

## 七、工具、隔离与回归

新增原创公开文件：

- **tools/audit_movie_codec_backend_pointer_stage34.py**：对两机原厂 Section2、只读 Ghidra C 和第33阶段审计基线交叉核验。每机检查 **14 条后端寄存器/指针相关原厂 A32 字、1 条 Codec LDRB、2 条主入口 BL**，以及**完整 152 字节函数 SHA-256 相同**，检查源指针身份、写入顺序、子模式条件、ctx 和 backend 的多个指针槽位。缺失硬件证据明示 False 或 UNKNOWN。
- **tests/test_audit_movie_codec_backend_pointer_stage34.py**：**65 项纯合成正反测试**，涵盖所有14条寄存器/指针 A32 原始机器字逐条损坏、错误跳转、偏移、分支条件、指针别名、静态调用顺序、跨机型 ABI/完整函数指纹不一致以及过度推断。没有厂商原始 ROM 数据。

私有材料仅留 Ubuntu 被 Git 忽略的 output/：双机 stage34_post_builder_pipeline、stage34_input_descriptor_and_ptr_forward_xrefs、stage34_downstream_pointer_offset_candidates、stage34_downstream_d00_reads 等只读 Ghidra 日志，以及 stage34_backend_pointer_audit_result.jsonlog、stage34_backend_pointer_d00_bounded_screen.log。

本地已执行：

~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/audit_movie_codec_backend_pointer_stage34.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

**结果：第26—34阶段全部原厂离线审计 PASS，65 项阶段34测试 PASS；仓库测试91项 + 本地忽略研究测试674项 = 累计765项 PASS。** 所有测试使用模拟数据、没有下发相机 USB/FF80 命令。

## 八、第35阶段重点

1. 从 **backend +0x3D00** 指针槽反向搜后端消费函数，特别考虑跨模块消息表、回调、其他固件镜像或来自动态对象的偏移间接访问。
2. 明确 **main +0x3A18** 的两个选择值如何映射实际编码器 API、Profile/Level/bit-depth。
3. 继续寻找 GUI MovieCodec → Recorder 当前输入结构 +0x5B0 的**初始生产者**，尤其是基于 0x200 动态模式描述符的装载/恢复路径。
4. 完成前述证据前，严格保持离线只读，无补丁/刷写建议、无“已解锁”结论。
