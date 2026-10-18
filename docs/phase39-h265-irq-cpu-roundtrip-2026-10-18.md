# 第39阶段：V61 H.265中断注册 → 状态位清除 → CPU事件通知 → VpuReceive任务 → 响应分派（2026-10-18）

> **本阶段突破：** 从Stage38两机的软件队列发送+控制寄存器写1，向另一个方向追到**原厂显式注册的CPU中断回调**，并完整连接该回调的MMIO状态位检测、清除、事件通知、CPU端VpuReceive任务等待与CPU响应分派。X-S10 3.11和X-T4 2.12的ARM字、函数调用BL、Ghidra原厂反编译数据流一致。这是**双方向CPU驱动控制流程**的证据，不是另一核硬件消费0x0BB9请求的证据。
>
> **修订Stage38未知点：** 编码初始化和解码初始化两条原厂ARM路径均先把当前channel标量写为0，再调用h265_MapSession。故对这些路径**若后续无中途改写**，控制区对+0x220写1的地址为 **0xFFE00220**。仍不得将此写成所有运行时通道永远为0或机身硬件已收到通知。
>
> **新增软件响应反馈：** CPU侧收到0x7D8分支，且运行态状态槽[0xC]等于1时，调用帧消息发送器发起下一帧。只证明CPU分支和BL调用，**不证明0x7D8就是0x0BB9的一一对应回包，更不证明HEVC Main10编码成功**。

## 0. 范围和绝对安全边界

- 只研究授权Ubuntu /home/zyubuntu/xs10hk 上已存在、未修改的 **X-S10原厂3.11与X-T4原厂2.12** X6 Sections1—4，以及本地Ghidra 12.1.4只读项目。用户之前报告的实体X-S10固件为**2.10**，本阶段全部地址均与该实机版本不直接对应。
- 没有物理相机、USB、FF80、机身内存、Flash或SD写入行为；没有修改原厂DAT、解压段、ROM/Ghidra数据库、没有改固件、做patch、刷机或生成可刷固件。
- 原厂Fuji固件二进制及Ghidra只读分析日志和临时项目均在Git忽略output/，永远不上传。Draft PR中仅原创Python验证器、纯合成测试、原创报告。
- 文中“确认”仅限静态ROM的原始A32指令及Ghidra中可还原的CPU端数据流和控制流。硬件没有实际执行、没有抓到VPU输出的编码视频、SPS或hvcC；Bit-depth、Main10、4K60能力仍不可推断。

## 1. Stage35—39的静态范围边界

~~~text
Movie Codec→Recorder active Codec→MovieContext+0xADDA
   → VPU init.video_codec+0x188; bit_depth+0x0C
   → 原厂初始化/工作内存布局W
   → 72B帧描述符（+0x18=0x201 或 0x121，物理像素格式未知）
   → CPU TX环形队列W+0x92000/W+0x94000
      0x0BB9消息，72B有效载荷；CPU index更新
   → CPU写 *(u32*)(0xFFE00000 + channel*0x40 + 0x220)=1
        编码/解码setup路径中channel首先置0
   ┊  【真正VPU/其它核：消息如何消费、注册定义、
   ┊    是否接收0x0BB9、哪些像素格式/位深：未知】
   → CPU中断注册ID 0xDEF00001，回调handler
      检查寄存器组0xFFE00000+0x18的bit0
      若不置位则直接返回
      若置位则STR 0到0xFFE00000+0x21C
      向已创建的CPU事件对象发送通知
   → VpuReceive CPU任务等待同一个事件对象
      收到后调用CPU响应分派函数
   → 软件RX队列W+0x93000/W+0x95000读取应答
      0x7D5：取Input相关的RX数据
      0x7D8：状态槽[0xC]==1才调用下一帧0xBB9发送例程
   ┊  【实机ISR触发/成功编码、SPS/Main10、4K60仍未知】
~~~

虚线表示**尚未找到的硬件/VPU一侧**，不可将两个CPU端路径连成已证实的实际硬件往返。

## 2. 两机一致的中断注册：ID 0xDEF00001、原厂回调地址

| 原厂固件证据 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| H.265初始化函数 | FUN_011F8460 | FUN_011CBB0C |
| 初始化/注册事件标识 | **0xDEF00001** | **0xDEF00001** |
| 初始化中断服务调用 | FUN_011FE398 | FUN_011D1A44 |
| 注册回调的API调用 | FUN_011FE340 | FUN_011D19EC |
| 被注册的回调入口 | **0x011F977C** | **0x011CCE28** |
| 构造完整回调地址MOVW/MOVT | 0x011F888C / 0x011F8890 | 0x011CBF38 / 0x011CBF3C |
| 原厂最终注册BL | **0x011F8898** | **0x011CBF44** |

两机原厂Ghidra C含完全对应的数据流：

~~~c
// XS10: FUN_011F8460（X-T4仅函数地址不同）
FUN_011FE398(0xDEF00001);
iVar6 = FUN_011FE340(0xDEF00001, &LAB_011F977C);
// register 失败分支记录interrupt_error
~~~

BL原厂32bit相对立即数字验：X-S10注册BL 0xEB0016A8 → FUN_011FE340，X-T4注册BL相同相对机器字 → FUN_011D19EC；登记回调地址经R1 MOVW/MOVT全32bit复原，不能只根据日志里有“interrupt”字样作推断。

对Section1—4原始字节分别做有界、对齐且无条件的A32 MOVW/MOVT相邻组合扫描：每机**Section1唯一**一对构造该回调地址，另外Section2/3/4没有同样的直接成对立即数。**这只是有界直接加载验证，不是全程序CFG或指针别名穷举。**

## 3. 找到过去Ghidra未自动识别的回调函数，独立完成反编译

这里是关键新证据。回调目标在原本Ghidra工程中没有被标成普通函数，但原始ARM确实存在对齐代码。单独在**只读、暂存（不保存）**的Ghidra处理事务里对这两个入口反汇编并临时创建函数，Ghidra都成功反编译为相同控制流。

| 回调要点 | X-S10原厂地址 | X-T4原厂地址 | 相同原始A32 |
|---|---|---|---|
| 函数入口MOVW/MOVT载入控制base槽 | 0x011F977C/+4 | 0x011CCE28/+4 | 机型相关 |
| 读取base全局槽的当前指针 | +0x08 | +0x08 | E5933000 |
| **LDR控制区+0x18** | **0x011F9788** | **0x011CCE34** | E5932018 |
| **TST bit0** | 0x011F978C | 0x011CCE38 | E3120001 |
| **BXEQ LR**（若未置位直接返回） | 0x011F9790 | 0x011CCE3C | 012FFF1E |
| 原厂MOV R2,#0 | 0x011F979C | 0x011CCE48 | E3A02000 |
| **STR R2到base+0x21C** | **0x011F97A0** | **0x011CCE4C** | E583221C |
| 构造CPU事件对象全局槽 | 0x011F97A4/+4 | 0x011CCE50/+4 | 机型相关 |
| LDR事件句柄 | 0x011F97AC | 0x011CCE58 | E5930000 |
| **BL CPU事件通知函数** | **0x011F97B0** | **0x011CCE5C** | EB0013E1 |

两机暂存Ghidra C的中心逻辑：

~~~c
void h265_interrupt_handler_candidate(void) {
    if ((*(uint32_t *)(CONTROL_BASE + 0x18) & 1) == 0)
        return;
    *(uint32_t *)(CONTROL_BASE + 0x21C) = 0;
    status = post_event(CPU_VpuReceive_event_handle);
    if (status != 0)
        log_error("h265Int_Handler_err");
}
~~~

这里“post_event”是**根据同一RTOS对象与wait路径推断的语义名**，原厂API函数并没有官方文档函数名；原厂只是API调用及对应H.265 debug标签。可以确认读取最低位、条件返回、清0x21C、传入事件句柄调用；**不能声称观察到实机IRQ或知道芯片中断控制器寄存器定义**。

两机回调入口在Stage37/38默认Ghidra项目中没有通常的函数xref：本阶段不仅从ROM字扫描找到指针MOVW/MOVT，还在VPU初始化函数中找到其作为中断注册参数的真实传递。暂存Ghidra内存不会变更原始二进制、导入项目或机身固件。

## 4. ISR发出的事件确实与CPU VpuReceive任务等待的是同一个句柄

| 事件和工作线程证据 | X-S10 | X-T4 |
|---|---|---|
| RTOS事件句柄的全局槽 | **0x01821950** | **0x01790D60** |
| 事件句柄创建函数 | FUN_011F7C8C | FUN_011CB338 |
| 创建RTOS对象调用 | FUN_011FE71C(0,1,1,0x14) | FUN_011D1DC8(0,1,1,0x14) |
| 创建对象BL | 0x011F7CA4 | 0x011CB350 |
| 成功后保存句柄的条件STRGT | **0x011F7CB4** | **0x011CB360** |
| VpuReceive任务登记者 | FUN_011F7C14 | FUN_011CB2C0 |
| 真正的任务入口 | **FUN_011F7D4C** | **FUN_011CB3F8** |
| 循环等待事件的RTOS函数 | FUN_011FE74C | FUN_011D1DF8 |
| 对应原始ARM等待BL | 0x011F7E40 | 0x011CB4EC |
| 接受通知后CPU响应分派调用BL | **0x011F7E6C** | **0x011CB518** |
| CPU响应分派函数 | FUN_011FCBC4 | FUN_011D0270 |

原厂Ghidra C分别证明：
- 创建服务返回正值后，将该值保存到每机对应的事件句柄全局槽。
- 注册的CPU工作任务名字为**VpuReceive**，入口为表中任务函数。
- ISR的事件通知API读取该事件槽并作为参数。
- VpuReceive任务执行无期限等待函数（参数0xFFFFFFFF），使用**同一个事件槽**；随后进入包含0x7D5等响应代码的CPU分派器。
- 两机 ISR→post、任务wait→dispatch各两条软件调用边均经原厂A32直接BL回算核实；响应任务还存在互斥/锁服务调用的同一个0xDEF00001标识，但其系统层具体语义需另外确认。

这建立了**CPU-side ISR事件对象→CPU处理线程→CPU响应函数**可审核链条，不再只是根据字符串猜测哪一个task读取响应队列。

## 5. 编码、解码初始化都写channel=0：收敛计算地址但不假设永久固定

| 软件路径 | XS10 | XT4 |
|---|---|---|
| 编码参数初始化 | FUN_011F8914 | FUN_011CBFC0 |
| encoder当前channel写零原始ARM | **0x011F893C** | **0x011CBFE8** |
| encoder随后MapSession BL | 0x011F8978 | 0x011CC024 |
| 解码参数初始化 | FUN_011F89F0 | FUN_011CC09C |
| decoder当前channel写零ARM | **0x011F8A18** | **0x011CC0C4** |
| decoder随后MapSession BL | 0x011F8A30 | 0x011CC0DC |

两机每一路都经原厂MOVW/MOVT生成channel全局槽地址、LDR取得实际RAM标量地址、MOV R1,#0、STR R1,[R2]、后面BL到对应MapSession。Ghidra同时反编译出先把channel设0再进入MapSession的语句。

结合Stage38确认的通知公式：

~~~text
固定base 0xFFE00000 + (该路径设置的channel=0) ×0x40 + 0x220
= 0xFFE00220
~~~

**限制：** 所有结论都是静态软件路径且需要没有其它并发/异步代码改变该共享标量；这不代表所有模式永久使用channel0，尤其也没有实际读过机身channel RAM的值。Stage38称其“运行时未知”是全局范围结论，本阶段仅针对编码/解码setup更精确。

## 6. CPU分派的0x7D5和0x7D8软件反馈闭环

VpuReceive等待后调用的分派器：
- 收到消息码 **0x7D5**，进入输入消息分支，并调用XS10 FUN_011FA974 / XT4 FUN_011CE020，从第一组**CPU-RX软件队列**读取响应数据（而非直接回读CPU-TX发送的0xBB9队列页）。
- 收到消息码 **0x7D8**，在运行态通道结构的**槽[0xC]等于1**时，进入下一帧分支：XS10在原始BL **0x011FD894** 调用帧发送FUN_011FAC24；XT4在原始BL **0x011D0F40** 调用FUN_011CE2D0。该函数是Stage37已证实携带**0x0BB9 / 72B**描述符的软件发送者。原始BL回算及Ghidra xref都已核实。

这证明CPU源码存在**接收特定软件响应后继续发送下一帧**的可能分支，不证明另一核真的发送过0x7D8、该事件与0xBB9是一一请求响应对、该帧属于10bit，更不证明实机循环无误。

## 7. 仍未突破的硬件和编码能力证据

1. **缺真正VPU/另核0xBB9接收函数/专有指令解码和官方手册。** 0xDEF00001注册在CPU服务内、ISR源码存在，也不等于芯片实际触发过中断、VPU固件消费者真的读取W+0x92010。
2. 0xFFE00000一组寄存器中，+0x220通知样操作、+0x18状态位、+0x21C清零操作已证实为CPU侧软件指令，但**寄存器确切的芯片官方含义、IRQ routing和实际返回状态未知**。
3. 0x121/0x201帧描述符+0x18值及内部bit_depth enum仍不能映射真实像素格式、P010/NV12、SPS profile或bit_depth_luma_minus8；**未证实HEVC Main10/真正内录10-bit**。
4. GUI MovieCodec→Recorder最初输入+0x5B0的值来源仍未知。
5. 未证实X-S10的传感器、ISP、编码器/存储及温度资源具备**4K60持续内录**。绝不声称解锁或建议将当前地址用于不同版本实体机。

## 8. 原创离线审计、纯合成回归和可复现性

拟纳入独立Draft PR、叠加在Stage38分支：
- tools/audit_stage39_h265_irq_callback.py — 原厂Section1精确尺寸和SHA256、原厂Sections1—4有界ARM callback-pair扫描、V61参数初始化中断注册ID+BL、回调入口A32及只读Ghidra临时函数、event create/handle、VpuReceive任务wait/dispatch、0x7D5/0x7D8分别核对、两机编码/解码channel=0以及Stage37/38“不证明真实硬件”边界。
- tests/test_audit_stage39_h265_irq_callback.py — **145项纯合成正反测试**，编码的全部ARM字与原厂数据独立、不包含任何厂商内容，逐字变异回调、唤醒链、通道复位、响应码条件、错误地址及越界等。
- docs/phase39-h265-irq-cpu-roundtrip-2026-10-18.md — 本报告。

本机的私有证据包括：
- output/xs10_stage39_h265_isr_registration_c.log / xt4同名；
- output/xs10_stage39_isr_candidate_independent_ghidra.log / xt4同名；
- output/xs10_stage39_irq_event_create_and_signal.log / xt4同名；
- output/xs10_stage39_vpu_interrupt_outer_dispatch_parent.log / xt4同名；
- output/xs10_stage39_mmio_status_router_c.log / xt4同名；
- output/xs10_stage39_frame_response_loop_callrefs.log / xt4同名；
- output/stage39_h265_irq_callback_original_audit.jsonlog。

两机Section1原厂SHA256：
- X-S10 3.11：c86c9446a15a39e6e761c4ca96383e943cdb3a09cab6e609b85b3e48f3e91aff
- X-T4 2.12：0b5b0fb0ee5fe6b109dae9964b5cddfe18edab46b4a0c195f9da194448906eeb

本机只读验证：
~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/audit_stage39_h265_irq_callback.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

**实测**：Stage39双机原厂审核PASS；从Stage26到39全部原厂审核PASS；Stage39全新**145项合成测试**在独立public-only目录PASS；仓库追踪91项 + 本机研究1285项 = **1376项自动化离线测试全部通过**（本机原有FF80检查只打印No command sent，未操作USB/设备）。本地main仍然clean，原厂固件仍不上传。

**结论：本阶段成功由IRQ注册函数逐字追到CPU H.265回调，连接状态位+0x18、清除+0x21C、RTOS事件通知和VpuReceive CPU响应分派，新增channel=0静态值及0x7D8条件帧续送。离硬件VPU实际消费和Main10/4K60证明仍有明确缺口。**
