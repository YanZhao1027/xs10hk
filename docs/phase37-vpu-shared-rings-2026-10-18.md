# 第37阶段：VPU共享环形队列内存基址、发送接收方向、0xBB9消息边界（2026-10-18）

> 核心成果：对原厂 X-S10 3.11 与 X-T4 2.12 的 ARM 和 Ghidra 只读审计，已从第36阶段的位深控制/72字节帧描述符继续追到 **7个连续4KiB共享页**，其中有两对不同的CPU侧TX/RX环形队列；原厂代码对0x7000字节进行初始化，包中每个共享页地址都由相同工作内存基址W计算。第一组TX含帧描述符消息0xBB9，独立的RX侧由原厂响应分派函数读取，含0x7D5分支。**没有发现另一核对0xBB9真正执行消费的代码；不能推断Main10、10-bit、4K60已经启用或解锁。**

## 研究范围与限制

用户授权 Ubuntu 项目为 /home/zyubuntu/xs10hk。本阶段只读使用原厂 X-S10 **3.11** / X-T4 **2.12** X6 section-1/2，Ghidra 12.1.4 headless、-noanalysis -readOnly。用户报告的**实机X-S10是2.10**，不得套用3.11地址到实机。没有相机操作、USB/FF80命令、机身RAM或Flash访问、DAT编辑、打补丁、绕签名、生成可刷固件。原厂ROM和所有私有日志均留在Git忽略的 output/，仅原创审计代码、纯合成测试和本报告可以上传。

“确认”只针对静态固件指令、已加载Ghidra数据库中可追踪的引用；不等于真实运行、硬件VPU成功读取、Main10码流生成。

## 1. 从 Recorder Codec 到共享内存的新位置

第35阶段已证实：Recorder活跃Codec字节，经MovieContext+0xADDA流入VPU init video_codec +0x188，且已定位电影初始化函数向bit_depth +0x0C写内部枚举1。第36阶段已证实：VPU驱动将缓存video_codec、bit_depth传入0x298字节的初始化数据块；块的+0x0C为有条件归一化位深、+0x190为codec。帧描述符构造器对参数块+0x0C做0/非0判断，往72字节描述符+0x18写入0x201或0x121；两机完整204字节函数的39条机器指令相同，另外12条仅地址常量不同。

**本阶段延伸**：VPU初始化参数包的运行时字段+0x18还承载工作内存基址W，CPU驱动用它建立内存队列布局，把72字节的帧描述符放入软件共享环形TX队列。

## 2. 工作内存W：不要把静态指针槽当动态地址

| 项目 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 驱动私有缓存基址 | 0x01C25970 | 0x01B840D8 |
| 缓存中的W字段 +0x18 | 0x01C25988 | 0x01B840F0 |
| 动态VPU初始化参数包指针槽 | 0x01C8573C | 0x01BE5808 |
| 初始化包构造函数 | FUN_011F8460 | FUN_011CBB0C |
| 工作内存布局函数 | **FUN_011FB93C** | **FUN_011CEFE8** |
| 读取包+0x18中W的原厂LDR | **0x011FB954** | **0x011CF000** |

静态语义：P是动态参数包指针，W = *(uint32_t*)(P+0x18)。P本身是从对应的静态全局指针槽间接读取的，**W的实际运行时地址未知**。ARM机器字0xE5923018两机相同。包构造代码明确将私有缓存 +0x18 复制到P+0x18。

## 3. 完整七段共享内存布局

| 参数包内部字段 | 值（相对W） | 本次找到的作用 |
|---|---|---|
| +0x1AC | W + 0x90000 | 七段清零区域起点 |
| +0x1B0 | W + 0x91000 | 辅助共享页，具体消费者待核实 |
| **+0x1B4** | **W + 0x92000** | 第一组CPU-TX索引头 |
| **+0x1B8** | **W + 0x93000** | 第一组CPU-RX索引头 |
| **+0x1BC** | **W + 0x94000** | 第二组CPU-TX索引头 |
| **+0x1C0** | **W + 0x95000** | 第二组CPU-RX索引头 |
| +0x1C4 | W + 0x96000 | 额外共享页，具体用途待确认 |

已逐条复算原始ARM旋转立即数和内存写入字段：

- X-S10：0x011FB97C—0x011FB9B3，7对ADD/STR共14个机器字。
- X-T4：0x011CF028—0x011CF05F，同样7对ADD/STR，**14条机器字逐个完全一致**。
- 对 W+0x90000 开始清零 0x7000 字节：XS10原始 BL 0x011FBC9C → FUN_011FCB5C；XT4 0x011CF348 → FUN_011D0208；核验实有LDR来源包+0x1AC、MOV R2,#0x7000、MOV R1,#0和BL编码。

原厂TX/RX的环形索引按 **0x3FC个u32** 取模，消息数据相对各队列头 **+0x10** 开始：
0x10 + 0x3FC × 4 = **0x1000字节/页**；全部清零0x7000 = 7 × 0x1000。两机的记录格式高度对称，但没有证明每个被清零的共享页都有一个完成识别的消费函数。

## 4. 两机的TX与RX是不同页面、不同全局指针槽

| 软件方向 | 参数包字段 | X-S10索引指针槽 → 数据指针槽 | X-T4索引指针槽 → 数据指针槽 |
|---|---|---|---|
| 第一组TX | +0x1B4 | 0x019E6880 → **0x01C7B720** | 0x019567B0 → **0x01BDBAB0** |
| 第一组RX | +0x1B8 | 0x01C62850 → **0x01B53D38** | 0x01BC2230 → **0x01ABDD74** |
| 第二组TX | +0x1BC | 0x01B4A104 → **0x01ADD918** | 0x01AB2104 → **0x01A44C18** |
| 第二组RX | +0x1C0 | 0x01B4C47C → **0x019E33E4** | 0x01AB63AC → **0x01953324** |

所有表中列出的“指针槽”都是静态ARM会写的内存位置，**不等于指针槽所保存的共享页动态地址**。每个数据指针槽的值等于对应索引头指针值 +0x10。已交叉核对MOVW/MOVT构造的实际地址、LDR包字段、原始STR以及ADD +0x10数据起点。

四个索引指针槽STR：
- XS10：0x011FBCF4、0x011FBD04、0x011FBD14、0x011FBD24。
- XT4：0x011CF3A0、0x011CF3B0、0x011CF3C0、0x011CF3D0。

四个数据指针槽的ADD +0x10和STR：
- XS10：0x011FBD64、0x011FBD74、0x011FBD84、0x011FBD94。
- XT4：0x011CF410、0x011CF420、0x011CF430、0x011CF440。

## 5. 0xBB9: CPU发送者先编码命令和长度，再写环形TX数据

| 项目 | X-S10 | X-T4 |
|---|---|---|
| 第一组CPU TX写队列 | FUN_011FA714 | FUN_011CDDC0 |
| 第二组CPU TX写队列 | FUN_011FA844 | FUN_011CDEF0 |
| 携带帧缓冲描述符的上游函数 | FUN_011FAC24 | FUN_011CE2D0 |
| 帧消息0xBB9的两条MOVW | 0x011FAD74 / 0x011FAF20 | 0x011CE420 / 0x011CE5CC |
| 帧消息数据长度 | **0x48 = 72字节** | 同左 |

软件队列的第一个32位消息头为 **(payload_bytes << 16) | command_id**，后续按32位复制payload；索引+2对应TX写侧halfword，环形位置按0x3FC循环。接收侧操作另一独立页面，读取本地RX索引、使用消息头高16位取得载荷长度，不是读取刚写的同一TX数据页。

严格有界扫描Section1/2中对齐的无条件A32 MOVW立即数0xBB9：两个机型Section1都4条候选（两条在上面帧消息函数中）；Section2均0条。其余两处 XS10 0x01085F8C、0x0109EE44，XT4 0x01084CB4、0x0109D310，在已载入Ghidra项目中没有识别到所属函数。**这不是穷尽所有消费者的证据**：接收者可使用其它加载方式、其他CPU、微码、硬件DMA或尚未加载的映像。

## 6. CPU端两组RX与VPU响应处理

| 功能 | X-S10 | X-T4 |
|---|---|---|
| 第一组CPU-RX出队 | **FUN_011FA974** | **FUN_011CE020** |
| 第二组CPU-RX出队 | **FUN_011FAA68** | **FUN_011CE114** |
| CPU响应分派函数 | **FUN_011FCBC4** | **FUN_011D0270** |
| 原厂响应代码分支 | **0x7D5** | **0x7D5** |
| 原厂字符串 | VPU_H265_RSP_CODE_INPUT | 同左 |
| 第一组RX两个原始BL | 0x011FD6D4 / 0x011FD6FC | 0x011D0D80 / 0x011D0DA8 |
| 第二组RX两个原始BL | 0x011FD22C / 0x011FD3A0 | 0x011D08D8 / 0x011D0A4C |

每机四条响应调用边经原始ARM BL相对位移核实。0x7D5分支确实调用CPU侧RX出队函数；但**0xBB9与0x7D5是否属于同一请求响应对，尚未证明**。0xBB9的另一处理器侧消费者仍没有被定位到，也没有真实VPU成功接受描述符或返回视频编码位深证据。

## 7. bit_depth其他赋值者：只核实有界直接引用

| 项目 | X-S10 | X-T4 |
|---|---|---|
| Movie VPU输入bit_depth字段 | 0x02945A14 | 0x028A515C |
| 当前Ghidra唯一直接WRITE引用 | 0x022DEF50 | 0x0224B748 |
| VPU驱动缓存bit_depth字段 | 0x01C2597C | 0x01B840E4 |
| 缓存字段已加载Ghidra直接引用数 | 1条 READ | 1条 READ |
| VPU动态API包装器引用 | 2处，包含COMPUTED_JUMP | 2处，包含COMPUTED_JUMP |

这些只是已经加载的Ghidra直接交叉引用的数量，不排除指针别名、400字节原厂结构拷贝、其它运行时调用或另一个处理器的写入。因此，**不能宣称除了Stage35常数1外，其他bit_depth值不可达**，也不能因为驱动有0x201分支就认为0x201=10-bit。

GUI MovieCodec → Recorder输入+0x5B0第一次赋值的生产者依旧未知；0x201/0x121映射到真实硬件像素格式仍未知；Main10 SPS/hvcC、机身实际成功编码、4K60持续录制均未证明。

## 8. 审计产物、测试和复现

原创且不含厂商代码/图像/固件的待公开文件：

- tools/audit_vpu_ring_memory_stage37.py —— 只读X6 Section1/2、Stage36审计结果及本地Ghidra C/xrefs；逐机核验7对内存页ADD/STR、0x7000清零BL、4组index全局槽和+0x10数据槽、TX与RX不同页面、0x3FC字循环、0xBB9消息头、0x7D5响应分支、4条CPU RX调用BL及bit_depth有界xrefs；核验两机14条原厂ARM字完全相同。所有硬件/ Main10 /4K60结论仍为UNKNOWN/False。
- tests/test_audit_vpu_ring_memory_stage37.py —— **115项纯合成正反测试**，使用自造ARM A32编码，反例覆盖错误队列页、错误索引、TX/RX别名、0xBB9命令、0x7D5响应分支、ARM指令逐字改写、错误bit_depth证明及不得声称硬件已接收。无原厂二进制。
- docs/phase37-vpu-shared-rings-2026-10-18.md —— 本报告。

私有数据只在Git忽略的 Ubuntu output/：两机所有 stage37_ring_init_reader_cand_decomp、stage37_workmem_ring_layout_arm、stage37_ring_rx_reader_refs、stage37_ring_host_irq_dispatch、stage37_bitdepth_altwriter_and_rx_refs、stage37_bbb9_raw_other_callers 原厂Ghidra日志，stage37_vpu_ring_memory_audit.jsonlog，以及历史阶段的ROM和私有数据库。

复验（依赖本机私有X6 Sections和既有Ghidra日志）：

~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/audit_vpu_ring_memory_stage37.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

**本轮实测**：Stage37两机原厂只读审计通过、Phase26—37共12阶段双机离线审计通过；Stage37独立public-only布局115项合成测试通过；仓库追踪测试91项 + 本地忽略研究测试974项 = **1065项离线测试通过**。原项目FF80测试只报告服务未发现，No command sent，完全未操作真实相机。本地main工作树无改变。

## 9. 下一阶段（Stage38）精准方向

1. 找出真正消费W+0x92010 / W+0x94010 TX队列的 VPU/其它核固件，若当前X6未提供则诚实标记缺失，不补猜。
2. 查明硬件侧如何解码0xBB9内72B帧描述符的+0x18（0x121/0x201）及其真实像素格式，只有获得独立原厂定义或码流位深证据才能连接Main10。
3. 继续离线找VPU init bit_depth除已见常数1外的真实生产者（间接赋值和模式服务），同时反查GUI MovieCodec → Recorder初始输入+0x5B0；不修改设备和固件。
4. 4K60的传感器、ISP、VPU和持续录制链仍必须分开验证。

**第37阶段结论：已定位并验证两机共享消息队列的布局、CPU端TX/RX与响应分派，未打通外部VPU端实际消费，也未证明或解锁内录Main10/4K60。**
