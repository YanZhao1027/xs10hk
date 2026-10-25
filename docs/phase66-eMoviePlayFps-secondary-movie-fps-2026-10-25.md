# 第66阶段：独立的 eMoviePlayFps 真实来源 → Movie+0x5C7 与高速类别选择（2026-10-25）

## 核心结果

**问题一（之前未闭合）：Movie运行对象`+0x5C7`到底从哪里来？现在已经用原厂X-S10 FW3.11 / X-T4 FW2.12的ARM与只读Ghidra定位。** 它不是把`eMovieFps`随便复制两遍，而是另一独立的、原厂日志直接命名的配置：**`eMoviePlayFps`**。在第58、64、65阶段所证实的配置传输**成立的前提下**，链路如下：

~~~text
GUI eMoviePlayFps setter, GUI+0x6F （原厂字段名已核验）
  → [第58阶段条件式GUI→独立type0x200 Recorder输入P的全结构传送]
Recorder P[+0x6F]
  → 第32/64阶段转换器的原厂相邻LDRB/STRB → 中间模板+0x1F
  → 第32阶段活动Recorder模板全结构复制 → 活动模板+0x1F
  → 第65阶段Movie初始化全结构复制到Movie+0x5A8
  → Movie+0x5A8+0x1F = **Movie+0x5C7**
  → 类别1/2的原厂96×0x40联合模式查表读取该字段
~~

同一模板的`+0x1E`则是另一项**`eMovieFps`普通录像帧率**，进入Movie+`0x5C6`，给类别0使用。两项GUI RAM相邻但 setter、读取设置服务的ID、来源和Movie查表类别均不同；直接把+0x5C7等同+0x5C6是错误的。真实设备队列投递、状态事件、运行时最后覆盖顺序和硬件录制仍未实测。

## 双机精确原始证据

| 可复验原厂源/目标 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 普通GUI `eMovieFps`+0x6E | `0x01B8810E` | `0x01AF2876` |
| **播放GUI `eMoviePlayFps`+0x6F** | **`0x01B8810F`** | **`0x01AF2877`** |
| GUI播放FPS setter | `FUN_01153D74` | `FUN_0112844C` |
| setter的真实ARM `STRB` | `0x01153DD0`, `E5C3406F` | `0x011284A8`, 同机器字 |
| 播放FPS配置加载器 | `FUN_011769D4` | `FUN_0114A8C8` |
| 读取配置服务的播放FPS ID | **`0x3F7`** | **`0x3E0`** |
| 加载器另一个输入ID | `0x403` | `0x3EC` |
| 加载器条件切换ID | `0x400` | `0x3E9` |
| 用来验证播放FPS候选的**普通 FPS ROM允许性**ID | `0x3F6` | `0x3DF` |
| 原始加载器直接BL到setter（各3次） | `0x01176A6C / 0x01176A8C / 0x01176A98` | `0x0114A960 / 0x0114A980 / 0x0114A98C` |
| 源P `+0x6F` 的原始 `LDRB` | `0x012C95A4`, `E5D5306F` | `0x012A31E0`, 同机器字 |
| 中间`+0x1F`相邻`STRB` | `0x012C95A8`, `E5C4301F` | `0x012A31E4`, 同机器字 |
| 原始独立活动播放FPS RAM | `0x01C24DF7` | `0x01B8355F` |
| 活动播放FPS getter | `FUN_012BD590` | `FUN_01295C04` |
| getter原厂 `LDRB ...,#0x1F` | `0x012BD5A0` | `0x01295C14` |
| 最终Movie的播放FPS字段 | `Movie+0x5C7` | 同左 |

两个原厂setter的字符串引用均明确为`$INPUT eMoviePlayFps`；Ghidra直接 RAM xref显示GUI+0x6F各11个引用/直接setter写1次，活动模板+0x1F各2个直接引用。**这种有限直接引用不能证明不存在间接写者**。原厂加载器取播放FPS配置ID、另行按电影模式`0x2D`和**普通FPS**ID验证候选；失败时用普通FPS允许表默认值回退，另有设置条件选择第二输入ID及某状态强制赋值4。换句话说，“独立设置”不等于完全独立的合法枚举范围和持久运行态。

## 为什么视频类别决定是否用播放FPS

两机原厂高速类别分类器 `FUN_022D171C` / `FUN_0223DCAC`：影片类型`1/4/5/6/7`返回0；类型`2/3`返回1。**在首次有效Movie配置初始化条件下**，Movie类型2→帧类别1、类型3→帧类别2，其它上述类型→帧类别0。真正的联合查表函数`FUN_022E123C` / `FUN_0224DB10`只在类别1或2时读Movie+0x5C7；类别0从Movie+0x5C6读普通FPS。另一个 Movie模式参数构造器还根据高速类型分类结果选择普通/播放活动FPS getter，构成独立交叉证据。

注意最初写Movie运行时`+0x5F5`类别有`first frame/context index==0`门控，**不能宣称每次事件均重新分类**，也不能据此宣称类型2/3允许任何特定传感器FPS。原厂第46阶段2160P/FPS6静态六条候选皆为类别0，**并不通过播放FPS+0x5C7来匹配**。第67阶段继续把这六条记录的四项GUI键一一连回真正源字段。

## 复验、边界与安全

`tools/audit_stage66_playback_fps_movie_secondary.py`在第65阶段及更早全部SHA固定原厂ROM审计通过后核实GUI setter与配置加载器、ARM三次BL、P+6F→中间+1F、活动模板 getter、Movie分类器及原始直接xref；`tests/test_audit_stage66_playback_fps_movie_secondary.py`新增**71项纯人工合成A32/模拟参数和故意损坏映射测试**。本机原厂审计已经独立PASS，厂商原始Section1/2、完整Ghidra工程/日志、硬件微码都保存在授权Ubuntu Git忽略`output/`内，不上传。

实体X-S10之前报告FW2.10，静态研究样本为FW3.11（XT4 FW2.12），地址不能直接移植。**未连接相机、无USB/FF80、无机身RAM/Flash操作、无ROM/DAT修改、补丁、签名绕过和刷写**。未获得HEVC Main10 SPS、4K60稳定内录文件及传感器/ISP/VPU接受证据。