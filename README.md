# X-S10 Firmware Research / X-S10 固件研究

研究目标：评估富士 X-S10 的 **4K30 10-bit 机内录制** 和 **4K60** 是否受固件限制，区分视频菜单限制、硬件编码能力、传感器读取模式、HDMI 处理链与散热限制。

> 项目当前为 **只读研究阶段**。不刷写、不修改 SD 卡内容、不运行未经验证的相机端代码。尚无证据证明 X-S10 可以解锁 4K60 或 10-bit 内录。

## 当前状态（2026-10-14）

- 研究主机：Ubuntu 24.04.5 LTS (x86_64)。
- 已重新连接并通过标准 PTP 通信确认 Fujifilm X-S10，VID:PID `04cb:02ea`。Ubuntu 的相机桌面挂载已恢复。
- **机身运行版本：2.10**（2026-10-14 从实际 USB 相机标准 PTP `GetDeviceInfo` 读取两次确认）。它不同于本地已下载的 X-S10 **3.11** 官方固件包；不能混淆地址/代码版本。
- 用户已从官方页面下载 `FWUP0025.DAT` 至 `/home/zyubuntu/Downloads/`；文件头读取出 Ver.3.11，SHA-256 记录如下，但**尚未验证厂家签名或校验和**。
- 已在 `output/xs10-payload.bin` 离线提取约 48.7 MiB 负载；标记扫描结果仅保留在 `output/video-markers.json`。
- 目前发现 HEVC/H.265 编码器相关诊断文本与 `4K_59_94P_400M_16` 模式名，**不能据此推断机身具备可用的编码或 4K60 功能**。
- 已记录 [第一阶段研究笔记](docs/findings-2026-10-14.md)、[第二阶段 Ghidra / 编码模块分析](docs/phase2-2026-10-14.md)。
- Ghidra 12.1.4 + JDK 25 已验证并安装在 `/home/zyubuntu/tools/`；本地项目放在被忽略的 `output/ghidra/`。
- 同一套签名发现 H.265 Encoder、H.264 Encoder、H.264 Decoder 三组描述符，但是否执行仍未证实。
- 通过比对大小字段与公开压缩率记录，已经在 X-S10 3.11 与 X-T4 2.12 两套 X6 固件中各找到 **4 组压缩段头候选记录**；尚未解压主程序，也尚未恢复真实运行时地址。
- 注意：直接扁平导入负载会把非代码误解为代码，尚需还原分段及运行时内存映射。
- 仓库中的工具只用于电脑端检查和**离线、只读**文件分析。

## 当前重点：HDMI 10-bit 与机内 Main10 并非同一路径

官方 X-S10 说明书确认 HDMI 4:2:2 10-bit、SD 4:2:0 8-bit；X-T4 说明书则确认 SD 上的 H.265 4:2:0 10-bit。共享 HEVC 固件块不能证明 X-S10 已经具备机内 HEVC Main10 初始化能力。参见 [下一阶段研究路线与可选诊断模式的风险说明](docs/next-step-hdmi-and-diagnostic-2026-10-14.md)。

如果有 Atomos 外录样片，可以用 `bash tools/probe_recording.sh /path/to/clip.mov` 本地检查视频文件编解码元数据，但元数据不能独立证明 HDMI 输入位深。**当前不启动未验证的 X-S10 维修诊断模式；需要用户明确许可。**

## USB 维修诊断研究（尚未进入）

目前实机仍显示正常 PTP `04cb:02ea`，**尚未检测到 `04cb:ff80`、没有发送维修指令或读取 RAM**。已加入只接受 FF80 的受限探测脚本 `tools/ff80_info_only.py`，默认仅检查 USB ID；`--read-info` 才尝试型号和版本信息读取，不包含任意 RAM 写/读或校准访问。适配 X-S10 尚未验证。参见 [第六阶段风险与进度](docs/phase6-ff80-constrained-probe-2026-10-14.md)。

## USB 实机固件版本确认（安全只读）

~~~bash
bash scripts/ptp_device_info.sh
~~~

[完整实验记录](docs/phase5-ptp-current-firmware-2026-10-14.md)。该脚本仅通过标准 PTP 读取 DeviceInfo，必要时临时卸载并恢复 GNOME 的相机挂载；**不读取照片/RAM，不进入维修模式，不写入相机**。

## 从 USB 检查开始

在 Ubuntu 终端运行：

~~~bash
bash scripts/check_usb.sh
~~~

如未发现设备，使用支持数据的 USB-C 线，将相机设置为「USB 读卡器」，连接电脑后 **开机**，然后重跑脚本。无需安装驱动、无需 sudo。该脚本只读取 USB 枚举信息，不向相机写入数据。USB 读卡器模式不是读取相机固件的调试接口。

## 下载并检查原厂固件（需自行阅读并接受官方许可）

官方入口：https://www.fujifilm-x.com/global/support/download/firmware/cameras/x-s10/

官方公布的 Ver.3.11（2024-03-28）文件名为 **FWUP0025.DAT**。固件已下载到本机 Downloads，直接运行以下只读命令：

~~~bash
sha256sum /home/zyubuntu/Downloads/FWUP0025.DAT
python3 tools/fw_inspect.py /home/zyubuntu/Downloads/FWUP0025.DAT
~~~

若只读解析结果符合预期，且决定将原厂负载导出供后续静态分析，可执行：

~~~bash
python3 tools/fw_inspect.py /home/zyubuntu/Downloads/FWUP0025.DAT --extract output/xs10-payload.bin
~~~

首次提取已完成；重复执行会因目标文件已存在而停止，以免覆盖。分析脚本只读取 DAT 和写入指定的电脑本地输出文件；不会访问 USB 相机、不会生成可用于刷机的修改固件、也不校验厂家签名。**解析成功不代表固件安全或机型已被破解**。

## 扫描视频功能标记

~~~bash
python3 tools/video_markers.py output/xs10-payload.bin --json output/video-markers.json
~~~

此命令已运行过一次；再次输出 JSON 时请选择新路径，因为工具不会覆盖已有结果。字符串命中并不是功能可用的证据。

## 识别视频编解码模块描述符

~~~bash
python3 tools/module_inventory.py output/xs10-payload.bin
~~~

## 运行离线单元测试

~~~bash
python3 -m unittest discover -s tests -v
~~~

测试使用自造的合成字节数据；不包含富士原厂固件。

## 研究路线

1. USB 枚举与版本信息确认（不进行写入）。
2. 离线检查 X-S10 官方 DAT 包头及负载格式，记录 SHA-256。
3. 在合法且获得许可的前提下对比 X-S10 与 X-T4 的固件组件、视频模式表及编码器初始化。
4. 静态分析结果要与实际硬件能力分开记录；不能仅凭相同的 X-Processor 4 推断功能可解锁。
5. 在有可靠恢复手段、充分测试之前，不尝试补丁刷写。

## 安全与版权

- **禁止向本公开仓库提交** 原厂 \`.DAT\`、解包的 \`.bin\`、内存镜像、存储卡照片、含序列号的日志或其它可能属于第三方的受版权保护文件。
- 富士官方固件下载协议包含逆向工程限制，请自行查阅和考虑适用法律及使用许可。
- FujiHack 列出的「使用同类 RTOS 的机型」**不等于**针对该机型已有成熟补丁。
- 已有资料：[官方固件页面](https://www.fujifilm-x.com/global/support/download/firmware/cameras/x-s10/)、[FujiHack 固件格式](https://wiki.fujihack.org/firmware/)、[FujiHack 项目](https://github.com/fujihack/fujihack)、[FujiHack Patcher](https://github.com/fujihack/patcher)。
