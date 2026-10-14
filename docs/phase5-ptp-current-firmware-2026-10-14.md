# 第五阶段：X-S10 标准 PTP 实机信息确认（2026-10-14）

## 结果

在用户手动连接 X-S10 至 Ubuntu 24.04 后，USB 设备枚举为：

- USB Vendor/Product：`04cb:02ea`
- USB Class：Imaging / Still Image Capture / PTP
- 标准 PTP 操作码：`GetDeviceInfo (0x1001)`
- PTP Manufacturer：`FUJIFILM`
- PTP Model：`X-S10`
- **机身通过标准 PTP 报告的 DeviceVersion：`2.10`**
- PTP SupportedOperations 数量：25

该结果以两次独立执行同一标准 PTP 读取工具为依据，返回一致。**版本来自实际 USB 机身，不是已下载的官方固件包**。

已离线分析的 X-S10 原厂文件 `FWUP0025.DAT` 的版本为 **3.11**，因此此前在该文件中定位的 HEVC 和视频模式资源不能未经版本核对就映射到当前运行 **2.10** 的机身。不能假定两版本使用同一内存布局。

## 操作边界

- USB 自动挂载被 Ubuntu 的 `gvfsd-gphoto2` 占用。工具仅暂时卸载 GNOME 相机挂载，完成 USB 查询后自动恢复。均已验证成功。
- 仅发送标准 PTP `GetDeviceInfo`，不发送其它标准或厂家私有操作码。
- 未调用 `OpenSession`、`GetObject`、`GetDevicePropValue`，未列出或读取照片、SD 卡文件、序列号、校准信息或 RAM，也未修改相机设置/固件。
- **未进入** `04cb:ff80` 富士维修诊断模式，也未测试该模式在 X-S10 上是否可用。
- 含设备序列号的 USB 挂载路径及 PTP 原始数据不上传公开仓库。

## 复现

在 Ubuntu 相机正常开机并设置为 USB 读卡器模式，连接数据线后：

```bash
cd /home/zyubuntu/xs10hk
bash scripts/ptp_device_info.sh
```

脚本检查 `04cb:02ea` 设备数量是否为 1；必要时暂时释放 GNOME 自动挂载，然后运行 `tools/ptp_device_info.py` 发出 **仅一条标准设备信息命令**，退出时恢复挂载。它不会尝试进入维修模式。如果相机被其他程序占用，正常报告错误并停止，勿强制抢占。

本地合成数据单元测试还确认 DeviceInfo 解析不会输出序列号字段。此脚本依赖 Ubuntu 上已经存在的 `python3-usb` / PyUSB，以及 GNOME 系统的 `gio`。

## 下一步研究的决策

**路线 A（推荐默认）：** 继续研究 X6 四个压缩段的只读解压和映射，拿到真实的 ARM 代码后对 X-S10 3.11 / X-T4 2.12 分别反汇编。无需连接相机。

**路线 B（必须再次征求明确同意）：** 检查 X-S10 是否能进入公开研究中的 `04cb:ff80` 维修 USB 模式。初次仅检查 USB 枚举，不发送维修协议指令。注意 FF80 支持情况未证实，可能发生异常重启/卡死。再向下推进 RAM 读取，需要确认版本、具体读取范围、只读命令实现与恢复方法。未经授权不发送任何服务命令。

本阶段没有找到可用 HEVC Main10 初始化函数，也没有尝试刷机。
