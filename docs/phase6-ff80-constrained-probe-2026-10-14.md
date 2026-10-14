# 第六阶段：FF80 维修诊断入口的受限测试（2026-10-14）

## 当前完成情况

- 用户的 X-S10 在标准 PTP 模式下报告固件 **2.10**，USB VID:PID 为 `04cb:02ea`。
- 实机被动运行 `lsusb -d 04cb:ff80` 及 `python3 tools/ff80_info_only.py`：目前**没有检测到 FF80 服务接口**，所以**还没有执行任何维修协议指令，更没有读取 RAM**。
- 编写 `tools/ff80_info_only.py`，仅允许探测 FF80 USB ID，并可在明确调用 `--read-info` 时，读取 FF80 信息标签 0x04（型号）与 0x08（版本）；不读取序列号。
- 项目目前 **28 项单元测试全部通过**。

## 为什么不直接运行现成的 RAM 读取？

根据 [fffw 的 cmd.py](https://github.com/tiredboffin/fffw/blob/main/ff80/ff80_cmd/cmd.py)，普通 `ram read` 流程会调用 `set_config_usb_debug(1)`，从而更改相机的调试配置；然后尝试读 RAM 和还原原配置。如果中途异常，清理可能没有执行。该项目的 `info` 命令会查询序列号，不应将原始日志上传公开 GitHub。

本仓库新增的实验程序参考了 [ff80 transport](https://github.com/tiredboffin/fffw/blob/main/ff80/fftlib.py) 和 [ffjlib](https://github.com/tiredboffin/fffw/blob/main/ff80/ffjlib.py)，但故意不实现通用指令分发、读写 RAM、写入配置、校准、执行未知代码或更新固件。

程序默认**只验证 USB ID**，不发送厂商协议指令；可选的 `--read-info` 会短暂建立 USB 通信会话并请求两个只读性质的信息标签。这并不保证未知机型完全没有副作用。

## X-S10 进入模式的不确定性

[fffw README](https://github.com/tiredboffin/fffw) 给出的通用方法是接好 USB、关机后按住**快门键 + 上方向键**开机。X-S10 没有传统方向键，但有可以向上拨动的摇杆。因此“按住快门 + 上拨摇杆开机”只是**尚未验证的机型适配假设**。

机主必须亲自操作相机，先只由 Ubuntu 的 `lsusb` 判断有无 `04cb:ff80`，不能连续盲试其它按键组合。

## 下一步的安全关卡

1. 实机由机主尝试一次通用进入方式。
2. 仅 USB 被动检查 `04cb:ff80`。若没有出现，停止，不发任何维修命令。
3. 若 ID 和接口类型都正确，再用 `python3 tools/ff80_info_only.py --read-info` 请求型号和版本，检查是否实际支持此接口。
4. 只有确定机型适用的 RAM 地址映射、明确可读的物理内存范围、并排除 MMIO 后，才能讨论最小只读 RAM 实验。当前没有 X-S10 2.10 的验证过的内存布局，不能猜地址。
5. **不刷写固件、不写配置、校准区、EEPROM/NVRAM，不启用未审核的调试开关。**

当前没有 RAM dump，没有完成主程序解压和 HEVC 调用链追踪。任何来自第三方维修接口的不兼容风险都不能视为零。
