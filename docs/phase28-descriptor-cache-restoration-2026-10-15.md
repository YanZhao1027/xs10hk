# 第28阶段：Recorder 配置描述符的缓存备份与恢复路径（2026-10-15）

> **新增的可复验证据**：X-S10 原厂 3.11 与 X-T4 原厂 2.12 的配置描述符，并非只能通过单个 STR 指令赋值。Ghidra 与原始 A32 二进制证明两机各有一组 **16 条、每条 0x54 字节的配置记录缓存**，能备份和恢复整个描述符头部，以及长度由 RAM 元数据指定的后续数据。**描述符 +0x10 主配置指针可能被恢复复制覆盖，前提是动态复制长度至少 8 字节；该条件的实机值仍未获得。** 更下游的缓冲区 Codec 值、HEVC Main10 和 4K60 尚未证实。

本轮只在授权 Ubuntu 上读取已存在的 X-S10 **3.11**、X-T4 **2.12** 原始解压 X6 固件及本地 Ghidra 12.1.4 工程。机主 X-S10 此前报告的实机固件为 **2.10**。无 FF80、无相机 USB 访问、无 RAM/闪存操作、无 DAT 修改和可刷补丁。

## 1. 初步 A32 扫描：负结果不能代替指针别名证据

将前一轮（因远程连接中断而准备、尚未在原厂运行）的 `scan_profile_header_writes_stage28.py` 部署进 Ubuntu：

```bash
cd /home/zyubuntu/xs10hk
python3 tools/scan_profile_header_writes_stage28.py --output output \
  --json-report output/stage28_descriptor_header_candidates.json
```

实际扫描了两机的 Section1 + Section2 原始固件：

| 模型 | Phase27 已知 +0xAC4 指针槽写入正控 | 描述符字段直接写入候选 | 其他静态目标事件 |
|---|---|---:|---:|
| X-S10 3.11 | 通过 | **0** | 1055 |
| X-T4 2.12 | 通过 | **0** | 1094 |

**这个扫描器没有完整 CFG、动态指针别名和任意 memcpy 调用语义。** 零个命中不是“描述符 +0x10 不会写入”。扫描器以原始 MOVW/MOVT、立即数 LDR/STR 和少量寄存器推导为限，遇分支和未知指令会保守清除寄存器状态。它能验证上一轮已知指针槽写入，但不是源配置生成路径的穷举工具。

## 2. 转为 Ghidra 交集审计，恢复被漏掉的整块复制

使用私有只读脚本 `AuditDescriptorMemcpyIntersections.java`：
- 寻找**引用描述符基址**的函数；
- 与**调用已证实的内存复制 helper** 的函数取交集；
- Ghidra 对交集中每个函数反编译，核对复制的目的地、来源和长度。

| 项目 | X-S10 | X-T4 |
|---|---:|---:|
| 引用描述符基址的函数数 | 263 | 269 |
| 调用 memcpy helper 的函数数 | 1190 | 1176 |
| 两者交集函数数 | **24** | **25** |
| 可反编译的交集函数 | 24 | 25 |

交集不意味着这些函数全都写向描述符。必须进一步看 memcpy 参数。交叉审阅后，最明确的一组是以下**对应的配置记录保存/恢复函数**：

| 角色 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 描述符头基址 | `0x02D987E8` | `0x02D0BF48` |
| 主配置指针（描述符 +0x10） | `0x02D987F8` | `0x02D0BF58` |
| 记录表首项 | `0x02D9BD0C` | `0x02D0F46C` |
| 保存当前描述符 | `FUN_021F9338` | `FUN_021653B4` |
| 从表恢复描述符 | `FUN_021F93D8` | `FUN_02165454` |
| 初始化记录表 | `FUN_021F92F8` | `FUN_02165374` |
| memcpy helper | `FUN_012A9148` | `FUN_01281848` |
| 表记录数 / 条目跨度 | 16 / 0x54 | 16 / 0x54 |

记录表复位例程清理 `0x540`（16 × 0x54）跨度，恢复事件处理器遍历 16 项。不是推测的 HEVC 表。

## 3. 通过原厂 A32 二进制验证 12 条调用边

独立于 Ghidra 文字反编译，原创的 `audit_descriptor_cache_roundtrip_stage28.py` 从原厂 Section2 读取 A32 指令，对每条 BL 的位移和目标地址进行计算。

| 数据边 | X-S10 的 BL 指令 | X-T4 的 BL 指令 |
|---|---|---|
| 保存数据段 → memcpy | `0x021F9388` | `0x02165404` |
| 保存固定头 → memcpy | `0x021F93D0` | `0x0216544C` |
| 恢复固定头 → memcpy | `0x021F9404` | `0x02165480` |
| 恢复数据段 → memcpy | `0x021F9424` | `0x021654A0` |
| 上游调用保存函数 | `0x021FC608` | `0x021686DC` |
| 上游调用恢复函数 | `0x021FCA78` | `0x02168B48` |

两机总计 **8 条 memcpy BL + 4 条上游 BL = 12 条原始 ARM 调用边**全部通过验证。审计还检查了固定头长度指令为 `MOV R2,#0xC`，动态载荷长度来自 RAM、恢复时目标指针为描述符 `+0x0C`，以及记录步长 `0x54` 的真实 ARM 指令。

### 重要：复制是否覆盖 +0x10 取决于运行时长度

每次描述符恢复包含两个独立的 memcpy 操作：

1. 固定头：**12 字节**，目标为描述符 `+0x00…+0x0B`，**不覆盖主缓冲区指针 `+0x10`**；
2. 后续载荷：目标从描述符 `+0x0C` 开始，复制长度读取选定记录的**动态长度字段**（记录 `+0x04`）。

主缓冲区指针是四字节，处在载荷目标相对偏移 `+4…+7`。因此只有**动态长度 ≥8 字节**时，整个 `+0x10` 指针才会被恢复操作覆盖。静态固件无法得出这一长度在每次运行时的实际值。

缓存保存过程具有对应的反向搬运：描述符固定头写回缓存，后续从描述符 `+0x0C` 按描述符 `+0x04` 的运行时长度写入该记录。不同配置记录的实际内容、合法性和执行条件尚未由静态路径确认。

## 4. 对 HEVC 10-bit / 4K60 解锁的意义及当前边界

第27阶段确认：

`X-S10 头部 0x02D987F8 → 当前指针槽 0x02D9C2AC`

第28阶段现在补充：

`配置记录缓存 ⇄ 描述符头 0x02D987E8（条件式整块保存/恢复）`

但仍不能补上以下**缺失的数据边**：

```text
GUI MovieCodec byte 0x01B88650
        │   【尚未查明的分配 / 序列化 / 限制判断】
        ▼
动态主缓冲区里 +0x5B0 / +0x5B1 （实际内容未知）
        │
        └── Recorder 源快照 0x02D9D834 （第26阶段已证实复制）
                    ↓
            Recorder 活跃配置 0x01C25208
```

描述符缓存功能与 H.265 无直接已证实的特殊关系。X-T4 也拥有几乎同构的缓存机制，因此不能把它当作 X-S10 禁用 Main10 的代码位置。单看缓存长度和地址，也不能证明传感器/ISP 4K60。

## 5. 交付、测试、复验

本阶段原创公开文件：

- `tools/scan_profile_header_writes_stage28.py`：保守 A32 静态候选扫描器，输出仅含原厂地址及未知标记。
- `tests/test_scan_profile_header_writes_stage28.py`：前期准备的 **41 项纯合成测试**。
- `tools/audit_descriptor_cache_roundtrip_stage28.py`：原始 Section2 + 私有 Ghidra 文本联合审计器，核验 12 条原始 BL、缓存地址与表大小、动态复制边界。
- `tests/test_audit_descriptor_cache_roundtrip_stage28.py`：本轮新增 **35 项纯合成测试**。

私有日志及 JSON 留在获授权 Ubuntu 被忽略的 `output/`，不提交 GitHub：

`stage28_descriptor_header_candidates.json`、`xs10/xt4_stage28_descriptor_memcpy_intersections.log`、`xs10/xt4_stage28_descriptor_copy_family.log`、`xs10/xt4_stage28_profile_save_restore_callers.log`、`xs10/xt4_stage28_profile_save_restore_refs.log`、`xs10/xt4_stage28_profile_descriptor_registry.log`、`xs10_stage28_restore_payload_target.log`。

复验命令（需本机这些私有固件与 Ghidra 日志）：

```bash
cd /home/zyubuntu/xs10hk
python3 tools/scan_profile_header_writes_stage28.py --output output --json-report output/stage28_descriptor_header_candidates.json
python3 tools/audit_descriptor_cache_roundtrip_stage28.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
```

测试实测：阶段28 **41 + 35 = 76** 项新增合成测试全部通过。连同原仓库跟踪的 91 项和之前留在私有输出目录的 271 项，本机累计 **91 + 347 = 438 项离线测试通过**。两机原厂静态审计通过，**不等于任何实机录像能力测试**。

## 6. 下一阶段应聚焦

1. 在只读 Ghidra 中跟踪描述符 `+0x04` 的动态长度来源与 `0x200` 类型的配置实例化/消息处理；不要用保存缓存时未知的 payload 数据猜测录像 Codec。
2. 在已确认配置缓冲区身份之后，对其 `+0x5B0` 的真实生产者进行有上下文的指针别名和复制图分析，对照 X-T4 的同一路径。
3. 如果无法静态证实有效 Main10 参数和 Sensor/ISP 60fps 帧流，不制作可刷补丁、不建议连接实机 FF80。机身历史 2.10 与研究的 3.11 地址不同。

**结论：配置描述符缓存的备份/恢复路径已经验证；GUI→Recorder Codec 值的数据边仍缺，机内 10-bit 与 4K60 未解锁。**
