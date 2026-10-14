# 第十一阶段：X6 LZ77 完整离线解压突破（2026-10-14）

> **结论：已成功独立还原 Fujifilm X6 压缩流的解码规则，并将 X-S10 3.11 / X-T4 2.12 各四个压缩段完整解码。**
>
> **8/8** 段完成，长度严格匹配原厂未压缩长度，最大回溯距离 2047 字节，最大单次引用长度 15 字节；八个输出中不存在零长度引用或零距离引用。**两机前两段的入口函数已经全部通过 Ghidra ARM 反汇编实测**。
>
> 本阶段 **完全在 Ubuntu 主机离线执行**。没有使用相机 USB、FF80、RAM 读写或升级接口。没有尝试重打包、签名或刷写固件。

## 一、压缩外层结构

在经过逐字节按位取反还原的 Fuji X6 DAT payload 中，识别以下结构：

- 压缩段基址按 \`0x20000\` 字节对齐；
- 实际段头位于基址 + \`0x60\`；
- 段头 5 个连续 **little-endian uint32**，共 20 字节：

| 字段偏移 | 含义 | 验证 |
| --- | --- | --- |
| \`+0x00\` | 目标解压总长度 | 八段解压后 **全部严格相符** |
| \`+0x04\` | 压缩流字节长度 | 八段均精确到零填充边界 |
| \`+0x08\` | 16 KiB 压缩数据页数 | 八段均等于 \`ceil(compressed_size / 0x4000)\` |
| \`+0x0c\` | \`0x4000\` | 八段完全相同 |
| \`+0x10\` | \`0x4\` | 八段完全相同，具体枚举语义未证实 |

压缩字节流从 \`header+20\` 开始。读到 \`compressed_size\` 字节后，对齐到下一个 \`0x20000\` 边界之前剩余数据 **8/8 全零**。

该结构与 [fffw 研究笔记](https://github-wiki-see.page/m/tiredboffin/fffw/wiki/Route-0xff80) 描述的硬件 16 KiB DMA 传输路径一致。但 \`0x4\` 的完整含义、包裹在 X6 以外的格式适用性仍待确认。

## 二、已还原的压缩算法

解压形式是 **LZ77 型的字节流**，使用可变长度字面量块和两字节回溯引用，不使用已识别的熵编码表：

~~~python
while compressed_bytes_remain:
    first = read_u8()

    if first < 0x80:
        # 字面量：直接复制接下来的 first 个字节。
        output += input.read(first)

    else:
        # 2 字节回溯引用。
        second = read_u8()
        length = second & 0x0F                  # 1..15
        distance = ((first & 0x7F) << 4) | (second >> 4)  # 1..2047

        for _ in range(length):
            output.append(output[-distance])    # 须支持重叠自引用
~~~

该表达式的关键证据：

1. **完整压缩流解析**：八段源数据全部消耗完毕，无截断和剩余尾字节。
2. **无输出长度误差**：字面量总和 + 所有引用的低四位长度总和，八段全部**逐字节匹配**头部声明的解压长度。
3. **回溯范围与窗口相容**：八段每条真实引用均指向已解压的有效位置；最大 \`distance=2047\`。无非法引用。
4. **有意义的实际输出**：解压后的 ARM 函数序言、条件跳转、BL 目标、重复指令序列等均与 ARM32 代码高度一致；大规模填充、资源表结构也恢复。
5. **跨机型验证**：一套代码无需配置差异即可完整解码两台相机各四段。

常见指令示例：

- \`80 ff\` → 向前 15 字节复制 15 字节；
- \`81 4f\` → 向前 20 字节复制 15 字节；
- \`81 05\` → 向前 16 字节复制 5 字节；
- \`01 xx\` → 原样复制 1 字节。

这也解释了过去在压缩数据中观察到的大量 \`80 ff\` 和 \`81 4f\` 重复序列。

正式解码工具默认对零长度引用、距离为零、负偏移、截断及输出长度溢出**直接拒绝**，不尝试猜测未观测到的操作码扩展。八个原厂文件片段中没有出现上述异常。

## 三、原厂固件的完整解压结果

下面的 SHA-256 只用于校验**用户本地解压结果**，不是相机固件官方签名或刷机凭证。

| 机型与版本 | 段 | 压缩字节数 | 解压字节数 | 回溯引用次数 | SHA-256 |
| --- | ---: | ---: | ---: | ---: | --- |
| X-S10 3.11 | 1 | 3,914,256 | 8,012,912 | 942,003 | \`c86c9446a15a39e6e761c4ca96383e943cdb3a09cab6e609b85b3e48f3e91aff\` |
| X-S10 3.11 | 2 | 5,298,316 | 9,449,472 | 1,232,561 | \`f0c4db782031a81c620d764317ebf0219d10bb4b52eb4fd5998b9ce39c3afb8c\` |
| X-S10 3.11 | 3 | 4,563,800 | 10,027,008 | 1,065,543 | \`2625666839fd2fdb7ec92bc4486a5c5d6193441afd6f833f29cf0cf13524c5d7\` |
| X-S10 3.11 | 4 | 3,480,732 | 6,763,104 | 872,994 | \`40af0c55a2b8694b99f0eea01a65b6404b6a78da529514d5f42dce931df9ae9c\` |
| X-T4 2.12 | 1 | 3,449,330 | 7,420,408 | 849,274 | \`0b5b0fb0ee5fe6b109dae9964b5cddfe18edab46b4a0c195f9da194448906eeb\` |
| X-T4 2.12 | 2 | 5,254,523 | 9,437,184 | 1,226,720 | \`e1ef8b30903d3078fde103cdd134fca7bfc4337d67bcaf55c3080ffd5fd93b13\` |
| X-T4 2.12 | 3 | 4,632,713 | 10,240,000 | 1,085,890 | \`6c8d7b8b0a37df8c2b636c504c07a80318243b313d5bf435e2c39ef3f56e9f80\` |
| X-T4 2.12 | 4 | 3,309,617 | 6,446,348 | 829,627 | \`b1a6146fc89394e7c47a2bd5b0e92c07de085567da3aa8d6198bc1a32de9eec6\` |

总计约 **67.8 MB** 解压后的二进制数据。

已生成在**授权 Ubuntu 主机**：

- \`/home/zyubuntu/xs10hk/output/x6-xs10/section-{1,2,3,4}.bin\`
- \`/home/zyubuntu/xs10hk/output/x6-xt4/section-{1,2,3,4}.bin\`

这些文件是原厂二进制的解压副本，目录已被 git 忽略，**不会推送到公开仓库**。

## 四、装载头和入口函数：高置信度候选

每个机型的前两段解压文件均以 32 字节候选装载头开头：

~~~text
+0x00  uint32  0
+0x04  uint32  probable RAM load base
+0x08  uint32  unpacked length rounded up to 4096
+0x0c  uint32  probable entry function address
+0x10  uint32  0
+0x14  uint32  0
+0x18  uint32  0
+0x1c  uint32  0xAAAAFFFF
~~~

| 机型 | 段 | 候选 RAM 基址 | 页对齐长度 | 入口函数指针 | 指针指向有效 ARM 函数 |
| --- | ---: | --- | --- | --- | --- |
| X-S10 3.11 | 1 | \`0x01021000\` | \`0x7A5000\` | \`0x012B89E0\` | 是 |
| X-S10 3.11 | 2 | \`0x01EAF000\` | \`0x903000\` | \`0x01EBE588\` | 是 |
| X-T4 2.12 | 1 | \`0x01021000\` | \`0x714000\` | \`0x012910C4\` | 是 |
| X-T4 2.12 | 2 | \`0x01E0F000\` | \`0x900000\` | \`0x01E1DE60\` | 是 |

全部四个入口地址减去基址后都落在该二进制文件内，指向连续的 **ARM STMDB SP! 和 ADD R11, SP** 指令，是独立于解压长度的交叉验证。

尚未验证：固件启动时是否真的把**整个解压文件**逐字节复制到对应 RAM 基址；第三、四段的加载方式也待分析。因此这些是**高度可信的装载映射候选**，不是已实测的机身内存表。**更不能直接套用到机主运行的 X-S10 2.10。**

### Ghidra 12.1.4 实际验证

使用 \`ARM:LE:32:v7\` + \`BinaryLoader\` + 上述基址导入，并通过项目自带的 \`ghidra_scripts/InspectX6Entry.java\` 在上述四个入口地址测试。**4/4 均成功反汇编**，而且 Ghidra 给出合理的调用/跳转。

其中 X-S10 3.11 第一段：

~~~asm
012B89E0 stmdb sp!,{r4,r11,lr}
012B89E4 add r11,sp,#0x8
012B89E8 sub sp,sp,#0x24
012B89EC bl 0x012B8930
012B89F0 cmp r0,#0x1
012B89F4 beq 0x012B8A08
012B89F8 bl 0x012A67F4
~~~

Ghidra 本地项目保存在 \`output/ghidra_x6/\`；这是**无需相机**的本机分析。仅初步反汇编入口，尚未完成大量交叉引用或视频功能调用链分析。

## 五、公开工具与复现命令

所有程序均在 GitHub 开源，**代码不包含富士原厂二进制**：

- [\`tools/x6_decompress.py\`](../tools/x6_decompress.py)：完整 X6 LZ77 解码，严格校验尺寸与边界。
- [\`tests/test_x6_decompress.py\`](../tests/test_x6_decompress.py)：重叠回溯、最大距离、截断、越界、真实段头结构等全合成测试。
- [\`tools/x6_load_hints.py\`](../tools/x6_load_hints.py)：解压程序入口地址候选识别。
- [\`tests/test_x6_load_hints.py\`](../tests/test_x6_load_hints.py)：模拟 ARM 函数头验证。
- [\`ghidra_scripts/InspectX6Entry.java\`](../ghidra_scripts/InspectX6Entry.java)：Ghidra ARM 入口反汇编证明。

在 Ubuntu，直接使用之前已经提取的解码 payload：

~~~bash
cd /home/zyubuntu/xs10hk
python3 tools/x6_decompress.py output/xs10-payload.bin --output-dir output/x6-xs10
python3 tools/x6_decompress.py output/xt4-payload.bin --output-dir output/x6-xt4
python3 tools/x6_load_hints.py output/x6-xs10/section-1.bin output/x6-xs10/section-2.bin
python3 -m unittest discover -s tests -q
~~~

注意：解压工具使用独占新建模式写文件，**如果输出目录已存在，会拒绝覆盖**；可换用新的输出子目录，或不传 \`--output-dir\` 仅验证 SHA-256。上述命令对应第一次运行创建输出文件时的示例。

Ghidra 手动示例（需在 Ubuntu 有 Ghidra 12.1.4；项目与文件名请使用尚不存在的名称）：

~~~bash
/home/zyubuntu/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless \
  "$PWD/output/ghidra_x6" xs10_x6_s1_review \
  -import "$PWD/output/x6-xs10/section-1.bin" \
  -processor ARM:LE:32:v7 -cspec default \
  -loader BinaryLoader -loader-baseAddr 0x01021000 \
  -noanalysis -scriptPath "$PWD/ghidra_scripts" \
  -postScript InspectX6Entry.java 012b89e0
~~~

测试日志已经确认四个入口函数都能通过 Ghidra 反汇编。

## 六、这一步没有证明的内容

- **还未确认 X-S10 可启用机内 HEVC 10-bit / 4K60**。共用 H.265 编码代码或发现视频模式字符串都不是功能可用性的证明。
- **X6 解压成功不等于可重打包/刷机**。重压缩、包层校验、可能的签名、型号与版本校验、启动入口、分区操作和独立救援流程尚未完整验证。
- 外部研究者的压缩结果没有公开为可比对的 X-S10/X-T4 黄金样本，所以目前的信心来自**八段精确长度、100% 有效 LZ 引用、重复 ARM 程序结构与四次 Ghidra 导入验证**，不是第三方字节级校验。
- 机主真实机身普通 PTP 版本为 **2.10**，本次离线使用 **X-S10 3.11** 包；不能直接将这里的代码地址用于在机 RAM 读取。
- [上次 FF80 RAM 请求导致相机无法关机](phase8-ff80-ram-timeout-2026-10-14.md)；虽然机主通过取出电池恢复开机，**本次没有重启任何 USB 维修实验**。

## 七、下一阶段工作

1. 用新的 RAM/ELF 候选映射对 **X-S10 3.11 vs X-T4 2.12** 的视频设置、编解码初始化、HEVC Main10 控制路径做完整反汇编与交叉引用。
2. 解析解压第 3、4 段的真实装载地址、结构或外置协处理器资源。
3. 开展**电脑端** X6 压缩器开发，并与解码器互测；在了解 DAT 校验/版本/签名及安全回滚前，不生成给相机刷写的修改固件。
4. 验证两份原厂 DAT 头部 checksum 的完整计算方式及加载时检查方式。
5. 若希望最终实机刷写，应先解决独立救砖入口和备用机风险；当前不继续未知 FF80 RAM 读操作。

**本阶段的主要目标（解压 X6）已达成。**
