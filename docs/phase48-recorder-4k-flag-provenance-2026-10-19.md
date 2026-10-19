# 第48阶段：4K模式键状态A8E的来源与Recorder快照+581映射（2026-10-19）

> 核心突破：X-S10原厂3.11与X-T4原厂2.12中，第47阶段判断的Recorder父对象+A8E值，已从条件读者追溯到对象池构造时的原始写入者、活动Recorder配置中的真实RAM字节及其独立快照导出位置+0x581。两机的Section1/2原始ARM BL/LDRB指令、只读Ghidra函数、动态对象池地址运算及前阶段审计结果交叉验证通过。X-S10实体机此前报告为2.10，不可混同于研究的3.11样本。

## 1. 研究限制与溯源

使用的是授权Ubuntu /home/zyubuntu/xs10hk 内现有、未修改的X-S10 3.11与X-T4 2.12原厂X6 Section1/Section2和Ghidra 12.1.4只读项目。原厂全部Section1/2 SHA256与第45—47阶段已固定的值交叉核验。没有接触实体机、没有USB/FF80指令、没有实体RAM或Flash读写、没有修改ROM/DAT/签名、没有补丁或可刷文件。原厂二进制、V61微码、Ghidra数据库和所有完整私有日志均只存于Git忽略的output目录，GitHub仅提交原创文字、审计器和完全合成测试。

## 2. 同构的动态父对象池和A8E赋值

| 审计对象 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 活动父指针RAM变量 | 0x02EDA0B4 | 0x02E57934 |
| 动态父记录初始化器 | FUN_022D3E00 | FUN_022403C8 |
| 槽注册器、ARM BL地址 | FUN_022D2008 / 0x022D3E94 | FUN_0223E5D4 / 0x0224045C |
| 记录池第一个槽首址 | 0x02EDA0B8 | 0x02E57938 |
| 每记录步长 | 0x3C318 | 0x4B0A0 |
| 类型源函数及初始+A8C | FUN_022D1654 / 0x02EDAB44 | FUN_0223DBE4 / 0x02E583C4 |
| 4K类型判别 | FUN_022D1674 | FUN_0223DC04 |
| A8E值来源getter | FUN_012BD7D0 | FUN_01295E44 |
| 首槽A8E RAM位置 | 0x02EDAB46 | 0x02E583C6 |
| A8F值来源getter | FUN_012BD7F0 | FUN_01295E64 |
| 首槽A8F RAM位置 | 0x02EDAB47 | 0x02E583C7 |

原厂初始化器计算真正记录地址为pool_first + slot_index * stride。取得当前Movie类型后写入slot+A8C。若类型是4、5、6或7，调用对应A8E getter，将其返回的活动Recorder flag写入slot+A8E；若非4K类别则明确写0。其它原厂类别的另一路条件会用companion getter填slot+A8F，否则写0。两个模型的原始Section2各五条BL独立回算目标，两个getter原始Section1 LDRB字亦逐条检验。

关键误区：没有原始STRB [register,#0xA8E]形式的直接写不等于不存在赋值，真正的源是pool+index*stride+absolute-offset格式。所有这些地址均是动态RAM，不是可由ROM静态读取的运行时记录值。对于真实slot_index、其实际指针值及是否曾成功录制没有数据。

指针xref复核：两机父指针变量均有116条Ghidra静态引用（113 READ、1 WRITE、2 OTHER/PARAM）。注册器通过指针参数做间接更新。X-S10的FUN_022D3CDC直接把该变量复位为0xFFFFFFFF；X-T4的FUN_022402BC是通用setter，对param_4[1]写入调用方的param_3，**该实参是否为-1未核验**。所以不能声称两机指针重置的入值相同；但这不改变两机父记录初始化的A8E来源事实。

## 3. +A8E源字段具体来自活动Recorder配置RAM

| 值与地址 | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| 实际源RAM字节（A8E） | 0x01C251D4 | 0x01B83940 |
| A8F companion源RAM字节 | 0x01C251D5 | 0x01B83941 |
| 独立活动Recorder Codec源RAM字节 | 0x01C25208 | 0x01B83974 |
| A8E源getter的LDRB原始地址 | 0x012BD7E0 | 0x01295E54 |
| A8E getter LDRB机器字 | E5D303FC | E5D30400 |
| A8F getter的LDRB原始地址 | 0x012BD800 | 0x01295E74 |
| A8F getter LDRB机器字 | E5D303FD | E5D30401 |
| A8E getter的调用BL原始地址 | 0x022D4020 | 0x022405E8 |
| A8F getter的调用BL原始地址 | 0x022D3F34 | 0x022404FC |

两机活跃flag都在当前Codec字段之前0x34字节。通过原厂ARM+Ghidra可断定Getter从活动RAM返回flag，而不是直接读取Codec、GUI eModeMovieCodec或某个公共ROM常量。

额外独立交叉证据：反向Exporter X-S10 FUN_012BE684、X-T4 FUN_01296D38把当前flag源依次导出到Recorder snapshot+0x581，把companion导出到+0x580，把活动Codec导出到+0x5B0。两机对应源地址已与getter相同。这确证“活动配置→导出缓存”方向，**不能倒置成snapshot+581直接向活动flag赋值**；前向写者/整体结构拷贝尚未解析。

## 4. 为何现在不能称为X-S10 4K60锁

第46阶段两机静态96条×0x40同一Recorder表内确有3840×2160、4096×2160与fps枚举6约59.94的记录。第47阶段Movie初始化器判断4K电影类型且父状态A8E==1，会强制模式键low从7映射到6；在其它表查找键不变时，对应从3840×2160/4096×2160候选变到1920×1080/2048×1080静态项。第48阶段**仅证明该状态在初始化期间取自活动Recorder源RAM字节**。另一状态函数在4K类别还检查A8E==2，说明其至少在多个状态值上参与业务流程，绝不能直接将A8E命名成布尔“启用4K”或X-S10专有许可。

当前未知：活跃状态字段真正的前向赋值者、实体运行时具体取值、X-S10菜单能否选择该组合、VPU Main10的Profile设置/接收、传感器/ISP吞吐与编码码流数据、硬件带宽及4K60持续录制。这项flag判别逻辑两机存在，不支持“只需改一个隐藏字节即可解锁”推断。

## 5. 离线可复验的独立原创成果

公开文件：
- tools/audit_stage48_recorder_a8e_flag_origin.py：验两机原始ROM Section1/2完整SHA、父pool/register/分类器/getter五条真实ARM BL、原始两个LDRB、Ghidra动态槽写入顺序、两机指针reset差异、父指针116静态xref、Recorder活跃flag的两个直接READ、逆Exporter +581/+580/+5B0，及Stage46/47已证实的条件和未证实的业务边界。
- tests/test_audit_stage48_recorder_a8e_flag_origin.py：105项纯人工Ghidra风格文本和A32伪BL/错误行为的正负测试。完全没有富士固件原始ROM字节、V61微码或实体数据。
- docs/phase48-recorder-4k-flag-provenance-2026-10-19.md：本研究报告。

本轮原厂离线审计Phase26—48逐项PASS；Stage48合成105项在ROM/Ghidra完全隔离public-only目录PASS；完整离线自动单元测试为**91项仓库追踪 + 2372项本地Git忽略研究 = 2463项PASS**。FF80设备探测显示未检测到设备，No command sent；本地main保持clean，所有原厂文件未修改或上传。

执行原厂核验需要既有已授权素材和本地Ghidra日志，纯合成测试不需要ROM：

    cd /home/zyubuntu/xs10hk
    python3 tools/audit_stage48_recorder_a8e_flag_origin.py --output output
    PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
    PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q

## 6. 下一步：必须真正解决活动flag源值的前向赋值

目标为X-S10活动Recorder flag 0x01C251D4及X-T4 0x01B83940，进一步以真实结构体memcpy、setter或指针别名还原此字段的最终值来源；优先与当初原始Recorder current buffer的snapshot+0x581进行def-use，而非仅把相同偏移的STR视为同一内存对象。同步继续查0x5BD/+0x5BE尺寸键、0x5C6/+0x5C7帧率、GUI的模式可选性和机型差异。没有实体录制的HEVC Main10 SPS和4K60输出之前，绝不声称软件、硬件或内录已解锁。
