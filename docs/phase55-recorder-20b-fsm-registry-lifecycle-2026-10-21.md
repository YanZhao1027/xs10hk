# Phase55: Recorder 0x20B FSM event groups and descriptor registry lifecycle (2026-10-21)

**Original-ROM findings:** Both X-S10 firmware 3.11 and X-T4 firmware 2.12 have a static Recorder control-handler sequence of **(1) save the current descriptor to its typed registry, (2) conditionally deep-copy an entire GUI-sized source configuration from `descriptor+0x0C` if type is `0x20B`, (3) execute four fail-closed checks, and (4) only on the success path clear the `0x20B` registry record.** There is an important separate FSM dispatch distinction: receiving type `0x20B` normally routes through **event group 4**, whereas the snapshot lifecycle control-handler is in **event group 13**, with its own state guard. This stage does **not** prove the conditions needed to transition group 4 -> group 13 in an actual recording session.

The preceding [Phase54](https://github.com/YanZhao1027/xs10hk/pull/33) established a conditional original-ARM GUI->module7 receiver descriptor pointer chain. Phase55 closes part of the *separate, later* source snapshot/registry lifecycle and eliminates an incorrect immediate-dispatch assumption. **Still unknown:** actual OS queue delivery, runtime FSM sequence, GUI staging pointer lifetime, valid original content of dynamic Recorder P, P+0x581 first setter, or usable 4K60/Main10 internal recording.

## 1. Safety, firmware, and evidence limits

Analysis used only vendor X-S10 **3.11** / X-T4 **2.12** already unpacked X6 Section1/2 on the user's authorized Ubuntu, plus prior read-only Ghidra 12.1.4 data. The physical X-S10 firmware was previously reported as **2.10**, making ROM/RAM addresses from this study incompatible with direct device use. No camera was connected or operated; no USB/FF80, camera RAM/Flash operations, patch, firmware repack, flashing, or altered vendor ROM. Original firmware, decompilation transcripts and Ghidra projects stay in local Git-ignored `output/`, never pushed to GitHub.

Original A32 and SHA-pinned earlier stages (including the Phase54 module7 receiver and 0x20B snapshot target) are rerun by this audit. Private Ghidra logs are additionally cross-checked, but decompiler variable names and inferred C types are not the sole basis for data-direction or call-order claims.

## 2. A real FSM callback table, and its state != 0x102 gate

| Component | X-S10 3.11 | X-T4 2.12 |
|---|---|---|
| FSM group pointer array | `0x0266A5F8` | `0x025C4AD0` |
| Group-4 function table | `0x0266A5B8` | `0x025C4A90` |
| Group-13 function table | `0x02665D90` | `0x025BFE4C` |
| Group-13 slot +0x10 (index 2) | `0x02665DA0` | `0x025BFE5C` |
| Function pointer stored in that slot | `0x021CDF50` | `0x0213751C` |
| Stub's live state code byte pair | `0x035BD862` | `0x03672072` |
| If state != `0x102`, BNE at | `0x021CDF64` | `0x02137530` |
| BNE target: the controller | **`FUN_021CDF80`** | **`FUN_0213754C`** |

Raw Section2 values prove the group-13 pointer table and callback slot. The stub's actual ARM `MOVW/MOVT R3,global`, `LDRH R2,[R3,#2]`, `MOVW R3,#0x102`, `CMP`, and `BNE` targets were checked individually. When the code is **already in state 0x102**, the stub instead clears a separate status byte at its global `+0x46` and returns 1; it does **not** run the source-snapshot controller. The state number `0x102` is a state code, **not the `0x20B` message type**.

Crucially, the group-4 table is **not** the group-13 table in either firmware. Thus, locating a handler in the group-13 table cannot by itself establish its execution on a group-4 event.

## 3. Receiving type 0x20B selects event group 4; snapshot controller is in group 13

Both models' module7 `reccont` callback executes a wrapper after the receive/precheck process:

| Component | X-S10 | X-T4 |
|---|---|---|
| Module7 callback | `FUN_021C549C` | `FUN_0212EA80` |
| Post-receive FSM wrapper | `FUN_021B8B9C` | `FUN_02121478` |
| Type-to-event classifier called by wrapper | `FUN_021B8AD0` | `FUN_021213AC` |
| Generic FSM dispatcher | `FUN_021B859C` | `FUN_02120E78` |
| A32 BL dispatching **group 4** | `0x021B8B94` | `0x02121470` |
| An independent A32 BL dispatching **group 13** | `0x021BA7B4` | `0x02122FA8` |

The actual classifier has special cases for type `0x200` and model-specific `0x12xx` message types. Type **`0x20B`** belongs to none of these cases, so its fallback assigns **status 5** then calls **`dispatcher(4)`**. The verified dispatcher chooses callback-table groups via `(&PTR_DAT_GROUP_TABLE)[param_1]`, while the separate group-13 call passes decimal **13** (`MOV R0,#0x0D` + original BL).

**This is the critical dispatch qualification:** a valid queue packet with `type=0x20B` does *not automatically call* the group-13 snapshot handler. Additional FSM events and state transitions are required. The exact runtime transition, including event chronology and success state, remains unverified. Static code has paths for both, not a demonstrated recording execution trace.

## 4. Original ARM fixes the registry-save -> conditional full-copy order

| Exact controller call | X-S10 | X-T4 |
|---|---|---|
| Typed registry save: first BL | **`0x021CDF88` -> `FUN_021F8100`** | **`0x02137554` -> `FUN_0216417C`** |
| Stage54 source-snapshot consumer: next BL | **`0x021CDF8C` -> `FUN_0221C934`** | **`0x02137558` -> `FUN_02189348`** |
| Actual original source snapshot destination (Phase54) | `0x02D9D284` | `0x02D109D4` |
| Body memcpy size when `type=0x20B` and source pointer nonzero | `0x5DC` (1500B) | `0x5D8` (1496B) |

On **type `0x20B`**, the typed-registry save uses the exact stored registry payload pointer:

| Registry save proof | X-S10 | X-T4 |
|---|---|---|
| Registry payload original ROM literal | `0x021F8610` -> `0x02D98934` | `0x0216468C` -> `0x02D0C094` |
| Registry record header (`payload - 0x0C`) | `0x02D98928` | `0x02D0C088` |
| `memcpy(record_header, descriptor, 12)` | BL `0x021F81CC` | BL `0x02164248` |
| `memcpy(record_payload, descriptor+0x0C, descriptor.length)` | BL `0x021F81EC` | BL `0x02164268` |
| Dynamic length field | `descriptor+4` (`0x02D987EC`) | `0x02D0BF4C` |

Raw A32 verifies that the first memcpy is fixed 12 bytes and the second loads its runtime size from `[descriptor+4]` and its source from `descriptor+0x0C`. If the Stage54 queue receiver previously accepted the Stage53 **8-byte** body, the registry body saves **only the two 32-bit words**: GUI staging pointer and operation sequence. This is a **shallow pointer+sequence record**, **not** a 1500/1496-byte independent copy of GUI settings.

The subsequent source-snapshot consumer, which independently checks `type==0x20B && descriptor+0x0C != 0`, can deep-copy the actual staged GUI bytes. If the source pointer is invalid or changed by the time of that copy, the static chain cannot guarantee success. Whether this same handler ran after a real OS message is also unknown.

## 5. Four separate status checks gate the 0x20B registry clearing

| Original A32 status helper BL, in controller order | X-S10 | X-T4 |
|---|---|---|
| Check 1 | `0x021CDFFC` | `0x021375C8` |
| Check 2 | `0x021CE034` | `0x02137600` |
| Check 3 | `0x021CE06C` | `0x02137638` |
| Check 4 | `0x021CE0A4` | `0x02137670` |
| Status-check helper | `FUN_022B8438` | `FUN_02224BF8` |

Each check is immediately followed by `CMP R0,#0`; if zero, it stores failure code **1, 2, 3, 4** (respectively) and returns **0** before reaching cleanup. Original ARM validates BL targets, compares, conditional branches, failure codes and return paths. The four checked objects are not claimed to be equivalent to camera sensor/encoder/SD write tests; their exact business semantics require independent investigation.

Only when all four checks return nonzero does the controller continue to the follow-up Recorder export/notification path and finally:

| Successful cleanup action | X-S10 | X-T4 |
|---|---|---|
| `MOV R1,#0x8C` | `0x021CE130` | `0x021376FC` |
| `MOVW R0,#0x20B` | `0x021CE134` | `0x02137700` |
| Clear-typed-record BL | **`0x021CE138` -> `FUN_021FB3F8`** | **`0x02137704` -> `FUN_021674C8`** |

The two clear helpers look up the same typed record, then call a verified original zero-fill implementation (`FUN_012A9340` / `FUN_01281A40`) with `(record_header,0,12)` and `(record_payload,0,0x44)`. Four original zero-fill BL sites in each helper are checked because several branches may clear records in other contexts; for this specific call with `0x20B`, the 0x206-only ring decrement branches do not apply.

**Important distinction:** clearing the **typed registry** is not a proven zeroing of the **sender's GUI staging memory**. When the conditional deep copy already succeeded, subsequent zeroing of the shallow record alone does not erase the independent source snapshot. Conversely, this does *not* establish the staging pointer was valid before the copy, nor the runtime success of all four checks.

## 6. What is still not proven

- **OS delivery / FSM timing:** the static receiver may accept `0x20B`, but an automatically executed group-13 callback is not demonstrated. Group 4 and group 13 are distinct tables with independent event dispatches.
- **Pointer lifetime:** external queue sender stages data in its own RAM; no runtime proof that this staging remains intact until the group-13 source snapshot copy.
- **The real Recorder P:** `type=0x20B` descriptor `+0x10` is the *sequence word* of the message, while `type=0x200` initializer treats `+0x10` as its *current configuration pointer*. Neither a conversion between these contexts nor the initial `P+0x581` value/writer has been identified.
- **Recording capability:** no sensor/ISP 4K59.94 stream, working Main10 HEVC SPS, actual 10-bit internal recording, sustained output rate, or safe camera firmware patch has been demonstrated. X-S10-specific firmware permission remains unproved.

## 7. Reproducibility and published files

Only independent original code, artificial test vectors and this narrative are suitable for GitHub:

- `tools/audit_stage55_recorder_20b_fsm_lifecycle.py` independently reruns SHA-pinned original prior Phase54 and all its dependencies, then checks group4/group13 routing, callback state guard, registry record pointer, ARM save/full-copy order, four failure gates, success-only zeroing and original bytewise memset.
- `tests/test_audit_stage55_recorder_20b_fsm_lifecycle.py` has **183 ROM-free synthetic unit tests**, including bit changes to Ghidra-confirmed A32 fields, incorrect message and state types, swapped order, incorrect state-group identity, missing ARM branches or C direction, and pointer lifetime counterexamples.
- `docs/phase55-recorder-20b-fsm-registry-lifecycle-2026-10-21.md` is this report.

Local original audit result: `STAGE55 ORIGINAL 0x20B FSM REGISTRY SAVE / SNAPSHOT / SUCCESS CLEAR PASS`. Entire Ubuntu offline regression: **91 tracked + 3215 ignored = 3306/3306 tests PASS**, including 183 newly written synthetic tests. Original firmware, Ghidra database, full Ghidra decompilation logs and machine-specific original audit output remain exclusively in the Git-ignored `output/` folder.

Re-run *after producing the local Stage55 read-only Ghidra logs* using repository `ghidra_scripts/TraceX6Function.java` on both merged projects:

~~~bash
cd /home/zyubuntu/xs10hk
PYTHONPATH=tools:output python3 tools/audit_stage55_recorder_20b_fsm_lifecycle.py --output output
PYTHONPATH=tools:output python3 -m unittest discover -s tests -q
PYTHONPATH=tools:output python3 -m unittest discover -s output -p 'test_*.py' -q
~~~

The Stage55 audit uses the private log basenames `xs10/xt4_stage55_fsm_callchain`, `stage55_type20b_profile_save_fsm`, `stage55_zero_fill_helper_trace`, `stage55_fsm_driver_routing` (each `.log`) generated by the existing Ghidra read-only Trace script; their source function entry addresses are listed above. The cross-phase SHA evidence and original vendor Section1/2 files are required on the authorized Ubuntu only.

**Highest-value Phase56 task:** reconstruct the specific event/group13 state-table transition from a previously received group4 `type=0x20B` message, including how a real `0x20B` descriptor payload survives, how the 0x200 current-P initialization later obtains its own valid pointer, and where original `P+0x581` values are first produced. Avoid converting static path potential into a firmware unlock claim, and never run hardware FF80/flashing without a separate, explicit, appropriate safety plan.