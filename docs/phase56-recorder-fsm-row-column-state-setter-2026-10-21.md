# Phase56 | Recorder 0x20B event dispatch: real FSM row/column and state setter

**Authorized Ubuntu, 2026-10-21.** Original X-S10 3.11 and X-T4 2.12 Section2 ARM, read-only Ghidra 12.1.4. No camera USB/FF80, RAM/Flash, vendor ROM modifications, patch or flash. Real camera was previously v2.10; no address portability is implied. All ROM binaries and full Ghidra logs remain in gitignored `output/`.

## Finding 1: Group4 and group13 are separate two-dimensional callback matrices

| Source | X-S10 | X-T4 |
|---|---|---|
| Group callback pointer array | `0x0266A5F8` | `0x025C4AD0` |
| Group event pointer array | `0x0266A8B8` | `0x025C4D94` |
| Group4 event table, width 7 | `0x026639C4` | `0x025BDA80` |
| Group4 function table | `0x0266A5B8` | `0x025C4A90` |
| Group13 event table, width 5 | `0x02665B7C` | `0x025BFC38` |
| Group13 function table | `0x02665D90` | `0x025BFE4C` |
| Group4 classifier and cursor RAM | `0x0327DEDC`; `0x031BF494` | `0x032AAE9C`; `0x031ECC54` |
| Group13 classifier and cursor RAM | `0x0327DEEE`; `0x031BF4A6` | `0x032AAEAE`; `0x031ECC66` |

Normal module7 incoming type `0x20B` falls through Recorder type classifier to **group4 row5**, which has these seven `(function index, cursor delta)` entries on both models: `(8,+1), (9,+1), (10,+1), (2,+1), (11,+1), (12,+1), (13,+1)`. Actual runtime column is unknown. This is **not** the same function table as group13.

**CORRECTION to Phase55 prose:** Group13 source-snapshot controller stub is in function table **index 4** (base `+0x10`), not index 2. Group13 first two event rows have entries:

```
        col0     col1     col2     col3     col4
row0   (2,1)    (3,1)    (3,1)    (3,1)    (3,1)
row1   (4,1)    (5,1)    (5,1)    (5,1)    (5,1)
```

Thus row1 **and column0** is required to select group13 index4, whose callback pointer is `0x021CDF50` / `0x0213751C`. Index2 instead points to `0x021CDF20` / `0x021374EC`. All raw ROM values are asserted. The index4 callback branches to the Phase55 source-snapshot controller only when its separate 16-bit state is **not `0x102`**.

## Finding 2: state setter actually invokes group13 classifier

| Location | X-S10 | X-T4 |
|---|---|---|
| Setter | `FUN_0221CA7C` | `FUN_02189490` |
| State RAM base (byte0 and halfword+2) | `0x035BD860` | `0x03672070` |
| Original `STRB R0` and `STRH R1` | `0x0221CA8C/90` | `0x021894A0/A4` |
| BL to group13 classifier | `0x0221CA94` -> `FUN_021BA418` | `0x021894A8` -> `FUN_02122C0C` |
| Distinct call with `(1,0xA9)` | `0x021CA144` | `0x02133710` |
| Distinct call with `(1,0x102)` | `0x021C6928` | `0x0212FF0C` |

The setter stores both ARM arguments to its state object and calls the classifier. When byte0==1, the classifier sets group13 row1 and dispatches group13. If the **runtime column is 0**, this picks index4; with second argument `0xA9`, the index4 guard `state != 0x102` is satisfied and the controller **may** run. With second argument `0x102`, the same index4 callback **quickly returns** and does not run the controller. These are static conditional paths, not observations that a delivered `0x20B` message invokes those callers.

## Remaining proof gaps

1. What exact event and state transition takes a real delivered module7 `0x20B` from group4 to this **separate group13** status setter? The existence of multiple callers is not proof of that edge.
2. What sets the group13 runtime cursor to column0 and how does it evolve across consecutive messages?
3. Is the sender GUI staging pointer still valid when the separately gated source-snapshot memcpy runs? Does data reach current Recorder input P under the distinct `type=0x200` descriptor?
4. The first producer of P+`0x581`, an actual HEVC Main10 bitstream, and 4K60 internal recording remain **unproven**.

## Audit and tests

Original auditor: `tools/audit_stage56_fsm_20b_group4_to_13_selector.py` recursively revalidates original ROM/SHA Phase55 and earlier evidence, then validates all distinct ROM pointer tables, event rows, width words, 1/A9 vs 1/102 A32 setter sites, callback identities and `group4`/`group13` classification. Synthetic-only tests: `tests/test_audit_stage56_fsm_20b_group4_to_13_selector.py`, **110 tests**. Read-only original Ghidra traces and ROM remain private under `output/`. No executable vendor code, proprietary binary or private decompiled output published.