# LLVM backend: measured results

Evidence for the four changes in this branch. Every number here was produced by
the protocol in [Methodology](#methodology); the caveats in
[What these numbers do not show](#what-these-numbers-do-not-show) are part of
the result, not footnotes to it.

**Reference title:** Mario Kart: Double Dash!! (`GM4E01`), save state
`states/race.sav` (Luigi Circuit, lap 1, throttle held) unless noted. One title
is a real limitation — see the caveats.

**Overall arc.** Across the campaign the LLVM backend moved from **0.49x to
0.957x of a PGO'd C build** of the same title, and ended **correct at the
interpreter floor** — zero architectural divergences under exact-match lockstep,
the same result the C backend gets.

| stage | standing vs PGO'd C |
| --- | --- |
| campaign baseline | 0.4897 |
| + register-allocator chunk sizing (uniform-64) | ~0.527 |
| + IR-level PGO, single-scene profile | **0.9587** |
| + IR-level PGO, twelve-course profile | **0.9573** (single-player) |

---

## Methodology

Performance claims come from interleaved A/B series, not from single runs. The
protocol exists because this host is not stable enough for anything weaker: the
baseline drifted monotonically **0.8977 → 0.9989** across one session as the
machine cooled, which is larger than most of the effects being measured.

- **Interleaved pairs.** Minimum 5 alternating A/B pairs; the standard series
  here is 12 — **six forward pairs, then six with the arm order reversed**.
  Interleaving alone does not remove monotonic drift, so the reversed block is
  what makes a claim survive it. Where a reversed block is *worse* for the arm
  than the forward block, that is reported.
- **Same-session controls.** Every ratio is against a control measured in the
  same session on the same host, never against an archived number. Controls are
  expected to reproduce their own history, and where they do it is stated (the
  fixed-128 control reproduces across five experiments: 0.5506, 0.5513, 0.5515,
  0.5517, 0.5518, 0.5520, 0.5521, 0.5524, 0.5540, 0.5560).
- **Noise floor ±1.4%**, pair-to-pair. A result inside it is reported as a null,
  not as a small win.
- **Ranges, not just medians.** Every table gives the pair range and the count
  of pairs favouring the arm. "Disjoint" means the arm's worst run beat the
  control's best run.
- **Run conditions.** Uncapped, throttle held, 20 s warmup / 30 s measured,
  High Performance power plan. Effective FPS is `speed × 59.94` — never the
  runtime's own `fps` counter, which is a present rate.
- **Provenance.** Fresh isolated output root per arm. The intended IR or
  assembly change is verified **present in the artifact** before a number is
  believed — a cache hit is not proof a change was tested. Where two arms are
  meant to share objects, that is verified by hash.

**Correctness oracle: exact-match lockstep against the interpreter.** The
recompiled module and the interpreter are stepped in lockstep and full
architectural state is compared at every verified dispatch — GPRs, FPRs, `ps1`,
SPRs, RAM, locked cache, vmem, and the MMIO write sequence. Divergences are
classified; the `fpscr`-only bucket is a characterised harness artifact present
on **both** backends and is reported separately from architectural divergence.

---

## 1. O(1) dispatcher lookup

Replacing the linear chunk-table scan with a page index, **on a byte-identical
object set** — the two arms differ only in the dispatcher.

| series | control | arm | ratio | pairs | pair range |
| --- | --- | --- | --- | --- | --- |
| **irregular plan** | linear 0.3054 | **indexed 0.4884** | **1.5992** | **12/12** | +57.70% .. +63.10% |
| **uniform fixed-128** | linear 0.5515 | indexed 0.5513 | **0.9995** | 6/12 | -1.32% .. +1.86% |
| uniform-64 | linear 0.5748 | indexed 0.5940 | **1.0377** | 12/12 | +1.73% .. +5.26% |

**+59.9% where the chain is long, and a null where it is short.** On the
irregular plan the linear chain was 2,089 tests; the index removes it and 12/12
pairs agree with ranges nowhere near touching. On uniform fixed-128 the chain
was already 2 tests, so 0.9995 with 6/12 pairs and a mean pair delta of 0.01% is
a null inside the ±1.4% noise floor — **it costs the shipping configuration
nothing.**

**One honest complication:** at uniform-64 the indexed lookup *is* worth ~3.7%
(12/12 pairs), which does not reproduce D001's null at fixed-128. The value of
the fix scales with how much scanning the plan actually causes, and a uniform
plan with more chunks still causes some. Reported rather than reconciled.

**Cross-checks.** The irregular arm re-measured 0.3054 against its own archived
0.3011, rebuilt on current tools three experiments later; the fixed-128 arm
measured 0.5513 and 0.5524 in two different series against a third series'
0.5515.

**Correctness:** the dispatcher change holds the backend at the C floor — 0
architectural divergences.

**Covered by** the existing `tests/test_dispatch.c`, extended here (+54 lines) to
check the indexed path against the linear one for equivalence. It passes.

---

## 2. Register-allocator chunk sizing

The LLVM chunk size inherited the C backend's 1024-instruction default. That is
the wrong constant for a register allocator that keeps the whole guest register
file live across a chunk.

| plan | stride | power of two | ratio vs fixed-128 | pairs | ranges |
| --- | --- | --- | --- | --- | --- |
| fixed 32 | 128 B | yes | **0.7165** | 0/12 | disjoint |
| **fixed 64** | 256 B | yes | **1.0759** | **12/12** | **disjoint** (+5.85% .. +9.38%) |
| fixed 96 | 384 B | no | **0.6451** | — | — |
| fixed 128 | 512 B | yes | 1.000 | — | — |
| fixed 160 | 640 B | no | 0.9708 | 0/12 | disjoint, barely |

**64 is the knee, and it is a knee, not a slope.** Uniform-64 is **+7.6%** over
fixed-128 with 12/12 pairs and disjoint ranges. Halving again *reverses*:
uniform-32 loses **28.4%**, 0/12, arm best 0.3996 against control worst 0.5424.
The census says why this is at least plausible — at 32 instructions the plan
carries 3,261 cross-to-start and 67,617 cross-to-mid transfers, 5.9x and 1.3x
the fixed-128 baseline, and a cross-chunk edge costs a materialize, a call, a
returned-pc compare and a reload. Below 64, edge cost buys more than allocator
scope saves.

**A tempting hypothesis, falsified from both sides.** Stride being a power of
two does *not* explain the curve: 160 (not a power of two) is fine at -2.9%,
sitting where a smooth curve between 128 and 192 would put it, while 32 (a power
of two) tanks. 96's 35% loss remains a lone unexplained anomaly. Recorded so
nobody rebuilds on it.

Earlier evidence, superseded but relevant: against the original 1024 default,
128 was **+57.9% throughput and -66% .text**. An early chunk-64 arm measured
only +1.4% with *overlapping* ranges and was correctly rejected as unproven at
the time — it only became a real result under the indexed dispatcher.

**Correctness:** both arms at the C floor — 0 architectural divergences, 0 `ps1`
appearances.

Default here is 128, overridable with `DOLRECOMP_LLVM_CHUNK_INSTRUCTIONS`;
64 is the best-known setting on the reference title.

---

## 3. IR-level instrumentation PGO

| series | control | arm | ratio | pairs | pair range |
| --- | --- | --- | --- | --- | --- |
| **PGO, both halves** | unprofiled 0.6071 | **profiled 1.0527** | **1.7341** | **12/12** | +71.80% .. +77.13% |
| C half only (attribution) | 0.6046 | 0.6431 | 1.0638 | 12/12 | +4.79% .. +7.24% |
| **vs PGO'd C reference** | PGO'd C 1.1030 | 1.0574 | **0.9587** | 0/12 | -5.47% .. -2.16% |

**+73.4%, the largest single result in the campaign by a factor.** 12/12 pairs,
ranges nowhere near touching (arm worst 1.0415 against control best 0.6203).
The attribution control matters: the C half of the same module contributes only
1.0638, so the **LLVM-emitted chunks' own share is 1.6301** — the win is in the
backend's objects, not smuggled in by the C half.

In FPS: **63.4 FPS against the PGO'd C reference's 66.1** on the reference
scene, up from a starting point of 0.527.

**Why this was available and had been missed.** The premise "a profile cannot
attach to IR-emitted objects" is true of **sample** profiling only. AutoFDO
binds counts to source lines and the emitter attaches no `DILocation` anywhere
(verified by grep — not one `setDebugLoc` in the backend), so a sample profile
has nothing to bind to. IR-level *instrumentation* PGO needs no debug info at
all: `PGOInstrumentationGen`, `PGOInstrumentationUse` and
`InstrProfilingLoweringPass` over the module the backend already builds. No
CMake change, no new dependency, ~60 lines.

### Profile breadth

Training the profile on **twelve distinct courses** instead of one:

| series | control | arm | ratio | pairs | pairs clearing 95% |
| --- | --- | --- | --- | --- | --- |
| **single-player** | PGO'd C 1.0923 | **1.0456** | **0.9573** | 0/12 | **10/12** |
| **split-screen** | PGO'd C 0.8872 | **0.8320** | **0.9378** | 0/12 | **3/12** |
| breadth's price on the single scene | 1.0429 | 1.0296 | 0.9872 | 2/12 | — |

**Breadth buys consistency, not median speed.** 0.9573 against the single-scene
0.9587 is a non-move inside the ±1.4% noise floor. What changed is the spread:
sub-95% pairs **4 → 2**, and the pair range narrows from 3.31 points to
**1.69**. That is what a profile that is not over-fitted looks like.

**Count distinct tracks, not scenes.** The obvious first attempt — merging three
save states — measured **0.9546**, *below* the single-scene result, because all
three states were the same course. Scene count is not the axis.

**Correctness:** at the C floor under exact-match lockstep.

---

## 4. ps1 correctness fix

This one is a correctness result, not a performance one.

Lockstep found the LLVM backend diverging from the interpreter on `ps1` — the
high slot of a paired-single register — with native values carrying
`0x4330000000000000`, the int-to-double conversion bias. Two DolIR builder sites
splatted a scalar result into both slots where Gekko writes ps0 only.

| | PGO'd C (floor) | LLVM before | **LLVM after fix** |
| --- | --- | --- | --- |
| architectural divergences | 61 (0.63%) | 301 (5.20%) | **270 (4.75%)** |
| `ps1`/`fpscr`-only reports | 307 | 965 | **311** |
| **`ps1` field appearances** | 70 | **2,180** | **383** |
| `ps1` in `ps1`/`fpscr`-only reports | 70 | — | **0** |

**The `ps1` class is eliminated.** `ps1` appearances fell 2,180 → 383, the
`ps1`/`fpscr`-only bucket fell 965 → 311 (landing on the C backend's own floor
of 307), and **not one** of those 311 reports contains a `ps1` field — they are
all `fpscr`. Where `ps1` still differs, all 383 appearances now co-occur with
GPR or memory divergence, so it is a downstream symptom rather than a cause.

**Be precise about what this fix did and did not do.** Architectural divergences
moved only 301 → 270. A second, larger and independent defect remained at this
point, and the campaign's final "at the C floor" result came later, after the
verification harness itself was corrected (an arrival-matching artifact was
inflating counts on **both** backends).

**The load-bearing evidence is the control.** Under the final, corrected oracle:

| arm | blocks | reports | architectural | `ps1` appearances |
| --- | --- | --- | --- | --- |
| PGO'd C | 9,642 | 307 | **0 (0.00%)** | 0 |
| **LLVM, with fix** | 5,713 | 319 | **0 (0.00%)** | 0 |
| LLVM, pre-fix (control) | 5,717 | 1,039 | **34 (0.59%)** | **1,813** |

Both arms going to zero is exactly what a broken metric looks like, so the same
oracle was pointed at the pre-fix module whose defect is known and
characterised: it still reports 34 architectural divergences and 1,813 `ps1`
appearances, led by the `mem[]`/`ps1` signature. **The metric distinguishes the
module with the known defect from the one without it** — which is what makes
"0.00%" a result rather than an artifact.

The C emitter always had both guards, which is why C never showed this class.
DolIR feeds the LLVM pipeline only, so **no C codegen changes.** Bumps
`DOLLLVM_CACHE_VERSION` to v7.

---

## What these numbers do not show

- **Split-screen is ~6% short.** 0.9378 with only 3/12 pairs clearing 95%,
  against 0.9573 and 10/12 for single-player. More profile training does not fix
  it; it is a known limit, recorded rather than resolved.
- **One title, one host.** Everything here is `GM4E01` on a single Windows
  machine. The mechanisms argued for (allocator scope vs edge cost, chain length
  vs index) should generalise; the *magnitudes* should not be assumed to.
- **The gate passes on the median, not on every pair.** 0.9587 and 0.9573 clear
  95%; individual pairs do not all clear it.
- **This branch is built and tested, but not re-benchmarked.** The commits were
  rebased onto upstream `main` and de-entangled by hand from experimental work
  that is not included here. The result builds clean with
  `-DDOLRECOMP_ENABLE_LLVM=ON` against LLVM 20.1.8 and passes the repository
  suite — **18/19 with the LLVM backend enabled**, including `dispatch`,
  `llvm_backend`, `llvm_execute` and `llvm_pipeline`. The single failure,
  `codegen_compile`, reproduces identically on unmodified upstream `main` in the
  same environment (a nested CMake invocation with no resource compiler
  configured) and is unrelated to these changes. **The performance numbers above
  were not re-measured against this exact commit series** — they come from the
  campaign builds these commits were extracted from.
- **96 is unexplained.** A 35% loss at uniform-96 with no mechanism. Whatever it
  is, the power-of-two theory is not it.
