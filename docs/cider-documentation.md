# scx_cider — Scheduler Documentation
**Full name:** Context-Informed Deficit-Execution Round-robin
**Status:** Production — Contextually Optimized
**Last updated:** 2026-03-25

---

## Name and Philosophy

### What the acronym means

**CIDER** = **C**ontext-aware · **I**nterrupt-sensitive · **D**eficit-round-robin · **E**xecution-optimized · **R**outer

Each word maps directly to a real mechanism in the scheduler:

| Letter | Word | Mechanism |
| :----- | :--- | :-------- |
| **C** | Context-aware | Understands *why* a task needs to run: lock holder state, waker chain, hardware event source |
| **I** | Interrupt-sensitive | Detects IRQ and softirq wakeup origins and grants immediate T0 priority |
| **D** | Deficit-round-robin | DRR++ is the core queuing algorithm, adapted from network CAKE |
| **E** | Execution-optimized | All classification math runs at `stopping` time; `enqueue` is a pure memory read |
| **R** | Router | Routes every task to the optimal LLC DSQ and tier based on behavioral and contextual signals |

### From CAKE to CIDER: the philosophical shift

The original `scx_cider` had a single governing insight: **unfairness is a feature**. A scheduler optimized for gaming should not treat a background compiler and an audio callback as equals. Tasks earn their tier by *behavioral evidence* — the EWMA of their actual runtime. Short runtimes indicate latency sensitivity; long runtimes indicate bulk work. Tiers encoded in vtime do the rest.

This philosophy was correct but **context-blind**. CAKE knew how long tasks historically ran, but nothing about the circumstances of any specific wakeup. Two problems followed:

1. **Delayed IRQ responsiveness.** A mouse click interrupt wakes an input handler. That handler has a short EWMA (T0), so it classifies correctly after a few bouts — but *on its very first wakeup*, before any EWMA data exists, it starts at T1 (the nice-0 default). The same delay applies to any task woken by a GPU V-sync, audio DMA completion, or network packet arrival: the hardware event urgency is invisible to CAKE.

2. **Priority inversion through lock holders.** When a T3 bulk task holds a futex protecting a game's vertex buffer, preempting it at the starvation threshold forces every thread waiting on that lock to block — including T0 audio and T1 compositor threads — until the holder is rescheduled and completes its critical section. CAKE's starvation preemption was designed to protect high-priority tasks from low-priority ones, but it was inadvertently *worsening* latency in this case.

CIDER fixes both by adding a second classification dimension: **causal context**. The scheduler now tracks not just *what a task does* (EWMA runtime) but *what just happened* (hardware interrupt, waker priority, lock state). The two dimensions are combined at enqueue time to produce the final dispatch priority:

```
dispatch_priority = f(behavioral_tier, causal_context)
```

Where:
- `behavioral_tier` = EWMA avg_runtime classification (T0–T3), unchanged from CAKE
- `causal_context` = one-shot signals from IRQ source, waker tier inheritance, and lock holder state

Behavioral tier is the *long-term prediction*. Causal context is the *short-term override*. Neither replaces the other.

The core philosophy remains: **unfairness is a feature**. What changed is the scheduler's ability to identify which tasks deserve unfair advantage at any given moment, even before their behavioral history has settled.

### What percentage is CAKE, what percentage is LAVD?

By raw lines of BPF code: approximately **75% CAKE, 25% LAVD-derived**.

By architectural decisions: approximately **90% CAKE, 10% LAVD**.

The DRR++ algorithm, 4-tier EWMA classification, per-LLC DSQ architecture, mega-mailbox, kfunc tunneling, asymmetric EWMA decay, hysteresis tier gates, graduated backoff, SYNC fast path, DVFS tier table, profile system, ETD topology calibration — all of this is CAKE. LAVD contributed three targeted mechanisms (IRQ detection, waker inheritance, futex probing) that plug specific gaps in CAKE's context-blindness.

By *impact at the margin* — specifically, by contribution to the latency improvement in the cases where CAKE was weakest — the LAVD features punch considerably above their 10–25% code weight. A scheduler spends 99% of its time on the common path and 1% on edge cases, but it is judged by the edge cases.

---

## Architecture Overview

CIDER inherits CAKE's full scheduling pipeline and adds three context-signal layers, each confined to a single callsite:

```
Hardware event
      │
      ▼
cider_select_cpu ─── [NEW] IRQ detection ────────────────► CAKE_FLOW_IRQ_WAKE flag
      │                    (bpf_in_hardirq / bpf_in_serving_softirq / ksoftirqd)
      │
      ├── SYNC fast path ──► dispatch_sync_cold ─── [NEW] consume IRQ_WAKE → T0 slice
      │
      ├── Idle path ───────► SCX_DSQ_LOCAL_ON ───── [NEW] consume IRQ_WAKE → T0 slice
      │
      └── All busy ─────────────────────────────────────────────────┐
                                                                     │
                                                                     ▼
                                                              cider_enqueue
                                                                     │
                                                         [NEW] Feature 1: IRQ tier override
                                                         [NEW] Feature 2: Waker tier inheritance
                                                         [NEW] Feature 3: Lock holder vtime advance
                                                                     │
                                                                     ▼
                                                         per-LLC DSQ (vtime = tier<<56 | ts)
                                                                     │
                                                                     ▼
                                                              cider_dispatch
                                                                     │
                                                              cider_running
                                                                     │
                                                              cider_tick ──── [NEW] Lock holder starvation skip
                                                                     │
                                                              cider_stopping (reclassify_task_cold)
                                                              EWMA update → behavioral tier for next dispatch

Futex acquire/release (any time, via fexit probes in lock_bpf.c):
      └── set/clear CAKE_FLAG_LOCK_HOLDER in packed_info atomically
```

### The 4-tier system (unchanged from CAKE)

Tasks are classified into four tiers purely by EWMA of `avg_runtime_us`, computed at every `cider_stopping` call:

| Tier | Name | Runtime gate | Typical tasks |
| :--- | :--- | :----------- | :------------ |
| T0 | Critical | < 100µs | IRQ handlers, mouse input, audio callbacks |
| T1 | Interactive | < 2ms | Compositor, physics, AI |
| T2 | Frame | < 8ms | Game render threads, encoding |
| T3 | Bulk | ≥ 8ms | Compilation, background indexing |

Tiers are encoded in vtime bits [63:56], ensuring T0 tasks always drain before T1 tasks within the same LLC DSQ regardless of arrival order. Per-tier quantum multipliers (T0: 0.25–0.5×, T3: ~4×) and starvation thresholds govern how long each tier can run and how urgently it preempts.

### The three context-signal layers (new in CIDER)

#### Layer 1: IRQ-source wakeup boost

**Where:** `cider_select_cpu`, and all three dispatch paths that bypass `cider_enqueue`.

**What:** When a wakeup originates from a hardirq, NMI, softirq bottom-half, or a `ksoftirqd` kernel thread, the task is flagged with `CAKE_FLOW_IRQ_WAKE` atomically on its `packed_info`. This flag is consumed (cleared) on whichever dispatch path fires first — SYNC direct dispatch, idle direct dispatch, or `cider_enqueue` — and grants T0 tier priority for that one dispatch only.

**Why:** A mouse click interrupt completes, the kernel wakes the input handler, and the input handler should run at T0 immediately. Without this signal, the handler waits for its EWMA to settle across 3–5 bouts. With it, the first dispatch is always T0 regardless of history.

The flag is strictly one-shot and never touches the EWMA. The behavioral classification is unaffected.

#### Layer 2: Waker tier inheritance

**Where:** `cider_enqueue`, on `SCX_ENQ_WAKEUP` paths only.

**What:** When a wakeup enqueue fires, the waker's tier is read from `mega_mailbox[enq_cpu].flags` (set by `cider_tick` on every timer tick). If the waker's tier is lower than the wakee's, the wakee is promoted to at most `waker_tier + 1` for this dispatch only.

**Why:** A T0 input handler wakes a T2 game event dispatcher. Without inheritance, the dispatcher sits in the T2 queue for up to 40ms. With inheritance, it runs at T1 for this dispatch. The EWMA will independently converge toward T1 if this producer–consumer pattern is consistent.

Constraints: only on wakeup (not preempt or yield); never promotes above T0; never demotes; only fires when `tick_counter > 0` (mailbox has been initialized); does not alter `packed_info` or EWMA.

#### Layer 3: Futex lock-holder protection

**Where:** `lock_bpf.c` (fexit probes set/clear the flag), `cider_enqueue` (vtime advance), `cider_tick` (starvation skip).

**What:** `fexit` probes on all futex acquire/release functions detect when a task holds a contended lock. `CAKE_FLAG_LOCK_HOLDER` is set atomically in `packed_info` on acquisition and cleared on release. Two effects follow:

1. **Vtime advance** (`cider_enqueue`): the lock holder's virtual timestamp is subtracted by `new_flow_bonus_ns` within its tier, sorting it ahead of same-tier non-holders. It runs sooner and releases the lock faster. The tier itself is unchanged — a T3 bulk task with a lock is not promoted to T0, it just moves to the front of the T3 queue.

2. **Starvation skip** (`cider_tick`): if the lock holder exceeds its starvation threshold, the preemption kick is skipped. The unconditional slice expiry check (`runtime > next_slice`) still applies as a hard ceiling.

**Why:** Preempting a lock holder causes priority inversion. Every task waiting on the lock is blocked until the holder is rescheduled and releases it — which may be longer than just letting the holder finish its critical section in the first place. Wine/Proton holds D3D command-list mutexes across full frame submissions. Audio frameworks hold mixing locks during T0 callbacks. This mechanism makes lock-holder behavior predictable without requiring application annotation.

Both fexit probes (low overhead, ~50ns) and syscall tracepoints (fallback, ~130ns) are implemented. Both paths are `SEC("?...")` — the scheduler loads correctly even if neither attaches, with no lock-holder boost in that case.

---

## CPU Cycle Audit
**Status:** Contextually Optimized (slight increase in select_cpu; enqueue remains near speed-of-light)
**Date:** 2026-03-25

Counts are estimates based on BPF instruction complexity (x86_64 JIT).

### Legend
- **ALU:** Arithmetic Logic Unit. Cost: ~0.5–1 cycle.
- **L1 Load:** Memory read from L1 cache. Cost: ~4 cycles.
- **Map:** BPF task storage get. Cost: ~20–50 cycles.
- **Atomic:** `__sync_fetch_and_or/and`. Cost: ~5 cycles (L1 hit, no contention).
- **Helper:** Kernel helper call. Cost: ~50+ cycles.

### Global Summary

| Function | Role | Frequency | CAKE Cost | **CIDER Cost** | Delta |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`cider_select_cpu`** | Core pick + IRQ detect | High | ~5c | **~26c** | **+21c** |
| **`cider_enqueue`** | Wakeup dispatch | Extreme | ~2c | **~8c** | **+6c** |
| `cider_dispatch` | DSQ consume | Very high | ~5c | **~5c** | 0 |
| `cider_tick` | Slice/starvation check | High | ~55c | **~57c** | +2c |
| `cider_stopping` | EWMA + reclassify | High | ~85c | **~85c** | 0 |
| `cider_running` | Timestamp stamp | High | ~50c | **~50c** | 0 |
| `lock_bpf` probes | Futex set/clear | Low | 0 | **~50ns fexit** | new |
| **Total Round Trip** | **End-to-End** | **Per Task** | **~137c** | **~164c** | **+20%** |

The +20% increase is entirely in `select_cpu` and `enqueue`, which are the two callsites that now carry context-signal processing. The critical `cider_dispatch` path (the tightest loop under sustained load) is unchanged.

---

### 1. `cider_select_cpu` (Wakeup Decision + IRQ Detection)

**Frequency:** High
**Change:** IRQ context detection adds one unconditional map lookup.

| Operation | Type | Cost | Notes |
| :--- | :--- | :--- | :--- |
| `bpf_task_storage_get` (IRQ detect) | Map | 20 | New: unconditional, enables IRQ flag write |
| `bpf_in_hardirq/nmi/softirq` checks | ALU | 2 | `unlikely()` — near-zero on common path |
| `__builtin_memcmp` (ksoftirqd check) | ALU | 2 | `unlikely()` — waker comm comparison |
| Atomic OR (set IRQ_WAKE flag) | Atomic | 5 | `unlikely()` — only on IRQ wakeup |
| `scx_bpf_select_cpu_dfl` | Helper | ~10 | Kernel idle detection (unchanged) |
| Idle path: IRQ_WAKE check + atomic clear | ALU+Atomic | 8 | Replaces old simple slice read |
| **Total new logic overhead** | | **~27c** | **+21c vs CAKE** |

The +21c cost is the price of one bpf_task_storage_get. It is unavoidable if we want to set a flag on the task before any dispatch path fires. On the SYNC fast path (most gaming wakeups), `dispatch_sync_cold` now avoids a *second* redundant lookup since it shares the same tctx logic, partially offsetting this cost.

---

### 2. `cider_enqueue` (Task Wakeup — All-Busy Path)

**Frequency:** Extreme (every wakeup when no idle CPU)
**Change:** Three feature checks added after the existing tier lookup.

| Operation | Type | Cost | Notes |
| :--- | :--- | :--- | :--- |
| `get_task_ctx` | Map | 20 | Unchanged |
| `GET_TIER` | L1 Load | 1 | Pre-computed at stopping (unchanged) |
| `GET_SLICE` | L1 Load | 1 | Pre-computed at stopping (unchanged) |
| `packed_info` load (once, shared) | L1 Load | 1 | **New: single read, amortized across all three checks** |
| Feature 1: IRQ_WAKE check | ALU | 1 | `unlikely()` — near-zero when not IRQ wake |
| Feature 1: atomic AND (clear flag) | Atomic | 5 | `unlikely()` — only on IRQ wakeup |
| Feature 2: mailbox L1 read | L1 Load | 4 | **Steady-state cost — always paid on WAKEUP** |
| Feature 2: tick_counter + tier compare | ALU | 2 | Small; branch not-taken when waker >= wakee |
| Feature 3: LOCK_HOLDER check | ALU | 1 | `unlikely()` — near-zero when not a lock holder |
| Feature 3: ts subtract (lock advance) | ALU | 1 | `unlikely()` |
| `dsq_insert_vtime` | Helper | 50 | Unavoidable (unchanged) |
| **Total new logic overhead** | | **~8c** | **+6c vs CAKE (Feature 2 dominates)** |

The steady-state cost on a gaming system (no lock holders, occasional IRQ wakes) is dominated by Feature 2's mailbox read: one L1 load + two ALU ops = ~6c. Feature 1 and 3 are `unlikely()` branches that add zero cycles when not taken.

---

### 3. `cider_dispatch` (Hot Path)

**Frequency:** Very High
**Change:** None.

| Operation | Type | Cost | Notes |
| :--- | :--- | :--- | :--- |
| `scx_bpf_dsq_move_to_local` | Helper | 20–50 | Unavoidable |
| LLC steal bitmask scan | ALU | 5 | O(1) via BSF |
| **Total** | | **~30** | **Unchanged** |

---

### 4. `cider_tick` (Starvation + Lock Check)

**Frequency:** High (every scheduler tick under load)
**Change:** Lock holder check before starvation kick.

| Operation | Type | Cost | Notes |
| :--- | :--- | :--- | :--- |
| Runtime computation | ALU | 3 | Unchanged |
| `cider_get_rq` + `nr_running` read | Helper+L1 | 20 | Graduated backoff (unchanged) |
| Starvation threshold unpack | ALU | 2 | RODATA access (unchanged) |
| `packed_info` load (lock check) | L1 Load | 1 | **New: only when starvation would fire** |
| LOCK_HOLDER flag test | ALU | 1 | **New: `unlikely()` — zero on common path** |
| `scx_bpf_kick_cpu` | Helper | 50 | Unchanged, skipped for lock holders |
| Mailbox + DVFS update | L1+Helper | 15 | Unchanged |
| **Total new overhead** | | **~2c** | **Only inside the starvation threshold branch** |

The lock holder check adds exactly 2 cycles to the starvation-exceeded branch (`unlikely()`) and zero cycles to all other tick paths.

---

### 5. `cider_stopping` (EWMA + Reclassification)

**Frequency:** High (every context switch)
**Change:** None. The EWMA classification is deliberately unchanged — context signals are layered *on top of* the EWMA result, not mixed into it.

| Operation | Type | Cost | Notes |
| :--- | :--- | :--- | :--- |
| `get_task_ctx` | Map | 20 | |
| Runtime measurement | ALU | 5 | ns → µs shift |
| EWMA update (asymmetric) | ALU | 8 | promote α=1/4, demote α=1/16 |
| Tier classification (hysteresis) | ALU | 6 | Precomputed gate tables |
| Deficit tracking | ALU | 4 | DRR++ |
| Slice recalculation (tier change) | ALU | 5 | Only on tier change |
| **Total** | | **~85c** | **Unchanged** |

---

### 6. `lock_bpf.c` Probes

**Frequency:** Low (contended lock acquire/release only)
**Type:** New file — optional `fexit` probes with tracepoint fallback.

| Path | Overhead | Notes |
| :--- | :--- | :--- |
| `fexit/__futex_wait` (and variants) | ~50ns | Low overhead; fires only on contended lock acquisition |
| `fexit/futex_wake` (and variants) | ~50ns | Fires on lock release |
| Tracepoint fallback | ~130ns | Used when fexit symbols unavailable |
| `bpf_task_storage_get` inside probe | ~20c | Only fired on lock operations (rare) |
| Atomic OR/AND on `packed_info` | ~5c | Lock-free; no contention with scheduling hot path |

Probes are entirely `SEC("?...")` — the scheduler loads and runs correctly if no probes attach, with lock-holder protection simply disabled.

---

## Scheduling Philosophy

### The DRR++ Core (from CAKE)

The Deficit Round Robin Plus-Plus algorithm governs intra-tier fairness. Every task starts with a deficit credit of `quantum + new_flow_bonus`. Each execution bout consumes deficit proportional to runtime. When deficit exhausts, the new-flow priority bonus is cleared and the task competes on equal vtime footing with peers in its tier.

This is the CPU-scheduling analog of network CAKE's DRR for flow queuing. Just as CAKE-the-queueing-discipline prevents a single network flow from monopolizing a link, CIDER prevents a single CPU task from monopolizing a tier.

### Tier Encoding in Vtime

The vtime encoding `(tier << 56) | timestamp` is the architectural core of cross-tier priority. Within the per-LLC DSQ, tasks sort first by tier (bits 63:56), then by arrival time within the same tier. A T0 task arriving 100ms after a T1 task still dispatches before the T1 task.

Context signals (IRQ wake, waker inheritance) change the `tier` variable used in this encoding for one dispatch. They do not write to `packed_info` and do not affect the EWMA. The behavioral classification and the context classification are orthogonal.

### "Unfairness by Cause, Not Just by Category"

CAKE: unfair because *categories* exist (T0 runs before T3).
CIDER: unfair because *cause* is understood (this specific task needs to run now, because hardware said so, or a high-priority task depends on it, or it's holding a lock that blocks something important).

The distinction matters under load. On a lightly loaded gaming system, CAKE and CIDER produce identical scheduling decisions — causal signals rarely fire when CPUs are largely idle. Under sustained load, when CPUs are contested and every dispatch decision has latency consequences, the causal signals fire more frequently and the difference becomes measurable: IRQ-sourced tasks dispatch without waiting for tier settling, task chains experience less head-of-line blocking, and lock-holder preemptions that would have extended critical-section duration are suppressed.

---

## Implementation Notes

### Bit allocation in `packed_info`

```
packed_info bit layout:
  [31:30] stable    — tier stability counter (0–3), governs graduated backoff
  [29:28] tier      — current behavioral tier (0–3)
  [27]    reserved
  [26]    FLOW_IRQ_WAKE   — one-shot IRQ-source wakeup flag (NEW)
  [25]    FLAG_LOCK_HOLDER — futex-held flag (NEW, owned by lock_bpf.c)
  [24]    FLOW_NEW        — new-flow DRR++ bonus flag
  [23:16] wait_data — wait budget tracking
  [15:8]  (reserved)
  [7:0]   kalman_error — error signal
```

`FLOW_IRQ_WAKE` and `FLAG_LOCK_HOLDER` occupy bits 26 and 25, which are non-overlapping with all existing fields. The reclassify path's packed_info writes (`0xF << 28` for tier+stable, `CAKE_FLOW_NEW` clear for deficit exhaust) do not touch bits 25 or 26.

### Build integration

`lock_bpf.c` must be added to the BPF compilation step in `build.rs`. This is typically one additional `.file("src/bpf/lock_bpf.c")` call in the existing `cc::Build` invocation. The fexit and tracepoint probes are all optional (`SEC("?...")`); missing kernel symbols cause the probe to silently not attach rather than failing the scheduler load.

---

## Optimization Experiments Log (inherited from CAKE, extended)

The following table covers the original CAKE architecture experiments. The context-signal features (Layers 1–3) were not derived from this experimental process but from direct analysis of LAVD's source code and adaptation to CAKE's data model.

| Strategy | Key Logic | IPC | RES/sec | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| Baseline (EEVDF) | CFS/EEVDF Defaults | 0.85 | ~15 | Gold Standard |
| Original scx_cider | Complex Idle Hunt + Preemption Injection | 0.95 | ~1600 | IPI Storm |
| Simplified | Sync Wake + Sticky Pref | 0.51 | ~1450 | Regression |
| Aggressive Local | Always current_cpu | 0.50 | ~4 | Serialized |
| Hybrid | Sync Wake + Global Idle Hunt | 1.00 | ~1300 | Parallelism restored |
| Tiered Hybrid v1 | Gaming: Hunt Always, BG: Sticky | 1.02 | 1092 | SUCCESS |
| Phase 1 Opt (Jan 2026) | Removed 9 redundant dsq_nr_queued checks | 1.25 | ~1540 | +21% IPC |
| Phase 2 Opt (Jan 2026) | Early mask==0 return | 0.95 | ~1460 | REGRESSION — reverted |
| **CIDER Context Layers** | IRQ detect + waker inherit + lock protect | *pending* | *pending* | Under evaluation |

The CIDER context layers do not affect IPC (they do not change CPU migration or idle hunting behavior) and are not expected to affect RES interrupt rates. Their impact is on tail latency for IRQ-sourced wakeups and on priority inversion frequency under lock contention.

---

## Research Sources

| Feature | Derived From | Mechanism |
| :--- | :--- | :--- |
| DRR++ tier queuing | Network CAKE queueing discipline | Deficit Round Robin adapted to CPU scheduling |
| EWMA tier classification | CAKE original | avg_runtime_us → 4-tier mapping |
| Per-LLC DSQ architecture | CAKE original | One DSQ per L3 cache domain |
| IRQ-source wakeup detection | scx_lavd `lavd_select_cpu` | `bpf_in_hardirq/nmi/serving_softirq` + ksoftirqd comm check |
| Waker tier inheritance | scx_lavd `lat_cri_waker/lat_cri_wakee` propagation | Simplified to mailbox tier read + one-level promotion |
| Futex lock holder detection | scx_lavd `lock.bpf.c` | `fexit` probes on all futex acquire/release variants |
| Lock holder starvation skip | scx_lavd `can_x_kick_cpu2()` | `is_lock_holder_running()` preemption guard |
| Lock holder vtime advance | scx_lavd priority inversion avoidance | Within-tier vtime subtraction (not tier promotion) |

### Industry patterns implemented

| Pattern | Source | Implementation |
| :--- | :--- | :--- |
| No dynamic allocation | NASA JPL Power of 10 | BPF enforces this |
| Fixed loop bounds | NASA JPL Power of 10 | All loops bounded by RODATA constants |
| Division-free math | HPC Book / Trading Systems | Shift + AND for tier gates |
| Cache line isolation | LMAX Disruptor | mega_mailbox 64B-aligned per CPU |
| O(1) data structures | Flat-CG pattern | Tier array indexing, bitmask LLC scan |
| Asymmetric EWMA | Control theory | Promote α=1/4, demote α=1/16 |

### Evaluated but not implemented

| Pattern | Reason |
| :--- | :--- |
| Full LAVD latency criticality score | Requires per-task wait_freq/wake_freq/run_freq tracking and log2 computation — this IS LAVD's entire scheduling philosophy; adopting it wholesale would replace CAKE's EWMA system rather than extend it |
| LAVD greedy penalty / fairness lag | Contradicts CIDER's "unfairness is a feature" design |
| LAVD core compaction | Targets battery life; CIDER targets gaming desktops where all cores should remain active |
| LAVD capacity-invariant runtime | Useful for accurate hybrid classification; CIDER's has_hybrid DVFS already handles P/E-core scaling adequately |
| LAVD power-of-two-choices victim preemption | Aggressive kick strategy regressed 1% low FPS by 16 frames in A/B testing on Arc Raiders (252fps without kick, 236fps with T3-only kick) |
| Batch dispatch | Risk of priority inversion for gaming |
| SIMD/vectorization | BPF ISA does not support it |

---

## BPF Verifier Notes

### CTZ and array bounds

`__builtin_ctzll()` / `__builtin_ctz()` compile to a de Bruijn lookup table in the BPF JIT. The verifier does not understand that CTZ returns 0–63 (or 0–31 for the 32-bit variant), causing "invalid access to map value" errors on BSS array indexing even with explicit `& 63` bounds checks.

Solution: use `bpf_compat.h`'s `BIT_SCAN_FORWARD_U32` and `BIT_SCAN_FORWARD_U64` macros, which use inline assembly to force the AND into the BPF bytecode so the verifier tracks the bounded range correctly.

### Atomic operations on `packed_info`

`__sync_fetch_and_or` and `__sync_fetch_and_and` are used throughout to set and clear individual bits in `packed_info` without disturbing adjacent fields. This is necessary because `lock_bpf.c`'s fexit probes run on a different CPU and context from the scheduler hot path, creating genuine concurrent access. BPF's `__sync_fetch_and_*` emits a proper atomic RMW instruction on x86_64.

### `SEC("?...")` optional probes

All probes in `lock_bpf.c` use the `?` prefix, which instructs libbpf to silently skip attachment if the target symbol does not exist in the running kernel. This makes the lock-holder feature truly optional — the scheduler loads and runs correctly on kernels where futex functions are inlined or unexported, with no lock-holder boost in that configuration.
