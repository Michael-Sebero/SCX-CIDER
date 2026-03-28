# scx_imperator — Scheduler Documentation

**Full name:** Integrated Multitiered Priority Execution Ranked Adaptive Topology Ordered Runtime
**Status:** Production — Contextually Optimized
**Last updated:** 2026-03-28

---

## Name and Philosophy

### What the acronym means

**IMPERATOR** = **I**ntegrated · **M**ultitiered · **P**riority · **E**xecution · **R**anked · **A**daptive · **T**opology · **O**rdered · **R**untime

Every word maps to a concrete mechanism in the scheduler:

| Letter | Word | Mechanism |
| :----- | :--- | :-------- |
| **I** | Integrated | Context signals (IRQ, waker, lock) and behavioral EWMA are unified into a single dispatch decision per task |
| **M** | Multitiered | The T0–T3 hierarchy classifies every task into one of four tiers by measured average runtime |
| **P** | Priority | Vtime encoding `(tier << 56) \| timestamp` ensures T0 tasks always drain before T1 tasks regardless of arrival order |
| **E** | Execution | Classification math runs at `stopping` time; `enqueue` reads a pre-computed result — classification cost is amortized, not paid at dispatch |
| **R** | Ranked | DRR++ deficit tracking enforces intra-tier fairness: tasks with exhausted credit yield priority to new flows within the same tier |
| **A** | Adaptive | Asymmetric EWMA (promote α=1/4, demote α=1/16) tracks runtime behavior over time; graduated backoff reduces reclassification overhead for stable tasks |
| **T** | Topology | ETD calibration measures inter-core latency; the dispatch path prefers stealing from lower-latency LLCs first; `imperator_init` computes LLC membership masks from RODATA |
| **O** | Ordered | Every dispatch decision reflects a total order: tier first, then vtime within tier, then context-signal adjustments (IRQ, waker inheritance, lock-holder advance) |
| **R** | Runtime | Tier assignment is driven entirely by measured execution time — no manual annotation, no process name heuristics, no cgroup policy |

### Architectural lineage

scx_imperator descends from scx_cake (itself derived from network CAKE's DRR queueing discipline) and incorporates three targeted mechanisms adapted from scx_lavd. The two codebases contribute different things:

**CAKE's contribution (structural):** the 4-tier EWMA classification, DRR++ deficit tracking, per-LLC DSQ architecture, mega-mailbox, kfunc tunneling from `select_cpu` to `enqueue`, asymmetric EWMA decay, hysteresis tier gates, graduated backoff, SYNC fast path, DVFS tier table, profile system, and ETD topology calibration. Approximately 75–90% of BPF code is CAKE origin.

**LAVD's contribution (contextual):** IRQ-source wakeup detection, waker-tier inheritance, futex lock-holder tracking and starvation skip. Approximately 10–25% of BPF code is LAVD-derived. These three mechanisms solve CAKE's original blind spot: it classified tasks by *what they historically do* but had no signal about *why a specific wakeup is happening right now*.

### Why context signals matter

CAKE was context-blind by design. Two problems followed:

**Delayed IRQ responsiveness.** A mouse click interrupt wakes an input handler. If the handler's EWMA hasn't yet settled to T0 — because it is new, or just exec'd, or woke infrequently — it dispatches at T1 for 3–5 bouts before behavioral evidence accumulates. The same applies to any task woken by a GPU V-sync, audio DMA completion, or network packet arrival. The hardware urgency was invisible.

**Priority inversion through lock holders.** When a T3 bulk task holds a futex protecting a game's vertex buffer, starvation preemption forces every waiter to block until the holder is rescheduled and releases it — including T0 audio and T1 compositor threads. CAKE's starvation preemption was designed to *protect* high-priority tasks, but in this case it *extended* their wait.

IMPERATOR addresses both by treating context as a second, orthogonal classification axis:

```
dispatch_priority = f(behavioral_tier, causal_context)
```

`behavioral_tier` = EWMA avg_runtime classification (T0–T3), authoritative, updated every stop.
`causal_context` = one-shot signals from IRQ source, waker priority, and lock state.

Behavioral tier governs long-term placement. Causal context is a per-dispatch override. Neither replaces the other, and context signals never write to `packed_info` or affect the EWMA.

The core philosophy remains: **unfairness is a feature**. What changed is the scheduler's ability to identify *which tasks* deserve unfair advantage at any given moment, even before their behavioral history has settled.

---

## Architecture Overview

### Scheduling pipeline

```
Hardware event
      │
      ▼
imperator_select_cpu ──  IRQ detection ──────────────► CAKE_FLOW_IRQ_WAKE flag
      │                  (bpf_in_hardirq / bpf_in_nmi /
      │                   bpf_in_serving_softirq / ksoftirqd)
      │
      │   [tctx fetched only when needed: IRQ context or SCX_WAKE_SYNC]
      │
      ├── SYNC fast path ──► dispatch_sync_cold ─────  consume IRQ_WAKE → T0 slice
      │   (passes irq_tctx as hint; saves 1 storage lookup on hot path)
      │
      ├── Idle path ───────► SCX_DSQ_LOCAL_ON ────────  consume IRQ_WAKE → T0 slice
      │   (lazy tctx fetch; reuses irq_tctx if already obtained)
      │
      └── All busy ── tunnel (cached_llc, cached_now) ──────────────────────────┐
          return prev_cpu                                                         │
                                                                                  ▼
                                                                      imperator_enqueue
                                                                                  │
                                                          Feature 1: IRQ tier override (one-shot)
                                                          Feature 2: Waker tier inheritance
                                                          Feature 3: Lock holder vtime advance
                                                                                  │
                                                              vtime = (tier << 56) | timestamp
                                                                                  │
                                                                per-LLC DSQ (LLC_DSQ_BASE + llc)
                                                                                  │
                                                             [T0/T1 only] O(1) bitmask kick:
                                                             tier_cpu_mask[T3] & llc_cpu_mask
                                                             → BIT_SCAN_FORWARD → kick victim
                                                                                  │
                                                                                  ▼
                                                                      imperator_dispatch
                                                                                  │
                                                            local LLC first (zero cross-CCD traffic)
                                                            ETD-ordered steal if local empty
                                                                                  │
                                                                                  ▼
                                                                      imperator_running
                                                                                  │
                                                     stamp last_run_at, publish tier to mega_mailbox,
                                                     set bit in tier_cpu_mask[tier] for this CPU
                                                                                  │
                                                                                  ▼
                                                                      imperator_tick
                                                                                  │
                                                     slice expiry check, starvation check,
                                                     lock-holder starvation skip (cap 4),
                                                     mailbox update, DVFS frequency steering
                                                                                  │
                                                                                  ▼
                                                                      imperator_stopping
                                                                                  │
                                                     clear tier_cpu_mask bit (BEFORE reclassify),
                                                     reclassify_task_cold: EWMA + DRR++ + tier change

Futex acquire/release (any time, via fexit probes in lock_bpf.c):
      └── set/clear CAKE_FLAG_LOCK_HOLDER in packed_info atomically
```

### The 4-tier system

Tasks are classified into four tiers purely by EWMA of `avg_runtime_us`, computed at every `imperator_stopping` call:

| Tier | Name | Runtime gate | Typical tasks |
| :--- | :--- | :----------- | :------------ |
| T0 | Critical | < 100µs | IRQ handlers, mouse input, audio callbacks |
| T1 | Interactive | < 2ms | Compositor, physics, AI |
| T2 | Frame | < 8ms | Game render threads, encoding |
| T3 | Bulk | ≥ 8ms | Compilation, background indexing |

Tiers are encoded in vtime bits [63:56], so T0 tasks always drain before T1 tasks within the same LLC DSQ regardless of arrival order. Per-tier quantum multipliers (T0: 0.5×, T3: ~4×) and starvation thresholds govern how long each tier can run and how urgently it preempts.

### The three context-signal layers

#### Layer 1: IRQ-source wakeup boost

**Where:** `imperator_select_cpu`, and both direct-dispatch paths (SYNC and idle) that bypass `imperator_enqueue`.

**What:** When a wakeup originates from a hardirq, NMI, softirq bottom-half, or a `ksoftirqd` kernel thread, the task is flagged with `CAKE_FLOW_IRQ_WAKE` atomically in `packed_info`. The flag is consumed (cleared) on whichever dispatch path fires first — SYNC direct dispatch, idle direct dispatch, or `imperator_enqueue` — and grants T0 tier priority for that one dispatch only.

**Why:** A mouse click interrupt completes, the kernel wakes the input handler, and the handler should run at T0 immediately — not after 3–5 EWMA bouts. This mechanism makes the hardware urgency visible to the scheduler without any application annotation.

The flag is strictly one-shot. It is consumed by the shared helper `consume_irq_wake_get_tier_slice()`, called from both `dispatch_sync_cold` and the idle-path branch of `imperator_select_cpu`. Centralizing consumption prevents the two direct-dispatch paths from drifting apart silently. The behavioral EWMA is never affected.

**IRQ context detection is hoisted before the storage lookup.** `bpf_in_hardirq()`, `bpf_in_nmi()`, and `bpf_in_serving_softirq()` are pure register queries (~1 cycle each). `bpf_task_storage_get` costs ~20 cycles. On the dominant all-busy non-SYNC non-IRQ path under sustained gaming load, the storage lookup is skipped entirely — the task falls through to `return prev_cpu` with near-zero overhead.

#### Layer 2: Waker tier inheritance

**Where:** `imperator_enqueue`, on `SCX_ENQ_WAKEUP` paths only.

**What:** When a wakeup enqueue fires, the waker's tier is read from `mega_mailbox[enq_cpu].flags` (written by `imperator_running` on every context switch). If the waker's tier is lower than the wakee's current EWMA tier, the wakee is promoted to **exactly `waker_tier`** for this dispatch only — floored at T1 Interactive, never granted T0 through this path.

**Why:** A T0 input handler wakes a T2 game event dispatcher. Without inheritance the dispatcher sits in the T2 queue for up to 40ms. With inheritance it runs at T1 for this dispatch. The EWMA will independently converge toward T1 if the producer–consumer pattern is consistent.

The previous formula was `waker_tier + 1`, which meant a T1 waker promoted a T3 wakee to T2 only — a T2 wakee with a 40ms Gaming starvation threshold could still delay the event dispatcher by an entire frame. The current policy promotes to exactly `waker_tier`. The T1 floor prevents T0 audio wakers from granting T0 through inheritance to arbitrary wakees; genuine T0 priority is granted only through the IRQ-wake boost (Layer 1).

Constraints: only on `SCX_ENQ_WAKEUP` (producer→consumer, not preempt or yield); never promotes above T1; never demotes; only fires when `mega_mailbox[enq_cpu].flags != 0` (valid after `imperator_running` fires on the first context switch, not just after the first tick); does not write `packed_info`; does not affect EWMA.

#### Layer 3: Futex lock-holder protection

**Where:** `lock_bpf.c` (fexit probes set/clear the flag), `imperator_enqueue` (vtime advance), `imperator_tick` (starvation skip).

**What:** fexit probes on all futex acquire/release variants detect when a task holds a contended lock. `CAKE_FLAG_LOCK_HOLDER` is set atomically in `packed_info` on acquisition and cleared on release. Two effects follow while the flag is set:

1. **Vtime advance** (`imperator_enqueue`): the lock holder's virtual timestamp is subtracted by `new_flow_bonus_ns` (8ms) within its tier, sorting it ahead of same-tier non-holders. It runs sooner and releases the lock faster, unblocking any waiter (which may be a T0 audio or T1 compositor thread). The tier is unchanged — a T3 bulk task holding a lock is not promoted to T0; it moves to the front of the T3 queue.

2. **Starvation skip** (`imperator_tick`): if the lock holder exceeds its tier's starvation threshold, the preemption kick is skipped. Consecutive skips are capped at 4 to bound the maximum additional latency any T0 waiter can experience (at 1ms tick rate, 4 skips bound the delay to ~4ms regardless of critical section length). After 4 skips, the standard starvation preemption fires and the counter resets. The unconditional slice expiry check (`runtime > next_slice`) is never bypassed.

**Why:** Preempting a lock holder causes priority inversion — every waiter is blocked until the holder is rescheduled *and* releases the lock, which may be longer than simply allowing the holder to finish its critical section. Wine/Proton holds D3D command-list mutexes across full frame submissions. Audio frameworks hold mixing locks during T0 callbacks. This mechanism makes lock-holder behavior predictable without requiring application modification.

Both fexit probes (~50ns overhead) and syscall tracepoints (fallback, ~130ns) are implemented. All probes are `SEC("?...")` — the scheduler loads and runs correctly even if neither attaches.

**Clear-order fix:** `clear_lock_holder()` clears `CAKE_FLAG_LOCK_HOLDER` *before* resetting `lock_skip_count`. Reversing this order left a ~1ns window where an intervening tick could see the flag still set, increment the skip counter, and exit — leaving `lock_skip_count = 1` instead of 0 after the clear. Over many lock/unlock cycles on a hot audio or D3D submission thread this would erode the 4-skip budget and cause premature preemption.

---

## Additional Scheduling Behaviors

### Task initialization: fork inheritance and exec reset

`imperator_init_task` runs on both exec and fork events and handles them differently.

**On fork** (`args->fork == true`): the child's `avg_runtime_us` is seeded at half the parent's value, and its initial tier matches the parent's current tier. A game engine forking a render worker starts close to the correct tier immediately rather than waiting 6–16 EWMA bouts from the default T1 midpoint. Halving is intentional: child threads typically run shorter initial bouts while initializing stack and TLS before entering the main work loop.

**On exec** (`args->fork == false`): the task's `avg_runtime_us` and tier are reset to the nice-value-based midpoint — the same logic as `alloc_task_ctx_cold`. Without this reset, a shell or build tool that execs a game binary carries its pre-exec T3 classification into the new process image, causing the game's first render threads to compete at T3 for 6–16 bouts. The exec reset wipes that stale history. `overrun_count`, `reclass_counter`, and `lock_skip_count` are also zeroed. `next_slice` is recomputed for the reset tier.

### Multi-signal initial classification

`alloc_task_ctx_cold` uses two signals to set the starting point before EWMA data exists:

**Signal 1 — Nice value:** nice < 0 (prio < 120) starts at T0; nice > 10 (prio > 130) starts at T3; nice 0–10 starts at T1. This handles system services with negative nice, pipewire (-11), and explicitly deprioritized background tools.

**Signal 2 — PF_KTHREAD:** kthreads with negative nice get T0 from Signal 1. Kthreads with nice 0 start at T1, not T0 — `kcompactd`, `kswapd`, and similar bulk kthreads should not start at T0. They reclassify to the correct tier within a few stops.

**Signal 3 — Runtime behavior (authoritative):** EWMA `avg_runtime_us` → tier mapping in `reclassify_task_cold`. This is the only permanent classification source.

`avg_runtime_us` is seeded at the midpoint of the initial tier's expected range rather than 0. Starting from 0 caused any task with a short first bout to receive an EWMA small enough to classify as T0 — a bulk task with a 200µs first bout would earn T0 priority for 4–16 subsequent bouts before correction, starving gaming threads at application startup time.

### EWMA classification: asymmetric decay and hysteresis

The EWMA uses different decay rates for promotion and demotion:

- **Promote** (runtime shorter than current avg): α = 1/4 (~4 bouts to converge). Gaming threads spike during level loads then recover — fast promotion restores T0/T1 priority without waiting 16 bouts.
- **Demote** (runtime longer than current avg): α = 1/16 (~16 bouts to converge). Cautious demotion prevents transient spikes from permanently misclassifying a latency-sensitive thread.

Tier transitions use hysteresis gates: to promote (lower tier), the EWMA must fall 10% *below* the gate; to demote, it need only reach the gate. This prevents oscillation near boundaries.

### Graduated backoff for reclassification

Once a task's tier has been stable for 3 consecutive reclassification calls (the `stable` field reaches 3), the full reclassification path runs less frequently:

| Tier | Full recheck period | Rationale |
| :--- | :--- | :--- |
| T0 | Every 1024th stop | IRQ/input tasks almost never change behavior |
| T1 | Every 128th stop | Compositor may shift slightly but rarely changes tier |
| T2 | Every 32nd stop | Render threads are more variable |
| T3 | Every 16th stop | Bulk tasks may transition to T2 when work patterns change |

On skipped checks, EWMA arithmetic still runs and the deficit is still updated — only the tier comparison and `packed_info` write are deferred. A spot-check compares the updated EWMA against the hysteresis gates and resets stability if a tier change appears imminent, so the full path fires promptly when behavior genuinely shifts.

### Post-load sleep recovery

If a task has been sleeping for more than 500ms (e.g., a loading screen pause, an idle background service resuming), its `avg_runtime_us` is pulled halfway toward the midpoint of its current tier before the normal EWMA runs. Without this, a game thread that spends 30s at T3 during asset loading needs 10+ EWMA bouts (20–32ms) to recover to T1/T2 after the load completes, causing frame-time spikes at session start. The 500ms threshold is deliberately above any normal gaming frame cadence (even 24fps = ~42ms frame period) but below OS idle timers.

### Overrun detection: bit-history shift register

`overrun_count` is an 8-bit shift register of execution outcomes, not a simple counter. Each time `imperator_stopping` fires, the register shifts left one position and the current bout's result is inserted in the LSB:

- Bit = 1: this bout's runtime (clamped to µs) exceeded 1.5× the tier gate (T0: 150µs, T1: 3000µs, T2: 12000µs)
- Bit = 0: this bout ran within the gate

**Demotion trigger:** `__builtin_popcount(overrun_count) >= 4` — 4 or more of the last 8 bouts exceeded the gate. This is a strict superset of the original consecutive-counter behavior:

- 4 consecutive overruns → `hist = 0b00001111` → popcount = 4 ≥ 4 → demote (identical to original)
- 4 alternating overruns over 8 bouts → popcount = 4 ≥ 4 → demote (new capability: original counter reset on every normal bout and never fired in this pattern)

The threshold is 4, not 5. A threshold of 5 was a regression: 4 consecutive overruns → popcount = 4 < 5 → no demotion, breaking parity with the original consecutive counter.

### O(1) bitmask preemption kick

When a T0 or T1 task is enqueued into the LLC DSQ and all CPUs are busy, IMPERATOR kicks a victim CPU in the same LLC using bitmask intersection rather than a linear scan:

- `tier_cpu_mask[t]`: bitmask of CPUs currently running tier-t tasks (maintained by `imperator_running` / `imperator_stopping`)
- `llc_cpu_mask[l]`: bitmask of CPUs belonging to LLC l (computed once by `imperator_init` from `cpu_llc_id` RODATA)
- AND → CPUs in this LLC running tier t → `BIT_SCAN_FORWARD` → victim CPU

Victim preference: T3 (bulk) first — displacing a bulk task causes the least frame-time disruption. Falls back to T2 (frame) only when no T3 CPU is present in the LLC. T1 and T0 are never kicked to run another latency-critical task.

Net cost vs previous O(nr_cpus) mailbox scan on a 16-thread LLC: ~80–100 cycles removed, ~12 cycles added. T2 and T3 tasks enqueuing never trigger a kick at all (A/B testing confirmed indiscriminate kicks cause measurable 1% low FPS regression in Arc Raiders: 252fps without kick, 236fps with T3-only kick).

`tier_cpu_mask` is updated with a single BPF_ATOMIC_OR instruction (not a CAS loop) — each CPU owns its own bit so no two CPUs contend on the same bit. `imperator_running` only sets bits; `imperator_stopping` only clears bits. Clearing must happen before `reclassify_task_cold()` so `GET_TIER(tctx)` still returns the running-time tier, not the post-EWMA tier — clearing the wrong bit would break the kick path.

### Kthread-without-context fallback tier

Kthreads that reach `imperator_enqueue` before their task context has been allocated (a brief race window before `imperator_enable` fires) are dispatched at **T1 Interactive**, not T0 Critical. The previous T0 default gave bulk kthreads such as `kcompactd` and `kswapd` unwarranted priority. T1 matches the tier that `alloc_task_ctx_cold` assigns to nice-0 kthreads; they reclassify to the correct tier within a few stops once a context is allocated.

### Yield path uses actual tier

Tasks that yield (`!SCX_ENQ_WAKEUP && !SCX_ENQ_PREEMPT`) are dispatched at their actual EWMA tier, not forced to T3. The previous hard-coded T3 yield tier sent T0 audio and T1 input threads to the back of the T3 queue (up to 100ms starvation threshold) when they briefly yielded while waiting for hardware. Tasks with no context yet fall back to T3, since yield implies they are not urgent.

### `select_cpu` flat architecture

`imperator_select_cpu` is approximately 20 BPF instructions vs 200+ in the original cascade design. All idle detection is delegated to `scx_bpf_select_cpu_dfl()`, which performs a prev → sibling → LLC cascade internally with zero staleness and atomic claiming. When all CPUs are busy, the function returns `prev_cpu` and tunnels `(cached_llc, cached_now)` to `imperator_enqueue` via per-CPU scratch, saving 2 kfunc calls (~40–60ns) on the enqueue path.

**Tunneled LLC fix:** On the all-busy path, `cached_llc` is now derived from the *task's* target CPU (which is `prev_cpu` when all CPUs are busy), not from the *waker's* CPU. On dual-CCD systems, the previous bug placed nearly all "all-busy" tasks into the waker's LLC DSQ but dispatched them from `prev_cpu`'s LLC, forcing every task through the slower cross-LLC steal path.

---

## Dispatch: Per-LLC DSQ and ETD-Aware Work Stealing

### Normal dispatch

`imperator_dispatch` first tries the calling CPU's local LLC (`scx_bpf_dsq_move_to_local(LLC_DSQ_BASE + my_llc)`). This covers the overwhelming majority of dispatch events with zero cross-LLC traffic. If the local DSQ is empty, the flag is cleared and the steal path is entered.

Single-LLC systems (`nr_llcs <= 1`) skip the steal path entirely — the JIT dead-code-eliminates the loop at load time.

### ETD-ordered work stealing

After ETD calibration completes, `try_write_etd_costs()` writes the `llc_etd_cost[src][dst]` BSS table. Values are the minimum measured one-way latency between any CPU in LLC A and any CPU in LLC B, divided by 4 and clamped to `u8` (0 = unknown, 255 ≈ 1020 ns). The unit is 4 ns/unit.

The steal path:
1. Builds a `steal_mask` bitmask of LLCs that are non-empty (per-LLC `llc_nonempty` entries)
2. Identifies the cheapest candidate LLC from `llc_etd_cost` (minimum non-zero entry)
3. Tries the cheapest LLC first; on success, returns immediately
4. Falls back to remaining LLCs in `BIT_SCAN_FORWARD` order

All LLCs are always attempted — cheapest-first only changes the order, never skips work. When `llc_etd_cost` is all-zero (pre-calibration or single-LLC), the path degrades to index-order behavior with no functional change.

### Per-LLC non-empty flags

`llc_nonempty[CAKE_MAX_LLCS]` is an array where each entry is padded to 64B (one cache line). Each LLC writes only its own `nonempty` byte. The previous design used a single shared `volatile u32` updated with `__sync_fetch_and_or` on every enqueue — on a 16-core dual-CCD system at ~100K enqueues/sec this forced the cache line to bounce across all cores (~100ns of coherence traffic per enqueue, ~1% overhead at peak).

Intra-LLC writes (multiple CPUs in the same LLC all writing `nonempty = 1`) are not false-sharing: all CPUs write the same value, so the cache line stays in Shared state on x86 MESIF. Stale set flags are harmless: `scx_bpf_dsq_move_to_local` returns 0 on an empty DSQ, at which point the flag is cleared.

---

## Task Context Layout

### `imperator_task_ctx` (64B, one cache line)

```
Byte layout:
  [0–7]   next_slice (u64)         — pre-computed time slice for next dispatch
  [8–11]  deficit_us + avg_runtime_us (u16 each, fused as u32)
  [12–15] packed_info (u32)        — bitfield: stable|tier|flags|wait_data|kalman_error
  [16–19] last_run_at (u32)        — timestamp from imperator_running
  [20–21] reclass_counter (u16)    — graduated backoff counter
  [22]    overrun_count (u8)       — 8-bit shift register of execution outcomes
  [23]    lock_skip_count (u8)     — consecutive starvation-skip counter (cap 4)
  [24]    pending_futex_op (u8)    — per-task futex op for tracepoint migration fix
  [25–63] __pad[39]                — explicit padding to exactly 64B
```

A `_Static_assert` in `intf.h` enforces `sizeof(imperator_task_ctx) == 64`.

### `packed_info` bit layout

```
  [31:30] stable    — tier stability counter (0–3); governs graduated backoff
  [29:28] tier      — current behavioral tier (0–3)
  [27:24] flags     — 4-bit FLAGS nibble:
    bit 27 (1<<3): reserved
    bit 26 (1<<2): CAKE_FLOW_IRQ_WAKE   — one-shot IRQ-source wakeup flag
    bit 25 (1<<1): CAKE_FLAG_LOCK_HOLDER — futex-held flag (owned by lock_bpf.c)
    bit 24 (1<<0): CAKE_FLOW_NEW        — new-flow DRR++ bonus flag
  [23:16] wait_data — wait budget tracking
  [15:8]  (reserved)
  [7:0]   kalman_error — error signal
```

A `_Static_assert` enforces `SHIFT_TIER == SHIFT_FLAGS + 4` so the fused-packing expression in `alloc_task_ctx_cold` stays correct if either constant is later changed independently.

All writes to `packed_info` that modify multiple fields use relaxed atomic helpers (`imperator_relaxed_load_u32` / `imperator_relaxed_store_u32`) or RMW atomics (`__sync_fetch_and_or` / `__sync_fetch_and_and`). Plain struct member assignment is not atomic under C11 and is not safe on weakly-ordered architectures (ARM64).

### `mega_mailbox_entry` (64B, one cache line)

```
  [0]    flags (u8)       — MBOX_TIER_MASK bits: current running task's tier
  [1]    dsq_hint (u8)    — cached DVFS perf target (cpuperf_target >> 2); avoids
                             redundant kfunc calls when tier hasn't changed between ticks
  [2]    tick_counter (u8) — confidence counter for starvation check backoff
  [3–63] __reserved[61]
```

All reads and writes to `mega_mailbox` `u8` fields use `imperator_relaxed_load_u8` / `imperator_relaxed_store_u8`. Conditional stores (load first, skip if unchanged) keep the cache line in Shared state on x86 MESIF when multiple CPUs in the same LLC all set the same value.

`mega_mailbox` is written in `imperator_running` (eager context-switch update) and `imperator_tick` (periodic update). `imperator_enqueue` reads it for waker-tier inheritance. The eager write in `imperator_running` ensures the mailbox is valid from the very first context switch, not only after the first tick fires (~1–4ms later).

### Fused config layout (`fused_config_t`)

Tier parameters are packed into a single `u64` to fit all four tiers in one cache line fetch:

```
  [63:44] starvation_ns (20 bits, 1024-ns units, × 1024 to recover ns)
  [43:28] wait_budget_ns (16 bits, 1024-ns units)
  [27:12] quantum_ns (16 bits, 1024-ns units)
  [11:0]  multiplier (12 bits, raw)
```

Callers pass values in kns (right-shifted by 10). The `UNPACK_*_NS` macros left-shift by 10 to recover nanoseconds. The `_kns` suffix in macro parameter names reflects this unit convention.

---

## Profiles

Three gaming profiles are provided. `Default` delegates explicitly to `Gaming`:

| Profile | T3 Quantum | T3 New-Flow Bonus | T3 Starvation | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Gaming** | 2ms | 8ms | 100ms | General gaming desktop (default) |
| **Esports** | 1ms | 4ms | 50ms | Tournament play, minimum latency |
| **Legacy** | 4ms | 12ms | 200ms | Backward compatibility, higher fairness |

All profiles scale starvation thresholds proportionally across T0–T3 from the T3 base. T0 and T1 thresholds are tighter in absolute terms across all profiles. Multipliers control how much CPU time each tier receives relative to its quantum: T0 at 0.5× (Gaming) to 0.75× (Legacy), T3 at ~4× (Gaming/Esports) to 2× (Legacy).

A `--starvation` CLI override scales all tier starvation thresholds proportionally from the T3 base, preserving the inter-tier ratio.

---

## ETD Topology Calibration

The ETD (Edge-to-edge Transfer Delay) calibration measures inter-core latency via CAS ping-pong to build a full CPU-pair latency matrix. This matrix informs cross-CCD work-stealing decisions.

### Default configuration

| Parameter | Value | Notes |
| :-------- | :---- | :---- |
| `iterations` | 500 | Round-trips per sample |
| `samples` | 50 | Samples collected per CPU pair |
| `warmup` | 200 | Warmup iterations discarded (stabilize boost clocks) |
| `max_stddev` | 15.0 ns | Retries triggered if σ exceeds this; up to 3 retries |

### Measurement method

Two threads, each pinned to one CPU of the pair, atomically exchange a flag with CAS. One-way latency = `total_duration / (round_trips × 2)`. The **median** of collected samples is used as the final value (robust against IRQ jitter outliers). After 3 retries, the best available result is accepted regardless of stddev.

### Deadlock fix

A shared `abort: AtomicBool` was added to `SharedState`. Both threads store to `abort` *before* `barrier.wait()` unconditionally if their affinity pinning fails, then check the flag *after* the barrier. This ensures both threads always reach the barrier, preventing the case where one exits early and the other blocks forever.

### Affinity failure fallback

When `measure_pair()` returns `None`, affected matrix entries are filled with a **500 ns sentinel** (covers worst-case cross-NUMA latency on Threadripper/EPYC). A zero entry would always win the ETD comparison, permanently routing steals to the failed pair regardless of actual topology distance.

### ETD completion notification

ETD calibration runs in a background thread so the scheduler loads immediately. Completion is signaled via an `eventfd` (EFD_NONBLOCK | EFD_CLOEXEC), which the main event loop polls alongside the signal fd. When the eventfd fires, `try_write_etd_costs()` writes the `llc_etd_cost` table immediately — not up to 1 second later (the previous polling approach). The scheduler owns the read end (closed in `Drop`); the thread owns the write end (closed after signaling).

### RT priority

`try_set_realtime_priority()` emits a `warn!()` log message when `sched_setscheduler(SCHED_FIFO, 99)` returns `EPERM` rather than silently ignoring it. On non-root execution this is expected; measurements continue but may have elevated jitter.

---

## TUI Statistics Display

### Live per-second rates

`TuiApp` stores a `prev_stats` snapshot and a `prev_tick` timestamp. `tick_stats()` is called once per refresh interval to compute rates for the current window. The `[r]` key zeroes the BSS stats array; `invalidate_rates()` resets the snapshot so the next window starts clean.

### Stats table

The per-tier table includes a **Starve/s** column. Non-zero T0 and T1 rates are highlighted in red (audio/input tasks held past their starvation threshold). Lock-holder skip, IRQ-wake boost, and waker-tier boost counters are displayed only on the T0 row (system-wide totals). The **lock_skip/s** rate in the summary bar helps diagnose Wine/Proton stalls or audio mixing bottlenecks.

### Heatmap

Column headers use a two-row format (tens digit / ones digit) to avoid label ambiguity on ≥10-CPU systems. Cell colors are driven by measured ETD values with a gradient spanning the actual measured range; cells render in neutral gray during calibration.

### Signal handling

`signalfd` is the sole signal handler. The previous `ctrlc::set_handler` call installed a competing `sigaction` handler for SIGINT/SIGTERM that raced with the `signalfd`, causing one mechanism to silently eat signals meant for the other. `ctrlc` is no longer a dependency.

### Version string

The startup screen uses `concat!("v", env!("CARGO_PKG_VERSION"))` rather than a hardcoded literal.

---

## CPU Cycle Audit

**Date:** 2026-03-28
**Method:** Instruction-count estimation on x86_64 JIT.

### Cost legend

| Abbreviation | Operation | Approximate Cost |
| :--- | :--- | :--- |
| ALU | Arithmetic, comparison, branch | 0.5–1 cycle |
| L1 Load | Memory read from L1 cache | ~4 cycles |
| Map | `bpf_task_storage_get` | ~20–50 cycles |
| Atomic | `__sync_fetch_and_or/and` (L1 hit, uncontested) | ~5 cycles |
| Helper | Kernel helper call | ~50+ cycles |

### Global summary

| Function | Role | IMPERATOR Cost | Notes |
| :--- | :--- | :--- | :--- |
| `imperator_select_cpu` | Core pick + IRQ detect | ~26c | Storage skipped on dominant all-busy non-IRQ path |
| `imperator_enqueue` | Wakeup dispatch | ~8c | Feature 2 mailbox read dominates steady-state |
| `imperator_dispatch` | DSQ consume | ~5c | Unchanged from CAKE |
| `imperator_tick` | Slice/starvation check | ~57c | +2c for lock-holder check |
| `imperator_stopping` | EWMA + reclassify | ~85c | Graduated backoff reduces full-path frequency |
| `imperator_running` | Timestamp + mailbox publish + tier_cpu_mask set | ~52c | +2c for eager mailbox write |
| `lock_bpf` probes | Futex set/clear | ~50ns fexit | Only on contended lock operations (rare) |
| **Total round trip** | **End-to-end** | **~164c** | **~20% over CAKE baseline** |

The +20% increase is entirely in `select_cpu` and `enqueue`. `dispatch` — the tightest loop under sustained load — is unchanged.

### `imperator_select_cpu` detail

| Operation | Type | Cost | Notes |
| :--- | :--- | :--- | :--- |
| `bpf_in_hardirq/nmi/softirq` checks | ALU | 2 | Hoisted before storage; pure register queries |
| `bpf_task_storage_get` (lazy: IRQ/SYNC only) | Map | 20 | Skipped on dominant all-busy non-IRQ non-SYNC path |
| Atomic OR (set IRQ_WAKE flag) | Atomic | 5 | `unlikely()` |
| `scx_bpf_select_cpu_dfl` | Helper | ~10 | Kernel idle detection |
| Idle: `consume_irq_wake_get_tier_slice` | ALU+Atomic | 8 | Shared helper; reuses already-fetched tctx |
| SYNC: `dispatch_sync_cold` | ALU | 5 | Reuses `irq_tctx`; saves 1 Map call |
| **Total (common all-busy path)** | | **~12c** | **Storage entirely skipped** |

### `imperator_enqueue` detail

| Operation | Type | Cost | Notes |
| :--- | :--- | :--- | :--- |
| `get_task_ctx` | Map | 20 | |
| `GET_TIER` + `GET_SLICE` | L1 Load | 2 | Pre-computed at stopping |
| `packed_info` load (amortized across all 3 features) | L1 Load | 1 | Single read |
| Feature 1: IRQ_WAKE check + atomic AND | ALU+Atomic | 6 | `unlikely()` |
| Feature 2: mailbox read + tier compare | L1+ALU | 6 | Steady-state cost on WAKEUP path |
| Feature 3: LOCK_HOLDER check + ts subtract | ALU | 2 | `unlikely()` |
| `scx_bpf_dsq_insert_vtime` | Helper | 50 | Unchanged |
| **Total (steady-state, no IRQ or lock holder)** | | **~81c** | **+6c vs CAKE** |

### `imperator_tick` detail

| Operation | Type | Cost | Notes |
| :--- | :--- | :--- | :--- |
| Runtime computation | ALU | 3 | |
| `imperator_get_rq` + `nr_running` read | Helper+L1 | 20 | Graduated backoff reduces frequency |
| Starvation threshold unpack | ALU | 2 | RODATA access |
| Lock-holder check (`packed_info` load + flag test) | L1+ALU | 2 | Only inside starvation-exceeded branch |
| `scx_bpf_kick_cpu` | Helper | 50 | Unchanged; skipped for lock holders |
| Mailbox + DVFS update | L1+Helper | 15 | |
| **Total additional overhead** | | **+2c** | **Inside starvation branch only** |

---

## Scheduling Philosophy

### The DRR++ core

Deficit Round Robin Plus-Plus governs intra-tier fairness. Every task starts with a deficit credit of `quantum + new_flow_bonus`. Each execution bout consumes deficit proportional to runtime. When deficit exhausts, the new-flow priority bonus is cleared and the task competes on equal vtime footing with peers in its tier. This is the CPU-scheduling analog of network CAKE's DRR for flow queuing.

### Vtime encoding

`vtime = (tier << 56) | (timestamp & 0x00FFFFFFFFFFFFFF)` encodes cross-tier priority in the sort key itself. Within a per-LLC DSQ, tasks sort first by tier (bits 63:56), then by arrival time within the same tier. A T0 task arriving 100ms after a T1 task still dispatches before the T1 task. Context signals (IRQ wake, waker inheritance) change the `tier` variable used in this encoding for one dispatch; they do not write `packed_info` and do not affect the EWMA.

Two guards protect the timestamp portion: a saturation check prevents the DRR++ new-flow bonus subtraction from wrapping into the tier bits at [63:56]; the same guard applies to the lock-holder advance so both effects compound correctly (a new flow that holds a lock sorts to the front of its tier).

### "Unfairness by cause, not just by category"

CAKE knew that categories exist (T0 runs before T3). IMPERATOR additionally understands *why* a specific task needs to run *right now* — because hardware said so, because a high-priority task woke it, or because it is holding a lock that blocks something important.

Under light load, the two produce identical decisions — causal signals rarely fire when CPUs are largely idle. Under sustained load, when every dispatch decision has latency consequences, the causal signals fire more frequently: IRQ-sourced tasks dispatch without waiting for EWMA settling, producer–consumer task chains experience less head-of-line blocking, and lock-holder preemptions that would have extended critical-section duration are suppressed.

---

## Implementation Notes

### `imperator_running`: eager mailbox publish and tier_cpu_mask set

`imperator_running` writes the current task's tier to `mega_mailbox[cpu].flags` immediately on every context switch. `imperator_tick` fires at HZ intervals (1–4ms); any task woken in the window between a context switch and the first tick would inherit the *previous* task's tier — the wrong value at the worst time (right after a T0 audio thread is scheduled, the mailbox might still show T3 from the preempted bulk task). The eager write costs ~2 cycles per context switch.

`imperator_running` also sets the bit `1ULL << cpu` in `tier_cpu_mask[tier]` so the O(1) kick path in `imperator_enqueue` has valid data from the very first context switch.

### `imperator_stopping`: tier_cpu_mask cleared before reclassify

`imperator_stopping` clears the calling CPU's bit from `tier_cpu_mask` *before* calling `reclassify_task_cold()`. `GET_TIER(tctx)` must return the running-time tier at the point of clearing — the tier whose bit is set — not the post-EWMA tier produced by reclassification. Clearing after reclassify would clear the wrong bit, permanently corrupting the kick path.

### `imperator_init`: self-populating `llc_cpu_mask`

`imperator_init` computes `llc_cpu_mask[llc] |= 1ULL << cpu` for every CPU from the `cpu_llc_id` RODATA array before any task is scheduled. This eliminates the previous partial-deploy hazard: `llc_cpu_mask` was previously written by the Rust loader; a missing write left the mask all-zero and the O(1) kick path produced zero kicks without any error or warning. The Rust side no longer writes this field.

### `pending_futex_op` per-task migration fix

The tracepoint fallback previously stored the futex op in a per-CPU `lock_scratch` array at `sys_enter_futex`. Blocking futex variants put the calling task to sleep inside the kernel; Linux may wake it on a different CPU. The mismatch caused `imperator_tp_exit_futex` to read whichever op the *new* CPU's scratch last recorded — potentially a WAKE op — and call `clear_lock_holder()` for a task that just acquired a lock.

The fix stores the op in `imperator_task_ctx.pending_futex_op` (1B at offset 24, within the 64B cache line), carried with the task across migrations.

`alloc_task_ctx_cold` initializes `pending_futex_op` to `CAKE_FUTEX_OP_UNSET` (0xFF). BPF task-storage zero-initializes new entries; 0 maps to `CAKE_FUTEX_WAIT` (op = 0), so without explicit initialization an exit probe firing before any `sys_enter_futex` would call `set_lock_holder()` spuriously. All valid futex cmd values (0–13) fit in the lower nibble and never alias 0xFF.

### `lock_bpf.c`: `futex_trylock_pi` fexit probe

A `SEC("?fexit/futex_trylock_pi")` probe was added, covering the only PI-futex acquire path previously without a fexit probe. The tracepoint fallback (`CAKE_FUTEX_TRYLOCK_PI` case) was already present; the fexit path provides the faster (~50ns vs ~130ns) coverage on kernels that export the symbol. The resulting idempotent double `set_lock_holder()` on kernels with both paths is harmless.

### `lock_bpf.c`: Linux 6.x futex syscall tracepoints

`SEC("?tracepoint/syscalls/sys_exit_futex_wait")` and `SEC("?tracepoint/syscalls/sys_exit_futex_wake")` cover the dedicated `futex_wait` and `futex_wake` syscall entries introduced in Linux 6.x. These are separate syscalls from `futex(2)` and are not handled by `imperator_tp_exit_futex`. Both use `ret >= 0` for the wake/release path, matching fexit semantics.

### `imperator_scratch` dead field removal

Two dead fields were removed from `imperator_scratch`: `bpf_iter_scx_dsq it` (never referenced after the per-LLC DSQ migration) and `init_tier` (a local variable in `alloc_task_ctx_cold`, not a scratch field). Together they consumed ~79B of the 128B struct (4.8KB across 64 CPUs) and forced false-sharing through the iterator's alignment requirements. The struct still pads to 128B (`1 + 3 + 4 + 8 + 112 = 128`).

### `imperator_task_ctx` layout guarantee

`_Static_assert(sizeof(struct imperator_task_ctx) == 64, ...)` is enforced in `intf.h`. The `__pad` field (39B) must be updated whenever other fields change: `8 + 8 + 4 + 2 + 1 + 1 + 1 + 39 = 64`.

### `Default` profile explicit delegation

`Profile::Default` delegates to `Profile::Gaming` explicitly in all four `impl Profile` methods using match-arm sharing (`Profile::Gaming | Profile::Default`). When Gaming values are updated, Default automatically tracks them with no risk of silent divergence from duplicated literals.

### `llc_nonempty` per-LLC flag redesign

Replaced the previous single shared `volatile u32` (updated with `__sync_fetch_and_or` on every enqueue) with a `llc_nonempty[CAKE_MAX_LLCS]` array where each entry is padded to 64B. See the dispatch section for full details.

---

## BPF Verifier Notes

### CTZ and array bounds

`__builtin_ctzll()` / `__builtin_ctz()` compile to a De Bruijn lookup table in the BPF JIT. The verifier does not understand that CTZ returns 0–63 (or 0–31), causing "invalid access to map value" errors on BSS array indexing even with explicit `& 63` bounds checks.

Use `bpf_compat.h`'s `BIT_SCAN_FORWARD_U64` and `BIT_SCAN_FORWARD_U32` macros, which use inline assembly to force the AND into the BPF bytecode so the verifier tracks the bounded range correctly. `BIT_SCAN_FORWARD_U32` must be used for 32-bit operands — using the 64-bit variant on a `u32` mask uses a different De Bruijn multiplier and produces incorrect results. On Clang ≥19, `BIT_SCAN_FORWARD_U32` maps to `__builtin_ctz`; on Clang <19 it uses a 32-bit De Bruijn sequence with multiplier `0x077CB531`.

### Clang <18 De Bruijn barrier placement

On Clang <19, the LLVM post-RA peephole pass can recover a De Bruijn pattern from still-live registers and substitute `__builtin_ctzll`, emitting BPF opcode 191, which crashes hardware JITs that do not implement it. The fix places a compiler barrier (`asm volatile("" : "+r"(product))`) *after* the multiply (not after `lsb`), forcing the product to materialize as a named register and breaking the peephole's reconstruction chain. Both 64-bit (`imperator_ctz64`) and 32-bit (`imperator_ctz32`) variants apply this fix.

### Atomic operations on `packed_info`

`__sync_fetch_and_or` and `__sync_fetch_and_and` are used throughout to set and clear individual bits in `packed_info` without disturbing adjacent fields. This is necessary because `lock_bpf.c`'s fexit probes run on a different CPU and context from the scheduler hot path, creating genuine concurrent access. BPF's `__sync_fetch_and_*` emits a proper atomic RMW instruction on x86_64.

### Relaxed atomic helpers for `u8` fields

`imperator_relaxed_load_u8` / `imperator_relaxed_store_u8` in `bpf_compat.h` must be used for all reads and writes to `mega_mailbox` `u8` fields (`flags`, `dsq_hint`, `tick_counter`). Plain struct member assignment is not guaranteed atomic or visible on weakly-ordered architectures (ARM64). The helpers use `__atomic_load_n` / `__atomic_store_n` with `__ATOMIC_RELAXED` on Clang ≥21 and inline BPF ASM byte-width load/store on older compilers. RELAXED semantics are sufficient: no ordering with respect to surrounding operations is required — visibility alone is the goal.

### IRQ context kfuncs declared `__weak`

`bpf_in_hardirq`, `bpf_in_nmi`, and `bpf_in_serving_softirq` are declared `extern ... __ksym __weak` in `bpf_compat.h`. The scheduler loads cleanly on kernels that do not export these helpers — the verifier substitutes a zero return (false), silently disabling IRQ-wake boosting. Without `__weak`, Clang 21's strict `-Wimplicit-function-declaration` treats call sites as undeclared identifiers and fails the build.

### `SEC("?...")` optional probes

All probes in `lock_bpf.c` use the `?` prefix, instructing libbpf to silently skip attachment if the target symbol does not exist. The scheduler loads and runs correctly on kernels where futex functions are inlined or unexported, with lock-holder protection simply absent in that configuration.

### Loop bounds and RODATA constants

All BPF loops are bounded by RODATA constants (`nr_cpus`, `nr_llcs`) that the JIT treats as bounded. Where an interior `break` was previously used as a verifier workaround, the loop now iterates directly to the RODATA bound — cleaner and equally safe.

---

## Research Sources

| Feature | Derived From | Mechanism |
| :--- | :--- | :--- |
| DRR++ tier queuing | Network CAKE queueing discipline | Deficit Round Robin adapted to CPU scheduling |
| EWMA tier classification | CAKE original | avg_runtime_us → 4-tier mapping |
| Asymmetric EWMA | Control theory | Promote α=1/4, demote α=1/16 |
| Per-LLC DSQ architecture | CAKE original | One DSQ per L3 cache domain |
| Graduated backoff | CAKE original | Tier-specific recheck masks |
| IRQ-source wakeup detection | scx_lavd `lavd_select_cpu` | `bpf_in_hardirq/nmi/serving_softirq` + ksoftirqd comm check |
| Waker tier inheritance | scx_lavd `lat_cri_waker/lat_cri_wakee` | Simplified to mailbox tier read + direct promotion |
| Futex lock-holder detection | scx_lavd `lock.bpf.c` | fexit probes on all futex acquire/release variants |
| Lock holder starvation skip | scx_lavd `can_x_kick_cpu2()` | `is_lock_holder_running()` preemption guard |
| Lock holder vtime advance | scx_lavd priority inversion avoidance | Within-tier vtime subtraction (not tier promotion) |
| O(1) bitmask kick | CAKE-original extension | `tier_cpu_mask` × `llc_cpu_mask` + BSF |
| ETD topology calibration | CAKE original | CAS ping-pong latency matrix |
| ETD-ordered work stealing | CAKE-original extension | `llc_etd_cost` table in dispatch |

### Industry patterns implemented

| Pattern | Source | Implementation |
| :--- | :--- | :--- |
| No dynamic allocation | NASA JPL Power of 10 | BPF enforces this |
| Fixed loop bounds | NASA JPL Power of 10 | All loops bounded by RODATA constants |
| Division-free math | HPC / Trading Systems | Shift + AND for tier gates |
| Cache line isolation | LMAX Disruptor | `mega_mailbox` 64B-aligned per CPU; `llc_nonempty` 64B per LLC |
| O(1) data structures | Flat-CG pattern | Tier array indexing, bitmask LLC scan |
| Asymmetric EWMA | Control theory | Promote α=1/4, demote α=1/16 |
| Conditional store (MESI-friendly) | Coherence optimization | Load-compare-store on mailbox; skip if unchanged |

### Evaluated but not implemented

| Pattern | Reason |
| :--- | :--- |
| Full LAVD latency criticality score | Requires per-task wait_freq/wake_freq/run_freq tracking and log2 computation. Adopting it wholesale replaces CAKE's EWMA system rather than extending it |
| LAVD greedy penalty / fairness lag | Contradicts the "unfairness is a feature" design principle |
| LAVD core compaction | Targets battery life; IMPERATOR targets gaming desktops where all cores should remain active |
| LAVD capacity-invariant runtime | Useful for accurate hybrid classification; the `has_hybrid` DVFS path already handles P/E-core scaling adequately |
| LAVD power-of-two-choices victim preemption | A/B testing showed T3-only kicks cause a 16 fps 1% low regression in Arc Raiders (252fps without kick, 236fps with kick) |
| Batch dispatch | Risk of priority inversion for gaming |
| SIMD / vectorization | BPF ISA does not support it |

---

## Optimization Experiments Log

| Strategy | Key Logic | IPC | RES/sec | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| Baseline (EEVDF) | CFS/EEVDF Defaults | 0.85 | ~15 | Gold Standard |
| Original scx_cake | Complex Idle Hunt + Preemption Injection | 0.95 | ~1600 | IPI Storm |
| Simplified | Sync Wake + Sticky Pref | 0.51 | ~1450 | Regression |
| Aggressive Local | Always current_cpu | 0.50 | ~4 | Serialized |
| Hybrid | Sync Wake + Global Idle Hunt | 1.00 | ~1300 | Parallelism restored |
| Tiered Hybrid v1 | Gaming: Hunt Always, BG: Sticky | 1.02 | 1092 | SUCCESS |
| Phase 1 Opt (Jan 2026) | Removed 9 redundant dsq_nr_queued checks | 1.25 | ~1540 | +21% IPC |
| Phase 2 Opt (Jan 2026) | Early mask==0 return | 0.95 | ~1460 | REGRESSION — reverted |
| IMPERATOR Context Layers | IRQ detect + waker inherit + lock protect | *N/A* | *N/A* | Tail-latency impact, not IPC |
| T3 kick (A/B) | Kick T3 victim on T0/T1 enqueue | — | — | −16 fps 1% low — reverted |
| T0/T1 bitmask kick | O(1) tier_cpu_mask kick, T3 victim only | — | — | In production |

The context layers do not affect IPC or RES interrupt rates. Their impact is on tail latency for IRQ-sourced wakeups and on priority inversion frequency under lock contention.
