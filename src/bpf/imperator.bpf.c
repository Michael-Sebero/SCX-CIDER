// SPDX-License-Identifier: GPL-2.0
/* scx_imperator - CAKE DRR++ adapted for CPU scheduling: avg_runtime classification, direct dispatch, tiered DSQ */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include "intf.h"
#include "bpf_compat.h"

char _license[] SEC("license") = "GPL";

/* Scheduler RODATA config - JIT constant-folds these for ~200 cycle savings per decision */
const u64 quantum_ns = CAKE_DEFAULT_QUANTUM_NS;
const u64 new_flow_bonus_ns = CAKE_DEFAULT_NEW_FLOW_BONUS_NS;
const bool enable_stats = false;

/* Topology config - JIT eliminates unused P/E-core steering when has_hybrid=false */
const bool has_hybrid = false;

/* Per-LLC DSQ partitioning — populated by loader from topology detection.
 * Eliminates cross-CCD lock contention: each LLC has its own DSQ.
 * Single-CCD (9800X3D): nr_llcs=1, identical to single-DSQ behavior.
 * Multi-CCD (9950X): nr_llcs=2, halves contention, eliminates cross-CCD atomics. */
const u32 nr_llcs = 1;
const u32 nr_cpus = 8;  /* Set by loader — bounds kick scan loop (Rule 39) */
const u32 cpu_llc_id[CAKE_MAX_CPUS] = {};

/* [A] llc_cpu_mask — BSS, computed by imperator_init from cpu_llc_id RODATA.
 *
 * Writable at BPF runtime; guaranteed non-zero for any LLC with ≥1 CPU before
 * the first task is scheduled.  Eliminates the partial-deploy hazard where a
 * missing Rust-side write left the mask all-zeros and the O(1) bitmask kick
 * path silently produced zero kicks without any error or warning.
 *
 * LAYOUT: 8 × 8B = 64B, one cache line.  Read in imperator_enqueue: one miss
 * loads the entire array.  Read-only after imperator_init completes. */
u64 llc_cpu_mask[CAKE_MAX_LLCS] SEC(".bss") __attribute__((aligned(64)));

/* ═══════════════════════════════════════════════════════════════════════════
 * MEGA-MAILBOX: 64-byte per-CPU state (single cache line = optimal L1)
 * - Zero false sharing: each CPU writes ONLY to mega_mailbox[its_cpu]
 * - 50% less L1 pressure than 128B design (16 vs 32 cache lines)
 * ═══════════════════════════════════════════════════════════════════════════ */
struct mega_mailbox_entry mega_mailbox[CAKE_MAX_CPUS] SEC(".bss");

/* Per-LLC non-empty flag: one cache line per LLC, eliminating cross-LLC
 * coherence traffic on every enqueue.
 *
 * FIX (audit): The previous design used a single shared volatile u32
 * (llc_nonempty_mask) updated via __sync_fetch_and_or on every enqueue path.
 * On a 16-core dual-CCD system at ~100K enqueues/sec this forced the cache
 * line to bounce between all cores on every task placement — roughly 100ns of
 * unnecessary coherence traffic per enqueue (~1% overhead at peak).
 *
 * New design: each LLC writes ONLY its own entry.  Other LLCs read entries
 * they do not own only during the steal scan in imperator_dispatch, which is an
 * infrequent (drain) event.  Cross-LLC coherence traffic is eliminated on the
 * hot enqueue path and reduced to at most (nr_llcs - 1) reads on drain.
 *
 * Intra-LLC writes (multiple CPUs in the same LLC writing nonempty=1): still
 * share a cache line, but all CPUs write the same value (1), so the line
 * stays in Shared state on x86 MESIF — no false-sharing stall.
 *
 * Stale non-empty flags (set bit when DSQ has drained) are still harmless:
 * the dispatch steal path calls scx_bpf_dsq_move_to_local which returns 0
 * when empty, at which point we clear the flag. */
struct {
    u8 nonempty;
    u8 _pad[63];  /* Pad to one cache line — prevents false sharing between LLCs */
} __attribute__((aligned(64))) llc_nonempty[CAKE_MAX_LLCS] SEC(".bss")
    __attribute__((aligned(64)));

/* [B] tier_cpu_mask — per-tier bitmask of CPUs currently running tasks of that tier.
 *
 * INVARIANT: bit i of tier_cpu_mask[t] is set iff CPU i is currently running a
 * task whose EWMA tier is t.
 *
 * Responsibility split (no double-ownership):
 *   imperator_running  → sets   bit for the new task's tier  (never clears)
 *   imperator_stopping → clears bit for the stopping tier    (never sets)
 *                    MUST clear BEFORE reclassify_task_cold() so that
 *                    GET_TIER(tctx) still returns the running-time tier, not
 *                    the post-EWMA tier.
 *
 * CONCURRENCY: __sync_fetch_and_or / __sync_fetch_and_and map to BPF_ATOMIC_OR /
 * BPF_ATOMIC_AND (single instruction, not a CAS loop).  No two CPUs write the
 * same bit simultaneously (each CPU owns its own bit = 1ULL << cpu_id).
 *
 * LAYOUT: 4 × 8B = 32B.  All four tier words share one 64B cache line with
 * llc_cpu_mask when the allocator places them adjacently — both are loaded on
 * the T0/T1 kick path.  CAKE_TIER_MAX = 4 so the alignment covers the array. */
u64 tier_cpu_mask[CAKE_TIER_MAX] SEC(".bss") __attribute__((aligned(64)));

/* Helper: mark an LLC's DSQ as non-empty.  Skip the store when already set to
 * avoid a needless write to a hot cache line on every enqueue. */
static __always_inline void llc_mark_nonempty(u32 llc_id)
{
    u32 idx = llc_id & (CAKE_MAX_LLCS - 1);
    if (!imperator_relaxed_load_u8(&llc_nonempty[idx].nonempty))
        imperator_relaxed_store_u8(&llc_nonempty[idx].nonempty, 1);
}

/* Metadata accessors (Fused layout) */
#define GET_TIER_RAW(packed) EXTRACT_BITS_U32(packed, SHIFT_TIER, 2)
#define GET_TIER(ctx) GET_TIER_RAW(imperator_relaxed_load_u32(&(ctx)->packed_info))

/* Per-CPU scratch area - BSS-tunneled helper outputs, isolated to prevent MESI contention.
 *
 * FIX (audit): Removed dead fields bpf_iter_scx_dsq it and init_tier.
 * bpf_iter_scx_dsq was never referenced after the per-LLC DSQ migration;
 * init_tier is a local variable in alloc_task_ctx_cold, not a scratch field.
 * Together they consumed ~79B of the 128B line (4.8 KB across 64 CPUs) and
 * forced false-sharing through the iterator's alignment requirements. */
struct imperator_scratch {
    bool dummy_idle;            /* 1B: idle flag from scx_bpf_select_cpu_dfl */
    u8   _pad0[3];              /* Align cached_llc to u32 boundary */
    u32  cached_llc;            /* 4B: LLC ID tunneled from select_cpu → enqueue (saves 1 kfunc) */
    u64  cached_now;            /* 8B: scx_bpf_now() tunneled from select_cpu → enqueue (saves 1 kfunc) */
    u8   _pad[112];             /* Pad to 128B (2 cache lines): 1+3+4+8+112 = 128 */
} global_scratch[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(128)));
_Static_assert(sizeof(struct imperator_scratch) == 128,
    "imperator_scratch must be exactly 128B (2 cache lines) -- update _pad if fields change");

/* Global stats BSS array - 0ns lookup vs 25ns helper, 256-byte aligned per CPU */
struct imperator_stats global_stats[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(256)));

/* BSS tail guard - absorbs BTF truncation bugs instead of corrupting real data */
u8 __bss_tail_guard[64] SEC(".bss") __attribute__((aligned(64)));

/* LLC-pair ETD latency cost table — written from userspace after ETD calibration.
 * Unit: 4 ns/unit (0 = unknown or same LLC, 255 = ~1020 ns).
 * Zero-initialised (BSS): safe default before calibration completes — the steal
 * path treats all-zero costs as "no preference" and falls back to index order.
 *
 * Layout: llc_etd_cost[src_llc][dst_llc].  Values are symmetric (min round-trip
 * latency / 2) and set by the Rust-side try_write_etd_costs() after ETD finishes. */
u8 llc_etd_cost[CAKE_MAX_LLCS][CAKE_MAX_LLCS] SEC(".bss")
    __attribute__((aligned(64)));

/* Mailbox mask builders removed — select_cpu now delegates idle detection
 * to scx_bpf_select_cpu_dfl() which uses the kernel's authoritative idle
 * tracking (zero staleness, atomic claiming). */

static __always_inline struct imperator_stats *get_local_stats(void)
{
    u32 cpu = bpf_get_smp_processor_id();
    return &global_stats[cpu & (CAKE_MAX_CPUS - 1)];
}

/* ETD surgical seek / find_surgical_victim_logical removed — select_cpu
 * now delegates idle selection to scx_bpf_select_cpu_dfl() which does
 * prev → sibling → LLC cascade internally with kernel-native topology. */

/* Victim finder / arbiter removed — select_cpu now uses kernel-delegated
 * idle selection. When all CPUs are busy, enqueue handles placement via
 * per-LLC DSQs with vtime-encoded tier priority. */

/* User exit info for graceful scheduler exit */
UEI_DEFINE(uei);

/* Global vtime removed to prevent bus locking. Tasks inherit vtime from parent. */

/* Optimization: Precomputed threshold to avoid division in hot path */
/* BTF fix: Non-static + aligned(8) prevents tail truncation bug */
/* Cached threshold moved to RODATA */

/* A+B ARCHITECTURE: Per-LLC DSQs with vtime-encoded priority.
 * DSQ IDs: LLC_DSQ_BASE + 0, LLC_DSQ_BASE + 1, ... (one per LLC). */

/* Per-CPU Direct Dispatch Queues (1000-1063) */
#define CAKE_DSQ_LC_BASE 1000

/* Tier config table - 4 tiers + padding, AoS layout: single cache line fetch */
const fused_config_t tier_configs[8] = {
    /* T0: Critical (<100µs) — IRQ, input, audio */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T0,
                CAKE_DEFAULT_WAIT_BUDGET_T0 >> 10, CAKE_DEFAULT_STARVATION_T0 >> 10),
    /* T1: Interactive (<2ms) — compositor, physics */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T1,
                CAKE_DEFAULT_WAIT_BUDGET_T1 >> 10, CAKE_DEFAULT_STARVATION_T1 >> 10),
    /* T2: Frame Producer (<8ms) — game render, encoding */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T2,
                CAKE_DEFAULT_WAIT_BUDGET_T2 >> 10, CAKE_DEFAULT_STARVATION_T2 >> 10),
    /* T3: Bulk (≥8ms) — compilation, background */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_WAIT_BUDGET_T3 >> 10, CAKE_DEFAULT_STARVATION_T3 >> 10),
    /* Padding (copies of T3 for safe & 7 access) */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_WAIT_BUDGET_T3 >> 10, CAKE_DEFAULT_STARVATION_T3 >> 10),
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_WAIT_BUDGET_T3 >> 10, CAKE_DEFAULT_STARVATION_T3 >> 10),
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_WAIT_BUDGET_T3 >> 10, CAKE_DEFAULT_STARVATION_T3 >> 10),
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_WAIT_BUDGET_T3 >> 10, CAKE_DEFAULT_STARVATION_T3 >> 10),
};

/* Per-tier graduated backoff recheck masks (RODATA)
 * Lower tiers (more stable) recheck less often.
 * T0 IRQs almost never change behavior → every 1024th stop.
 * T3 bulk tasks may transition → every 16th stop. */
static const u16 tier_recheck_mask[] = {
    1023,  /* T0: every 1024th stop */
    127,   /* T1: every 128th  */
    31,    /* T2: every 32nd   */
    15,    /* T3: every 16th   */
    15, 15, 15, 15,  /* padding */
};

/* Vtime table removed - FIFO DSQs don't use dsq_vtime, saved 160B + 30 cycles */

/* Per-task context map */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct imperator_task_ctx);
} task_ctx SEC(".maps");

/* Bitfield accessors - relaxed atomics prevent tearing */

/* Metadata Accessors - Definitions moved to top */

/* FIX (audit): Guard the shift arithmetic in alloc_task_ctx_cold that packs
 * both TIER and FLAGS bits in a single expression using SHIFT_FLAGS as the
 * base with +4 offset for tier.  If SHIFT_TIER or SHIFT_FLAGS are ever
 * changed independently, the expression silently misplaces one field. */
_Static_assert(SHIFT_TIER == SHIFT_FLAGS + 4,
    "alloc_task_ctx_cold init expression assumes SHIFT_TIER == SHIFT_FLAGS + 4 -- update packing");

/* COLD PATH: Task allocation + kthread init - noinline keeps I-Cache tight for hot path */
/* Removed accounting functions - now in tick */
/* set_victim_status_cold removed - mailbox handles victim status */

/* perform_lazy_accounting removed - accounting in tick */

/* init_new_kthread_cold inlined into imperator_enqueue — reuses hoisted
 * now_cached + enq_llc, saving 2 kfunc calls per kthread enqueue. */

/* select_cpu_new_task_cold removed — new tasks go through the same
 * scx_bpf_select_cpu_dfl path as all other tasks. */

static __attribute__((noinline))
struct imperator_task_ctx *alloc_task_ctx_cold(struct task_struct *p)
{
    struct imperator_task_ctx *ctx;

    /* Heavy allocator call */
    ctx = bpf_task_storage_get(&task_ctx, p, 0,
                               BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ctx) return NULL;

    ctx->next_slice = quantum_ns;
    u16 init_deficit = (u16)((quantum_ns + new_flow_bonus_ns) >> 10);
    ctx->last_run_at = 0;
    ctx->reclass_counter = 0;
    ctx->overrun_count = 0;
    ctx->lock_skip_count = 0;

    /* FIX (C-2): Initialise pending_futex_op to CAKE_FUTEX_OP_UNSET (0xFF).
     *
     * BPF task-storage zero-initialises new entries, giving pending_futex_op
     * the value 0 == CAKE_FUTEX_WAIT.  The guard in imperator_tp_exit_futex only
     * returns early when pending_futex_op == 0xFF (UNSET); with 0 it falls
     * through to the switch-case and calls set_lock_holder() for any
     * sys_exit_futex with ret==0 — including tasks whose first kernel event
     * is a successful futex return before any sys_enter_futex was observed.
     *
     * Writing 0xFF here makes the UNSET guard unconditionally safe: the field
     * stays 0xFF until imperator_tp_enter_futex records a real op, and the exit
     * handler skips cleanly until then. */
    ctx->pending_futex_op = CAKE_FUTEX_OP_UNSET;

    /* MULTI-SIGNAL INITIAL CLASSIFICATION
     *
     * Two cheap signals set the starting point; avg_runtime classification
     * takes over after the first few execution bouts and is authoritative.
     *
     * Signal 1: Nice value (u32 field read, ~2 cycles)
     *   - nice < 0 (prio < 120): OS/user explicitly prioritized
     *     System services (-20), pipewire (-11), games with nice (-5)
     *     → T0 initially, avg_runtime reclassifies after first runs
     *   - nice > 10 (prio > 130): explicitly deprioritized
     *     Background builds, indexers → T3, stays if bulk
     *   - nice 0-10: default → T1, avg_runtime adjusts naturally
     *
     * Signal 2: PF_KTHREAD flag (1 bit test, already known by caller)
     *   Kthreads with nice < 0 get T0 from Signal 1 automatically.
     *   Kthreads with nice 0 start at T1 like all other nice-0 tasks.
     *   No pin — reclassify based on actual avg_runtime behavior:
     *   - ksoftirqd: ~10μs bursts → T0 within 3 stops
     *   - kcompactd: long runs → T2-T3 naturally
     *
     * Signal 3: Runtime behavior (ongoing, ~15ns/stop — authoritative)
     *   Pure avg_runtime → tier mapping in reclassify_task_cold(). */

    /* Nice value: static_prio 100 = nice -20, 120 = nice 0, 139 = nice 19 */
    u32 prio = p->static_prio;
    u8 init_tier;

    if (prio < 120) {
        /* Negative nice: OS or user explicitly prioritized.
         * avg_runtime=0 at init → T0 until first reclassify. */
        init_tier = CAKE_TIER_CRITICAL;
    } else if (prio > 130) {
        /* High nice (>10): explicitly deprioritized.
         * Background builds, indexers, low-priority daemons. */
        init_tier = CAKE_TIER_BULK;
    } else {
        /* Default (nice 0-10): start at Interactive.
         * avg_runtime reclassifies to correct tier within ~3 stops. */
        init_tier = CAKE_TIER_INTERACT;
    }

    /* FIX (audit): Seed avg_runtime_us at the midpoint of the initial tier's
     * expected range rather than 0. Starting from 0 caused any task with a
     * short first execution bout (< tier gate / 16) to receive an EWMA of
     * rt/16 after one bout — fast enough to classify as T0 — regardless of
     * its long-term behavior.  A bulk task (nice >10) with a 200µs first
     * bout would earn T0 priority for 4–16 subsequent bouts before the EWMA
     * corrected, starving gaming threads at application startup time.
     *
     * Midpoints chosen as the geometric mean of adjacent gate values so the
     * EWMA converges to the correct tier within ~3 bouts for well-behaved tasks:
     *   T0 Critical  (< 100µs):   midpoint ≈  50µs
     *   T1 Interact  (< 2000µs):  midpoint ≈ 1050µs
     *   T2 Frame     (< 8000µs):  midpoint ≈ 5000µs
     *   T3 Bulk      (≥ 8000µs):  floor  = 8001µs */
    u16 init_avg_rt;
    if (init_tier == CAKE_TIER_CRITICAL)
        init_avg_rt = TIER_GATE_T0 / 2;
    else if (init_tier == CAKE_TIER_INTERACT)
        init_avg_rt = (TIER_GATE_T0 + TIER_GATE_T1) / 2;
    else if (init_tier == CAKE_TIER_FRAME)
        init_avg_rt = (TIER_GATE_T1 + TIER_GATE_T2) / 2;
    else
        init_avg_rt = TIER_GATE_T2 + 1;

    ctx->deficit_avg_fused = PACK_DEFICIT_AVG(init_deficit, init_avg_rt);

    u32 packed = 0;
    packed |= (255 & MASK_KALMAN_ERROR) << SHIFT_KALMAN_ERROR;
    /* Fused TIER+FLAGS: bits [29:24] = [tier:2][flags:4] (Rule 37 coalescing) */
    packed |= (((u32)(init_tier & MASK_TIER) << 4) | (CAKE_FLOW_NEW & MASK_FLAGS)) << SHIFT_FLAGS;
    /* stable=0, wait_data=0: implicit from packed=0 */

    ctx->packed_info = packed;

    return ctx;
}

/* Get/init task context - hot path: fast lookup only, cold path: noinline alloc */
static __always_inline struct imperator_task_ctx *get_task_ctx(struct task_struct *p, bool create)
{
    struct imperator_task_ctx *ctx;

    /* Fast path: lookup existing context */
    ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (ctx)
        return ctx;

    /* If caller doesn't want allocation, return NULL */
    if (!create)
        return NULL;

    /* Slow path: delegate to cold section */
    return alloc_task_ctx_cold(p);
}

/* Noinline accounting - math-heavy ops moved here to free registers (now fully async in tick) */

/* T0 victim cold path removed — when all CPUs are busy, tasks go through
 * enqueue → per-LLC DSQ where vtime ordering ensures T0 tasks get pulled
 * first. Preemption handled by imperator_tick starvation checks. */

/* ═══════════════════════════════════════════════════════════════════════════
 * KERNEL-FIRST FLAT SELECT_CPU: ~20 instructions vs ~200+ in the old cascade.
 *
 * Architecture: delegate idle detection to the kernel's authoritative
 * scx_bpf_select_cpu_dfl() which does prev → sibling → LLC cascade internally
 * with zero staleness and atomic claiming. When all CPUs are busy, return
 * prev_cpu and let imperator_enqueue handle via per-LLC DSQ with vtime ordering.
 *
 * Benefits (tier-agnostic by design — all tiers equally important):
 * - All tiers 0-3 take the same placement path (tiers define latency, not affinity)
 * - Zero bpf_task_storage_get in select_cpu (no tier/slice needed)
 * - Zero mailbox reads (kernel has authoritative idle data)
 * - Zero stale mask cascades (kernel idle bitmap is real-time)
 * - ~90-110 cycles vs ~200-500 cycles (~20-40ns p50 improvement)
 * ═══════════════════════════════════════════════════════════════════════════ */
/* ── SHARED HELPER: IRQ-wake flag consumption ───────────────────────────────
 * Centralises the CAKE_FLOW_IRQ_WAKE one-shot flag consumption that previously
 * appeared identically in both dispatch_sync_cold and the dummy_idle branch of
 * imperator_select_cpu.  Keeping two copies risked them drifting apart silently.
 *
 * Consumes the flag atomically if set, writes the T0 slice to *slice_out, and
 * returns CAKE_TIER_CRITICAL.  If not set, passes through next_slice and the
 * task's current tier.  If tctx is NULL (task not yet classified), defaults to
 * quantum_ns + CAKE_TIER_INTERACT — safe for unclassified tasks on idle CPUs.
 *
 * Called only from direct-dispatch paths (SCX_DSQ_LOCAL_ON) where imperator_enqueue
 * will NOT run to consume the flag; leaving it set would cause a stale T0 boost
 * on the task's next wakeup. */
static __always_inline u8
consume_irq_wake_get_tier_slice(struct imperator_task_ctx *tctx, u64 *slice_out)
{
    if (tctx) {
        u32 packed = imperator_relaxed_load_u32(&tctx->packed_info);
        if (unlikely(packed & ((u32)CAKE_FLOW_IRQ_WAKE << SHIFT_FLAGS))) {
            __sync_fetch_and_and(&tctx->packed_info,
                                 ~((u32)CAKE_FLOW_IRQ_WAKE << SHIFT_FLAGS));
            u64 cfg = tier_configs[CAKE_TIER_IDX(CAKE_TIER_CRITICAL)];
            *slice_out = (quantum_ns * UNPACK_MULTIPLIER(cfg)) >> 10;
            if (enable_stats) {
                struct imperator_stats *s = get_local_stats();
                if (s) s->nr_irq_wake_boosts++;
            }
            return CAKE_TIER_CRITICAL;
        }
        *slice_out = tctx->next_slice;
        return CAKE_TIER_IDX(GET_TIER(tctx));
    }
    *slice_out = quantum_ns;
    return CAKE_TIER_INTERACT;
}

/* SYNC fast-path dispatch: waker's CPU is by definition running.
 * Noinline: only 3 args (p, wake_flags, hint_tctx) — r1→r6, r2→r7, r3→r8.
 * hint_tctx is the pointer already obtained by the IRQ-detection block at
 * the top of imperator_select_cpu; passing it here eliminates a second
 * bpf_task_storage_get (~20c) on the SYNC path (the dominant gaming wakeup).
 * hint_tctx may be NULL for unclassified tasks — consume_irq_wake_get_tier_slice
 * handles that case with safe defaults.
 *
 * CPUMASK GUARD: Check inside cold path (Rule 5/13: no extra work on
 * inline hot path). Wine/Proton threadpools use sched_setaffinity —
 * waker's CPU may not be in woken task's cpumask. Returns -1 to signal
 * fallthrough to kernel path which handles cpumask correctly. */
static __attribute__((noinline))
s32 dispatch_sync_cold(struct task_struct *p, u64 wake_flags,
                       struct imperator_task_ctx *hint_tctx)
{
    u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
        return -1;

    /* Use the tctx pointer already in hand — no second storage lookup needed. */
    struct imperator_task_ctx *tctx = hint_tctx;

    /* Determine effective tier and slice via shared helper.
     * consume_irq_wake_get_tier_slice() handles the CAKE_FLOW_IRQ_WAKE one-shot
     * flag, T0 slice computation, stats accounting, and NULL-tctx fallback. */
    u64 slice;
    u8 tier = consume_irq_wake_get_tier_slice(tctx, &slice);

    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, wake_flags);

    /* FIX (#11): Count direct-dispatch stats so TUI reflects the common idle-path case. */
    if (enable_stats) {
        struct imperator_stats *s = get_local_stats();
        if (s) {
            s->nr_new_flow_dispatches++;
            if (tier < CAKE_TIER_MAX)
                s->nr_tier_dispatches[tier]++;
        }
    }

    return (s32)cpu;
}

s32 BPF_STRUCT_OPS(imperator_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags)
{
    /* ── IRQ-SOURCE WAKEUP DETECTION (adapted from LAVD lavd_select_cpu) ──
     * S2: Hoist the three context checks BEFORE the storage lookup.
     * bpf_in_hardirq/nmi/softirq are pure register queries (~1 cycle each);
     * bpf_task_storage_get costs ~20 cycles.  On a loaded gaming system the
     * dominant path is all-CPUs-busy + non-SYNC + no IRQ — the lookup was
     * pure waste on that path.  Now we only pay for it when we'll use it:
     *   • IRQ context detected  → need tctx to stamp CAKE_FLOW_IRQ_WAKE
     *   • SCX_WAKE_SYNC         → dispatch_sync_cold uses tctx as hint
     *   • idle path (dummy_idle)→ lazy lookup deferred to after dfl call
     * The all-busy non-SYNC non-IRQ path (dominant under load) never touches
     * task storage in select_cpu. */
    bool in_hardirq_or_nmi = bpf_in_hardirq() || bpf_in_nmi();
    bool in_softirq        = bpf_in_serving_softirq();
    bool irq_context       = in_hardirq_or_nmi || in_softirq;

    /* ksoftirqd check: only on non-SYNC, non-IRQ paths (same guard as before) */
    if (!irq_context && !(wake_flags & SCX_WAKE_SYNC)) {
        struct task_struct *waker = bpf_get_current_task_btf();
        if (waker && (waker->flags & PF_KTHREAD) &&
            __builtin_memcmp(waker->comm, "ksoftirqd/", 10) == 0)
            irq_context = true;
    }

    /* Fetch tctx only when a downstream path will consume it */
    struct imperator_task_ctx *irq_tctx =
        (irq_context || (wake_flags & SCX_WAKE_SYNC)) ?
        bpf_task_storage_get(&task_ctx, p, 0, 0) : NULL;

    if (unlikely(irq_context) && irq_tctx)
        __sync_fetch_and_or(&irq_tctx->packed_info,
                            (u32)CAKE_FLOW_IRQ_WAKE << SHIFT_FLAGS);

    /* SYNC FAST PATH: Direct dispatch to waker's CPU.
     * Pass irq_tctx already obtained above — dispatch_sync_cold reuses it
     * directly, saving one bpf_task_storage_get (~20c) on this hot path.
     * Cold helper checks cpumask internally (Rule 5: zero extra hot-path
     * instructions). Returns -1 if cpumask disallows → fall through. */
    if (wake_flags & SCX_WAKE_SYNC) {
        s32 sync_cpu = dispatch_sync_cold(p, wake_flags, irq_tctx);
        if (sync_cpu >= 0)
            return sync_cpu;
    }

    u32 tc_id = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct imperator_scratch *scr = &global_scratch[tc_id];
    s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &scr->dummy_idle);

    if (scr->dummy_idle) {
        /* S2 lazy lookup: tctx was skipped above on non-IRQ non-SYNC paths.
         * Fetch it now that we know we're on the direct-dispatch path and
         * need the task's actual tier + slice.  If already fetched (IRQ path),
         * reuse it — no second lookup. */
        struct imperator_task_ctx *tctx = irq_tctx ?
            irq_tctx : bpf_task_storage_get(&task_ctx, p, 0, 0);

        /* Shared helper handles flag consumption, stats, and NULL-tctx fallback. */
        u64 slice;
        u8  tier = consume_irq_wake_get_tier_slice(tctx, &slice);

        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, wake_flags);

        /* FIX (#11): Count idle-path direct dispatches for accurate TUI stats. */
        if (enable_stats) {
            struct imperator_stats *s = get_local_stats();
            if (s) {
                s->nr_new_flow_dispatches++;
                if (tier < CAKE_TIER_MAX)
                    s->nr_tier_dispatches[tier]++;
            }
        }

        return cpu;
    }

    /* ALL BUSY: tunnel LLC ID + timestamp for enqueue (~22ns saved on
     * the 90% idle path above where these were previously wasted).
     * select_cpu runs on same CPU as enqueue — safe to tunnel.
     *
     * FIX (audit): Use the *task's* target LLC (derived from cpu, which is
     * prev_cpu when all CPUs are busy) rather than the *waker's* LLC (tc_id).
     * On a dual-CCD system nearly all "all-busy" enqueues previously landed
     * in the waker's LLC DSQ but were dispatched from prev_cpu's LLC, forcing
     * 100% of those tasks through the slower cross-LLC steal path. */
    scr->cached_llc = cpu_llc_id[(u32)cpu & (CAKE_MAX_CPUS - 1)];
    scr->cached_now = scx_bpf_now();
    return prev_cpu;
}

/* ENQUEUE-TIME KICK: DISABLED for T2/T3.
 * A/B testing confirmed indiscriminate kicks cause 16fps 1% low regression in Arc Raiders
 * (252fps without kick, 236fps with T3-only kick). Even T3-only kicks create
 * cache pollution and GPU pipeline bubbles. T0/T1 kicks are retained via the
 * O(1) bitmask path below; tick-based starvation detection covers the rest. */

/* Enqueue - A+B architecture: per-LLC DSQ with vtime = (tier << 56) | timestamp */
void BPF_STRUCT_OPS(imperator_enqueue, struct task_struct *p, u64 enq_flags)
{
    register struct task_struct *p_reg asm("r6") = p;
    u32 task_flags = p_reg->flags;

    /* KFUNC TUNNELING: Reuse LLC ID + timestamp cached by select_cpu in scratch.
     * Eliminates 2 kfunc trampolines (~40-60ns) — select_cpu always runs on
     * the same CPU immediately before enqueue, so values are fresh. */
    u32 enq_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct imperator_scratch *scr = &global_scratch[enq_cpu];
    u64 now_cached = scr->cached_now;
    u32 enq_llc = scr->cached_llc;

    struct imperator_task_ctx *tctx = get_task_ctx(p_reg, false);

    /* FIX (#10): Kthreads without a tctx (race window before imperator_enable fires)
     * previously received CAKE_TIER_CRITICAL unconditionally, giving kcompactd,
     * kswapd, and similar bulk kthreads unwarranted T0 priority that could starve
     * game threads. Changed to CAKE_TIER_INTERACT (T1) which matches the tier
     * assigned to nice=0 kthreads by alloc_task_ctx_cold(). They will reclassify
     * to their correct tier within a few stops once a tctx is allocated. */
    if (unlikely((task_flags & PF_KTHREAD) && !tctx)) {
        u64 vtime = ((u64)CAKE_TIER_INTERACT << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, quantum_ns, vtime, enq_flags);
        llc_mark_nonempty(enq_llc);
        return;
    }

    register struct imperator_task_ctx *tctx_reg asm("r7") = tctx;

    /* FIX (#3): Voluntarily yielding T0/T1 tasks (sched_yield, brief hardware wait)
     * were previously hard-coded to CAKE_TIER_BULK, sending audio/input threads to
     * the back of the T3 queue for up to 100ms. They now use their actual tier so
     * latency-sensitive tasks remain properly prioritized even when yielding.
     * Tasks with no context yet fall back to T3 (yield implies they're not urgent). */
    if (!(enq_flags & (SCX_ENQ_WAKEUP | SCX_ENQ_PREEMPT))) {
        u8 yield_tier = tctx_reg ? CAKE_TIER_IDX(GET_TIER(tctx_reg)) : CAKE_TIER_BULK;
        u64 vtime = ((u64)yield_tier << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, quantum_ns, vtime, enq_flags);
        llc_mark_nonempty(enq_llc);
        return;
    }

    if (unlikely(!tctx_reg)) {
        /* No context yet - use Frame tier */
        u64 vtime = ((u64)CAKE_TIER_FRAME << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, quantum_ns, vtime, enq_flags);
        llc_mark_nonempty(enq_llc);
        return;
    }

    /* Standard Tier Logic */
    u8 tier = CAKE_TIER_IDX(GET_TIER(tctx_reg));
    u64 slice = tctx_reg->next_slice;

    /* Load packed_info once — shared by all three feature checks below. */
    u32 task_packed = imperator_relaxed_load_u32(&tctx_reg->packed_info);

    /* ── FEATURE 1: IRQ-SOURCE TIER OVERRIDE (adapted from LAVD) ──────────
     * If imperator_select_cpu stamped CAKE_FLOW_IRQ_WAKE, this task was woken
     * directly from a hardware interrupt or softirq bottom-half. It should
     * run at T0 for this dispatch regardless of its current EWMA tier, for
     * the same reason LAVD applies LAVD_LC_WEIGHT_BOOST_HIGHEST: the
     * interrupt represents completed hardware I/O and the woken task is the
     * direct consumer (mouse handler, audio callback, network receive).
     *
     * Semantics: one-shot — the flag is cleared atomically here so it cannot
     * accumulate across bounces or affect the EWMA classification path.
     * This does NOT permanently alter the task's tier; reclassify_task_cold
     * continues to govern long-term placement via avg_runtime_us. */
    if (unlikely(task_packed & ((u32)CAKE_FLOW_IRQ_WAKE << SHIFT_FLAGS))) {
        /* Consume the flag atomically before branching — prevents double-boost
         * if select_cpu and enqueue race on a re-enqueue path. */
        __sync_fetch_and_and(&tctx_reg->packed_info,
                             ~((u32)CAKE_FLOW_IRQ_WAKE << SHIFT_FLAGS));
        task_packed &= ~((u32)CAKE_FLOW_IRQ_WAKE << SHIFT_FLAGS);
        tier = CAKE_TIER_CRITICAL;  /* T0 for this dispatch only */

        if (enable_stats) {
            struct imperator_stats *s = get_local_stats();
            if (s) s->nr_irq_wake_boosts++;
        }
    }

    /* ── FEATURE 2: WAKER TIER INHERITANCE (adapted from LAVD) ─────────────
     * LAVD propagates latency criticality through task graphs via
     * lat_cri_waker/lat_cri_wakee fields. CAKE's simpler equivalent: when
     * a high-priority task wakes a lower-priority task, temporarily promote
     * the wakee to at most (waker_tier + 1).
     *
     * Rationale for gaming: a T0 input handler wakes the game's event
     * dispatcher (T2) — without promotion, the event dispatcher sits in
     * the T2 queue for up to 40ms. With promotion it runs in the T1 queue
     * for this dispatch, and its EWMA will naturally converge to T1 within
     * a few bouts if the pattern is consistent.
     *
     * Cost: one BSS L1 read (mega_mailbox[enq_cpu].flags, already in L1
     * from any recent imperator_tick on this CPU) + one comparison + one branch.
     * ~4 cycles on an uncontested cacheline; zero if waker_tier >= tier.
     *
     * Constraints:
     *   - Only on SCX_ENQ_WAKEUP (producer→consumer, not preempt or yield).
     *   - Never promotes above CAKE_TIER_CRITICAL (floor is 0).
     *   - Never demotes: if the wakee is already T0, this is a no-op.
     *   - One-dispatch only: does not alter packed_info, so EWMA is unaffected.
     *   - Only when tick_counter > 0: mega_mailbox flags are zero-initialized
     *     (BSS). If no tick has fired on the waker's CPU yet, waker_tier would
     *     read 0 (CRITICAL) spuriously, promoting every T2/T3 wakee on first
     *     boot. tick_counter is incremented on the very first tick, making
     *     it a reliable "mailbox is valid" sentinel.
     *
     * NOTE: enq_cpu is the waker's CPU — the same CPU that ran select_cpu
     * and is now running enqueue. mega_mailbox[enq_cpu].flags contains the
     * tier of the last task that ran on this CPU, set by imperator_tick. */
    if ((enq_flags & SCX_ENQ_WAKEUP) && tier > CAKE_TIER_CRITICAL) {
        struct mega_mailbox_entry *waker_mbox = &mega_mailbox[enq_cpu];
        /* Guard: only inherit when imperator_running has written valid tier data to
         * this CPU's mailbox.  imperator_running writes flags unconditionally on every
         * context switch, so a non-zero flags byte means the mailbox is initialized.
         * tick_counter was previously used here but becomes valid only after the
         * first imperator_tick — a longer window than necessary since imperator_running
         * makes the mailbox valid from the very first context switch. */
        u8 cur_mbox_flags = imperator_relaxed_load_u8(&waker_mbox->flags);
        if (cur_mbox_flags != 0) {
            u8 waker_tier = MBOX_GET_TIER(cur_mbox_flags);
            if (waker_tier < tier) {
                /* FIX (audit): Previous formula was waker_tier + 1, which meant a T1
                 * waker promoted a T3 wakee only to T2, not T1.  On a 4ms frame budget
                 * a T2 wakee (40ms starvation threshold) could still delay the event
                 * dispatcher by an entire frame.
                 *
                 * New policy: promote wakee to exactly waker_tier, but never to T0
                 * (CRITICAL) for ordinary wakeups — that tier is reserved for hardware
                 * IRQ consumers (CAKE_FLOW_IRQ_WAKE path).  A T0 audio waker therefore
                 * promotes the game's event dispatcher to T1 directly rather than T2,
                 * cutting its maximum dispatch latency from 40ms to 8ms (Gaming T1
                 * starvation threshold).  A T1 compositor waking a T2 render thread
                 * promotes it to T1 for one dispatch, keeping the pipeline tight.
                 *
                 * Floor at CAKE_TIER_INTERACT (1): prevents T0-wakers from erroneously
                 * giving T0 to arbitrary wakees through the inheritance path.  Genuine
                 * T0 priority is still granted via IRQ-wake boosting for the hardware
                 * I/O consumer path, which is the correct source of T0 authority. */
                u8 promoted = (waker_tier < CAKE_TIER_INTERACT) ? CAKE_TIER_INTERACT
                                                                 : waker_tier;
                if (promoted < tier) {
                    tier = promoted;
                    if (enable_stats) {
                        struct imperator_stats *s = get_local_stats();
                        if (s) s->nr_waker_tier_boosts++;
                    }
                }
            }
        }
    }

    if (enable_stats) {
        struct imperator_stats *s = get_local_stats();
        if (s) {
            if (enq_flags & SCX_ENQ_WAKEUP)
                s->nr_new_flow_dispatches++;
            else
                s->nr_old_flow_dispatches++;
            if (tier < CAKE_TIER_MAX)
                s->nr_tier_dispatches[tier]++;
        }
    }

    /* A+B: Vtime-encoded priority: (tier << 56) | timestamp
     *
     * DRR++ NEW FLOW BONUS: Tasks with CAKE_FLOW_NEW get a vtime reduction,
     * making them drain before established same-tier tasks. This gives
     * newly spawned threads instant responsiveness (e.g., game launching a
     * new worker). Cleared by reclassify_task_cold when deficit exhausts.
     *
     * FIX (#2): Guard vtime subtraction to prevent underflow into the tier
     * bits at [63:56]. If now_cached is small (early boot or timer wrap) and
     * new_flow_bonus_ns is large (8ms), the raw subtraction wraps the u64
     * into the tier field, silently misclassifying the task. Use saturating
     * arithmetic on the timestamp portion only.
     *
     * ── FEATURE 3: LOCK HOLDER VTIME ADVANCE (adapted from LAVD) ──────────
     * If this task currently holds a futex (set by lock_bpf.c fexit probes),
     * advance its virtual timestamp within the tier by subtracting
     * lock_holder_advance_ns. This sorts it ahead of same-tier peers without
     * changing its tier, so it runs sooner and releases the lock faster,
     * unblocking any waiter (which may be a T0 audio or input thread).
     *
     * Why within-tier rather than tier promotion?
     *   Promoting a T3 bulk task that happens to hold a lock to T0 would
     *   preempt audio and input threads. A within-tier advance is precise:
     *   the holder races only against other same-tier tasks.
     *
     * Magnitude: new_flow_bonus_ns (8ms) is a natural sentinel — it is
     * the largest advance already in the system (DRR++ new-flow bonus), so
     * using the same value keeps the relative ordering consistent and avoids
     * introducing a new tuning parameter. */
    u64 ts = now_cached & 0x00FFFFFFFFFFFFFFULL;
    if (task_packed & ((u32)CAKE_FLOW_NEW << SHIFT_FLAGS))
        ts = (ts > new_flow_bonus_ns) ? (ts - new_flow_bonus_ns) : 0;

    /* Lock-holder advance: sort ahead of same-tier non-holders. Applied after
     * new-flow bonus so both effects compound (a new flow that also holds a
     * lock sorts to the very front of its tier). Saturating to preserve tier
     * bits — same FIX (#2) guard. */
    if (unlikely(task_packed & ((u32)CAKE_FLAG_LOCK_HOLDER << SHIFT_FLAGS)))
        ts = (ts > new_flow_bonus_ns) ? (ts - new_flow_bonus_ns) : 0;

    u64 vtime = ((u64)tier << 56) | ts;

    scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, slice, vtime, enq_flags);
    /* Mark LLC as non-empty so dispatch can find work */
    llc_mark_nonempty(enq_llc);

    /* ── [F] s6: O(1) BITMASK PREEMPTION KICK ────────────────────────────────
     * When a T0/T1 task is enqueued into the LLC DSQ and all CPUs are busy,
     * kick a victim CPU in the same LLC that is running a lower-priority task
     * (T3 preferred, then T2) so it context-switches and pulls the waiting
     * high-priority task via imperator_dispatch.
     *
     * O(1) via tier_cpu_mask × llc_cpu_mask:
     *   tier_cpu_mask[t]: bitmask of CPUs currently running tier-t tasks
     *                     (maintained by imperator_running/imperator_stopping)
     *   llc_cpu_mask[l]:  bitmask of CPUs belonging to LLC l
     *                     (computed by imperator_init from cpu_llc_id RODATA)
     *   AND of the two → CPUs in this LLC running that tier → BSF → victim
     *
     * Victim preference: T3 (bulk) first — displacing a bulk task costs the
     * least in frame-time disruption.  Fallback to T2 (frame) only when no T3
     * CPU is present in the LLC.  T1 and T0 are not kicked — we never displace
     * a latency-critical task to run another one.
     *
     * Cost vs previous O(nr_cpus) mailbox scan (16-thread LLC):
     *   Removed: 16 relaxed u8 loads (scattered mailbox lines) + 16 cpu_llc_id
     *            reads + loop overhead + max-tracking branch
     *   Added:   2 relaxed u64 loads (tier_cpu_mask, same cache line)
     *            + 1 relaxed u64 load (llc_cpu_mask, RODATA)
     *            + 1 AND + 1 BSF per tier attempted
     *   Net: ~80–100 cycles removed, ~12 cycles added
     *
     * Correctness: llc_cpu_mask is guaranteed non-zero by imperator_init [C] for
     * any LLC with at least one CPU.  AND with tier_cpu_mask produces zero only
     * when genuinely no T3/T2 CPU exists in the LLC — the correct "no victim"
     * result.  The previous all-zero risk from a missing Rust write no longer
     * exists. */
    if (tier <= CAKE_TIER_INTERACT) {
        u64 my_llc_mask = imperator_relaxed_load_u64(
            &llc_cpu_mask[enq_llc & (CAKE_MAX_LLCS - 1)]);

        /* Prefer displacing T3 (bulk) — lowest frame-time displacement cost */
        u64 t3_in_llc = imperator_relaxed_load_u64(
            &tier_cpu_mask[CAKE_TIER_BULK]) & my_llc_mask;
        if (t3_in_llc) {
            scx_bpf_kick_cpu(BIT_SCAN_FORWARD_U64(t3_in_llc), SCX_KICK_PREEMPT);
        } else {
            /* Fall back to displacing T2 (frame) when no T3 present in LLC */
            u64 t2_in_llc = imperator_relaxed_load_u64(
                &tier_cpu_mask[CAKE_TIER_FRAME]) & my_llc_mask;
            if (t2_in_llc)
                scx_bpf_kick_cpu(BIT_SCAN_FORWARD_U64(t2_in_llc), SCX_KICK_PREEMPT);
        }
    }
}

/* Dispatch: per-LLC DSQ scan with bitmask-driven cross-LLC stealing.
 * Direct-dispatched tasks (SCX_DSQ_LOCAL_ON) bypass this callback entirely —
 * kernel handles them natively. Only tasks that went through
 * imperator_enqueue → per-LLC DSQ arrive here.
 *
 * FIX (audit): steal mask is now built by reading per-LLC nonempty[] bytes
 * rather than a single shared llc_nonempty_mask word.  This eliminates the
 * cross-LLC cache-line bounce on every enqueue while keeping the steal scan
 * O(nr_llcs) — at most 8 reads, each from a distinct LLC-local cache line. */
void BPF_STRUCT_OPS(imperator_dispatch, s32 raw_cpu, struct task_struct *prev)
{
    u32 my_llc = cpu_llc_id[raw_cpu & (CAKE_MAX_CPUS - 1)];

    /* Local LLC first — zero cross-CCD contention in steady state */
    if (scx_bpf_dsq_move_to_local(LLC_DSQ_BASE + my_llc))
        return;

    /* Drain confirmed empty — clear our entry so other CPUs don't steal here */
    imperator_relaxed_store_u8(&llc_nonempty[my_llc & (CAKE_MAX_LLCS - 1)].nonempty, 0);

    /* RODATA gate: single-LLC systems skip steal entirely (Rule 5).
     * JIT DCEs the loop below when nr_llcs == 1. */
    if (nr_llcs <= 1)
        return;

    /* Build steal mask from per-LLC nonempty bytes.
     * Each read is a separate cache line — no false sharing.
     * Stale set flags cause at most one failed dsq_move per race — harmless.
     *
     * FIX (audit): Loop to nr_llcs (RODATA const), not CAKE_MAX_LLCS.
     * On a dual-CCD system with nr_llcs=2 the old loop ran 8 iterations
     * with 6 unconditional i < nr_llcs misses.  The JIT treats nr_llcs as a
     * bounded constant and unrolls/DCEs the body accordingly. */
    /* FIX (gap/etd-steal): ETD-cost-aware work stealing.
     * When llc_etd_cost[] has been populated by userspace after ETD calibration,
     * prefer stealing from the lowest-latency source LLC first.  This reduces
     * cross-CCD cache-miss penalties on dual-CCD systems (e.g. 9950X) by trying
     * the cheaper CCD before the more expensive one.
     *
     * Correctness: all LLCs are still attempted — cheapest_llc is tried first,
     * then remaining LLCs in BSF order.  No work is ever skipped or dropped.
     * When costs are all 0 (pre-calibration), cheapest_llc sentinel remains at
     * nr_llcs and the loop degrades to the original index-order behaviour. */
    u32 steal_mask   = 0;
    u32 cheapest_llc = nr_llcs;  /* sentinel: no ETD-preferred candidate */
    u8  min_cost     = 0;        /* 0 = no calibration data present */

    for (u32 i = 0; i < nr_llcs; i++) {
        if (i != my_llc &&
            imperator_relaxed_load_u8(&llc_nonempty[i].nonempty)) {
            steal_mask |= 1u << i;
            u8 c = llc_etd_cost[my_llc & (CAKE_MAX_LLCS - 1)][i & (CAKE_MAX_LLCS - 1)];
            /* Only update cheapest when ETD data is present (c > 0). */
            if (c > 0 && (min_cost == 0 || c < min_cost)) {
                min_cost     = c;
                cheapest_llc = i;
            }
        }
    }

    /* Steal from cheapest LLC first when ETD data is available */
    if (cheapest_llc < nr_llcs && min_cost > 0) {
        steal_mask &= ~(1u << cheapest_llc);
        if (scx_bpf_dsq_move_to_local(LLC_DSQ_BASE + cheapest_llc))
            return;
        imperator_relaxed_store_u8(&llc_nonempty[cheapest_llc & (CAKE_MAX_LLCS - 1)].nonempty, 0);
    }

    /* Try remaining LLCs in BSF order (original behaviour) */
    for (u32 i = 0; steal_mask && i < nr_llcs; i++) {
        /* i is a verifier-required trip-count bound; actual iteration is BSF-driven.
         * steal_mask bits are set only for indices in [0, nr_llcs) by the loop above,
         * so victim is always a valid LLC index — no bounds check needed. */
        u32 victim = BIT_SCAN_FORWARD_U32(steal_mask);
        steal_mask &= steal_mask - 1;  /* clear LSB */
        if (scx_bpf_dsq_move_to_local(LLC_DSQ_BASE + victim))
            return;
        /* Victim was empty despite flag being set — clear stale entry */
        imperator_relaxed_store_u8(&llc_nonempty[victim & (CAKE_MAX_LLCS - 1)].nonempty, 0);
    }
}

/* DVFS RODATA LUT: Tier → CPU performance target (branchless via array index)
 * SCX_CPUPERF_ONE = 1024 = max hardware frequency. JIT constant-folds the array.
 * ALL tiers can contain gaming workloads — tiers control latency priority, not
 * execution speed. Conservative targets: never below 75% to avoid starving
 * game-critical work. */
const u32 tier_perf_target[8] = {
    1024,  /* T0 Critical: 100% — IRQ, input, audio, network (<100µs) */
    1024,  /* T1 Interactive: 100% — compositor, physics, AI (<2ms) */
    1024,  /* T2 Frame: 100% — game render, encoding (<8ms) */
    768,   /* T3 Bulk: 75% — compilation, background (≥8ms) */
    768, 768, 768, 768,  /* padding */
};

void BPF_STRUCT_OPS(imperator_tick, struct task_struct *p)
{
    /* Register pin p to r6 to avoid stack spills */
    register struct task_struct *p_reg asm("r6") = p;
    register struct imperator_task_ctx *tctx_reg asm("r7") = get_task_ctx(p_reg, false);
    register u32 cpu_id_reg asm("r8") = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);

    u32 now = (u32)scx_bpf_now();

    /* SAFETY GATE: tctx must exist and have been stamped */
    if (unlikely(!tctx_reg || tctx_reg->last_run_at == 0)) {
        if (tctx_reg) tctx_reg->last_run_at = now;
        return;
    }

    /* PHASE 1: COMPUTE RUNTIME */
    register u8 tier_reg asm("r9") = GET_TIER(tctx_reg);
    u32 last_run = tctx_reg->last_run_at;
    u64 runtime = (u64)(now - last_run);

    /* Slice exceeded: force context switch.
     * FIX (M-2): Update mailbox tier before kicking — mirrors the starvation
     * preemption path (FIX #4).  A task woken from this CPU in the window
     * between the slice-expiry kick and the next imperator_running would otherwise
     * inherit the kicked task's stale tier from the mailbox rather than the
     * new task's tier.  The starvation path was already fixed; this makes the
     * two kick paths consistent. */
    if (unlikely(runtime > tctx_reg->next_slice)) {
        struct mega_mailbox_entry *exp_mbox = &mega_mailbox[cpu_id_reg];
        u8 exp_flags = (tier_reg & MBOX_TIER_MASK);
        if (imperator_relaxed_load_u8(&exp_mbox->flags) != exp_flags)
            imperator_relaxed_store_u8(&exp_mbox->flags, exp_flags);
        scx_bpf_kick_cpu(cpu_id_reg, SCX_KICK_PREEMPT);
        return;
    }

    /* PHASE 2: STARVATION CHECK — graduated confidence backoff.
     * tick_counter tracks ticks without contention (nr_running <= 1).
     * As confidence grows, check frequency drops:
     *   counter < 8:  check every tick     (settling, ~8ms)
     *   counter < 16: check every 2nd tick (warming, max 1ms delay)
     *   counter < 32: check every 4th tick (confident, max 3ms delay)
     *   counter >= 32: check every 8th tick (high confidence, max 7ms delay)
     *
     * On contention, tc is decayed by 25% (tc -= tc >> 2) rather than reset
     * to 0.  A hard reset caused permanent low-confidence on workloads that
     * oscillate between 1 and 2 runnable tasks (game thread + background shader
     * compiler), defeating the backoff entirely.  At tc=32 a contention event
     * yields tc=24 (still in the every-4th-tick zone); the counter recovers to
     * tc=32 in ~8 ticks (~8ms) under oscillating contention. */
    struct mega_mailbox_entry *mbox = &mega_mailbox[cpu_id_reg];
    u8 tc = imperator_relaxed_load_u8(&mbox->tick_counter);
    u8 skip_mask = tc < 8 ? 0 : tc < 16 ? 1 : tc < 32 ? 3 : 7;

    if (!(tc & skip_mask)) {
        struct rq *rq = imperator_get_rq(cpu_id_reg);
        if (rq && rq->scx.nr_running > 1) {
            /* Contention detected — quarter-decay confidence (tc -= tc >> 2).
             * Subtracting 25% keeps tc in the same skip-mask zone after a
             * single event (tc=32 → tc=24, still every-4th-tick), recovering
             * to tc=32 in ~8 ticks (~8ms) under oscillating contention. */
            imperator_relaxed_store_u8(&mbox->tick_counter, tc - (tc >> 2));

            u64 threshold = UNPACK_STARVATION_NS(tier_configs[CAKE_TIER_IDX(tier_reg)]);
            if (unlikely(runtime > threshold)) {
                /* ── FEATURE 3: LOCK HOLDER STARVATION SKIP (adapted from LAVD) ──
                 * LAVD's can_x_kick_cpu2() explicitly refuses to preempt a CPU
                 * running a lock holder (is_lock_holder_running()). We apply the
                 * same principle here: if the running task holds a futex, skip the
                 * starvation preemption.
                 *
                 * Rationale: preempting a lock holder causes priority inversion —
                 * any task waiting on the lock is blocked until the holder is
                 * rescheduled AND releases it. For gaming this matters because:
                 *   - Wine/Proton hold D3D command-list mutexes across full frames
                 *   - Audio callbacks hold mixing locks at T0 priority
                 *   - The waiting task (T0/T1) is blocked longer than if we had
                 *     simply let the holder (T2/T3) finish its critical section.
                 *
                 * Safety: the starvation threshold still applies on the *next* tick
                 * after the lock is released (CAKE_FLAG_LOCK_HOLDER is cleared by the
                 * fexit probe). We do NOT skip the slice check above (runtime >
                 * next_slice), which remains an unconditional hard ceiling. Lock
                 * holders that run indefinitely still get preempted at slice expiry.
                 *
                 * Cost: one relaxed atomic read of packed_info (already in L1 from
                 * PHASE 1) + one AND + one branch-not-taken. ~2 cycles on the common
                 * path (not a lock holder). */
                u32 tick_packed = imperator_relaxed_load_u32(&tctx_reg->packed_info);
                if (unlikely(tick_packed & ((u32)CAKE_FLAG_LOCK_HOLDER << SHIFT_FLAGS))) {
                    /* FIX (gap/lock-skip-cap): Cap consecutive skips at 4.
                     * Each skip defers preemption by one starvation-threshold
                     * window; with a 1ms tick rate the cap fires within ~4ms
                     * of the first skip, bounding the maximum additional T0
                     * latency regardless of how long the critical section runs.
                     *
                     * After 4 skips, fall through to normal starvation preemption
                     * and reset the counter so the next lock acquisition starts
                     * with a fresh allowance. */
                    u8 skips = tctx_reg->lock_skip_count;
                    if (skips < 4) {
                        tctx_reg->lock_skip_count = skips + 1;
                        if (enable_stats) {
                            struct imperator_stats *s = get_local_stats();
                            if (s) s->nr_lock_holder_skips++;
                        }
                        goto mailbox_dvfs;  /* Still update mailbox and DVFS */
                    }
                    /* Cap reached: fall through to starvation preemption.
                     * Reset so next lock acquisition starts with a full cap. */
                    tctx_reg->lock_skip_count = 0;
                }

                scx_bpf_kick_cpu(cpu_id_reg, SCX_KICK_PREEMPT);

                if (enable_stats && tier_reg < CAKE_TIER_MAX) {
                    struct imperator_stats *s = get_local_stats();
                    if (s) s->nr_starvation_preempts_tier[tier_reg]++;
                }

                /* FIX (#4): Flush mailbox tier before returning.
                 * The old early-return skipped the mailbox_dvfs block, leaving
                 * mega_mailbox[cpu].flags stale.  Any task woken from this CPU
                 * immediately after the kick would inherit the preempted task's
                 * tier via the Feature 2 waker-tier inheritance path in
                 * imperator_enqueue — exactly the wrong value at the worst time.
                 * Update flags unconditionally here (same 2-cycle conditional
                 * store as the mailbox_dvfs block) before kicking so the next
                 * wakee sees the correct tier.  DVFS is still skipped (next
                 * task's first tick will correct frequency within ~1ms). */
                u8 kick_flags = (tier_reg & MBOX_TIER_MASK);
                if (imperator_relaxed_load_u8(&mbox->flags) != kick_flags)
                    imperator_relaxed_store_u8(&mbox->flags, kick_flags);

                return;
            }
        } else {
            /* No contention — grow confidence (saturate at 255) */
            if (tc < 255) imperator_relaxed_store_u8(&mbox->tick_counter, tc + 1);
        }
    } else {
        /* Skipped check — still increment counter for next mask eval */
        if (tc < 255) imperator_relaxed_store_u8(&mbox->tick_counter, tc + 1);
    }

mailbox_dvfs:; /* FIX: empty statement separates label from declaration (C99 §6.8.1) */

    /* MEGA-MAILBOX UPDATE: tier for dispatch to consume.
     *
     * FIX (audit): Plain struct-member assignment is a data race under the C11
     * memory model on weakly-ordered architectures (ARM64).  imperator_tick writes
     * mbox->flags and mbox->dsq_hint on the owning CPU; imperator_enqueue reads
     * mbox->flags on other CPUs for waker-tier inheritance.  Without atomic
     * semantics the store is not guaranteed to be visible.  Use
     * imperator_relaxed_store_u8 which emits __ATOMIC_RELAXED on Clang ≥21 (a plain
     * MOV with a compiler barrier) and the targeted inline-asm store on older
     * compilers.  Both paths prevent compiler reordering and guarantee
     * architectural store visibility — the minimal requirement for a flag. */
    u8 new_flags = (tier_reg & MBOX_TIER_MASK);
    if (imperator_relaxed_load_u8(&mbox->flags) != new_flags)
        imperator_relaxed_store_u8(&mbox->flags, new_flags);

    /* DVFS: Tier-proportional CPU frequency steering.
     * Runs in tick (rq-locked) = ~15-20ns vs ~30-80ns unlocked in running.
     * Hysteresis: skip kfunc if perf target unchanged (MESI-friendly).
     *
     * Hybrid scaling: on Intel P/E-core systems, scale target by each core's
     * cpuperf_cap so E-cores don't get over-requested. JIT eliminates this
     * branch entirely on non-hybrid CPUs (has_hybrid = false in RODATA). */
    u32 target = tier_perf_target[CAKE_TIER_IDX(tier_reg)];
    if (has_hybrid) {
        u32 cap = scx_bpf_cpuperf_cap(cpu_id_reg);
        target = (target * cap) >> 10;  /* scale by capability (1024 = 100%) */
    }
    u8 cached_perf = imperator_relaxed_load_u8(&mbox->dsq_hint);
    u8 target_cached = (u8)(target >> 2);
    if (cached_perf != target_cached) {
        scx_bpf_cpuperf_set(cpu_id_reg, target);
        imperator_relaxed_store_u8(&mbox->dsq_hint, target_cached);
    }
}

/* Task started running — stamp last_run_at for runtime measurement and
 * eagerly publish tier to mega_mailbox + tier_cpu_mask.
 *
 * [D] s6: Set this CPU's bit in tier_cpu_mask for the new task's tier.
 * imperator_stopping owns all clears; running only sets — no double-ownership.
 *
 * DVFS moved to imperator_tick where rq lock is held (cpuperf_set ~15-20ns vs
 * ~30-80ns unlocked here). Saves ~44-84 cycles per context switch. */
void BPF_STRUCT_OPS(imperator_running, struct task_struct *p)
{
    struct imperator_task_ctx *tctx = get_task_ctx(p, false);
    if (!tctx)
        return;
    tctx->last_run_at = (u32)scx_bpf_now();

    u32 run_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct mega_mailbox_entry *mbox = &mega_mailbox[run_cpu];
    u8 tier = CAKE_TIER_IDX(GET_TIER(tctx));

    /* FIX (audit): Eagerly publish the task's tier to mega_mailbox so that
     * waker-tier inheritance in imperator_enqueue sees the correct tier from the
     * very first nanosecond of this task's run, not after its first tick.
     *
     * imperator_tick updates the mailbox at HZ intervals (1–4ms).  Any task woken
     * by this CPU in the window between context switch and the first tick
     * inherited the *previous* task's tier from the mailbox — the wrong value
     * at the worst time (right after a T0 audio thread is scheduled, the
     * mailbox might still show T3 from the bulk task it preempted).
     *
     * Cost: one conditional relaxed store per context switch (~2 cycles on an
     * uncontested cache line). */
    u8 cur_flags = imperator_relaxed_load_u8(&mbox->flags);
    if ((cur_flags & MBOX_TIER_MASK) != tier)
        imperator_relaxed_store_u8(&mbox->flags,
            (cur_flags & ~MBOX_TIER_MASK) | tier);

    /* [D] s6: Mark this CPU as running a task of 'tier'.
     * BPF_ATOMIC_OR: single instruction, not a CAS loop.  Each CPU writes
     * only its own bit (1ULL << run_cpu) — no two CPUs contend on the same
     * bit.  The word-level atomic prevents torn read-modify-write when two
     * CPUs in different tiers update the same u64 simultaneously. */
    __sync_fetch_and_or(&tier_cpu_mask[tier & (CAKE_TIER_MAX - 1)], 1ULL << run_cpu);
}

/* Precomputed hysteresis gate tables (RODATA — JIT constant-folds these).
 * _demote[i]: standard gate — task at or above this average demotes past tier i.
 * _promote[i]: 90% of gate — task must be clearly faster to earn promotion.
 * Eliminates 3 runtime divisions per reclassify call. */
static const u16 tier_gate_demote[3]  = { TIER_GATE_T0, TIER_GATE_T1, TIER_GATE_T2 };
static const u16 tier_gate_promote[3] = {
    TIER_GATE_T0 - TIER_GATE_T0 / 10,   /* 90 */
    TIER_GATE_T1 - TIER_GATE_T1 / 10,   /* 1800 */
    TIER_GATE_T2 - TIER_GATE_T2 / 10,   /* 7200 */
};

/* S5: 1.5× tier-gate overrun thresholds.
 * A task consistently exceeding its tier gate triggers forced demotion.
 * 1.5× rather than 1.0× avoids false-triggering on normal EWMA bounce near
 * the boundary.  T3 entry is 0: bulk tasks have no gate to exceed. */
static const u16 tier_overrun_gate[4] = {
    TIER_GATE_T0 + TIER_GATE_T0 / 2,   /* T0: 150µs  */
    TIER_GATE_T1 + TIER_GATE_T1 / 2,   /* T1: 3000µs */
    TIER_GATE_T2 + TIER_GATE_T2 / 2,   /* T2: 12000µs */
    0,                                   /* T3: no check */
};

/* ═══════════════════════════════════════════════════════════════════════════
 * AVG_RUNTIME CLASSIFICATION + DRR++: Dynamic tier reclassification on every stop.
 * CPU analog of network CAKE's flow classification:
 * - Sparse flows (audio, input) → short bursts + yield → settle at T0-T1
 * - Bulk flows (compilation, renders) → run until preempted → demote to T2-T3
 * - Mixed flows (game logic) → medium bursts → settle at T1-T2
 *
 * This is the engine that makes tier-encoded vtime and per-tier starvation
 * actually differentiate traffic. Without it, all userspace tasks compete
 * at the same tier.
 * ═══════════════════════════════════════════════════════════════════════════ */
static __attribute__((noinline))
void reclassify_task_cold(struct imperator_task_ctx *tctx)
{
    u32 packed = imperator_relaxed_load_u32(&tctx->packed_info);

    /* ── RUNTIME MEASUREMENT ── */
    u32 now = (u32)scx_bpf_now();
    u32 last_run = tctx->last_run_at;
    if (!last_run)
        return;  /* Never ran — skip (safety gate) */

    u32 runtime_raw = now - last_run;

    /* FIX (post-load recovery): If the task has been sleeping for over 500ms
     * (e.g. a loading screen, an idle background service resuming), pull its
     * avg_runtime_us halfway toward the midpoint of its current tier before
     * running the EWMA.  Without this, a game thread that spends 30s at T3
     * during asset loading needs 10+ EWMA bouts (20–32ms) to recover to T1/T2
     * after the load completes — during which game frames compete at the wrong
     * tier, causing frame-time spikes at session start.
     *
     * 500ms threshold is deliberately above any gaming frame cadence (even at
     * 24fps the frame period is ~42ms) but below OS idle timers, so only genuine
     * sleeps trigger the decay.  We write the corrected value back immediately so
     * both the fast-backoff path and the full reclassify path below read the
     * decayed base.  Single-step: halve the distance to the tier midpoint — the
     * EWMA then converges to the true runtime within 3–5 bouts instead of 10+.
     *
     * Tier midpoints (geometric mean of adjacent gates):
     *   T0 Critical  (<100µs):   ~50µs
     *   T1 Interact  (<2000µs):  ~1050µs
     *   T2 Frame     (<8000µs):  ~5000µs
     *   T3 Bulk      (≥8000µs):  floor = 8001µs */
    if (runtime_raw > 500000000U) {
        static const u16 tier_sleep_mid[4] = { 50, 1050, 5000, 8001 };
        u8 s_tier = (packed >> SHIFT_TIER) & MASK_TIER;
        u32 cur_fused = tctx->deficit_avg_fused;
        u16 cur_avg   = EXTRACT_AVG_RT(cur_fused);
        u16 mid       = tier_sleep_mid[CAKE_TIER_IDX(s_tier)];
        /* Halve the distance: one step toward midpoint, preserving EWMA direction */
        tctx->deficit_avg_fused = PACK_DEFICIT_AVG(EXTRACT_DEFICIT(cur_fused),
                                                   (u16)((cur_avg + mid) >> 1));
    }

    u32 runtime_us = runtime_raw >> 10;  /* ns → ~μs (÷1024 ≈ ÷1000) */

    /* Clamp to u16 max for EWMA field (65ms max, more than any reasonable burst) */
    u16 rt_clamped = runtime_us > 0xFFFF ? 0xFFFF : (u16)runtime_us;

    /* ── GRADUATED BACKOFF ──
     * When tier has been stable for 3+ consecutive stops, throttle reclassify
     * frequency based on current tier. T0 tasks (IRQ/input) almost never
     * change → recheck every 1024th stop. T3 tasks (bulk) may transition
     * → recheck every 16th stop. Uses per-task counter + RODATA masks. */
    u8 stable = (packed >> SHIFT_STABLE) & 3;
    if (stable == 3) {
        /* FIX (#2 / #9): EWMA computation moved inside the early-return branch.
         *
         * Previously (pre-#2): EWMA arithmetic was hoisted above the counter-mask
         * check, so ~10 instructions ran unconditionally and their outputs were
         * silently discarded on every periodic-fallthrough boundary — pure dead work
         * every 16th stop for T3, every 128th for T1, every 1024th for T0.
         *
         * FIX (#9) single-EWMA guarantee is still intact: the computation only runs
         * inside the early-return branch (committed + returned) OR in the full path
         * below (committed + continues).  Never both in the same call.
         *
         * FIX (audit): CAKE_TIER_IDX() used for all tier array accesses — canonical
         * bounds-check matching the _Static_assert in intf.h. */
        u8 tier = (packed >> SHIFT_TIER) & MASK_TIER;
        u16 mask = tier_recheck_mask[CAKE_TIER_IDX(tier)];
        u16 counter = tctx->reclass_counter + 1;
        tctx->reclass_counter = counter;
        if (counter & mask) {
            /* Not time for full recheck — compute EWMA and return. */
            u32 old_fused = tctx->deficit_avg_fused;
            u16 avg_rt = EXTRACT_AVG_RT(old_fused);
            /* Asymmetric EWMA: promote fast (α=1/4), demote cautiously (α=1/16).
             * Gaming threads spike during loads then recover — fast promotion
             * restores T0/T1 priority within ~4 bouts instead of ~16. */
            u16 new_avg;
            if (rt_clamped < avg_rt)
                new_avg = avg_rt - (avg_rt >> 2) + (rt_clamped >> 2);  /* promote α=1/4 */
            else
                new_avg = avg_rt - (avg_rt >> 4) + (rt_clamped >> 4);  /* demote  α=1/16 */
            u16 deficit = EXTRACT_DEFICIT(old_fused);
            deficit = (rt_clamped >= deficit) ? 0 : deficit - rt_clamped;

            u32 new_fused = PACK_DEFICIT_AVG(deficit, new_avg);
            if (new_fused != old_fused)
                tctx->deficit_avg_fused = new_fused;

            /* Spot-check: would new EWMA classify to a different tier?
             * Uses hysteresis-adjusted gates so spot-check agrees exactly
             * with full reclassify logic. Only resets stability when a genuine
             * tier change is imminent. Zero false triggers from normal frame
             * variance. */
            u16 g0 = (tier > 0) ? tier_gate_promote[0] : tier_gate_demote[0];
            u16 g1 = (tier > 1) ? tier_gate_promote[1] : tier_gate_demote[1];
            u16 g2 = (tier > 2) ? tier_gate_promote[2] : tier_gate_demote[2];
            u8 spot_tier;
            if      (new_avg < g0) spot_tier = 0;
            else if (new_avg < g1) spot_tier = 1;
            else if (new_avg < g2) spot_tier = 2;
            else                   spot_tier = 3;

            if (spot_tier != tier) {
                u32 reset = packed & ~((u32)3 << SHIFT_STABLE);
                imperator_relaxed_store_u32(&tctx->packed_info, reset);
                tctx->reclass_counter = 0;
            }
            return;
        }
        /* Fall through → periodic full reclassify.
         * tctx->deficit_avg_fused is unmodified above — full path reads the
         * original value and applies EWMA exactly once. */
    }

    /* ── FULL RECLASSIFICATION ── */

    /* ── EWMA RUNTIME UPDATE ── */
    /* Asymmetric decay: promote fast (α=1/4 ≈ 4 bouts), demote cautiously
     * (α=1/16 ≈ 16 bouts). Gaming threads spike during level loads then
     * recover — fast promotion restores T0/T1 priority without waiting 8+
     * bouts. Symmetric 1/8 allowed loading screens to permanently demote
     * game threads for the remainder of the session. */
    u32 old_fused = tctx->deficit_avg_fused;
    u16 avg_rt = EXTRACT_AVG_RT(old_fused);
    u16 new_avg;
    if (rt_clamped < avg_rt)
        new_avg = avg_rt - (avg_rt >> 2) + (rt_clamped >> 2);  /* promote α=1/4 */
    else
        new_avg = avg_rt - (avg_rt >> 4) + (rt_clamped >> 4);  /* demote  α=1/16 */

    /* ── DRR++ DEFICIT TRACKING ── */
    /* Each execution bout consumes deficit. When deficit exhausts, clear the
     * new-flow flag → task loses its priority bonus within the tier.
     * Initial deficit = quantum + new_flow_bonus ≈ 10ms of credit. */
    u16 deficit = EXTRACT_DEFICIT(old_fused);
    deficit = (rt_clamped >= deficit) ? 0 : deficit - rt_clamped;

    /* Pre-compute deficit_exhausted before rt_clamped/deficit die (Rule 36) */
    bool deficit_exhausted = (deficit == 0 && (packed & ((u32)CAKE_FLOW_NEW << SHIFT_FLAGS)));

    /* Write fused deficit + avg_runtime (MESI-friendly: skip if unchanged) */
    u32 new_fused = PACK_DEFICIT_AVG(deficit, new_avg);
    if (new_fused != old_fused)
        tctx->deficit_avg_fused = new_fused;

    /* ── HYSTERESIS TIER CLASSIFICATION ──
     * Precomputed gate tables (RODATA) eliminate runtime division.
     * To PROMOTE (lower tier): avg must be 10% below the gate.
     * To DEMOTE  (higher tier): standard gate — fast demotion.
     * Asymmetric by design: give more CPU time quickly, take back cautiously. */
    u8 old_tier = (packed >> SHIFT_TIER) & MASK_TIER;
    u8 new_tier;

    u16 g0 = (old_tier > 0) ? tier_gate_promote[0] : tier_gate_demote[0];
    u16 g1 = (old_tier > 1) ? tier_gate_promote[1] : tier_gate_demote[1];
    u16 g2 = (old_tier > 2) ? tier_gate_promote[2] : tier_gate_demote[2];

    if      (new_avg < g0) new_tier = 0;
    else if (new_avg < g1) new_tier = 1;
    else if (new_avg < g2) new_tier = 2;
    else                   new_tier = 3;

    /* ── HARD-DEMOTE CAP (runaway task safety) ──
     * FIX (audit): The asymmetric EWMA (demote α=1/16) is intentionally slow to
     * prevent transient spikes from permanently demoting game threads.  The
     * downside is a task that genuinely runs long (e.g. a misbehaving physics
     * thread stuck in a loop) can spend up to ~128ms misclassified in T1/T2,
     * competing ahead of legitimate render threads.
     *
     * Cap: if avg_runtime has been above TIER_GATE_T2 × 3 (24ms) for 3+
     * consecutive stable stops, force T3 regardless of the stability counter.
     * The 3× multiplier avoids false-triggering on normal level-load spikes
     * (~8–16ms) while catching tasks that are genuinely bulk.  stable >= 3
     * ensures we've had at least 3 consistent EWMA bouts before forcing, so
     * a single anomalous 25ms burst won't cause premature demotion. */
    if (new_avg > (u16)(TIER_GATE_T2 * 3) && stable >= 3 && new_tier < CAKE_TIER_BULK)
        new_tier = CAKE_TIER_BULK;

    /* ── [H] s6: BIT-HISTORY OVERRUN DEMOTION ───────────────────────────────
     * overrun_count is an 8-bit shift register of the last 8 execution outcomes.
     * Each stop shifts left one position and inserts the current bout's result
     * in the LSB; the oldest result falls off the MSB.
     *
     *   bit = 1  →  that bout's rt_clamped exceeded 1.5× the tier gate
     *   bit = 0  →  that bout ran within the gate
     *
     * DEMOTION TRIGGER: __builtin_popcount(overrun_count) >= 4
     *   Fires when 4 of the last 8 bouts exceeded the gate.
     *
     * BEHAVIORAL SUPERSET OF THE ORIGINAL CONSECUTIVE COUNTER:
     *   4 consecutive overruns → hist=0b00001111 → popcount=4 ≥ 4 → DEMOTE ✓
     *   4 alternating overruns → popcount=4 ≥ 4 → DEMOTE ✓ (new capability)
     *   Original counter reset on every clean bout — alternating never fired.
     *
     * THRESHOLD CORRECTION vs previous patch: 5 → 4.
     *   With threshold 5: 4 consecutive overruns → popcount=4 < 5 → NO DEMOTE.
     *   That was a regression vs the original counter which fired at exactly 4.
     *   With threshold 4: parity restored; non-consecutive patterns gain coverage.
     *
     * Only checked for T0–T2; T3 tasks are already bulk.
     * COST: shift + OR + popcount ≈ 4 cycles (identical to original inc+compare). */
    if (old_tier < CAKE_TIER_BULK) {
        u16 og      = tier_overrun_gate[CAKE_TIER_IDX(old_tier)];
        u8  outcome = (rt_clamped > og) ? 1u : 0u;

        /* Shift register: oldest outcome falls off MSB, new enters LSB */
        u8 hist = (u8)((tctx->overrun_count << 1) | outcome);
        tctx->overrun_count = hist;

        if (__builtin_popcount((unsigned int)hist) >= 4) {
            /* Force-demote by one tier; floor at CAKE_TIER_BULK.
             * We are inside (old_tier < CAKE_TIER_BULK) so old_tier+1 is safe. */
            u8 forced = (u8)(old_tier + 1);
            if (new_tier < forced)
                new_tier = forced;
            tctx->overrun_count = 0;
            stable = 0;  /* reset so new_stable below starts from 0 */
        }
    }

    /* ── WRITE PACKED_INFO (MESI-friendly: skip if unchanged) ── */
    bool tier_changed = (new_tier != old_tier);

    /* Tier-stability counter: increment toward 3 if tier held, reset on change.
     * When stable==3, subsequent calls take the graduated backoff path. */
    u8 new_stable = tier_changed ? 0 : ((stable < 3) ? stable + 1 : 3);

    if (tier_changed || deficit_exhausted || new_stable != stable) {
        u32 new_packed = packed;
        /* Fused tier+stable: bits [31:28] = [stable:2][tier:2]
         * Bitfield coalescing — 2 ops instead of 4 (Rule 24 mask fusion) */
        new_packed &= ~((u32)0xF << 28);
        new_packed |= (((u32)new_stable << 2) | (u32)new_tier) << 28;
        /* DRR++: Clear new-flow flag when deficit exhausted */
        if (deficit_exhausted)
            new_packed &= ~((u32)CAKE_FLOW_NEW << SHIFT_FLAGS);

        imperator_relaxed_store_u32(&tctx->packed_info, new_packed);
    }

    /* ── SLICE RECALCULATION on tier change ── */
    /* When tier changes, the quantum multiplier changes (T0=0.75x → T3=1.4x).
     * Update next_slice so the next execution bout uses the correct quantum. */
    if (tier_changed) {
        u64 cfg = tier_configs[CAKE_TIER_IDX(new_tier)];
        u64 mult = UNPACK_MULTIPLIER(cfg);
        tctx->next_slice = (quantum_ns * mult) >> 10;
        tctx->reclass_counter = 0;
    }
}

/* Propagate scheduling classification from parent to child on fork.
 *
 * FIX (audit): Without inheritance every new thread starts at the nice-value
 * seed (T1 midpoint ≈ 1050µs for nice=0) regardless of the parent's actual
 * behavior.  A game engine forking a render worker — which will behave like
 * the parent's T2 render threads — starts at T1 and takes 6–16 EWMA bouts
 * (~12–32ms at 2ms quantum) to converge to T2.  During this window it
 * competes at the wrong tier, wasting T1 budget and potentially displacing
 * audio/compositor threads.
 *
 * Strategy: seed child's avg_runtime_us at half the parent's value.  Halving
 * is intentional — child threads typically run shorter initial bouts as they
 * initialize stack and TLS before entering the main work loop.  The EWMA
 * corrects to the true tier within ~3–4 bouts either way; we just start much
 * closer to the right answer.  Child tier is set to match the parent's current
 * tier so the very first dispatch also goes into the correct DSQ bucket.
 *
 * The child context is guaranteed to exist because imperator_fork fires after
 * imperator_enable (which pre-allocates it).  If alloc somehow raced and ctx is
 * NULL, we return 0 cleanly — the child falls back to nice-value seeding. */
s32 BPF_STRUCT_OPS(imperator_init_task, struct task_struct *p,
                   struct scx_init_task_args *args)
{
    /* init_task fires for every task entering scx control, not just forked
     * children.  For exec() (args->fork == false) the task retains its old
     * task_struct — and therefore its old imperator_task_ctx — from before the
     * exec.  A shell or build tool that execs a game binary would carry a T3
     * avg_runtime classification into the new process image, causing the game's
     * first render threads to compete at T3 for 6-16 EWMA bouts before
     * converging to the correct tier.
     *
     * Fix: reset avg_runtime and tier to the nice-value-based midpoint (same
     * logic as alloc_task_ctx_cold) so the post-exec EWMA starts from a
     * sensible prior rather than the pre-exec process's stale history. */
    if (!args->fork) {
        struct imperator_task_ctx *tctx = get_task_ctx(p, false);
        if (!tctx)
            return 0;

        u32 prio = p->static_prio;
        u8  init_tier;
        u16 init_avg_rt;

        if (prio < 120) {
            init_tier   = CAKE_TIER_CRITICAL;
            init_avg_rt = TIER_GATE_T0 / 2;
        } else if (prio > 130) {
            init_tier   = CAKE_TIER_BULK;
            init_avg_rt = TIER_GATE_T2 + 1;
        } else {
            init_tier   = CAKE_TIER_INTERACT;
            init_avg_rt = (TIER_GATE_T0 + TIER_GATE_T1) / 2;
        }

        /* Reset tier[29:28] + stable[31:30] to (stable=0, tier=init_tier).
         * All other packed_info bits (FLAGS, WAIT_DATA, KALMAN_ERROR) are
         * preserved — CAKE_FLOW_NEW is already set by alloc_task_ctx_cold
         * and is still appropriate for a freshly exec'd process. */
        u32 packed = imperator_relaxed_load_u32(&tctx->packed_info);
        packed &= ~((u32)0xF << 28);
        packed |=  (u32)init_tier << SHIFT_TIER;
        imperator_relaxed_store_u32(&tctx->packed_info, packed);

        /* Reset avg_runtime to tier midpoint; preserve existing deficit so the
         * new-flow bonus (already credited) is not revoked. */
        u32 old_fused = tctx->deficit_avg_fused;
        tctx->deficit_avg_fused =
            PACK_DEFICIT_AVG(EXTRACT_DEFICIT(old_fused), init_avg_rt);

        tctx->overrun_count   = 0;
        tctx->reclass_counter = 0;
        tctx->lock_skip_count = 0;

        /* Recompute pre-fetched slice for the reset tier */
        u64 cfg  = tier_configs[CAKE_TIER_IDX(init_tier)];
        u64 mult = UNPACK_MULTIPLIER(cfg);
        tctx->next_slice = (quantum_ns * mult) >> 10;

        return 0;
    }

    struct task_struct *parent = p->real_parent;
    struct imperator_task_ctx *ptctx = parent ?
        bpf_task_storage_get(&task_ctx, parent, 0, 0) : NULL;
    struct imperator_task_ctx *ctctx = get_task_ctx(p, false);

    if (!ptctx || !ctctx)
        return 0;

    /* Read parent state atomically (relaxed — we only need approximate values) */
    u32  pfused  = ptctx->deficit_avg_fused;
    u16  pavg    = EXTRACT_AVG_RT(pfused);
    u32  ppacked = imperator_relaxed_load_u32(&ptctx->packed_info);
    u8   ptier   = (ppacked >> SHIFT_TIER) & MASK_TIER;

    /* Child avg starts at half the parent's — converges in ~3 bouts */
    u16 child_avg = pavg >> 1;
    u16 init_deficit = (u16)((quantum_ns + new_flow_bonus_ns) >> 10);

    ctctx->deficit_avg_fused = PACK_DEFICIT_AVG(init_deficit, child_avg);

    /* Inherit parent tier into packed_info, preserving all other bits
     * (CAKE_FLOW_NEW is already set by alloc_task_ctx_cold). */
    u32 cpacked = imperator_relaxed_load_u32(&ctctx->packed_info);
    cpacked &= ~((u32)MASK_TIER << SHIFT_TIER);
    cpacked |=  ((u32)ptier     << SHIFT_TIER);
    imperator_relaxed_store_u32(&ctctx->packed_info, cpacked);

    /* Pre-compute slice for inherited tier so first dispatch uses correct quantum */
    u64 cfg  = tier_configs[CAKE_TIER_IDX(ptier)];
    u64 mult = UNPACK_MULTIPLIER(cfg);
    ctctx->next_slice = (quantum_ns * mult) >> 10;

    return 0;
}

/* Pre-allocate task context when a task enters scx control.
 * Fires once per task — not in the scheduling hot path.
 * Guarantees imperator_running/imperator_stopping never see a NULL context,
 * converting those null guards from live code paths to safety assertions. */
s32 BPF_STRUCT_OPS(imperator_enable, struct task_struct *p)
{
    get_task_ctx(p, true);
    return 0;
}

/* Task stopping — clear tier_cpu_mask bit BEFORE reclassification, then
 * run avg_runtime reclassification + DRR++ deficit tracking.
 *
 * [E] s6: ORDER IS CRITICAL.
 *   GET_TIER(tctx) before reclassify = the tier the task was running at
 *   = the tier whose bit is set in tier_cpu_mask = the correct bit to clear.
 *   After reclassify_task_cold(), GET_TIER returns the new post-EWMA tier.
 *   Clearing after reclassify would clear the wrong bit. */
void BPF_STRUCT_OPS(imperator_stopping, struct task_struct *p, bool runnable)
{
    struct imperator_task_ctx *tctx = get_task_ctx(p, false);
    /* Skip tasks that have never been stamped by imperator_running.
     * Avoids the noinline call overhead (~3-5 cycles) for the
     * uncommon case of a task stopping before its first run. */
    if (tctx && likely(tctx->last_run_at)) {
        /* [E] s6: Clear this CPU's bit from the tier that was running.
         * Must happen before reclassify changes packed_info.tier. */
        u32 stop_cpu  = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
        u8  stop_tier = CAKE_TIER_IDX(GET_TIER(tctx));
        __sync_fetch_and_and(
            &tier_cpu_mask[stop_tier & (CAKE_TIER_MAX - 1)],
            ~(1ULL << stop_cpu));

        reclassify_task_cold(tctx);
    }
}

/* Initialize the scheduler.
 * [C] s6: Compute llc_cpu_mask from cpu_llc_id RODATA before any task runs.
 *
 * This eliminates the partial-deploy hazard: previously llc_cpu_mask had to
 * be written by the Rust loader; if that write was absent (e.g. rolling update
 * midway through deployment) the mask stayed all-zero and the O(1) bitmask
 * kick produced zero kicks without any error or warning.  Now imperator_init fills
 * it unconditionally from the already-correct cpu_llc_id RODATA. */
s32 BPF_STRUCT_OPS_SLEEPABLE(imperator_init)
{
    /* [C] Populate llc_cpu_mask from cpu_llc_id.
     * Loop is bounded by both nr_cpus (RODATA const, JIT treats as bounded)
     * and CAKE_MAX_CPUS (compile-time constant) — verifier sees a safe bound.
     * Plain |= is safe: imperator_init runs exactly once before any task is
     * scheduled, so no concurrent BPF program can read llc_cpu_mask yet. */
    for (u32 cpu = 0; cpu < nr_cpus && cpu < CAKE_MAX_CPUS; cpu++) {
        u32 llc = cpu_llc_id[cpu] & (CAKE_MAX_LLCS - 1);
        llc_cpu_mask[llc] |= 1ULL << cpu;
    }

    /* Create per-LLC DSQs — one per cache domain.
     * Single-CCD: 1 DSQ (single per-LLC DSQ).
     * Multi-CCD: N DSQs (eliminates cross-CCD lock contention).
     *
     * FIX (audit): Loop directly to nr_llcs rather than CAKE_MAX_LLCS with an
     * interior break. The original form was a verifier workaround for older
     * kernels that required compile-time-bounded loops; nr_llcs is a RODATA
     * const volatile that the JIT treats as a bounded constant. */
    for (u32 i = 0; i < nr_llcs; i++) {
        s32 ret = scx_bpf_create_dsq(LLC_DSQ_BASE + i, -1);
        if (ret < 0)
            return ret;
    }

    return 0;
}

/* Scheduler exit - record exit info */
void BPF_STRUCT_OPS(imperator_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(imperator_ops,
               .select_cpu     = (void *)imperator_select_cpu,
               .enqueue        = (void *)imperator_enqueue,
               .dispatch       = (void *)imperator_dispatch,
               .tick           = (void *)imperator_tick,
               .running        = (void *)imperator_running,
               .stopping       = (void *)imperator_stopping,
               .init_task      = (void *)imperator_init_task,
               .enable         = (void *)imperator_enable,
               .init           = (void *)imperator_init,
               .exit           = (void *)imperator_exit,
               .flags          = SCX_OPS_KEEP_BUILTIN_IDLE,
               .name           = "imperator");
