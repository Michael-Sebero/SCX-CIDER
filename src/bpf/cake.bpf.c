// SPDX-License-Identifier: GPL-2.0
/* scx_cake - CAKE DRR++ adapted for CPU scheduling: avg_runtime classification, direct dispatch, tiered DSQ */

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

/* ═══════════════════════════════════════════════════════════════════════════
 * MEGA-MAILBOX: 64-byte per-CPU state (single cache line = optimal L1)
 * - Zero false sharing: each CPU writes ONLY to mega_mailbox[its_cpu]
 * - 50% less L1 pressure than 128B design (16 vs 32 cache lines)
 * ═══════════════════════════════════════════════════════════════════════════ */
struct mega_mailbox_entry mega_mailbox[CAKE_MAX_CPUS] SEC(".bss");

/* LLC non-empty bitmask: bit i is set when LLC i has tasks queued.
 * Updated in enqueue (set) and dispatch (cleared on drain).
 * Allows O(1) steal target selection vs O(nr_llcs) sequential scan.
 * Races are harmless: a stale set bit causes one extra failed dsq_move. */
volatile u32 llc_nonempty_mask SEC(".bss");

/* Metadata accessors (Fused layout) */
#define GET_TIER_RAW(packed) EXTRACT_BITS_U32(packed, SHIFT_TIER, 2)
#define GET_TIER(ctx) GET_TIER_RAW(cake_relaxed_load_u32(&(ctx)->packed_info))

/* Per-CPU scratch area - BSS-tunneled helper outputs, isolated to prevent MESI contention */
struct cake_scratch {
    bool dummy_idle;
    u32 init_tier;
    u32 cached_llc;            /* LLC ID tunneled from select_cpu → enqueue (saves 1 kfunc) */
    u64 cached_now;            /* scx_bpf_now() tunneled from select_cpu → enqueue (saves 1 kfunc) */
    struct bpf_iter_scx_dsq it; /* BSS-Tunneling for iterators */
    /* FIX (#18): bpf_iter_scx_dsq assumed ~75B; adjust _pad if _Static_assert fires
     * after a kernel update that changes the iterator struct layout. */
    u8 _pad[36]; /* Pad to 128 bytes (2 cache lines) */
} global_scratch[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(128)));
_Static_assert(sizeof(struct cake_scratch) <= 128,
    "cake_scratch exceeds 128B -- adjacent CPUs will false-share");

/* Global stats BSS array - 0ns lookup vs 25ns helper, 256-byte aligned per CPU */
struct cake_stats global_stats[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(256)));

/* BSS tail guard - absorbs BTF truncation bugs instead of corrupting real data */
u8 __bss_tail_guard[64] SEC(".bss") __attribute__((aligned(64)));

/* Mailbox mask builders removed — select_cpu now delegates idle detection
 * to scx_bpf_select_cpu_dfl() which uses the kernel's authoritative idle
 * tracking (zero staleness, atomic claiming). */

static __always_inline struct cake_stats *get_local_stats(void)
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
    __type(value, struct cake_task_ctx);
} task_ctx SEC(".maps");

/* Bitfield accessors - relaxed atomics prevent tearing */

/* Metadata Accessors - Definitions moved to top */

/* COLD PATH: Task allocation + kthread init - noinline keeps I-Cache tight for hot path */
/* Removed accounting functions - now in tick */
/* set_victim_status_cold removed - mailbox handles victim status */

/* perform_lazy_accounting removed - accounting in tick */

/* init_new_kthread_cold inlined into cake_enqueue — reuses hoisted
 * now_cached + enq_llc, saving 2 kfunc calls per kthread enqueue. */

/* select_cpu_new_task_cold removed — new tasks go through the same
 * scx_bpf_select_cpu_dfl path as all other tasks. */

static __attribute__((noinline))
struct cake_task_ctx *alloc_task_ctx_cold(struct task_struct *p)
{
    struct cake_task_ctx *ctx;

    /* Heavy allocator call */
    ctx = bpf_task_storage_get(&task_ctx, p, 0,
                               BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ctx) return NULL;

    ctx->next_slice = quantum_ns;
    u16 init_deficit = (u16)((quantum_ns + new_flow_bonus_ns) >> 10);
    ctx->last_run_at = 0;
    ctx->reclass_counter = 0;

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
static __always_inline struct cake_task_ctx *get_task_ctx(struct task_struct *p, bool create)
{
    struct cake_task_ctx *ctx;

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
 * first. Preemption handled by cake_tick starvation checks. */

/* ═══════════════════════════════════════════════════════════════════════════
 * KERNEL-FIRST FLAT SELECT_CPU: ~20 instructions vs ~200+ in the old cascade.
 *
 * Architecture: delegate idle detection to the kernel's authoritative
 * scx_bpf_select_cpu_dfl() which does prev → sibling → LLC cascade internally
 * with zero staleness and atomic claiming. When all CPUs are busy, return
 * prev_cpu and let cake_enqueue handle via per-LLC DSQ with vtime ordering.
 *
 * Benefits (tier-agnostic by design — all tiers equally important):
 * - All tiers 0-3 take the same placement path (tiers define latency, not affinity)
 * - Zero bpf_task_storage_get in select_cpu (no tier/slice needed)
 * - Zero mailbox reads (kernel has authoritative idle data)
 * - Zero stale mask cascades (kernel idle bitmap is real-time)
 * - ~90-110 cycles vs ~200-500 cycles (~20-40ns p50 improvement)
 * ═══════════════════════════════════════════════════════════════════════════ */
/* SYNC fast-path dispatch: waker's CPU is by definition running.
 * Noinline: only 2 args (p, wake_flags) → r1→r6, r2→r7 saves
 * leave r8,r9 free. Single kfunc call (get_smp_id) + dispatch.
 * Splitting this out lets the main function avoid hoisting
 * bpf_get_smp_processor_id above the SYNC branch, which was the
 * root cause of Spill A (p had to survive across the shared call).
 *
 * CPUMASK GUARD: Check inside cold path (Rule 5/13: no extra work on
 * inline hot path). Wine/Proton threadpools use sched_setaffinity —
 * waker's CPU may not be in woken task's cpumask. Returns -1 to signal
 * fallthrough to kernel path which handles cpumask correctly. */
static __attribute__((noinline))
s32 dispatch_sync_cold(struct task_struct *p, u64 wake_flags)
{
    u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
        return -1;

    struct cake_task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);

    /* Determine effective tier and slice.
     *
     * CAKE_FLOW_IRQ_WAKE: if the IRQ detection block in select_cpu stamped
     * this flag, consume it here — we are taking the direct-dispatch path
     * (SCX_DSQ_LOCAL_ON) so cake_enqueue will never run to consume it.
     * Leaving it set would cause a stale T0 boost on the task's NEXT wakeup.
     *
     * When the flag is set: use T0 slice (CAKE's shortest, fastest-releasing
     * quantum) so the IRQ-sourced task gets CPU time with minimal latency and
     * vacates the core quickly. Use T0 stats bucket.
     * When not set: use the pre-computed tier-adjusted next_slice as normal. */
    u64 slice = quantum_ns;
    u8 tier = CAKE_TIER_INTERACT;  /* default for unclassified tasks */

    if (tctx) {
        u32 sc_packed = cake_relaxed_load_u32(&tctx->packed_info);

        if (unlikely(sc_packed & ((u32)CAKE_FLOW_IRQ_WAKE << SHIFT_FLAGS))) {
            /* Consume the one-shot flag atomically */
            __sync_fetch_and_and(&tctx->packed_info,
                                 ~((u32)CAKE_FLOW_IRQ_WAKE << SHIFT_FLAGS));
            /* T0 quantum (multiplier 0.25-0.5x) for fast core release */
            u64 cfg = tier_configs[CAKE_TIER_CRITICAL & 7];
            u64 mult = UNPACK_MULTIPLIER(cfg);
            slice = (quantum_ns * mult) >> 10;
            tier  = CAKE_TIER_CRITICAL;

            if (enable_stats) {
                struct cake_stats *s = get_local_stats();
                if (s) s->nr_irq_wake_boosts++;
            }
        } else {
            slice = tctx->next_slice;
            tier  = GET_TIER(tctx) & 3;
        }
    }

    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, wake_flags);

    /* FIX (#11): Count direct-dispatch stats so TUI reflects the common idle-path case. */
    if (enable_stats) {
        struct cake_stats *s = get_local_stats();
        if (s) {
            s->nr_new_flow_dispatches++;
            if (tier < CAKE_TIER_MAX)
                s->nr_tier_dispatches[tier]++;
        }
    }

    return (s32)cpu;
}

s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags)
{
    /* ── IRQ-SOURCE WAKEUP DETECTION (adapted from LAVD lavd_select_cpu) ──
     * Detect whether the task is being woken from a hardirq, NMI, softirq
     * bottom-half, or a ksoftirqd kernel thread. Any of these represent
     * completed hardware I/O whose consumer should run at T0 immediately
     * rather than waiting for EWMA settling.
     *
     * Gaming relevance:
     *   hardirq:    mouse click, GPU V-sync, audio DMA completion
     *   softirq:    network packet (online game), timer (frame cadence)
     *   ksoftirqd:  deferred bottom-half for the above when load is high
     *
     * bpf_in_hardirq/nmi/serving_softirq() are x86 and arm64 only; on
     * unsupported architectures they always return 0 (correct no-op).
     *
     * NOTE: ksoftirqd IS NOT covered by bpf_in_serving_softirq(). That
     * helper is true only during actual softirq vector execution. ksoftirqd
     * is a kernel thread that runs softirqs from process context, so its
     * wakeups appear as normal SCX_WAKE_SYNC or non-sync kthread wakeups.
     * We check it independently via comm prefix, matching LAVD's
     * is_ksoftirqd() which uses the same __builtin_memcmp approach. */
    struct cake_task_ctx *irq_tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (irq_tctx) {
        bool set_irq_wake = false;

        if (unlikely((bpf_in_hardirq() || bpf_in_nmi()) &&
                     !bpf_in_serving_softirq())) {
            /* Hard IRQ or NMI wakeup — highest urgency */
            set_irq_wake = true;
        } else if (unlikely(bpf_in_serving_softirq())) {
            /* Softirq bottom-half wakeup */
            set_irq_wake = true;
        } else {
            /* Check whether the waker is a ksoftirqd thread.
             * Unlike the IRQ context checks above, this can occur on any
             * wakeup type (SYNC or not), so we check it here independently.
             *
             * p is a trusted BTF pointer in STRUCT_OPS context — we can
             * read waker->comm directly via __builtin_memcmp without going
             * through bpf_probe_read_kernel (which would add unnecessary
             * overhead and a potential failure path). This is the same
             * technique used by LAVD's is_ksoftirqd(). */
            struct task_struct *waker = bpf_get_current_task_btf();
            if (waker && (waker->flags & PF_KTHREAD) &&
                __builtin_memcmp(waker->comm, "ksoftirqd/", 10) == 0) {
                set_irq_wake = true;
            }
        }

        if (unlikely(set_irq_wake))
            __sync_fetch_and_or(&irq_tctx->packed_info,
                                (u32)CAKE_FLOW_IRQ_WAKE << SHIFT_FLAGS);
    }

    /* SYNC FAST PATH: Direct dispatch to waker's CPU.
     * Cold helper checks cpumask internally (Rule 5: zero extra hot-path
     * instructions). Returns -1 if cpumask disallows → fall through. */
    if (wake_flags & SCX_WAKE_SYNC) {
        s32 sync_cpu = dispatch_sync_cold(p, wake_flags);
        if (sync_cpu >= 0)
            return sync_cpu;
    }

    u32 tc_id = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct cake_scratch *scr = &global_scratch[tc_id];
    s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &scr->dummy_idle);

    if (scr->dummy_idle) {
        /* Kernel found & claimed an idle CPU — direct dispatch.
         * cake_enqueue will NOT run on this path, so we must consume
         * CAKE_FLOW_IRQ_WAKE here if set — same as dispatch_sync_cold.
         * Use tier-adjusted slice so kernel preemption matches tick's check. */
        struct cake_task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
        u64 slice = quantum_ns;
        u8  tier  = CAKE_TIER_INTERACT;

        if (tctx) {
            u32 idle_packed = cake_relaxed_load_u32(&tctx->packed_info);
            if (unlikely(idle_packed & ((u32)CAKE_FLOW_IRQ_WAKE << SHIFT_FLAGS))) {
                __sync_fetch_and_and(&tctx->packed_info,
                                     ~((u32)CAKE_FLOW_IRQ_WAKE << SHIFT_FLAGS));
                u64 cfg = tier_configs[CAKE_TIER_CRITICAL & 7];
                slice = (quantum_ns * UNPACK_MULTIPLIER(cfg)) >> 10;
                tier  = CAKE_TIER_CRITICAL;
                if (enable_stats) {
                    struct cake_stats *s = get_local_stats();
                    if (s) s->nr_irq_wake_boosts++;
                }
            } else {
                slice = tctx->next_slice;
                tier  = GET_TIER(tctx) & 3;
            }
        }

        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, wake_flags);

        /* FIX (#11): Count idle-path direct dispatches for accurate TUI stats. */
        if (enable_stats) {
            struct cake_stats *s = get_local_stats();
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

/* ENQUEUE-TIME KICK: DISABLED.
 * A/B testing confirmed kicks cause 16fps 1% low regression in Arc Raiders
 * (252fps without kick, 236fps with T3-only kick). Even T3-only kicks create
 * cache pollution and GPU pipeline bubbles. Tick-based starvation detection
 * is sufficient for gaming workloads. */

/* Enqueue - A+B architecture: per-LLC DSQ with vtime = (tier << 56) | timestamp */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
    register struct task_struct *p_reg asm("r6") = p;
    u32 task_flags = p_reg->flags;

    /* KFUNC TUNNELING: Reuse LLC ID + timestamp cached by select_cpu in scratch.
     * Eliminates 2 kfunc trampolines (~40-60ns) — select_cpu always runs on
     * the same CPU immediately before enqueue, so values are fresh. */
    u32 enq_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct cake_scratch *scr = &global_scratch[enq_cpu];
    u64 now_cached = scr->cached_now;
    u32 enq_llc = scr->cached_llc;

    struct cake_task_ctx *tctx = get_task_ctx(p_reg, false);

    /* FIX (#10): Kthreads without a tctx (race window before cake_enable fires)
     * previously received CAKE_TIER_CRITICAL unconditionally, giving kcompactd,
     * kswapd, and similar bulk kthreads unwarranted T0 priority that could starve
     * game threads. Changed to CAKE_TIER_INTERACT (T1) which matches the tier
     * assigned to nice=0 kthreads by alloc_task_ctx_cold(). They will reclassify
     * to their correct tier within a few stops once a tctx is allocated. */
    if (unlikely((task_flags & PF_KTHREAD) && !tctx)) {
        u64 vtime = ((u64)CAKE_TIER_INTERACT << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, quantum_ns, vtime, enq_flags);
        __sync_fetch_and_or(&llc_nonempty_mask, 1u << enq_llc);
        return;
    }

    register struct cake_task_ctx *tctx_reg asm("r7") = tctx;

    /* FIX (#3): Voluntarily yielding T0/T1 tasks (sched_yield, brief hardware wait)
     * were previously hard-coded to CAKE_TIER_BULK, sending audio/input threads to
     * the back of the T3 queue for up to 100ms. They now use their actual tier so
     * latency-sensitive tasks remain properly prioritized even when yielding.
     * Tasks with no context yet fall back to T3 (yield implies they're not urgent). */
    if (!(enq_flags & (SCX_ENQ_WAKEUP | SCX_ENQ_PREEMPT))) {
        u8 yield_tier = tctx_reg ? (GET_TIER(tctx_reg) & 3) : CAKE_TIER_BULK;
        u64 vtime = ((u64)yield_tier << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, quantum_ns, vtime, enq_flags);
        __sync_fetch_and_or(&llc_nonempty_mask, 1u << enq_llc);
        return;
    }

    if (unlikely(!tctx_reg)) {
        /* No context yet - use Frame tier */
        u64 vtime = ((u64)CAKE_TIER_FRAME << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, quantum_ns, vtime, enq_flags);
        __sync_fetch_and_or(&llc_nonempty_mask, 1u << enq_llc);
        return;
    }

    /* Standard Tier Logic */
    u8 tier = GET_TIER(tctx_reg) & 3;
    u64 slice = tctx_reg->next_slice;

    /* Load packed_info once — shared by all three feature checks below. */
    u32 task_packed = cake_relaxed_load_u32(&tctx_reg->packed_info);

    /* ── FEATURE 1: IRQ-SOURCE TIER OVERRIDE (adapted from LAVD) ──────────
     * If cake_select_cpu stamped CAKE_FLOW_IRQ_WAKE, this task was woken
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
            struct cake_stats *s = get_local_stats();
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
     * from any recent cake_tick on this CPU) + one comparison + one branch.
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
     * tier of the last task that ran on this CPU, set by cake_tick. */
    if ((enq_flags & SCX_ENQ_WAKEUP) && tier > CAKE_TIER_CRITICAL) {
        struct mega_mailbox_entry *waker_mbox = &mega_mailbox[enq_cpu];
        /* Guard: only inherit when the waker's CPU has had at least one tick */
        if (waker_mbox->tick_counter > 0) {
            u8 waker_tier = MBOX_GET_TIER(waker_mbox->flags);
            if (waker_tier < tier) {
                /* Promote to at most one tier above waker, never below CRITICAL. */
                u8 promoted = (waker_tier < CAKE_TIER_BULK) ? waker_tier + 1
                                                             : waker_tier;
                if (promoted < tier) {
                    tier = promoted;
                    if (enable_stats) {
                        struct cake_stats *s = get_local_stats();
                        if (s) s->nr_waker_tier_boosts++;
                    }
                }
            }
        }
    }

    if (enable_stats) {
        struct cake_stats *s = get_local_stats();
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
    /* Mark LLC as non-empty so dispatch can find work in O(1) */
    __sync_fetch_and_or(&llc_nonempty_mask, 1u << enq_llc);
}

/* Dispatch: per-LLC DSQ scan with O(1) bitmask-driven cross-LLC stealing.
 * Direct-dispatched tasks (SCX_DSQ_LOCAL_ON) bypass this callback entirely —
 * kernel handles them natively. Only tasks that went through
 * cake_enqueue → per-LLC DSQ arrive here. */
void BPF_STRUCT_OPS(cake_dispatch, s32 raw_cpu, struct task_struct *prev)
{
    u32 my_llc = cpu_llc_id[raw_cpu & (CAKE_MAX_CPUS - 1)];

    /* Local LLC first — zero cross-CCD contention in steady state */
    if (scx_bpf_dsq_move_to_local(LLC_DSQ_BASE + my_llc))
        return;

    /* Drain confirmed empty — clear our bit */
    __sync_fetch_and_and(&llc_nonempty_mask, ~(1u << my_llc));

    /* RODATA gate: single-LLC systems skip steal entirely (Rule 5) */
    if (nr_llcs <= 1)
        return;

    /* O(1) steal: only visit LLCs that have reported work.
     * Stale set bits cause at most one failed dsq_move per race — harmless. */
    u32 steal_mask = cake_relaxed_load_u32(&llc_nonempty_mask) & ~(1u << my_llc);
    for (u32 i = 0; steal_mask && i < CAKE_MAX_LLCS; i++) {
        /* FIX (#15): steal_mask is u32 — use BIT_SCAN_FORWARD_U32 instead of the u64
         * variant. The u64 De Bruijn path works by zero-extension but uses a 64-bit
         * multiplier and index table that is semantically incorrect for u32 operands. */
        u32 victim = BIT_SCAN_FORWARD_U32(steal_mask);
        steal_mask &= steal_mask - 1;  /* clear LSB */
        if (victim >= nr_llcs)
            continue;
        if (scx_bpf_dsq_move_to_local(LLC_DSQ_BASE + victim))
            return;
        /* Victim was empty despite bit being set — clear stale bit */
        __sync_fetch_and_and(&llc_nonempty_mask, ~(1u << victim));
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

void BPF_STRUCT_OPS(cake_tick, struct task_struct *p)
{
    /* Register pin p to r6 to avoid stack spills */
    register struct task_struct *p_reg asm("r6") = p;
    register struct cake_task_ctx *tctx_reg asm("r7") = get_task_ctx(p_reg, false);
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

    /* Slice exceeded: force context switch */
    if (unlikely(runtime > tctx_reg->next_slice)) {
        scx_bpf_kick_cpu(cpu_id_reg, SCX_KICK_PREEMPT);
        return;
    }

    /* PHASE 2: STARVATION CHECK — graduated confidence backoff.
     * tick_counter tracks consecutive ticks without contention (nr_running <= 1).
     * As confidence grows, check frequency drops:
     *   counter < 8:  check every tick     (settling, ~8ms)
     *   counter < 16: check every 2nd tick (warming, max 1ms delay)
     *   counter < 32: check every 4th tick (confident, max 3ms delay)
     *   counter >= 32: check every 8th tick (high confidence, max 7ms delay)
     * Any contention (nr_running > 1) resets to 0 → full alertness.
     * Core ideology: good scheduling earns reduced overhead. */
    struct mega_mailbox_entry *mbox = &mega_mailbox[cpu_id_reg];
    u8 tc = mbox->tick_counter;
    u8 skip_mask = tc < 8 ? 0 : tc < 16 ? 1 : tc < 32 ? 3 : 7;

    if (!(tc & skip_mask)) {
        struct rq *rq = cake_get_rq(cpu_id_reg);
        if (rq && rq->scx.nr_running > 1) {
            /* Contention detected — reset confidence immediately */
            mbox->tick_counter = 0;

            u64 threshold = UNPACK_STARVATION_NS(tier_configs[tier_reg & 7]);
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
                u32 tick_packed = cake_relaxed_load_u32(&tctx_reg->packed_info);
                if (unlikely(tick_packed & ((u32)CAKE_FLAG_LOCK_HOLDER << SHIFT_FLAGS))) {
                    /* Skip preempt — let the lock holder finish the critical section */
                    if (enable_stats) {
                        struct cake_stats *s = get_local_stats();
                        if (s) s->nr_lock_holder_skips++;
                    }
                    goto mailbox_dvfs;  /* Still update mailbox and DVFS */
                }

                scx_bpf_kick_cpu(cpu_id_reg, SCX_KICK_PREEMPT);

                if (enable_stats && tier_reg < CAKE_TIER_MAX) {
                    struct cake_stats *s = get_local_stats();
                    if (s) s->nr_starvation_preempts_tier[tier_reg]++;
                }
                return;  /* Already kicked — skip mailbox/DVFS */
            }
        } else {
            /* No contention — grow confidence (saturate at 255) */
            if (tc < 255) mbox->tick_counter = tc + 1;
        }
    } else {
        /* Skipped check — still increment counter for next mask eval */
        if (tc < 255) mbox->tick_counter = tc + 1;
    }

mailbox_dvfs:; /* FIX: empty statement separates label from declaration (C99 §6.8.1) */

    /* MEGA-MAILBOX UPDATE: tier for dispatch to consume (MESI-guarded) */
    u8 new_flags = (tier_reg & MBOX_TIER_MASK);
    if (mbox->flags != new_flags)
        mbox->flags = new_flags;

    /* DVFS: Tier-proportional CPU frequency steering.
     * Runs in tick (rq-locked) = ~15-20ns vs ~30-80ns unlocked in running.
     * Hysteresis: skip kfunc if perf target unchanged (MESI-friendly).
     *
     * Hybrid scaling: on Intel P/E-core systems, scale target by each core's
     * cpuperf_cap so E-cores don't get over-requested. JIT eliminates this
     * branch entirely on non-hybrid CPUs (has_hybrid = false in RODATA). */
    u32 target = tier_perf_target[tier_reg & 7];
    if (has_hybrid) {
        u32 cap = scx_bpf_cpuperf_cap(cpu_id_reg);
        target = (target * cap) >> 10;  /* scale by capability (1024 = 100%) */
    }
    u8 cached_perf = mbox->dsq_hint;
    u8 target_cached = (u8)(target >> 2);
    if (cached_perf != target_cached) {
        scx_bpf_cpuperf_set(cpu_id_reg, target);
        mbox->dsq_hint = target_cached;
    }
}

/* Task started running - stamp last_run_at for runtime measurement.
 * DVFS moved to cake_tick where rq lock is held (cpuperf_set ~15-20ns vs
 * ~30-80ns unlocked here). Saves ~44-84 cycles per context switch. */
void BPF_STRUCT_OPS(cake_running, struct task_struct *p)
{
    struct cake_task_ctx *tctx = get_task_ctx(p, false);
    if (!tctx)
        return;
    tctx->last_run_at = (u32)scx_bpf_now();
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
void reclassify_task_cold(struct cake_task_ctx *tctx)
{
    u32 packed = cake_relaxed_load_u32(&tctx->packed_info);

    /* ── RUNTIME MEASUREMENT ── */
    u32 now = (u32)scx_bpf_now();
    u32 last_run = tctx->last_run_at;
    if (!last_run)
        return;  /* Never ran — skip (safety gate) */

    u32 runtime_raw = now - last_run;
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
        /* FIX (#9): EWMA double-update on graduated backoff trigger.
         *
         * Previously, the fast path unconditionally wrote deficit_avg_fused and
         * then fell through to full reclassification, which read the already-updated
         * value and applied EWMA a second time — effectively doubling alpha on every
         * backoff-period boundary (promoting at α=1/2 instead of 1/4).
         *
         * Fix: compute EWMA values but only write deficit_avg_fused when taking the
         * early-return path. The full reclassify path below reads the original
         * (unmodified) old_fused and applies EWMA exactly once. */
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

        /* Per-tier recheck: increment counter, check against tier mask */
        u8 tier = (packed >> SHIFT_TIER) & MASK_TIER;
        /* FIX (audit): Use & 7 to match all other tier array accesses.
         * & 3 was semantically correct (tier is 2-bit) but inconsistent
         * with tier_configs[] and tier_perf_target[] which use & 7. */
        u16 mask = tier_recheck_mask[tier & 7];
        u16 counter = tctx->reclass_counter + 1;
        tctx->reclass_counter = counter;
        if (counter & mask) {
            /* Not time for full recheck — commit fast path results and return.
             * Writing here (and NOT in the fall-through path below) prevents
             * the double-EWMA application that was the original bug. */
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
                cake_relaxed_store_u32(&tctx->packed_info, reset);
                tctx->reclass_counter = 0;
            }
            return;
        }
        /* Fall through → periodic full reclassify.
         * Do NOT write deficit_avg_fused here — full path reads the original
         * old_fused so EWMA is applied exactly once. */
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

        cake_relaxed_store_u32(&tctx->packed_info, new_packed);
    }

    /* ── SLICE RECALCULATION on tier change ── */
    /* When tier changes, the quantum multiplier changes (T0=0.75x → T3=1.4x).
     * Update next_slice so the next execution bout uses the correct quantum. */
    if (tier_changed) {
        u64 cfg = tier_configs[new_tier & 7];
        u64 mult = UNPACK_MULTIPLIER(cfg);
        tctx->next_slice = (quantum_ns * mult) >> 10;
        tctx->reclass_counter = 0;
    }
}

/* Pre-allocate task context when a task enters scx control.
 * Fires once per task — not in the scheduling hot path.
 * Guarantees cake_running/cake_stopping never see a NULL context,
 * converting those null guards from live code paths to safety assertions. */
s32 BPF_STRUCT_OPS(cake_enable, struct task_struct *p)
{
    get_task_ctx(p, true);
    return 0;
}

/* Task stopping — avg_runtime reclassification + DRR++ deficit tracking */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
    struct cake_task_ctx *tctx = get_task_ctx(p, false);
    /* Skip tasks that have never been stamped by cake_running.
     * Avoids the noinline call overhead (~3-5 cycles) for the
     * uncommon case of a task stopping before its first run. */
    if (tctx && likely(tctx->last_run_at))
        reclassify_task_cold(tctx);
}

/* Initialize the scheduler */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init)
{
    /* Per-CPU DSQs eliminated — SCX_DSQ_LOCAL_ON dispatches directly to
     * the kernel's built-in local DSQ, skipping dispatch callback entirely.
     * Per-LLC DSQs used for enqueue → dispatch path. */
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
void BPF_STRUCT_OPS(cake_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cake_ops,
               .select_cpu     = (void *)cake_select_cpu,
               .enqueue        = (void *)cake_enqueue,
               .dispatch       = (void *)cake_dispatch,
               .tick           = (void *)cake_tick,
               .running        = (void *)cake_running,
               .stopping       = (void *)cake_stopping,
               .enable         = (void *)cake_enable,
               .init           = (void *)cake_init,
               .exit           = (void *)cake_exit,
               .flags          = SCX_OPS_KEEP_BUILTIN_IDLE,
               .name           = "cake");
