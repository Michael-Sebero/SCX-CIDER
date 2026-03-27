/* SPDX-License-Identifier: GPL-2.0 */
/* scx_cider BPF/userspace interface - shared data structures and constants */

#ifndef __CAKE_INTF_H
#define __CAKE_INTF_H

#include <limits.h>

/* Type defs for BPF/userspace compat - defined when vmlinux.h is not included */
#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
#endif

/* CAKE TIER SYSTEM — 4-tier classification by avg_runtime
 *
 * Tiers group tasks with similar scheduling needs. Classification is
 * purely by EWMA avg_runtime — shorter runtime = more latency-sensitive.
 * DRR++ deficit handles intra-tier fairness (yield vs preempt). */
enum cider_tier {
    CAKE_TIER_CRITICAL  = 0,  /* <100µs:  IRQ, input, audio, network */
    CAKE_TIER_INTERACT  = 1,  /* <2ms:    compositor, physics, AI */
    CAKE_TIER_FRAME     = 2,  /* <8ms:    game render, encoding */
    CAKE_TIER_BULK      = 3,  /* ≥8ms:    compilation, background */
    CAKE_TIER_MAX       = 4,
};

/* FIX (consistency): Use CAKE_TIER_IDX() for all tier array bounds-checking.
 * This replaces the mix of (tier & 3) and (tier & 7) at different call sites
 * with a single canonical form.  The mask of 7 is correct because all tier
 * arrays (tier_configs[], tier_perf_target[], tier_recheck_mask[]) are sized
 * to 8 elements for safe access.  A _Static_assert below ensures CAKE_TIER_MAX
 * never exceeds the array size. */
#define CAKE_TIER_IDX(t)  ((t) & 7)
_Static_assert(CAKE_TIER_MAX <= 8,
    "CAKE_TIER_MAX exceeds array size — update CAKE_TIER_IDX mask");

#define CAKE_MAX_CPUS 64
#define CAKE_MAX_LLCS 8

/* Per-LLC DSQ base — DSQ IDs are LLC_DSQ_BASE + llc_index (0..nr_llcs-1) */
#define LLC_DSQ_BASE 200

/* ═══════════════════════════════════════════════════════════════════════════
 * FLOW STATE FLAGS — live in the 4-bit FLAGS nibble of packed_info.
 * SHIFT_FLAGS = 24, MASK_FLAGS = 0x0F → bits 24–27 of packed_info.
 *
 * Bit layout (packed_info bits 27:24):
 *   bit 0 (1<<0): CAKE_FLOW_NEW        new-flow bonus active; cleared on deficit exhaust
 *   bit 1 (1<<1): CAKE_FLAG_LOCK_HOLDER  task holds a futex; set/cleared atomically by
 *                                        fexit probes in lock_bpf.c via __sync_fetch_and_or/and.
 *                                        Prevents preemption in cider_tick; advances vtime in
 *                                        cider_enqueue to sort ahead of same-tier peers.
 *   bit 2 (1<<2): CAKE_FLOW_IRQ_WAKE   one-shot: task was woken from hardirq/softirq context.
 *                                        Set in cider_select_cpu via bpf_in_hardirq/softirq helpers
 *                                        (adapted from LAVD lavd_select_cpu). Consumed in
 *                                        cider_enqueue to override tier=0 for this dispatch only.
 *   bit 3 (1<<3): reserved
 *
 * Sources:
 *   CAKE_FLAG_LOCK_HOLDER — adapted from LAVD lock.bpf.c futex priority boosting.
 *   CAKE_FLOW_IRQ_WAKE    — adapted from LAVD lavd_select_cpu IRQ-context wakeup detection.
 * ═══════════════════════════════════════════════════════════════════════════ */
enum cider_flow_flags {
    CAKE_FLOW_NEW         = 1 << 0,  /* Task is newly created */
    CAKE_FLAG_LOCK_HOLDER = 1 << 1,  /* Task currently holds a futex */
    CAKE_FLOW_IRQ_WAKE    = 1 << 2,  /* Task was woken from IRQ/softirq context */
};

/* Per-task flow state - 64B aligned, first 16B coalesced for cider_stopping writes */
struct cider_task_ctx {
    /* --- Hot Write Group (cider_stopping) [Bytes 0-15] --- */
    u64 next_slice;        /* 8B: Pre-computed slice (ns) */

    /* STATE FUSION: Union allows atomic u64 access to both state fields */
    union {
        struct {
            union {
                struct {
                    u16 deficit_us;        /* 2B: Deficit (us) */
                    u16 avg_runtime_us;    /* 2B: EMA runtime estimate */
                };
                u32 deficit_avg_fused;     /* 4B: Fused access */
            };
            u32 packed_info;               /* 4B: Bitfield */
        };
        u64 state_fused_u64;               /* 8B: Direct burst commit */
    };

    /* --- Timestamp (cider_running) [Bytes 16-19] --- */
    u32 last_run_at;       /* 4B: Last run timestamp (ns), wraps 4.2s */

    /* --- Graduated backoff counter [Bytes 20-21] --- */
    u16 reclass_counter;   /* 2B: Per-task stop counter for per-tier backoff */

    /* S5: consecutive above-1.5×-gate overrun counter.
     * Incremented in reclassify_task_cold when rt_clamped > 1.5× tier gate.
     * After 4 consecutive overruns, forces a one-tier demotion regardless of
     * EWMA, cutting worst-case misclassification from ~128ms to ~8ms. */
    u8 overrun_count;      /* 1B: consecutive overrun counter */
    u8 __pad[41];          /* Pad to 64 bytes: 8+8+4+2+1+41 = 64 */
} __attribute__((aligned(64)));

/* Bitfield layout for packed_info (write-set co-located, Rule 24 mask fusion):
 * [Stable:2][Tier:2][Flags:4][Rsvd:8][Wait:8][Error:8]
 *  31-30     29-28   27-24    23-16   15-8     7-0
 * TIER+STABLE adjacent → fused 4-bit clear/set in reclassify (2 ops vs 4) */
#define SHIFT_KALMAN_ERROR  0
#define SHIFT_WAIT_DATA     8
#define SHIFT_FLAGS         24  /* 4 bits: flow flags (see cider_flow_flags above) */
#define SHIFT_TIER          28  /* 2 bits: tier 0-3 (coalesced with STABLE) */
#define SHIFT_STABLE        30  /* 2 bits: tier-stability counter (0-3) */

#define MASK_KALMAN_ERROR   0xFF  /* 8 bits: 0-255 */
#define MASK_WAIT_DATA      0xFF  /* 8 bits: violations<<4 | checks */
#define MASK_TIER           0x03  /* 2 bits: 0-3 */
#define MASK_FLAGS          0x0F  /* 4 bits */

/* Load fusing helpers for deficit_avg_fused */
#define EXTRACT_DEFICIT(fused)  ((u16)((fused) & 0xFFFF))
#define EXTRACT_AVG_RT(fused)   ((u16)((fused) >> 16))
#define PACK_DEFICIT_AVG(deficit, avg)  (((u32)(deficit) & 0xFFFF) | ((u32)(avg) << 16))

/* Pure avg_runtime tier gates (µs) */
#define TIER_GATE_T0   100   /* < 100µs  → T0 Critical: IRQ, input, audio */
#define TIER_GATE_T1   2000  /* < 2000µs → T1 Interact: compositor, physics */
#define TIER_GATE_T2   8000  /* < 8000µs → T2 Frame:    game render, encode */
                             /* ≥ 8000µs → T3 Bulk:     compilation, bg */

/* ═══════════════════════════════════════════════════════════════════════════
 * MEGA-MAILBOX: Per-CPU state (64 bytes = single cache line)
 * - Zero false sharing: each CPU writes only to its own entry
 * - Prefetch-accelerated reads: one prefetch loads entire CPU state
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Mailbox flags (packed in flags byte) */
#define MBOX_TIER_MASK    0x03  /* Bits [1:0] = tier (0-3) */

/* Mailbox flag accessors */
#define MBOX_GET_TIER(f)   ((f) & MBOX_TIER_MASK)

/* 64-byte mega-mailbox entry (single cache line = optimal L1 efficiency)
 * Per-CPU write isolation: each CPU writes ONLY its own entry.
 * Only flags (tier) and dsq_hint (DVFS cache) are actively used.
 * Reserved space kept at 64B for future per-CPU-write features. */
struct mega_mailbox_entry {
    u8 flags;              /* [1:0]=tier — written by cider_tick */
    u8 dsq_hint;           /* DVFS perf target cache — written by cider_tick */
    u8 tick_counter;       /* 2-tick starvation gate — alternates rq lookup */
    u8 __reserved[61];     /* Pad to 64B cache line, available for future use */
} __attribute__((aligned(64)));

/* Statistics shared with userspace */
struct cider_stats {
    u64 nr_new_flow_dispatches;    /* Tasks dispatched from new-flow */
    u64 nr_old_flow_dispatches;    /* Tasks dispatched from old-flow */
    u64 nr_tier_dispatches[CAKE_TIER_MAX]; /* Per-tier dispatch counts */
    u64 nr_starvation_preempts_tier[CAKE_TIER_MAX]; /* Per-tier starvation preempts */
    u64 nr_lock_holder_skips;      /* Starvation preempts skipped for lock holders */
    u64 nr_irq_wake_boosts;        /* IRQ-source wakeup tier-0 overrides */
    u64 nr_waker_tier_boosts;      /* Wakee promotions via waker tier inheritance */
    u64 _pad[19];                  /* Pad to 256 bytes: (2+4+4+3+19)*8 = 256 */
} __attribute__((aligned(64)));

/* Topology flags - enables zero-cost specialization (false = code path eliminated by verifier) */

/* Default values (Gaming profile) */
#define CAKE_DEFAULT_QUANTUM_NS         (2 * 1000 * 1000)   /* 2ms */
#define CAKE_DEFAULT_NEW_FLOW_BONUS_NS  (8 * 1000 * 1000)   /* 8ms */

/* Default tier arrays (Gaming profile) — 4 tiers */

/* Per-tier starvation thresholds (nanoseconds) */
#define CAKE_DEFAULT_STARVATION_T0  3000000    /* Critical: 3ms */
#define CAKE_DEFAULT_STARVATION_T1  8000000    /* Interact: 8ms */
#define CAKE_DEFAULT_STARVATION_T2  40000000   /* Frame: 40ms */
#define CAKE_DEFAULT_STARVATION_T3  100000000  /* Bulk: 100ms */

/* Tier quantum multipliers (fixed-point, 1024 = 1.0x)
 * Power-of-4 progression: each tier gets 4x the quantum of the tier above.
 * T2 at 4ms lets 300fps+ render threads complete entire frames without preemption.
 * T0 at 1ms releases cores to game work faster (T0 runs <100µs anyway).
 *
 * FIX (#5): T0 default raised from 256 (0.25x = 0.5ms) to 512 (0.5x = 1ms) to
 * match the Gaming profile multiplier written by the userspace loader.  Previously
 * the BPF RODATA default and the Gaming profile were silently divergent: if the
 * loader's rodata_data write were ever skipped (skeleton version mismatch, future
 * refactor), T0 audio/input tasks would receive 0.5ms slices instead of 1ms,
 * causing them to release their CPU before completing useful work — the opposite
 * of the intended behaviour.  Keeping the two values in sync makes the fallback
 * safe and documents the canonical Gaming intent at the definition site. */
#define CAKE_DEFAULT_MULTIPLIER_T0  512    /* Critical: 0.5x  = 1.0ms */
#define CAKE_DEFAULT_MULTIPLIER_T1  1024   /* Interact: 1.0x  = 2.0ms */
#define CAKE_DEFAULT_MULTIPLIER_T2  2048   /* Frame:    2.0x  = 4.0ms */
#define CAKE_DEFAULT_MULTIPLIER_T3  4095   /* Bulk:     ~4.0x = 8.0ms (12-bit max = 4095) */

/* Wait budget per tier (nanoseconds) */
#define CAKE_DEFAULT_WAIT_BUDGET_T0 100000     /* Critical: 100µs */
#define CAKE_DEFAULT_WAIT_BUDGET_T1 2000000    /* Interact: 2ms */
#define CAKE_DEFAULT_WAIT_BUDGET_T2 8000000    /* Frame: 8ms */
#define CAKE_DEFAULT_WAIT_BUDGET_T3 0          /* Bulk: no limit */

/* Fused tier config - packs 4 params into 64-bit: [Mult:12][Quantum:16][Budget:16][Starve:20] */
typedef u64 fused_config_t;

#define CFG_SHIFT_MULTIPLIER  0
#define CFG_SHIFT_QUANTUM     12
#define CFG_SHIFT_BUDGET      28
#define CFG_SHIFT_STARVATION  44

#define CFG_MASK_MULTIPLIER   0x0FFFULL
#define CFG_MASK_QUANTUM      0xFFFFULL
#define CFG_MASK_BUDGET       0xFFFFULL
#define CFG_MASK_STARVATION   0xFFFFFULL

/* Extraction Macros (BPF Side) */
/* Multiplier: bits 0-11. AND only. */
#define UNPACK_MULTIPLIER(cfg)    ((cfg) & CFG_MASK_MULTIPLIER)
/* Quantum: bits 12-27. SHR; AND; SHL. */
#define UNPACK_QUANTUM_NS(cfg)    ((((cfg) >> CFG_SHIFT_QUANTUM) & CFG_MASK_QUANTUM) << 10)
/* Budget: bits 28-43. SHR; AND; SHL. */
#define UNPACK_BUDGET_NS(cfg)     ((((cfg) >> CFG_SHIFT_BUDGET) & CFG_MASK_BUDGET) << 10)
/* Starvation: bits 44-63. SHR; SHL. (Mask redundant) */
#define UNPACK_STARVATION_NS(cfg) (((cfg) >> CFG_SHIFT_STARVATION) << 10)

/* FIX (#14): PACK_CONFIG unit clarification.
 * Parameters q_kns, budget_kns, starv_kns are in 1024-nanosecond slots (kns),
 * NOT microseconds — callers pass (value_in_ns >> 10). The "us" suffix in the
 * original name was misleading; renamed to _kns to reflect the actual unit.
 * Userspace callers: divide nanoseconds by 1024 before passing.
 * BPF unpack macros (UNPACK_*_NS) shift left by 10 to recover nanoseconds. */
#define PACK_CONFIG(q_kns, mult, budget_kns, starv_kns) \
    ((((u64)(mult) & CFG_MASK_MULTIPLIER) << CFG_SHIFT_MULTIPLIER) | \
     (((u64)(q_kns) & CFG_MASK_QUANTUM) << CFG_SHIFT_QUANTUM) | \
     (((u64)(budget_kns) & CFG_MASK_BUDGET) << CFG_SHIFT_BUDGET) | \
     (((u64)(starv_kns) & CFG_MASK_STARVATION) << CFG_SHIFT_STARVATION))

#endif /* __CAKE_INTF_H */
