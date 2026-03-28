/* SPDX-License-Identifier: GPL-2.0 */
/* scx_cider BPF/userspace interface - shared data structures and constants */

#ifndef __CAKE_INTF_H
#define __CAKE_INTF_H

#include <limits.h>

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

/* CAKE TIER SYSTEM — 4-tier classification by avg_runtime */
enum cider_tier {
    CAKE_TIER_CRITICAL  = 0,  /* <100µs:  IRQ, input, audio, network */
    CAKE_TIER_INTERACT  = 1,  /* <2ms:    compositor, physics, AI */
    CAKE_TIER_FRAME     = 2,  /* <8ms:    game render, encoding */
    CAKE_TIER_BULK      = 3,  /* ≥8ms:    compilation, background */
    CAKE_TIER_MAX       = 4,
};

#define CAKE_TIER_IDX(t)  ((t) & 7)
_Static_assert(CAKE_TIER_MAX <= 8,
    "CAKE_TIER_MAX exceeds array size — update CAKE_TIER_IDX mask");

#define CAKE_MAX_CPUS 64
#define CAKE_MAX_LLCS 8

#define LLC_DSQ_BASE 200

#define CAKE_ETD_CROSS_LLC_THRESHOLD 5

/* FLOW STATE FLAGS */
enum cider_flow_flags {
    CAKE_FLOW_NEW         = 1 << 0,
    CAKE_FLAG_LOCK_HOLDER = 1 << 1,
    CAKE_FLOW_IRQ_WAKE    = 1 << 2,
};

/* Per-task flow state — 64B, one cache line */
struct cider_task_ctx {
    /* Hot write group (cider_stopping) [Bytes 0-15] */
    u64 next_slice;

    union {
        struct {
            union {
                struct {
                    u16 deficit_us;
                    u16 avg_runtime_us;
                };
                u32 deficit_avg_fused;
            };
            u32 packed_info;
        };
        u64 state_fused_u64;
    };

    /* Timestamp (cider_running) [Bytes 16-19] */
    u32 last_run_at;

    /* Graduated backoff counter [Bytes 20-21] */
    u16 reclass_counter;

    /* S5: overrun_count — 8-bit shift register of execution outcomes.
     *
     * SEMANTICS: Each stop, the register shifts left one position and the
     * current bout's result is inserted in the LSB.  The oldest result falls
     * off the MSB.
     *
     *   bit value 1 → that bout's rt_clamped exceeded 1.5× the tier gate
     *   bit value 0 → that bout ran within the gate
     *
     * DEMOTION TRIGGER: __builtin_popcount(overrun_count) >= 4
     *   Fires when 4 of the last 8 bouts exceeded the gate.
     *
     * BEHAVIORAL EQUIVALENCE TO ORIGINAL CONSECUTIVE COUNTER:
     *   4 consecutive overruns → hist = 0b00001111 → popcount = 4 ≥ 4 → DEMOTE
     *   This is identical to the original counter-based trigger at N=4.
     *
     * NEW CAPABILITY (non-consecutive detection):
     *   4 alternating overruns over 8 bouts → popcount = 4 ≥ 4 → DEMOTE
     *   Original counter reset on every normal bout and never fired.
     *   Example: physics thread spiking every other frame for 8 frames.
     *
     * This change is strictly a superset of the original: every pattern that
     * triggered before still triggers; additional patterns now also trigger.
     *
     * INIT VALUE: 0 (empty history) — correct for alloc_task_ctx_cold.
     * FIELD NAME: kept as `overrun_count` to avoid disrupting external tools;
     *             the type (u8) and offset (byte 22) are unchanged.
     * NO STRUCT SIZE CHANGE: __pad[39] is unchanged. */
    u8 overrun_count;

    u8 lock_skip_count;
    u8 pending_futex_op;
    u8 __pad[39];
} __attribute__((aligned(64)));

_Static_assert(sizeof(struct cider_task_ctx) == 64,
    "cider_task_ctx must be exactly 64B (one cache line) — update __pad if fields change");

/* packed_info bitfield layout:
 * [Stable:2][Tier:2][Flags:4][Rsvd:8][Wait:8][Error:8]
 *  31-30     29-28   27-24    23-16   15-8     7-0      */
#define SHIFT_KALMAN_ERROR  0
#define SHIFT_WAIT_DATA     8
#define SHIFT_FLAGS         24
#define SHIFT_TIER          28
#define SHIFT_STABLE        30

#define MASK_KALMAN_ERROR   0xFF
#define MASK_WAIT_DATA      0xFF
#define MASK_TIER           0x03
#define MASK_FLAGS          0x0F

#define EXTRACT_DEFICIT(fused)  ((u16)((fused) & 0xFFFF))
#define EXTRACT_AVG_RT(fused)   ((u16)((fused) >> 16))
#define PACK_DEFICIT_AVG(deficit, avg)  (((u32)(deficit) & 0xFFFF) | ((u32)(avg) << 16))

/* avg_runtime tier gates (µs) */
#define TIER_GATE_T0   100
#define TIER_GATE_T1   2000
#define TIER_GATE_T2   8000

/* MEGA-MAILBOX */
#define MBOX_TIER_MASK    0x03
#define MBOX_GET_TIER(f)  ((f) & MBOX_TIER_MASK)

struct mega_mailbox_entry {
    u8 flags;
    u8 dsq_hint;
    u8 tick_counter;
    u8 __reserved[61];
} __attribute__((aligned(64)));

/* Statistics */
struct cider_stats {
    u64 nr_new_flow_dispatches;
    u64 nr_old_flow_dispatches;
    u64 nr_tier_dispatches[CAKE_TIER_MAX];
    u64 nr_starvation_preempts_tier[CAKE_TIER_MAX];
    u64 nr_lock_holder_skips;
    u64 nr_irq_wake_boosts;
    u64 nr_waker_tier_boosts;
    u64 _pad[19];
} __attribute__((aligned(64)));

/* Defaults (Gaming profile) */
#define CAKE_DEFAULT_QUANTUM_NS         (2 * 1000 * 1000)
#define CAKE_DEFAULT_NEW_FLOW_BONUS_NS  (8 * 1000 * 1000)
#define CAKE_DEFAULT_STARVATION_T0   3000000
#define CAKE_DEFAULT_STARVATION_T1   8000000
#define CAKE_DEFAULT_STARVATION_T2  40000000
#define CAKE_DEFAULT_STARVATION_T3 100000000
#define CAKE_DEFAULT_MULTIPLIER_T0  512
#define CAKE_DEFAULT_MULTIPLIER_T1  1024
#define CAKE_DEFAULT_MULTIPLIER_T2  2048
#define CAKE_DEFAULT_MULTIPLIER_T3  4095
#define CAKE_DEFAULT_WAIT_BUDGET_T0 100000
#define CAKE_DEFAULT_WAIT_BUDGET_T1 2000000
#define CAKE_DEFAULT_WAIT_BUDGET_T2 8000000
#define CAKE_DEFAULT_WAIT_BUDGET_T3 0

/* Fused tier config: [Mult:12][Quantum:16][Budget:16][Starve:20] */
typedef u64 fused_config_t;

#define CFG_SHIFT_MULTIPLIER  0
#define CFG_SHIFT_QUANTUM     12
#define CFG_SHIFT_BUDGET      28
#define CFG_SHIFT_STARVATION  44

#define CFG_MASK_MULTIPLIER   0x0FFFULL
#define CFG_MASK_QUANTUM      0xFFFFULL
#define CFG_MASK_BUDGET       0xFFFFULL
#define CFG_MASK_STARVATION   0xFFFFFULL

#define UNPACK_MULTIPLIER(cfg)    ((cfg) & CFG_MASK_MULTIPLIER)
#define UNPACK_QUANTUM_NS(cfg)    ((((cfg) >> CFG_SHIFT_QUANTUM) & CFG_MASK_QUANTUM) << 10)
#define UNPACK_BUDGET_NS(cfg)     ((((cfg) >> CFG_SHIFT_BUDGET) & CFG_MASK_BUDGET) << 10)
#define UNPACK_STARVATION_NS(cfg) (((cfg) >> CFG_SHIFT_STARVATION) << 10)

#define PACK_CONFIG(q_kns, mult, budget_kns, starv_kns) \
    ((((u64)(mult) & CFG_MASK_MULTIPLIER) << CFG_SHIFT_MULTIPLIER) | \
     (((u64)(q_kns) & CFG_MASK_QUANTUM) << CFG_SHIFT_QUANTUM) | \
     (((u64)(budget_kns) & CFG_MASK_BUDGET) << CFG_SHIFT_BUDGET) | \
     (((u64)(starv_kns) & CFG_MASK_STARVATION) << CFG_SHIFT_STARVATION))

#define CAKE_FUTEX_OP_UNSET  0xFF

#endif /* __CAKE_INTF_H */
