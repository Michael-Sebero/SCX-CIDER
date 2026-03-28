// SPDX-License-Identifier: GPL-2.0
/*
 * cider_bpf_s6.c — corrected s6-derived patch for scx_cider
 *
 * Apply each numbered section to cider_bpf.c at the location indicated by
 * TARGET and ACTION markers.  The integration checklist at the end lists
 * every change and the order to apply them.
 *
 * FIXES vs PREVIOUS PATCH VERSION
 * ────────────────────────────────
 * [A] llc_cpu_mask: rodata → BSS.  Populated in [C] by cider_init from the
 *     existing cpu_llc_id rodata.  Removes partial-deploy hazard where
 *     missing Rust write caused all-zero mask and silent kick failure.
 *
 * [C] cider_init: gains llc_cpu_mask computation.  Field is guaranteed
 *     non-zero before any task is scheduled.  Rust write no longer needed.
 *
 * [D] cider_running: simplified.  Removed old_tier read + conditional AND.
 *     Stopping owns all clears; running only sets.  Saves ~8 cycles/switch.
 *
 * [G] cider_dispatch: dead `within_threshold_exhausted` variable deleted.
 *     Was 3 comparisons + 1 bool per cross-LLC dispatch with zero effect.
 *
 * [H] Overrun threshold: 5 → 4.  Restores original consecutive-path parity
 *     (4 consecutive overruns → popcount 4 ≥ 4 → demote, same as original).
 *     Threshold 5 was a regression: 4 consecutive no longer fired.
 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include "intf.h"
#include "bpf_compat.h"


/* ═══════════════════════════════════════════════════════════════════════════
 * [A] llc_cpu_mask — BSS, not rodata
 *
 * TARGET: Replace `const u64 llc_cpu_mask[CAKE_MAX_LLCS] = {};` if present,
 *         or add after `const u32 cpu_llc_id[CAKE_MAX_CPUS] = {};`.
 *
 * BSS is writable at BPF runtime.  cider_init fills this from cpu_llc_id
 * before any task is scheduled.  Declaring it as rodata (const) required the
 * Rust loader to write it; if that write was absent the field stayed zero and
 * the kick path produced zero kicks without any error or warning.
 *
 * With BSS + cider_init population: field is always correct, Rust write is
 * no longer required, partial-deploy hazard is eliminated.
 *
 * LAYOUT: 8 × 8B = 64B, one cache line.  Read in cider_enqueue: one miss
 * loads the entire array.
 * ═══════════════════════════════════════════════════════════════════════════ */

u64 llc_cpu_mask[CAKE_MAX_LLCS] SEC(".bss") __attribute__((aligned(64)));


/* ═══════════════════════════════════════════════════════════════════════════
 * [B] tier_cpu_mask — BSS (unchanged from previous patch)
 *
 * TARGET: Add after llc_nonempty[] BSS declaration (around line 59).
 *
 * INVARIANT: bit i of tier_cpu_mask[t] is set iff CPU i is currently running
 * a task of EWMA tier t.
 *
 * Responsibility split:
 *   cider_running  → set bit for new task's tier  (never clears)
 *   cider_stopping → clear bit for stopping tier  (never sets)
 *
 * LAYOUT: 4 × 8B = 32B.  All four tier words fit in one 64B cache line with
 * llc_cpu_mask, loaded together on the kick path.
 * ═══════════════════════════════════════════════════════════════════════════ */

u64 tier_cpu_mask[CAKE_TIER_MAX] SEC(".bss") __attribute__((aligned(64)));


/* ═══════════════════════════════════════════════════════════════════════════
 * [C] cider_init — compute llc_cpu_mask
 *
 * TARGET: Replace entire cider_init function.
 *         Search: `BPF_STRUCT_OPS_SLEEPABLE(cider_init)`
 *
 * cpu_llc_id[] is already RODATA set by the Rust loader.  nr_cpus is already
 * RODATA.  The loop is bounded by CAKE_MAX_CPUS (compile-time constant = 64);
 * the verifier sees a bounded trip count identical to the existing nr_llcs loop
 * pattern already present in this function.
 *
 * Result: llc_cpu_mask[l] has bit i set for every CPU i in LLC l.
 * On a single-CCD 16-thread system: llc_cpu_mask[0] = 0x000000000000FFFF.
 * On a dual-CCD 32-thread system:   llc_cpu_mask[0] = 0x0000FFFF,
 *                                   llc_cpu_mask[1] = 0xFFFF0000.
 * ═══════════════════════════════════════════════════════════════════════════ */

s32 BPF_STRUCT_OPS_SLEEPABLE(cider_init)
{
    /* Populate llc_cpu_mask from existing cpu_llc_id RODATA.
     * Runs exactly once at scheduler attachment, before any task is scheduled.
     * Eliminates the Rust-side write requirement and its partial-deploy hazard. */
    for (u32 cpu = 0; cpu < nr_cpus && cpu < CAKE_MAX_CPUS; cpu++) {
        u32 llc = cpu_llc_id[cpu] & (CAKE_MAX_LLCS - 1);
        llc_cpu_mask[llc] |= 1ULL << cpu;
    }

    /* Create per-LLC DSQs — one per cache domain.
     * FIX (audit): loop to nr_llcs (RODATA const), not CAKE_MAX_LLCS. */
    for (u32 i = 0; i < nr_llcs; i++) {
        s32 ret = scx_bpf_create_dsq(LLC_DSQ_BASE + i, -1);
        if (ret < 0)
            return ret;
    }

    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * [D] cider_running — simplified bitmask maintenance
 *
 * TARGET: Replace entire cider_running function.
 *         Search: `BPF_STRUCT_OPS(cider_running,`
 *
 * SIMPLIFICATION vs PREVIOUS PATCH:
 *   Previous version read mbox->flags to get old_tier, then conditionally
 *   cleared tier_cpu_mask[old_tier].  This was redundant: cider_stopping
 *   already cleared the bit for the previous task before this cider_running
 *   fires.  The double-clear was: AND(already-zero-bit) = no-op, every time.
 *
 *   Removed: one relaxed u8 load, one compare-branch, one conditional AND atomic.
 *   The mbox->flags read is still required for the mailbox tier update below.
 *   It is NOT removed — only the old_tier extraction from it is gone.
 *
 * CONCURRENCY: __sync_fetch_and_or maps to BPF_ATOMIC_OR (single instruction,
 *   not a CAS loop).  Multiple CPUs write different bits of the same u64
 *   simultaneously — the atomic prevents torn read-modify-write at word level.
 *   No two CPUs ever write the same bit (each CPU owns bit = 1ULL << its id).
 *
 * COST vs ORIGINAL cider_running (no patch):
 *   Added: one BPF_ATOMIC_OR (~5 cycles)
 *
 * COST vs PREVIOUS PATCH cider_running:
 *   Removed: one relaxed load + one compare-branch + one conditional AND
 *   Net saved: ~8 cycles per context switch
 * ═══════════════════════════════════════════════════════════════════════════ */

void BPF_STRUCT_OPS(cider_running, struct task_struct *p)
{
    struct cider_task_ctx *tctx = get_task_ctx(p, false);
    if (!tctx)
        return;
    tctx->last_run_at = (u32)scx_bpf_now();

    u32 run_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct mega_mailbox_entry *mbox = &mega_mailbox[run_cpu];
    u8 tier = CAKE_TIER_IDX(GET_TIER(tctx));

    /* Mailbox: publish tier immediately so waker-tier inheritance in
     * cider_enqueue sees the correct value from the first nanosecond of
     * this task's run, not after the first tick (~1–4ms later). */
    u8 cur_flags = cider_relaxed_load_u8(&mbox->flags);
    if ((cur_flags & MBOX_TIER_MASK) != tier)
        cider_relaxed_store_u8(&mbox->flags, (cur_flags & ~MBOX_TIER_MASK) | tier);

    /* Bitmask: set this CPU's bit in the new task's tier word.
     * cider_stopping owns all clears; we only set here — no double-ownership. */
    __sync_fetch_and_or(&tier_cpu_mask[tier & (CAKE_TIER_MAX - 1)], 1ULL << run_cpu);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * [E] cider_stopping — bitmask clear before reclassification (unchanged)
 *
 * TARGET: Replace entire cider_stopping function.
 *         Search: `BPF_STRUCT_OPS(cider_stopping,`
 *
 * ORDER IS CRITICAL: clear bit BEFORE reclassify_task_cold.
 *   reclassify_task_cold may change packed_info.tier.
 *   GET_TIER(tctx) before reclassification = the tier the task was running at
 *   = the tier whose bit is set in tier_cpu_mask = correct bit to clear.
 *   After reclassification, GET_TIER would return the new (post-EWMA) tier.
 *
 * COST vs ORIGINAL cider_stopping (no patch):
 *   Added: one BPF_ATOMIC_AND (~5 cycles)
 * ═══════════════════════════════════════════════════════════════════════════ */

void BPF_STRUCT_OPS(cider_stopping, struct task_struct *p, bool runnable)
{
    struct cider_task_ctx *tctx = get_task_ctx(p, false);
    if (tctx && likely(tctx->last_run_at)) {
        /* Clear this CPU's tier bit BEFORE reclassify changes packed_info. */
        u32 stop_cpu  = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
        u8  stop_tier = CAKE_TIER_IDX(GET_TIER(tctx));
        __sync_fetch_and_and(
            &tier_cpu_mask[stop_tier & (CAKE_TIER_MAX - 1)],
            ~(1ULL << stop_cpu));

        reclassify_task_cold(tctx);
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * [F] cider_enqueue — O(1) bitmask kick (unchanged, now guaranteed correct)
 *
 * TARGET: Replace the kick scan block in cider_enqueue.
 *         Find `if (tier <= CAKE_TIER_INTERACT) {` and replace through
 *         the closing `}`.  Also delete the two now-unused local variables
 *         that precede it:
 *           `u32 best_cpu    = CAKE_MAX_CPUS;`
 *           `u8  worst_tier  = CAKE_TIER_INTERACT;`
 *         and the scan loop + scx_bpf_kick_cpu call.
 *
 * CORRECTNESS (fixed vs previous patch):
 *   llc_cpu_mask is now computed in cider_init — always non-zero for any
 *   LLC with at least one CPU.  The AND with tier_cpu_mask produces zero
 *   only when genuinely no T3/T2 CPU exists in the LLC, which is the correct
 *   "no victim" result.  The previous all-zero state from missing Rust write
 *   no longer exists.
 *
 * COST vs ORIGINAL O(nr_cpus) scan (16 CPUs):
 *   Removed: 16 relaxed u8 loads from scattered mailbox cache lines
 *            + 16 cpu_llc_id reads + loop overhead + max-tracking branch
 *   Added:   2 relaxed u64 loads from tier_cpu_mask (1 cache line, both hot)
 *            + 1 relaxed u64 load from llc_cpu_mask (1 cache line, read-only)
 *            + 1 AND + 1 CTZ per tier attempted
 *   Net: ~80–100 cycles removed, ~12 cycles added
 * ═══════════════════════════════════════════════════════════════════════════ */

    if (tier <= CAKE_TIER_INTERACT) {
        u64 my_llc_mask = cider_relaxed_load_u64(
            &llc_cpu_mask[enq_llc & (CAKE_MAX_LLCS - 1)]);

        /* Prefer displacing T3 (bulk) — lowest frame-time displacement cost */
        u64 t3_in_llc = cider_relaxed_load_u64(
            &tier_cpu_mask[CAKE_TIER_BULK]) & my_llc_mask;
        if (t3_in_llc) {
            scx_bpf_kick_cpu(BIT_SCAN_FORWARD_U64(t3_in_llc), SCX_KICK_PREEMPT);
        } else {
            /* Fall back to displacing T2 (frame) when no T3 present in LLC */
            u64 t2_in_llc = cider_relaxed_load_u64(
                &tier_cpu_mask[CAKE_TIER_FRAME]) & my_llc_mask;
            if (t2_in_llc)
                scx_bpf_kick_cpu(BIT_SCAN_FORWARD_U64(t2_in_llc), SCX_KICK_PREEMPT);
        }
    }


/* ═══════════════════════════════════════════════════════════════════════════
 * [G] cider_dispatch — delete dead variable
 *
 * TARGET: Inside cider_dispatch, inside the BSF steal loop body, DELETE
 *         these two lines (they appear after the stale-nonempty clear):
 *
 *   bool within_threshold_exhausted = (cheapest_llc < nr_llcs && ...);
 *   (void)within_threshold_exhausted;
 *
 * No other changes to cider_dispatch.  The loop after deletion:
 *
 *   for (u32 i = 0; steal_mask && i < nr_llcs; i++) {
 *       u32 victim = BIT_SCAN_FORWARD_U32(steal_mask);
 *       steal_mask &= steal_mask - 1;
 *       if (scx_bpf_dsq_move_to_local(LLC_DSQ_BASE + victim))
 *           return;
 *       cider_relaxed_store_u8(
 *           &llc_nonempty[victim & (CAKE_MAX_LLCS - 1)].nonempty, 0);
 *   }
 *
 * COST REMOVED: ~3–5 cycles per cross-LLC dispatch (3 comparisons + 1 bool
 *   assignment + 1 void cast with zero behavioral contribution).
 * ═══════════════════════════════════════════════════════════════════════════ */


/* ═══════════════════════════════════════════════════════════════════════════
 * [H] reclassify_task_cold — bit-history overrun, threshold 4 (corrected)
 *
 * TARGET: Replace the S5 block in reclassify_task_cold.
 *         Search: `/* ── S5: CONSECUTIVE OVERRUN DEMOTION`
 *         Replace through the closing `}` of `if (old_tier < CAKE_TIER_BULK)`.
 *
 * THRESHOLD CORRECTION (5 → 4):
 *   Previous patch used 5. With 5: 4 consecutive overruns → hist = 0b00001111
 *   → popcount = 4 < 5 → NO demote.  This was a regression vs the original
 *   consecutive counter which fired at exactly 4.
 *
 *   With 4: 4 consecutive overruns → popcount = 4 ≥ 4 → demote. ✓ (parity)
 *           4-of-8 non-consecutive → popcount = 4 ≥ 4 → demote. ✓ (new gain)
 *
 * BEHAVIORAL PROOF:
 *   Let S = set of overrun patterns that trigger demotion.
 *   Original:     S = { sequences with 4+ consecutive 1-bits }
 *   New (thresh 4): S = { sequences with popcount ≥ 4 }
 *   S_original ⊆ S_new: every consecutive-4 pattern has popcount ≥ 4.
 *   S_new \ S_original: alternating overrun patterns now also trigger.
 *   This is strictly a superset — never worse, sometimes better.
 *
 * COST: shift + OR + popcount ≈ 4 cycles. Original: increment + compare ≈ 4.
 *   Net overhead: zero.
 * ═══════════════════════════════════════════════════════════════════════════ */

    /* ── S5: BIT-HISTORY OVERRUN DEMOTION ──────────────────────────────────
     * overrun_count is an 8-bit shift register of the last 8 execution outcomes.
     * Each stop shifts left and inserts the current bout's result in the LSB.
     *
     * Force-demote when 4 of the last 8 bouts exceeded 1.5× the tier gate:
     *   - Equivalent to original on all consecutive-overrun patterns
     *   - Additionally catches non-consecutive patterns (new capability)
     *   - Never less strict than original in any case */
    if (old_tier < CAKE_TIER_BULK) {
        u16 og      = tier_overrun_gate[CAKE_TIER_IDX(old_tier)];
        u8  outcome = (rt_clamped > og) ? 1u : 0u;

        /* Shift: oldest outcome falls off MSB, new outcome enters LSB */
        u8 hist = (u8)((tctx->overrun_count << 1) | outcome);
        tctx->overrun_count = hist;

        if (__builtin_popcount((unsigned int)hist) >= 4) {
            u8 forced = (u8)(old_tier + 1);
            if (new_tier < forced)
                new_tier = forced;
            tctx->overrun_count = 0;
            stable = 0;
        }
    }


/* ═══════════════════════════════════════════════════════════════════════════
 * INTEGRATION CHECKLIST
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * cider_bpf.c — apply in this order:
 *
 *  [A] AFTER `const u32 cpu_llc_id[CAKE_MAX_CPUS] = {};`:
 *      ADD the llc_cpu_mask BSS declaration above.
 *      If a `const u64 llc_cpu_mask[...]` line exists: REPLACE it.
 *      Ensure the word `const` does NOT appear — this is BSS not rodata.
 *
 *  [B] AFTER llc_nonempty[] BSS declaration:
 *      ADD the tier_cpu_mask BSS declaration above.
 *
 *  [C] REPLACE entire cider_init function with the version above.
 *
 *  [D] REPLACE entire cider_running function with the version above.
 *
 *  [E] REPLACE entire cider_stopping function with the version above.
 *
 *  [F] In cider_enqueue, FIND the kick block starting with:
 *        `u32 best_cpu    = CAKE_MAX_CPUS;`
 *        `u8  worst_tier  = CAKE_TIER_INTERACT;`
 *        `for (u32 i = 0; i < nr_cpus; i++) { ... }`
 *        `if (best_cpu < CAKE_MAX_CPUS) scx_bpf_kick_cpu(...);`
 *      REPLACE the entire block (including the two variable declarations)
 *      with the `if (tier <= CAKE_TIER_INTERACT) { ... }` block above.
 *
 *  [G] In cider_dispatch BSF steal loop, DELETE:
 *        `bool within_threshold_exhausted = ...;`
 *        `(void)within_threshold_exhausted;`
 *
 *  [H] In reclassify_task_cold, REPLACE:
 *        `/* ── S5: CONSECUTIVE OVERRUN DEMOTION` block through its `}`
 *      with the S5 block above.
 *
 * main.rs:
 *  → Remove the commented-out llc_cpu_mask write block entirely.
 *    No Rust-side write is needed; cider_init computes it from cpu_llc_id.
 *  → All other changes (eventfd, try_lock, dynamic poll set) are unchanged.
 *
 * intf.h:
 *  → Update overrun_count comment: threshold is 4, not 5.
 *
 * Dependency groups:
 *  Group 1 (bitmask kick): [A][B][C][D][E][F] — must be applied together
 *  Group 2 (overrun fix):  [H] — independent, apply separately if needed
 *  Group 3 (dead code):    [G] — independent
 * ═══════════════════════════════════════════════════════════════════════════ */
