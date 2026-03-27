// SPDX-License-Identifier: GPL-2.0
/*
 * scx_cider/lock_bpf.c — Futex lock-holder priority boosting
 *
 * Adapted from LAVD (scx_lavd/lock.bpf.c) by Changwoo Min <changwoo@igalia.com>.
 * Ported to CAKE's packed_info flag model; fexit and tracepoint fallback paths
 * preserved from the original.
 *
 * PURPOSE
 * -------
 * When a task holds a futex (userspace mutex), preempting it causes priority
 * inversion: any task waiting on the lock is blocked until the holder is
 * rescheduled and releases it. On gaming workloads this matters greatly:
 *
 *   - Wine/Proton use futexes extensively for D3D command-list submission.
 *   - Game engines hold vertex-buffer locks across full render frames (T2).
 *   - Audio pipelines hold mixing locks that block the T0 audio callback.
 *
 * Two effects are applied while CAKE_FLAG_LOCK_HOLDER is set:
 *
 *   1. cider_tick skips the starvation preemption check (lock_bpf.c sets the
 *      flag; cider_bpf.c reads it).
 *   2. cider_enqueue advances the virtual timestamp so the lock holder sorts
 *      ahead of same-tier peers, unblocking waiters sooner.
 *
 * TRACING STRATEGY
 * ----------------
 * We use the same two-path approach as LAVD:
 *   - Primary:   SEC("?fexit/...") — low-overhead, attached when available.
 *   - Fallback:  SEC("?tracepoint/syscalls/...") — stable ABI, higher cost
 *                (~130 ns vs ~50 ns for fentry/fexit), used as a backup when
 *                the kernel does not export the target function for BPF fexit.
 *
 * Both paths are optional (SEC("?...")); the scheduler loads and runs
 * correctly even if neither attaches — lock holders just won't receive the
 * priority boost, which is the current CAKE behavior.
 *
 * KNOWN LIMITATIONS (inherited from LAVD)
 * ----------------------------------------
 * - User-level mutex implementations (e.g., glibc pthreads) can elide the
 *   futex_wait/futex_wake syscall when there is no contention, so we only
 *   observe *contended* lock acquisitions.
 * - Spurious futex_wait returns (ret != 0) are correctly ignored.
 * - A task that calls futex_wait repeatedly before futex_wake (spurious
 *   wake-up retries) will set the flag multiple times, which is harmless
 *   since the flag is a single bit.
 * - CAKE_FLAG_LOCK_HOLDER is never explicitly cleared on task death because
 *   the task context itself is freed; there is no stale-flag risk.
 * - FUTEX_CMP_REQUEUE_PI transfers lock ownership to a new task without the
 *   new owner ever calling futex_wait or futex_lock_pi.  Neither the fexit
 *   probes nor the tracepoint fallback cover this implicit grant, so the new
 *   owner's CAKE_FLAG_LOCK_HOLDER is not set until its next explicit
 *   futex_wait or futex_lock_pi call.  This is uncommon (primarily glibc
 *   condition variables with priority ceiling, rare in Wine/Proton) and
 *   represents a missed optimisation for a single-frame window, not a
 *   correctness failure.  A future fexit probe on futex_requeue() on the
 *   WAKING side would close this gap.
 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include "intf.h"
#include "bpf_compat.h"

char _lock_license[] SEC("license") = "GPL";

/* Shared task-context map (defined in cider_bpf.c, resolved by libbpf linker) */
extern struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct cider_task_ctx);
} task_ctx;

/* ── Helpers ────────────────────────────────────────────────────────────── */

static __always_inline void set_lock_holder(void)
{
    struct task_struct *p = bpf_get_current_task_btf();
    struct cider_task_ctx *tctx;

    if (!p)
        return;

    tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (tctx)
        /* Atomic OR: safe against concurrent reads in cider_tick/cider_enqueue */
        __sync_fetch_and_or(&tctx->packed_info,
                            (u32)CAKE_FLAG_LOCK_HOLDER << SHIFT_FLAGS);
}

static __always_inline void clear_lock_holder(void)
{
    struct task_struct *p = bpf_get_current_task_btf();
    struct cider_task_ctx *tctx;

    if (!p)
        return;

    tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (tctx) {
        /* FIX (clear-order): Clear the flag BEFORE resetting lock_skip_count.
         * A tick interrupt firing between the two stores observes
         * CAKE_FLAG_LOCK_HOLDER already cleared and never reaches the
         * lock_skip_count increment in cider_tick, so the skip budget is
         * not silently decremented for the next lock acquisition.
         *
         * Previous order (counter reset first, then flag clear) left a ~1 ns
         * window where a tick could see the flag still set, increment the
         * counter back to 1, and then clear_lock_holder() would clear the
         * flag — leaving lock_skip_count = 1 instead of 0.  Over many
         * lock/unlock cycles on a hot audio or D3D submission thread this
         * erodes the 4-skip budget, causing premature preemption of a lock
         * holder. */
        __sync_fetch_and_and(&tctx->packed_info,
                             ~((u32)CAKE_FLAG_LOCK_HOLDER << SHIFT_FLAGS));
        /* Reset the skip counter so the next lock acquisition starts with a
         * fresh cap of 4 consecutive skip allowances.  Plain store is safe:
         * lock_skip_count is only read and written by cider_tick on the CPU
         * currently running this task, and clear_lock_holder fires in a
         * fexit/tracepoint context on the same CPU. */
        tctx->lock_skip_count = 0;
    }
}

/* ── fexit probes (primary path, ~50 ns overhead) ───────────────────────── */
/*
 * NOTE: On kernels that export both the fexit target symbols AND the
 * sys_enter/exit_futex tracepoints (which are universally available), both
 * path families attach simultaneously.  A single futex_wait returning 0 will
 * therefore call set_lock_holder() twice — once via fexit, once via tracepoint.
 * The double atomic-OR is idempotent and correctness is preserved.  The
 * ~130 ns tracepoint overhead is paid unnecessarily on these kernels, but no
 * mutual-exclusion mechanism is implemented because the cost is low relative
 * to the futex syscall itself.  This is an accepted known tradeoff.
 */

/*
 * futex_wait variants — lock *acquired* on return value 0.
 *
 * int __futex_wait(u32 *uaddr, unsigned int flags, u32 val,
 *                  struct hrtimer_sleeper *to, u32 bitset)
 */
struct hrtimer_sleeper;

SEC("?fexit/__futex_wait")
int BPF_PROG(cider_fexit_futex_wait,
             u32 *uaddr, unsigned int flags, u32 val,
             struct hrtimer_sleeper *to, u32 bitset,
             int ret)
{
    if (ret == 0)
        set_lock_holder();
    return 0;
}

/*
 * int futex_wait_requeue_pi(u32 *uaddr, unsigned int flags, u32 val,
 *                           ktime_t *abs_time, u32 bitset, u32 *uaddr2)
 * PI requeue wait — lock acquired on return value 0.
 */
SEC("?fexit/futex_wait_requeue_pi")
int BPF_PROG(cider_fexit_futex_wait_requeue_pi,
             u32 *uaddr, unsigned int flags, u32 val,
             ktime_t *abs_time, u32 bitset, u32 *uaddr2,
             int ret)
{
    if (ret == 0)
        set_lock_holder();
    return 0;
}

/*
 * PI-futex lock — lock *acquired* on return value 0.
 *
 * int futex_lock_pi(u32 *uaddr, unsigned int flags, ktime_t *time, int trylock)
 */
SEC("?fexit/futex_lock_pi")
int BPF_PROG(cider_fexit_futex_lock_pi,
             u32 *uaddr, unsigned int flags,
             ktime_t *time, int trylock,
             int ret)
{
    if (ret == 0)
        set_lock_holder();
    return 0;
}

/*
 * FIX (gap/trylock-pi): futex_trylock_pi was the only PI-futex variant without
 * a fexit probe, creating an asymmetry between the fexit path and the tracepoint
 * fallback (which already handled CAKE_FUTEX_TRYLOCK_PI in cider_tp_exit_futex).
 * On kernels that export futex_trylock_pi as a BPF fexit target, this probe
 * fires at ~50ns overhead instead of the ~130ns tracepoint path.  The SEC("?...")
 * prefix keeps the load safe on kernels that do not export the symbol — the
 * tracepoint fallback remains active as a backup, and the resulting idempotent
 * double-set_lock_holder() is harmless (same semantics as the other probe pairs).
 *
 * int futex_trylock_pi(u32 *uaddr, unsigned int flags, ktime_t *time, int trylock)
 * PI trylock — lock *acquired* on return value 0.
 */
SEC("?fexit/futex_trylock_pi")
int BPF_PROG(cider_fexit_futex_trylock_pi,
             u32 *uaddr, unsigned int flags,
             ktime_t *time, int trylock,
             int ret)
{
    if (ret == 0)
        set_lock_holder();
    return 0;
}

/*
 * futex_wake variants — lock *released*; clear the flag.
 *
 * int futex_wake(u32 *uaddr, unsigned int flags, int nr_wake, u32 bitset)
 */
SEC("?fexit/futex_wake")
int BPF_PROG(cider_fexit_futex_wake,
             u32 *uaddr, unsigned int flags,
             int nr_wake, u32 bitset,
             int ret)
{
    if (ret >= 0)
        clear_lock_holder();
    return 0;
}

/*
 * int futex_wake_op(u32 *uaddr1, unsigned int flags, u32 *uaddr2,
 *                  int nr_wake, int nr_wake2, int op)
 */
SEC("?fexit/futex_wake_op")
int BPF_PROG(cider_fexit_futex_wake_op,
             u32 *uaddr1, unsigned int flags, u32 *uaddr2,
             int nr_wake, int nr_wake2, int op,
             int ret)
{
    if (ret >= 0)
        clear_lock_holder();
    return 0;
}

/*
 * PI-futex unlock — lock released.
 *
 * int futex_unlock_pi(u32 *uaddr, unsigned int flags)
 */
SEC("?fexit/futex_unlock_pi")
int BPF_PROG(cider_fexit_futex_unlock_pi,
             u32 *uaddr, unsigned int flags,
             int ret)
{
    if (ret == 0)
        clear_lock_holder();
    return 0;
}

/* ── tracepoint fallback path (~130 ns overhead) ─────────────────────────
 *
 * When fexit probes fail to attach (kernel does not export the symbol),
 * the tracepoint path provides equivalent coverage via the stable
 * syscalls ABI.
 *
 * FIX (migration): The previous implementation stored the futex op in a
 * per-CPU scratch array (lock_scratch[smp_processor_id()]) at sys_enter
 * and read it back at sys_exit.  Blocking futex_wait variants put the
 * calling task to sleep inside the kernel; Linux may wake it on a
 * different CPU, so the CPU at sys_exit is not guaranteed to be the same
 * CPU at sys_enter.  The mismatch causes cider_tp_exit_futex to read
 * whichever op the *new* CPU's scratch last recorded — potentially a
 * WAKE op — and call clear_lock_holder() for a task that just acquired
 * a lock (ret == 0), discarding the priority boost silently.
 *
 * Fix: record the op in cider_task_ctx.pending_futex_op (per-task storage,
 * carried with the task across migrations) and read it back in the exit
 * handler on whichever CPU the task wakes up on.  The lock_scratch array
 * and its cider_lock_scratch struct are no longer needed and are removed.
 *
 * The CAKE_FUTEX_OP_UNSET (0xFF) guard in the exit handler protects against
 * the narrow window where both tracepoints attach after a sys_enter_futex
 * but before its sys_exit_futex — or when cider_init_task in cider_bpf.c
 * has not yet initialised pending_futex_op (BPF task-storage zero-inits
 * new entries; 0 == CAKE_FUTEX_WAIT, which would be a false set_lock_holder).
 */

/* Futex op constants (from uapi/linux/futex.h) */
#define CAKE_FUTEX_WAIT          0
#define CAKE_FUTEX_WAKE          1
#define CAKE_FUTEX_WAIT_BITSET   9
#define CAKE_FUTEX_WAKE_BITSET   10
#define CAKE_FUTEX_WAIT_REQUEUE_PI 11
#define CAKE_FUTEX_LOCK_PI       6
#define CAKE_FUTEX_LOCK_PI2      13
#define CAKE_FUTEX_TRYLOCK_PI    8
#define CAKE_FUTEX_UNLOCK_PI     7
#define CAKE_FUTEX_WAKE_OP       5
#define CAKE_FUTEX_PRIVATE_FLAG  128
#define CAKE_FUTEX_CLOCK_RT      256
#define CAKE_FUTEX_CMD_MASK      (~(CAKE_FUTEX_PRIVATE_FLAG | CAKE_FUTEX_CLOCK_RT))

struct tp_cider_futex_enter {
    /* trace_entry fields (opaque here) */
    unsigned long long unused[2];
    int __syscall_nr;
    u32 __attribute__((btf_type_tag("user"))) *uaddr;
    int op;
    u32 val;
};

struct tp_cider_futex_exit {
    unsigned long long unused[2];
    int __syscall_nr;
    long ret;
};

SEC("?tracepoint/syscalls/sys_enter_futex")
int cider_tp_enter_futex(struct tp_cider_futex_enter *ctx)
{
    struct task_struct *p = bpf_get_current_task_btf();
    struct cider_task_ctx *tctx;

    if (!p)
        return 0;
    tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (tctx)
        /* Store raw op as u8.  CLOCK_RT (bit 8 = 256) truncates to 0, which is
         * harmless: CAKE_FUTEX_CMD_MASK strips it in the exit handler regardless.
         * All valid cmd values (0–13) fit in a u8. */
        tctx->pending_futex_op = (u8)(ctx->op);
    return 0;
}

SEC("?tracepoint/syscalls/sys_exit_futex")
int cider_tp_exit_futex(struct tp_cider_futex_exit *ctx)
{
    struct task_struct *p = bpf_get_current_task_btf();
    struct cider_task_ctx *tctx;
    int cmd;
    long ret = ctx->ret;

    if (!p)
        return 0;
    tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (!tctx)
        return 0;

    /* Guard: treat uninitialised storage as a no-op.  cider_init_task writes
     * CAKE_FUTEX_OP_UNSET (0xFF) so this fires only in the attach-race window
     * or on kernels without a cider_init_task hook. */
    if (tctx->pending_futex_op == CAKE_FUTEX_OP_UNSET)
        return 0;

    cmd = (int)(tctx->pending_futex_op) & CAKE_FUTEX_CMD_MASK;

    switch (cmd) {
    case CAKE_FUTEX_WAIT:
    case CAKE_FUTEX_WAIT_BITSET:
    case CAKE_FUTEX_WAIT_REQUEUE_PI:
        if (ret == 0)
            set_lock_holder();
        break;

    case CAKE_FUTEX_WAKE:
    case CAKE_FUTEX_WAKE_BITSET:
    case CAKE_FUTEX_WAKE_OP:
        /* FIX (tracepoint/fexit alignment): use ret >= 0 to match the fexit
         * path (cider_fexit_futex_wake uses ret >= 0).  The previous ret > 0
         * left CAKE_FLAG_LOCK_HOLDER set when futex_wake succeeded but woke
         * zero waiters (ret == 0), causing spurious starvation-skip on the
         * next tick even though no lock is held. */
        if (ret >= 0)
            clear_lock_holder();
        break;

    case CAKE_FUTEX_LOCK_PI:
    case CAKE_FUTEX_LOCK_PI2:
    case CAKE_FUTEX_TRYLOCK_PI:
        if (ret == 0)
            set_lock_holder();
        break;

    case CAKE_FUTEX_UNLOCK_PI:
        if (ret == 0)
            clear_lock_holder();
        break;
    }

    return 0;
}

/* Complementary tracepoints for the newer futex_wait / futex_wake syscalls
 * introduced in Linux 6.x as explicit syscall entries. */

SEC("?tracepoint/syscalls/sys_exit_futex_wait")
int cider_tp_exit_futex_wait(struct tp_cider_futex_exit *ctx)
{
    if (ctx->ret == 0)
        set_lock_holder();
    return 0;
}

SEC("?tracepoint/syscalls/sys_exit_futex_wake")
int cider_tp_exit_futex_wake(struct tp_cider_futex_exit *ctx)
{
    /* FIX (tracepoint/fexit alignment): use ret >= 0 to match the fexit
     * path (cider_fexit_futex_wake uses ret >= 0).  The previous ret > 0
     * left CAKE_FLAG_LOCK_HOLDER set when futex_wake succeeded but woke
     * zero waiters (ret == 0), causing spurious starvation-skip on the
     * next tick even though no lock is held. */
    if (ctx->ret >= 0)
        clear_lock_holder();
    return 0;
}
