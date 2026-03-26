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
    if (tctx)
        /* Atomic AND: safe against concurrent reads in cider_tick/cider_enqueue */
        __sync_fetch_and_and(&tctx->packed_info,
                             ~((u32)CAKE_FLAG_LOCK_HOLDER << SHIFT_FLAGS));
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
 * syscalls ABI. A per-CPU scratch cell holds the futex op observed at
 * sys_enter so that sys_exit can branch correctly.
 *
 * Note: like LAVD, we do not distinguish futex user addresses to keep
 * tracing overhead minimal. The resulting approximation is identical to
 * the fexit path for contended locks.
 */

/* Per-CPU scratch for the futex op seen at sys_enter */
struct cider_lock_scratch {
    int futex_op;
    u8  _pad[60]; /* cache-line isolated */
} __attribute__((aligned(64)));

struct cider_lock_scratch lock_scratch[CAKE_MAX_CPUS] SEC(".bss")
    __attribute__((aligned(64)));

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
#define CAKE_FUTEX_OP_INVALID    (-1)

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
    u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    lock_scratch[cpu].futex_op = ctx->op;
    return 0;
}

SEC("?tracepoint/syscalls/sys_exit_futex")
int cider_tp_exit_futex(struct tp_cider_futex_exit *ctx)
{
    u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    int cmd = lock_scratch[cpu].futex_op & CAKE_FUTEX_CMD_MASK;
    long ret = ctx->ret;

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
