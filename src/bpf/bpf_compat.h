/* scx_cake/bpf/bpf_compat.h */
#ifndef __CAKE_BPF_COMPAT_H
#define __CAKE_BPF_COMPAT_H

/* Compiler abstraction: Clang 21+ uses formal atomics for MLP; <21 uses scalpel-optimized ASM */

#if defined(__clang__) && __clang_major__ >= 21

    /* MODERN PATH: Formal Atomics (Max Performance) */
    #define cake_relaxed_load_u32(ptr)      __atomic_load_n(ptr, __ATOMIC_RELAXED)
    #define cake_relaxed_store_u32(ptr, v)  __atomic_store_n(ptr, v, __ATOMIC_RELAXED)
    #define cake_relaxed_load_u64(ptr)      __atomic_load_n(ptr, __ATOMIC_RELAXED)
    #define cake_relaxed_store_u64(ptr, v)  __atomic_store_n(ptr, v, __ATOMIC_RELAXED)

#else

    /* COMPAT PATH: Scalpel-Optimized Inline Assembly */

    static __always_inline u32 cake_relaxed_load_u32(const volatile u32 *ptr) {
        u32 val;
        asm volatile(
            "%0 = *(u32 *)(%1 + 0)"
            : "=r"(val)
            : "r"(ptr), "m"(*ptr)  /* Targeted dependency, no global spill */
        );
        return val;
    }

    static __always_inline void cake_relaxed_store_u32(volatile u32 *ptr, u32 val) {
        asm volatile(
            "*(u32 *)(%1 + 0) = %2"
            : "=m"(*ptr)           /* Only this address modified */
            : "r"(ptr), "r"(val)
        );
    }

    static __always_inline u64 cake_relaxed_load_u64(const volatile u64 *ptr) {
        u64 val;
        asm volatile(
            "%0 = *(u64 *)(%1 + 0)"
            : "=r"(val)
            : "r"(ptr), "m"(*ptr)
        );
        return val;
    }

    static __always_inline void cake_relaxed_store_u64(volatile u64 *ptr, u64 val) {
        asm volatile(
            "*(u64 *)(%1 + 0) = %2"
            : "=m"(*ptr)
            : "r"(ptr), "r"(val)
        );
    }

#endif

/* Bitfield extraction: shift + mask (2 cycles) — BMI2 BEXTR unavailable in BPF ISA */
#define EXTRACT_BITS_U32(val, start, len) \
    (((u32)(val) >> (start)) & ((1U << (len)) - 1))
#define EXTRACT_BITS_U64(val, start, len) \
    (((u64)(val) >> (start)) & ((1ULL << (len)) - 1))

/* BIT SCAN FORWARD (CTZ): Clang <19 fallback uses De Bruijn to avoid opcode 191 crash */
#if defined(__clang__) && __clang_major__ < 19
    static __always_inline u32 cake_ctz64(u64 mask, u64 mult) {
        static const u8 de_bruijn_bits[64] = {
            0,  1,  2, 53,  3,  7, 54, 27, 4, 38, 41,  8, 34, 55, 48, 28,
            62, 5, 39, 46, 44, 42, 22,  9, 24, 35, 59, 56, 49, 18, 29, 11,
            63, 52, 6, 26, 37, 40, 33, 47, 61, 45, 43, 21, 23, 58, 17, 10,
            51, 25, 36, 32, 60, 20, 57, 16, 50, 31, 19, 15, 30, 14, 13, 12
        };

        u64 lsb = mask & -mask;

        /* Obfuscation barrier: prevents Clang 18 from optimizing back to __builtin_ctzll */
        asm volatile("" : "+r"(lsb));

        return de_bruijn_bits[(lsb * mult) >> 58];
    }
    #define BIT_SCAN_FORWARD_U64(mask) cake_ctz64(mask, 0x022FDD63CC95386DULL)
    #define BIT_SCAN_FORWARD_U64_RAW(mask, mult) cake_ctz64(mask, mult)

    /* FIX (#15): U32-specific BSF using De Bruijn sequence for 32-bit masks.
     * Avoids zero-extending u32 into the 64-bit De Bruijn table which uses a
     * 64-bit multiplier — correct by accident but semantically wrong. */
    static __always_inline u32 cake_ctz32(u32 mask) {
        static const u8 de_bruijn32[32] = {
            0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
            31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9
        };
        u32 lsb = mask & (u32)(-(s32)mask);
        asm volatile("" : "+r"(lsb));
        return de_bruijn32[(lsb * 0x077CB531U) >> 27];
    }
    #define BIT_SCAN_FORWARD_U32(mask) cake_ctz32(mask)
#else
    #define BIT_SCAN_FORWARD_U64(mask) __builtin_ctzll(mask)
    #define BIT_SCAN_FORWARD_U64_RAW(mask, mult) __builtin_ctzll(mask)
    /* FIX (#15): Use __builtin_ctz for u32 operands (correct width, avoids implicit widening) */
    #define BIT_SCAN_FORWARD_U32(mask) __builtin_ctz(mask)
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * PREFETCH: Materialize address early to encourage prefetch-like behavior
 * - Forces compiler to compute the address, enabling earlier load scheduling
 * - No "memory" clobber: avoids acting as a compiler barrier that would
 *   flush store buffers and inhibit register caching / ILP / MLP
 * ═══════════════════════════════════════════════════════════════════════════ */
#define CAKE_PREFETCH(addr) \
    asm volatile("" : : "r"(addr))

/* rq access — scx_bpf_cpu_rq() is universally available (~10-15ns).
 *
 * scx_bpf_rq_locked() would be ~3-5ns faster (skips RCU + bounds check) but
 * common.bpf.h declares it as strong __ksym — libbpf fails to load if the
 * kernel doesn't export it. A __weak redeclaration CANNOT override the strong
 * one already seen from common.bpf.h. Until the scx team makes it __weak or
 * all kernels export it, we use cpu_rq. */
static __always_inline struct rq *cake_get_rq(s32 cpu) {
    return scx_bpf_cpu_rq(cpu);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * IRQ CONTEXT KFUNCS
 *
 * bpf_in_hardirq / bpf_in_nmi / bpf_in_serving_softirq are x86/arm64 kfuncs
 * introduced in Linux 6.x. Declared __weak so the scheduler loads cleanly on
 * kernels that do not export them — on those kernels the verifier substitutes
 * a zero return (false), which silently disables IRQ-wake boosting without
 * any code changes required. This mirrors the approach used by LAVD for the
 * same helpers.
 *
 * WITHOUT these declarations Clang 21 (strict -Wimplicit-function-declaration)
 * treats the call sites as undeclared identifiers and hard-errors the build.
 * ═══════════════════════════════════════════════════════════════════════════ */
extern bool bpf_in_hardirq(void) __ksym __weak;
extern bool bpf_in_nmi(void) __ksym __weak;
extern bool bpf_in_serving_softirq(void) __ksym __weak;

#endif /* __CAKE_BPF_COMPAT_H */
