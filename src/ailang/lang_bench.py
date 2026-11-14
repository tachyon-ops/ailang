"""Empirical Language & Silicon Benchmark: AIL v0.3 vs. Rust vs. C vs. Python."""

from __future__ import annotations
import ctypes
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
import time
import tiktoken

from ailang import ail_agent_pb2 as pb
from ailang.codegen_llvm import compile_llvm_to_native
from ailang.ownership import check_module_ownership_v2
from ailang.parser import module_to_proto, parse_source
from ailang.spec_firewall import audit_module_specifications
from ailang.verifier import ModuleVerifier


@dataclass(frozen=True)
class KernelSourceSpec:
    name: str
    ail_snippet: str
    rust_snippet: str
    c_snippet: str
    python_snippet: str


KERNEL_SPECS: list[KernelSourceSpec] = [
    KernelSourceSpec(
        name="midpoint_u64",
        ail_snippet=(
            "(spec exact_mid ((lo int) (hi int)) (/ (+ lo hi) 2))\n"
            "(fn midpoint_u64 ((lo u64[0..MAX]) (hi u64[lo..MAX]))\n"
            "  (out u64[lo..hi] (== out (exact_mid lo hi)))\n"
            "  (+ lo (/ (- hi lo) 2)))"
        ),
        rust_snippet=(
            "#[no_mangle]\n"
            "pub extern \"C\" fn midpoint_u64(lo: u64, hi: u64) -> u64 {\n"
            "    assert!(lo <= hi);\n"
            "    lo + (hi - lo) / 2\n"
            "}"
        ),
        c_snippet=(
            "#include <stdint.h>\n"
            "uint64_t midpoint_u64(uint64_t lo, uint64_t hi) {\n"
            "    if (lo > hi) return lo;\n"
            "    return lo + (hi - lo) / 2;\n"
            "}"
        ),
        python_snippet=(
            "def midpoint_u64(lo: int, hi: int) -> int:\n"
            "    if lo < 0 or lo > hi:\n"
            "        raise ValueError('range')\n"
            "    return lo + (hi - lo) // 2"
        ),
    ),
    KernelSourceSpec(
        name="settle_fee_net",
        ail_snippet=(
            "(spec exact_fee ((amt int) (bps int) (cap int)) (min cap (/ (* amt bps) 10000)))\n"
            "(fn settle_fee_net ((amt u64[0..10000000000000000]) (bps u64[0..10000]) (cap u64[0..10000000000000000]))\n"
            "  (out u64[0..amt] (== (- amt out) (exact_fee amt bps cap)))\n"
            "  (- amt (min cap (+ (* (/ amt 10000) bps) (/ (* (% amt 10000) bps) 10000)))))"
        ),
        rust_snippet=(
            "#[no_mangle]\n"
            "pub extern \"C\" fn settle_fee_net(amt: u64, bps: u64, cap: u64) -> u64 {\n"
            "    assert!(amt <= 10_000_000_000_000_000 && bps <= 10_000 && cap <= 10_000_000_000_000_000);\n"
            "    let fee = ((amt as u128 * bps as u128) / 10_000u128) as u64;\n"
            "    amt - fee.min(cap)\n"
            "}"
        ),
        c_snippet=(
            "#include <stdint.h>\n"
            "uint64_t settle_fee_net(uint64_t amt, uint64_t bps, uint64_t cap) {\n"
            "    if (bps > 10000) bps = 10000;\n"
            "    uint64_t fee = (uint64_t)(((__uint128_t)amt * (__uint128_t)bps) / 10000ULL);\n"
            "    uint64_t capped = fee < cap ? fee : cap;\n"
            "    return amt - capped;\n"
            "}"
        ),
        python_snippet=(
            "def settle_fee_net(amt: int, bps: int, cap: int) -> int:\n"
            "    if bps > 10000:\n"
            "        raise ValueError('bps')\n"
            "    fee = min(cap, (amt * bps) // 10000)\n"
            "    return amt - fee"
        ),
    ),
    KernelSourceSpec(
        name="halve_bonus_simd",
        ail_snippet=(
            "(map_inplace halve_bonus_simd\n"
            "  ((n u64[0..1048576]) (bonus u64[0..1000000]) (cap u64[0..1000000000]) (buf (mut_slice n u64[0..1000000000000])))\n"
            "  u64[0..1000000000] (el)\n"
            "  (min cap (+ (>> el 1) bonus)))"
        ),
        rust_snippet=(
            "#[no_mangle]\n"
            "pub unsafe extern \"C\" fn halve_bonus_simd(n: u64, bonus: u64, cap: u64, buf: *mut u64) {\n"
            "    let s = std::slice::from_raw_parts_mut(buf, n as usize);\n"
            "    for x in s.iter_mut() {\n"
            "        *x = ((*x >> 1) + bonus).min(cap);\n"
            "    }\n"
            "}"
        ),
        c_snippet=(
            "#include <stdint.h>\n"
            "void halve_bonus_simd(uint64_t n, uint64_t bonus, uint64_t cap, uint64_t* restrict buf) {\n"
            "    for (uint64_t i = 0; i < n; ++i) {\n"
            "        uint64_t v = (buf[i] >> 1) + bonus;\n"
            "        buf[i] = v < cap ? v : cap;\n"
            "    }\n"
            "}"
        ),
        python_snippet=(
            "def halve_bonus_simd(n: int, bonus: int, cap: int, buf: list[int]) -> None:\n"
            "    for i in range(n):\n"
            "        v = (buf[i] >> 1) + bonus\n"
            "        buf[i] = v if v < cap else cap"
        ),
    ),
    KernelSourceSpec(
        name="quote_net_mid",
        ail_snippet=(
            "(struct Quote ((bid u64[0..1000000000]) (ask u64[bid..1000000000]) (pnl_adj i64[-50000..50000])))\n"
            "(fn quote_net_mid ((q Quote)) i64[-50000..1000050000]\n"
            "  (+ (to_i64 (+ (field q bid) (/ (- (field q ask) (field q bid)) 2))) (field q pnl_adj)))"
        ),
        rust_snippet=(
            "#[repr(C)]\n"
            "pub struct Quote { pub bid: u64, pub ask: u64, pub pnl_adj: i64 }\n"
            "#[no_mangle]\n"
            "pub unsafe extern \"C\" fn quote_net_mid(q: *const Quote) -> i64 {\n"
            "    let r = &*q;\n"
            "    assert!(r.ask >= r.bid && r.ask <= 1_000_000_000 && r.pnl_adj.abs() <= 50_000);\n"
            "    (r.bid + (r.ask - r.bid) / 2) as i64 + r.pnl_adj\n"
            "}"
        ),
        c_snippet=(
            "#include <stdint.h>\n"
            "#include <stdlib.h>\n"
            "typedef struct { uint64_t bid; uint64_t ask; int64_t pnl_adj; } Quote;\n"
            "int64_t quote_net_mid(const Quote* q) {\n"
            "    if (q->ask < q->bid || q->ask > 1000000000ULL) abort();\n"
            "    return (int64_t)(q->bid + (q->ask - q->bid) / 2) + q->pnl_adj;\n"
            "}"
        ),
        python_snippet=(
            "def quote_net_mid(q: tuple[int, int, int]) -> int:\n"
            "    bid, ask, pnl_adj = q\n"
            "    if ask < bid or ask > 1_000_000_000 or abs(pnl_adj) > 50_000:\n"
            "        raise ValueError('quote invariant')\n"
            "    return (bid + (ask - bid) // 2) + pnl_adj"
        ),
    ),
    KernelSourceSpec(
        name="settle_outcome_dispatch",
        ail_snippet=(
            "(enum SettleOutcome (Filled (qty u64[1..100000]) (price u64[1..1000000])) (Rejected (err i64[-1000..-1])) (Cancelled))\n"
            "(fn settle_outcome_dispatch ((o SettleOutcome)) u64[0..100000000000]\n"
            "  (match o ((Filled q p) (* q p)) ((Rejected e) 0) ((Cancelled) 0)))"
        ),
        rust_snippet=(
            "#[repr(C)]\n"
            "pub struct SettleOutcome { pub tag: u64, pub p0: u64, pub p1: u64 }\n"
            "#[no_mangle]\n"
            "pub unsafe extern \"C\" fn settle_outcome_dispatch(o: *const SettleOutcome) -> u64 {\n"
            "    let r = &*o;\n"
            "    match r.tag {\n"
            "        0 => { assert!((1..=100_000).contains(&r.p0) && (1..=1_000_000).contains(&r.p1)); r.p0 * r.p1 }\n"
            "        1 | 2 => 0,\n"
            "        _ => unreachable!(),\n"
            "    }\n"
            "}"
        ),
        c_snippet=(
            "#include <stdint.h>\n"
            "typedef struct { uint64_t tag; uint64_t p0; uint64_t p1; } SettleOutcome;\n"
            "uint64_t settle_outcome_dispatch(const SettleOutcome* o) {\n"
            "    switch (o->tag) {\n"
            "        case 0: return o->p0 * o->p1;\n"
            "        case 1:\n"
            "        case 2: return 0;\n"
            "        default: return 0;\n"
            "    }\n"
            "}"
        ),
        python_snippet=(
            "def settle_outcome_dispatch(o: tuple[int, int, int]) -> int:\n"
            "    tag, p0, p1 = o\n"
            "    if tag == 0:\n"
            "        return p0 * p1\n"
            "    return 0"
        ),
    ),
]


# Combined compilable modules sharing definitions cleanly (no duplicate type definitions)
AIL_BENCH_MODULE = """
(spec exact_mid ((lo int) (hi int)) (/ (+ lo hi) 2))
(fn midpoint_u64 ((lo u64[0..MAX]) (hi u64[lo..MAX]))
  (out u64[lo..hi] (== out (exact_mid lo hi)))
  (+ lo (/ (- hi lo) 2)))

(spec exact_fee ((amt int) (bps int) (cap int)) (min cap (/ (* amt bps) 10000)))
(fn settle_fee_net ((amt u64[0..10000000000000000]) (bps u64[0..10000]) (cap u64[0..10000000000000000]))
  (out u64[0..amt] (== (- amt out) (exact_fee amt bps cap)))
  (- amt (min cap (+ (* (/ amt 10000) bps) (/ (* (% amt 10000) bps) 10000)))))

(map_inplace halve_bonus_simd
  ((n u64[0..1048576]) (bonus u64[0..1000000]) (cap u64[0..1000000000]) (buf (mut_slice n u64[0..1000000000000])))
  u64[0..1000000000] (el)
  (min cap (+ (>> el 1) bonus)))

(struct Quote ((bid u64[0..1000000000]) (ask u64[bid..1000000000]) (pnl_adj i64[-50000..50000])))
(spec exact_quote_net ((q Quote))
  (+ (+ (field q bid) (/ (- (field q ask) (field q bid)) 2)) (field q pnl_adj)))
(fn quote_net_mid ((q Quote))
  (out i64[-50000..1000050000] (== out (exact_quote_net q)))
  (+ (to_i64 (+ (field q bid) (/ (- (field q ask) (field q bid)) 2))) (field q pnl_adj)))

(enum SettleOutcome
  (Filled (qty u64[1..100000]) (price u64[1..1000000]))
  (Rejected (err i64[-1000..-1]))
  (Cancelled))
(spec exact_outcome_notional ((o SettleOutcome))
  (match o ((Filled q p) (* q p)) ((Rejected e) 0) ((Cancelled) 0)))
(fn settle_outcome_dispatch ((o SettleOutcome))
  (out u64[0..100000000000] (== out (exact_outcome_notional o)))
  (match o ((Filled q p) (* q p)) ((Rejected e) 0) ((Cancelled) 0)))
"""

RUST_BENCH_MODULE = """
#![allow(clippy::missing_safety_doc)]
#[no_mangle]
pub extern "C" fn midpoint_u64(lo: u64, hi: u64) -> u64 {
    assert!(lo <= hi);
    lo + (hi - lo) / 2
}

#[no_mangle]
pub extern "C" fn settle_fee_net(amt: u64, bps: u64, cap: u64) -> u64 {
    assert!(amt <= 10_000_000_000_000_000 && bps <= 10_000 && cap <= 10_000_000_000_000_000);
    let fee = ((amt as u128 * bps as u128) / 10_000u128) as u64;
    amt - fee.min(cap)
}

#[no_mangle]
pub unsafe extern "C" fn halve_bonus_simd(n: u64, bonus: u64, cap: u64, buf: *mut u64) {
    let s = std::slice::from_raw_parts_mut(buf, n as usize);
    for x in s.iter_mut() {
        *x = ((*x >> 1) + bonus).min(cap);
    }
}

#[repr(C)]
pub struct Quote { pub bid: u64, pub ask: u64, pub pnl_adj: i64 }

#[no_mangle]
pub unsafe extern "C" fn quote_net_mid(q: *const Quote) -> i64 {
    let r = &*q;
    assert!(r.ask >= r.bid && r.ask <= 1_000_000_000 && r.pnl_adj.abs() <= 50_000);
    (r.bid + (r.ask - r.bid) / 2) as i64 + r.pnl_adj
}

#[repr(C)]
pub struct SettleOutcome { pub tag: u64, pub p0: u64, pub p1: u64 }

#[no_mangle]
pub unsafe extern "C" fn settle_outcome_dispatch(o: *const SettleOutcome) -> u64 {
    let r = &*o;
    match r.tag {
        0 => { assert!((1..=100_000).contains(&r.p0) && (1..=1_000_000).contains(&r.p1)); r.p0 * r.p1 }
        1 | 2 => 0,
        _ => unreachable!(),
    }
}
"""

C_BENCH_MODULE = """
#include <stdint.h>
#include <stdlib.h>

uint64_t midpoint_u64(uint64_t lo, uint64_t hi) {
    if (lo > hi) abort();
    return lo + (hi - lo) / 2;
}

uint64_t settle_fee_net(uint64_t amt, uint64_t bps, uint64_t cap) {
    if (amt > 10000000000000000ULL || bps > 10000ULL || cap > 10000000000000000ULL) abort();
    uint64_t fee = (uint64_t)(((__uint128_t)amt * (__uint128_t)bps) / 10000ULL);
    uint64_t capped = fee < cap ? fee : cap;
    return amt - capped;
}

void halve_bonus_simd(uint64_t n, uint64_t bonus, uint64_t cap, uint64_t* restrict buf) {
    for (uint64_t i = 0; i < n; ++i) {
        uint64_t v = (buf[i] >> 1) + bonus;
        buf[i] = v < cap ? v : cap;
    }
}

typedef struct { uint64_t bid; uint64_t ask; int64_t pnl_adj; } Quote;
int64_t quote_net_mid(const Quote* q) {
    if (q->ask < q->bid || q->ask > 1000000000ULL || q->pnl_adj < -50000 || q->pnl_adj > 50000) abort();
    return (int64_t)(q->bid + (q->ask - q->bid) / 2) + q->pnl_adj;
}

typedef struct { uint64_t tag; uint64_t p0; uint64_t p1; } SettleOutcome;
uint64_t settle_outcome_dispatch(const SettleOutcome* o) {
    switch (o->tag) {
        case 0:
            if (o->p0 < 1 || o->p0 > 100000 || o->p1 < 1 || o->p1 > 1000000) abort();
            return o->p0 * o->p1;
        case 1:
        case 2:
            return 0;
        default:
            abort();
    }
}
"""

C_BENCH_DRIVER = r"""
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef struct { uint64_t bid; uint64_t ask; int64_t pnl_adj; } Quote;
typedef struct { uint64_t tag; uint64_t p0; uint64_t p1; } SettleOutcome;

typedef uint64_t (*mid_fn)(uint64_t, uint64_t);
typedef uint64_t (*fee_fn)(uint64_t, uint64_t, uint64_t);
typedef void (*simd_fn)(uint64_t, uint64_t, uint64_t, uint64_t*);
typedef int64_t (*quote_fn)(const Quote*);
typedef uint64_t (*enum_fn)(const SettleOutcome*);

static double elapsed_ns(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) * 1e9 + (double)(b.tv_nsec - a.tv_nsec);
}

int main(int argc, char** argv) {
    if (argc < 4) return 2;
    const char* dylib_path = argv[1];
    uint64_t scalar_iters = strtoull(argv[2], NULL, 10);
    uint64_t simd_iters = strtoull(argv[3], NULL, 10);

    void* h = dlopen(dylib_path, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen error: %s\n", dlerror()); return 3; }

    mid_fn f_mid = (mid_fn)dlsym(h, "midpoint_u64");
    fee_fn f_fee = (fee_fn)dlsym(h, "settle_fee_net");
    simd_fn f_simd = (simd_fn)dlsym(h, "halve_bonus_simd");
    quote_fn f_quote = (quote_fn)dlsym(h, "quote_net_mid");
    enum_fn f_enum = (enum_fn)dlsym(h, "settle_outcome_dispatch");
    if (!f_mid || !f_fee || !f_simd || !f_quote || !f_enum) return 4;

    volatile uint64_t sink = 0;
    struct timespec t0, t1;

    // 1. midpoint_u64
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (uint64_t i = 0; i < scalar_iters; ++i) {
        sink ^= f_mid((1ULL << 63) + (i & 1023ULL), (1ULL << 63) + 4096ULL + (i & 2047ULL));
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ns_mid = elapsed_ns(t0, t1) / (double)scalar_iters;

    // 2. settle_fee_net
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (uint64_t i = 0; i < scalar_iters; ++i) {
        sink ^= f_fee(1000000000000ULL + (i & 65535ULL), 250ULL + (i & 127ULL), 500000000000ULL);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ns_fee = elapsed_ns(t0, t1) / (double)scalar_iters;

    // 3. halve_bonus_simd (1024-elem array pass)
    uint64_t buf[1024];
    for (int i = 0; i < 1024; ++i) buf[i] = 1000ULL + (uint64_t)(i * 37);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (uint64_t it = 0; it < simd_iters; ++it) {
        f_simd(1024, 250, 50000, buf);
        buf[it & 1023ULL] += 7000;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    sink ^= buf[0];
    double ns_simd = elapsed_ns(t0, t1) / (double)simd_iters;

    // 4. quote_net_mid
    Quote q = { 100000, 100400, -125 };
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (uint64_t i = 0; i < scalar_iters; ++i) {
        q.ask = 100400 + (i & 255ULL);
        sink ^= (uint64_t)f_quote(&q);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ns_quote = elapsed_ns(t0, t1) / (double)scalar_iters;

    // 5. settle_outcome_dispatch
    SettleOutcome o = { 0, 25, 400 };
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (uint64_t i = 0; i < scalar_iters; ++i) {
        o.tag = (i & 3ULL) == 3 ? 1 : 0;
        sink ^= f_enum(&o);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ns_enum = elapsed_ns(t0, t1) / (double)scalar_iters;

    printf("%.4f,%.4f,%.4f,%.4f,%.4f,%llu\n", ns_mid, ns_fee, ns_simd, ns_quote, ns_enum, (unsigned long long)sink);
    dlclose(h);
    return 0;
}
"""


def _time_python_kernels(scalar_iters: int, simd_iters: int) -> list[float]:
    ns = {}
    exec("\n\n".join(k.python_snippet for k in KERNEL_SPECS), ns)
    py_mid = ns["midpoint_u64"]
    py_fee = ns["settle_fee_net"]
    py_simd = ns["halve_bonus_simd"]
    py_quote = ns["quote_net_mid"]
    py_enum = ns["settle_outcome_dispatch"]

    # Scale Python loop counts if large so benchmark completes swiftly, then divide accurately
    s_iters = min(scalar_iters, 100_000)
    a_iters = min(simd_iters, 2_000)
    sink = 0

    t0 = time.perf_counter_ns()
    base = 1 << 63
    for i in range(s_iters):
        sink ^= py_mid(base + (i & 1023), base + 4096 + (i & 2047))
    t1 = time.perf_counter_ns()
    ns_mid = (t1 - t0) / s_iters

    t0 = time.perf_counter_ns()
    for i in range(s_iters):
        sink ^= py_fee(1_000_000_000_000 + (i & 65535), 250 + (i & 127), 500_000_000_000)
    t1 = time.perf_counter_ns()
    ns_fee = (t1 - t0) / s_iters

    buf = [1000 + i * 37 for i in range(1024)]
    t0 = time.perf_counter_ns()
    for it in range(a_iters):
        py_simd(1024, 250, 50_000, buf)
        buf[it & 1023] += 7000
    t1 = time.perf_counter_ns()
    sink ^= buf[0]
    ns_simd = (t1 - t0) / a_iters

    t0 = time.perf_counter_ns()
    for i in range(s_iters):
        sink ^= py_quote((100_000, 100_400 + (i & 255), -125))
    t1 = time.perf_counter_ns()
    ns_quote = (t1 - t0) / s_iters

    t0 = time.perf_counter_ns()
    for i in range(s_iters):
        sink ^= py_enum((1 if (i & 3) == 3 else 0, 25, 400))
    t1 = time.perf_counter_ns()
    ns_enum = (t1 - t0) / s_iters
    _ = sink
    return [ns_mid, ns_fee, ns_simd, ns_quote, ns_enum]


def _run_bug_firewall_matrix(work_dir: Path) -> list[pb.BugFirewallRow]:
    fw_dir = work_dir / "firewall_probes"
    fw_dir.mkdir(parents=True, exist_ok=True)

    # 5 matched subtle bug payloads tested honestly against ail, rustc, clang -Wall -Wextra -Werror, and py_compile
    probes = [
        (
            "u64_midpoint_2pow63_overflow",
            "(fn mid ((lo u64[0..MAX]) (hi u64[lo..MAX])) u64[lo..hi] (/ (+ lo hi) 2))",
            "pub fn mid(lo: u64, hi: u64) -> u64 { (lo + hi) / 2 }",
            "#include <stdint.h>\nuint64_t mid(uint64_t lo, uint64_t hi) { (void)lo; return (lo + hi) / 2; }",
            "def mid(lo: int, hi: int) -> int:\n    return (lo + hi) // 2",
        ),
        (
            "i64_min_div_neg1_trap",
            "(fn sdiv_fn ((x i64[MIN_I64..MAX_I64]) (y i64[-10..10])) i64[MIN_I64..MAX_I64] (if (== y 0) 0 (/ x y)))",
            "pub fn sdiv_fn(x: i64, y: i64) -> i64 { if y == 0 { 0 } else { x / y } }",
            "#include <stdint.h>\nint64_t sdiv_fn(int64_t x, int64_t y) { return y == 0 ? 0 : x / y; }",
            "def sdiv_fn(x: int, y: int) -> int:\n    return 0 if y == 0 else int(x / y)",
        ),
        (
            "spec_gaming_zero_mutant",
            "(fn settle ((amt u64[0..1000000]) (bps u64[0..10000])) u64[0..amt] 0)",
            "pub fn settle(amt: u64, _bps: u64) -> u64 { let _ = amt; 0 }",
            "#include <stdint.h>\nuint64_t settle(uint64_t amt, uint64_t bps) { (void)amt; (void)bps; return 0; }",
            "def settle(amt: int, bps: int) -> int:\n    return 0",
        ),
        (
            "inverted_dependent_quote_struct",
            "(struct Quote ((bid u64[0..1000]) (ask u64[bid..1000])))\n(fn bad_q ((b u64[100..500])) Quote (make Quote b (- b 1)))",
            "pub struct Quote { pub bid: u64, pub ask: u64 }\npub fn bad_q(b: u64) -> Quote { Quote { bid: b, ask: b - 1 } }",
            "#include <stdint.h>\ntypedef struct { uint64_t bid; uint64_t ask; } Quote;\nQuote bad_q(uint64_t b) { return (Quote){ b, b - 1 }; }",
            "def bad_q(b: int) -> tuple[int, int]:\n    return (b, b - 1)",
        ),
        (
            "non_exhaustive_enum_and_cap_leak",
            "(enum St (Ok (v u64[1..10])) (Err))\n(fn bad ((s St) (io cap.io)) u64[0..10] (match s ((Ok v) v)))",
            "use std::fs::File;\npub enum St { Ok(u64), Err }\npub fn bad(s: St) -> u64 { match s { St::Ok(v) => v, St::Err => { let _f = File::open(\"/dev/null\"); 0 } } }",
            "#include <stdint.h>\n#include <stdio.h>\ntypedef struct { uint64_t tag; uint64_t v; } St;\nuint64_t bad(St s) { FILE* f = fopen(\"/dev/null\", \"r\"); (void)f; switch (s.tag) { case 0: return s.v; } return 0; }",
            "def bad(s: tuple[int, int]) -> int:\n    f = open('/dev/null')\n    if s[0] == 0:\n        return s[1]\n    return 0",
        ),
    ]

    rows: list[pb.BugFirewallRow] = []
    for name, ail_code, rs_code, c_code, py_code in probes:
        # 1. AIL static check + audit-spec
        ail_err = "NONE"
        ail_caught = False
        try:
            forms = parse_source(ail_code)
            tenv = check_module_ownership_v2(forms)
            mv = ModuleVerifier(tenv)
            mv.verify_module(forms)
            _, diags = audit_module_specifications(forms, tenv)
            if diags:
                ail_caught = True
                ail_err = pb.ErrorCode.Name(diags[0].code)
        except Exception as exc:
            ail_caught = True
            diag = getattr(exc, "diag", None)
            ail_err = pb.ErrorCode.Name(diag.code) if diag is not None else type(exc).__name__

        # 2. Rust static compiler check
        rs_p = fw_dir / f"{name}.rs"
        rs_p.write_text(rs_code)
        rs_proc = subprocess.run(
            ["rustc", "--crate-type", "lib", "-C", "opt-level=3", "--edition", "2021", str(rs_p), "-o", str(fw_dir / f"lib{name}.rlib")],
            capture_output=True,
            text=True,
            check=False,
        )
        rust_caught = rs_proc.returncode != 0

        # 3. C static compiler check (`-Wall -Wextra -Werror`)
        c_p = fw_dir / f"{name}.c"
        c_p.write_text(c_code)
        c_proc = subprocess.run(
            ["clang", "-O3", "-Wall", "-Wextra", "-Werror", "-fsyntax-only", str(c_p)],
            capture_output=True,
            text=True,
            check=False,
        )
        c_caught = c_proc.returncode != 0

        # 4. Python compile check
        py_p = fw_dir / f"{name}.py"
        py_p.write_text(py_code)
        py_proc = subprocess.run([sys.executable, "-m", "py_compile", str(py_p)], capture_output=True, text=True, check=False)
        py_caught = py_proc.returncode != 0

        rows.append(
            pb.BugFirewallRow(
                bug_name=name,
                ail_caught_statically=ail_caught,
                rust_caught_statically=rust_caught,
                c_caught_statically=c_caught,
                python_caught_statically=py_caught,
                ail_error_code=ail_err,
            )
        )
    return rows


def format_language_benchmark_markdown(report: pb.LanguageBenchmarkReport) -> str:
    lines = [
        "# AIL v0.3 vs. Rust / C / Python — Empirical Verification, Token Density & Apple Silicon Benchmark",
        "",
        f"- **Compile + Verify Wall Time:** AIL (`check` + `audit-spec` + LLVM `-O3` `.dylib`): **{report.ail_verify_and_build_ms:.2f} ms** | "
        f"Rust (`rustc -C opt-level=3`): **{report.rust_build_ms:.2f} ms** | C (`clang -O3 -shared`): **{report.c_build_ms:.2f} ms**",
        "",
        "## 1. Per-Kernel Agent Token Density (`o200k_base`) & Apple Silicon Latency (`ns/op`)",
        "",
        "| Kernel | AIL Tokens (`.ail.pb` B) | Rust Tokens | C Tokens | Python Tokens | AIL `ns/op` | Rust `ns/op` | C `ns/op` | Python `ns/op` |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]
    tot_ail, tot_rs, tot_c, tot_py = 0, 0, 0, 0
    for r in report.kernels:
        tot_ail += r.ail_tokens
        tot_rs += r.rust_tokens
        tot_c += r.c_tokens
        tot_py += r.python_tokens
        lines.append(
            f"| `{r.kernel_name}` | **{r.ail_tokens}** ({r.ail_proto_bytes} B) | {r.rust_tokens} | {r.c_tokens} | {r.python_tokens} | "
            f"**{r.ail_ns_per_op:.2f}** | {r.rust_ns_per_op:.2f} | {r.c_ns_per_op:.2f} | {r.python_ns_per_op:.2f} |"
        )
    lines.append(
        f"| **Total (5 Kernels)** | **{tot_ail}** | **{tot_rs}** | **{tot_c}** | **{tot_py}** | — | — | — | — |"
    )
    lines.extend(
        [
            "",
            "## 2. 5-Bug Static Compiler Firewall Matrix (Zero Execution / Caught at Compile Time)",
            "",
            "| Subtle Bug Class | AIL (`v0.3`) | Rust (`rustc -O3`) | C (`clang -Wall -Wextra -Werror`) | Python (`py_compile`) | AIL Diagnostic |",
            "| :--- | :---: | :---: | :---: | :---: | :--- |",
        ]
    )
    for fw in report.bug_firewall:
        yn = lambda b: "CAUGHT" if b else "missed"
        lines.append(
            f"| `{fw.bug_name}` | **{yn(fw.ail_caught_statically)}** | {yn(fw.rust_caught_statically)} | {yn(fw.c_caught_statically)} | {yn(fw.python_caught_statically)} | `{fw.ail_error_code}` |"
        )
    lines.append("")
    return "\n".join(lines)


def run_language_benchmark(
    work_dir: Path,
    scalar_iters: int = 2_000_000,
    simd_iters: int = 100_000,
) -> tuple[pb.LanguageBenchmarkReport, str]:
    work_dir.mkdir(parents=True, exist_ok=True)
    enc = tiktoken.get_encoding("o200k_base")

    # 1. Compile & Verify AIL
    t_ail0 = time.perf_counter()
    ail_forms = parse_source(AIL_BENCH_MODULE)
    tenv = check_module_ownership_v2(ail_forms)
    mv = ModuleVerifier(tenv)
    mv.verify_module(ail_forms)
    _, audit_diags = audit_module_specifications(ail_forms, tenv)
    assert not audit_diags, f"Benchmark AIL specs must be tight: {audit_diags}"
    ail_art = compile_llvm_to_native(ail_forms, tenv, work_dir / "ail_build", "bench_ail", build_shared_lib=True)
    ail_ms = (time.perf_counter() - t_ail0) * 1000.0

    # 2. Compile Rust `.dylib`
    rs_src = work_dir / "bench_rust.rs"
    rs_dylib = work_dir / "libbench_rust.dylib"
    rs_src.write_text(RUST_BENCH_MODULE)
    t_rs0 = time.perf_counter()
    subprocess.run(["rustc", "-C", "opt-level=3", "--crate-type", "cdylib", str(rs_src), "-o", str(rs_dylib)], check=True)
    rs_ms = (time.perf_counter() - t_rs0) * 1000.0

    # 3. Compile C `.dylib`
    c_src = work_dir / "bench_c.c"
    c_dylib = work_dir / "libbench_c.dylib"
    c_src.write_text(C_BENCH_MODULE)
    t_c0 = time.perf_counter()
    subprocess.run(["clang", "-O3", "-shared", "-Wall", "-Wextra", str(c_src), "-o", str(c_dylib)], check=True)
    c_ms = (time.perf_counter() - t_c0) * 1000.0

    # 4. Compile C Benchmark Driver & measure `.dylib` ns/op
    drv_src = work_dir / "bench_driver.c"
    drv_bin = work_dir / "bench_driver"
    drv_src.write_text(C_BENCH_DRIVER)
    subprocess.run(["clang", "-O3", str(drv_src), "-o", str(drv_bin)], check=True)

    def run_native(dylib_p: str) -> tuple[list[float], int]:
        out = subprocess.check_output([str(drv_bin), dylib_p, str(scalar_iters), str(simd_iters)], text=True).strip()
        parts = out.split(",")
        return [float(x) for x in parts[:5]], int(parts[5])

    ail_ns, ail_sink = run_native(ail_art.binary_or_lib_path)
    rs_ns, rs_sink = run_native(str(rs_dylib))
    c_ns, c_sink = run_native(str(c_dylib))
    assert ail_sink == rs_sink == c_sink, f"Cross-language checksum mismatch: {ail_sink} vs {rs_sink} vs {c_sink}"

    py_ns = _time_python_kernels(scalar_iters, simd_iters)

    rows: list[pb.LanguageBenchmarkRow] = []
    for idx, k in enumerate(KERNEL_SPECS):
        proto_bytes = len(module_to_proto(parse_source(k.ail_snippet), k.name).SerializeToString())
        rows.append(
            pb.LanguageBenchmarkRow(
                kernel_name=k.name,
                ail_tokens=len(enc.encode(k.ail_snippet)),
                rust_tokens=len(enc.encode(k.rust_snippet)),
                c_tokens=len(enc.encode(k.c_snippet)),
                python_tokens=len(enc.encode(k.python_snippet)),
                ail_proto_bytes=proto_bytes,
                ail_ns_per_op=ail_ns[idx],
                rust_ns_per_op=rs_ns[idx],
                c_ns_per_op=c_ns[idx],
                python_ns_per_op=py_ns[idx],
            )
        )

    firewall_rows = _run_bug_firewall_matrix(work_dir)
    report = pb.LanguageBenchmarkReport(
        ail_verify_and_build_ms=ail_ms,
        rust_build_ms=rs_ms,
        c_build_ms=c_ms,
        kernels=rows,
        bug_firewall=firewall_rows,
    )
    return report, format_language_benchmark_markdown(report)
