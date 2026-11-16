---
name: ailang
description: >-
  Synthesize, formally prove (Z3 + Bitwuzla), SpecMut-audit, repair, and compile
  high-assurance AIL kernels to native LLVM, WebAssembly, ISO C11, and #![no_std]
  Rust via the ailang-mcp server. Use when implementing overflow-safe financial
  math, bounds-checked binary wire parsers, or verified state machines.
---

# AIL Verified Kernel Synthesis Workflow

Use the `ailang-mcp` MCP tools whenever correctness, arithmetic safety, or bounds
safety matters more than hand-writing unverified C, Rust, or WebAssembly.

## When to Use AIL

- **Overflow-prone arithmetic & DeFi/financial kernels:** fee waterfalls, basis-points
  (`bps`) math, clamping, fixed-point division, signed/unsigned transitions.
- **Zero-CVE bidirectional binary codecs:** packet headers and frame decoders/encoders
  using `(bytes len)` and `(mut_bytes len)` (enforced non-aliasing) with `byte_at`,
  `bytes_eq4`, `read_u{16,32,64}_{be,le}`, and `write_{byte,u16_*,u32_*,u64_*}`.
- **128-bit widening arithmetic:** `(mul_div_u64 a b denom)` and
  `(mul_div_ceil_u64 a b denom)` for exact full-`u64` scaling without intermediate overflow.
- **Algebraic state machines, type aliases & nested ADTs:** `(type Alias <TypeSpec>)`,
  nested `(struct ...)` and `(enum ...)` fields, aggregate `==`/`!=`, dependent invariants,
  and exhaustive `(match ...)` settlement logic.
- **Multi-target portable kernels:** compile one verified `.ail` source to native
  ARM64/x86-64 LLVM (`.dylib`/binary), WebAssembly 1.0 (`.wasm` + `.mjs` + `.d.ts`),
  strict ISO C11 (`.c`/`.h`), and `#![no_std] #![forbid(unsafe_code)]` Rust (`.rlib`).

## Step-by-Step Workflow

1. **Discover Standard Library Primitives (`ail_stdlib_catalog`)**
   Call `ail_stdlib_catalog` first to check reusable verified modules (`stdlib/math`,
   `stdlib/finance`, `stdlib/bits`, `stdlib/parse`, `stdlib/wire`) that can be imported
   via `(import "stdlib/wire")` or used as structural references.

2. **Author the AIL Module**
   - Declare unbounded mathematical `(spec ...)` reference functions for every pure
     scalar/struct/enum kernel.
   - Constrain every parameter with `(type ...)` aliases, tight `u64[lo..hi]` or
     `i64[lo..hi]` refinements, `(bytes len_var)`, or `(mut_bytes len_var)`.
   - Bind a named return value with an exact relational postcondition:
     `(out u64[lo..hi] (== out (exact_spec ...)))` so `SpecMut` kills all mutants.
   - To prevent `u64` intermediate multiplication overflow in `(a * b) / c`, use
     `(mul_div_u64 a b c)` or `(mul_div_ceil_u64 a b c)`.
   - For signed `i64` `/` and `%` in specs, use `trunc_div` and `trunc_rem` to match
     C/LLVM/WASM truncation-toward-zero semantics.

3. **Verify & Prove (`ail_check_and_prove`)**
   Run `ail_check_and_prove` with `source` (or `path`). Confirm `verified: true`
   and inspect `proof_stats` (`tier0_interval_discharged`, `tier1_bitwuzla_queries`,
   `tier2_z3_queries`, `o1_loop_steps`) or any counterexamples and `repair_hint`s.

4. **Audit Specification Tightness (`ail_audit_spec`)**
   Run `ail_audit_spec` to verify non-vacuity and 100% mutant kill rate (`SpecMut`).
   When formalizing an ambiguous requirement, pass `spec_b_source` (or `spec_b_path`)
   to extract concrete `Clover` distinguishing witnesses before implementation.

5. **Autonomous Repair (`ail_repair_code`)**
   If verification or `SpecMut` flags a counterexample (`E_U64_OVERFLOW`,
   `E_U64_UNDERFLOW`, `E_SPEC_MUTANT_SURVIVED`, `E_NON_EXHAUSTIVE_MATCH`,
   `E_LINEAR_USE_AFTER_MOVE`, `E_LINEAR_UNCONSUMED`, `E_ALIASING_VIOLATION`),
   run `ail_repair_code` or apply the `repair_hint` directly, then re-verify.

6. **Compile & Differential-Fuzz (`ail_compile_target`, `ail_fuzz_targets`)**
   Once both proof and spec audit pass, call `ail_compile_target` with
   `target: "native" | "wasm" | "c" | "rust" | "all"` and `require_tight_specs: true`,
   and optionally run `ail_fuzz_targets` to assert 0 bit-level mismatches across all
   4 compiled targets.
