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
- **Zero-CVE binary parsers:** packet headers and frame decoders using `(bytes len)`
  with `byte_at`, `read_u16_be`, `read_u32_be`, `read_u64_be`, and `bytes_eq4`.
- **Algebraic state machines & structs:** dependent `(struct ...)` invariants and
  exhaustive `(enum ...)` + `(match ...)` settlement logic.
- **Multi-target portable kernels:** compile one verified `.ail` source to native
  ARM64/x86-64 LLVM (`.dylib`/binary), WebAssembly 1.0 (`.wasm` + `.mjs` + `.d.ts`),
  strict ISO C11 (`.c`/`.h`), and `#![no_std] #![forbid(unsafe_code)]` Rust (`.rlib`).

## Step-by-Step Workflow

1. **Discover Standard Library Primitives (`ail_stdlib_catalog`)**
   Call `ail_stdlib_catalog` first to check reusable verified modules (`stdlib/math`,
   `stdlib/finance`, `stdlib/bits`, `stdlib/parse`) that can be imported via
   `(import "stdlib/math")` or used as structural references.

2. **Author the AIL Module**
   - Declare unbounded mathematical `(spec ...)` reference functions for every pure
     scalar/struct/enum kernel.
   - Constrain every parameter with tight `u64[lo..hi]` or `i64[lo..hi]` refinements
     (or `(bytes len_var)` where `len_var` is an earlier `u64` parameter).
   - Bind a named return value with an exact relational postcondition:
     `(out u64[lo..hi] (== out (exact_spec ...)))` so `SpecMut` kills all mutants.
   - To prevent `u64` intermediate multiplication overflow in `(a * b) / c`, decompose:
     `(+ (* (/ a c) b) (/ (* (% a c) b) c))`.
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
   `E_LINEAR_USE_AFTER_MOVE`, `E_LINEAR_UNCONSUMED`), run `ail_repair_code` or
   apply the `repair_hint` directly, then re-verify.

6. **Compile to Target(s) (`ail_compile_target`)**
   Once both proof and spec audit pass, call `ail_compile_target` with
   `target: "native" | "wasm" | "c" | "rust" | "all"` and `require_tight_specs: true`
   to generate verified artifacts and bindings.
