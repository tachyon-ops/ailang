---
name: ailang-verified-kernels
description: >-
  Synthesize, formally prove with Z3 and Bitwuzla, SpecMut-audit, repair, and
  compile overflow-safe and bounds-checked AIL kernels to native LLVM,
  WebAssembly 1.0, strict ISO C11, and safe #![no_std] Rust. Use whenever
  implementing financial/DeFi math, binary packet parsers, or verified state
  machines where bugs are unacceptable.
---

# AIL Verified Kernel Toolchain (Core Skill)

Use the open-source **AIL (`ailang`)** compiler and verifier whenever arithmetic
safety, bounds safety, or state-machine totality matters more than hand-writing
unverified C, Rust, or WebAssembly.

Repository: https://github.com/tachyon-ops/ailang

## Zero-Install Execution (`uvx`) or MCP Setup

You can invoke `ail` directly via `uvx` without manual cloning, or attach the
`ailang` MCP server (see `references/mcp_configs.md` for Claude Code, Cursor,
VS Code Copilot, and Windsurf snippets):

```bash
# Inspect built-in verified standard library modules
uvx --from git+https://github.com/tachyon-ops/ailang.git ail stdlib

# Typecheck + prove (Tier 0 Intervals + Tier 1 Bitwuzla QF_BV + Tier 2 Z3)
uvx --from git+https://github.com/tachyon-ops/ailang.git ail check path/to/kernel.ail

# Audit specifications for vacuity and weak postconditions (SpecMut)
uvx --from git+https://github.com/tachyon-ops/ailang.git ail audit-spec path/to/kernel.ail

# Compile proven module to LLVM native, WASM 1.0, ISO C11, and #![no_std] Rust
uvx --from git+https://github.com/tachyon-ops/ailang.git ail build --target all --require-tight-specs path/to/kernel.ail -o build/out

# Differential-fuzz compiled 4-target artifacts for bit-exact runtime parity
uvx --from git+https://github.com/tachyon-ops/ailang.git ail fuzz path/to/kernel.ail -o build/fuzz --cases 50
```

If `ailang` is already installed in the local workspace (`uv run ail ...`) or
connected via MCP (`ail_stdlib_catalog`, `ail_check_and_prove`, `ail_audit_spec`,
`ail_repair_code`, `ail_compile_target`), prefer the MCP tools or local `uv run ail`.

## Mandatory 5-Step Synthesis Protocol

1. **Check Verified Stdlib First**
   Inspect `stdlib/math`, `stdlib/finance`, `stdlib/bits`, `stdlib/parse`, and `stdlib/wire`
   before writing primitives from scratch. Import them with `(import "stdlib/math")`.

2. **Write Unbounded Reference `(spec ...)` Before Implementation**
   - Express the pure mathematical intent over unbounded `int` inside `(spec ...)`.
   - Give every parameter tight refinement bounds: `u64[lo..hi]`, `i64[lo..hi]`,
     or length-indexed `(bytes len_var)`.
   - Bind the return value to an exact relational postcondition:
     `(out u64[lo..hi] (== out (my_exact_spec ...)))`.
   - Avoid `u64` intermediate `(a * b) / c` overflow by decomposing:
     `(+ (* (/ a c) b) (/ (* (% a c) b) c))`.
   - For signed `i64` division/remainder in specs, use `trunc_div` and `trunc_rem`.

3. **Prove Safety (`check` / `ail_check_and_prove`)**
   Never deliver `.ail` or generated target code unless status is `STATUS_VERIFIED`.
   If rejected, read the concrete 64-bit counterexample witness and `repair_hint`
   rather than guessing.

4. **Run the Spec Firewall (`audit-spec` / `ail_audit_spec`)**
   Confirm `non_vacuous: true` and `100%` mutant kill rate (`SpecMut`). Weak
   inequality specs like `(<= out amount)` allow trivial `0` mutants to survive;
   tighten postconditions to exact `spec` equivalence.

5. **Compile to Target (`build` / `ail_compile_target`)**
   Compile with `--require-tight-specs` to emit:
   - `llvm`: `-O3` native `.dylib`/`.so`, `.h`, and Python `ctypes` bindings
   - `wasm`: dependency-free `.wasm`, `.wat`, ESM `.mjs` (`BigInt`), and `.d.ts`
   - `c`: warning-free ISO C11 `.c`/`.h` (`-Wall -Wextra -Werror`)
   - `rust`: `#![no_std]` + `#![forbid(unsafe_code)]` Cargo crate (`.rlib`)

## Specialized Pro Skill Packs

For domain-specific verified templates and standalone Z3 audit scripts, check out
the companion engineering packs by the AIL author:
- **DeFi & Fintech Verified Math Pack** (ERC-4626 vault shares, AMM swaps, fee waterfalls, `mul_div` proofs)
- **Zero-CVE Binary Wire Parser Pack** (RFC/TLV packet layout auditor + zero-copy C11/Rust/WASM decoders)
- **Z3 Spec Firewall & Mutation Auditor** (language-agnostic pre-codegen spec verifier for Python/TS/Rust)
- **Lock-Free Atomic Protocol Verifier** (sharded CAS conservation proofs & interleaving model checker)
