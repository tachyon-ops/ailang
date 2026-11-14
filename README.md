# AIL (`ailang` v0.3) — Protobuf-Native Verified Compiler, Self-Repair & Benchmark Stack for AI Agents

`ailang` is a programming language, stratified formal verifier, autonomous Protobuf self-repair harness, and LLVM native compiler designed from first principles around **AI agent economics**:
- **High semantic density** (spanned S-expressions with optional `(module <name> ...)` wrappers & binary `ModuleProto` ASTs)
- **Lossless Protocol Buffer IPC** (`uint64` / `int64` varints without IEEE-754 $2^{53}$ precision loss)
- **Millisecond stratified formal verification** (Interval Abstract Interpretation + Bitwuzla `QF_BV(64)` + Z3 `Int`)
- **Zero-cost algebraic sum types (`enum`/`match`) & dependent `struct`s** (exhaustive pattern matching compiled to LLVM `switch` + register aggregates)
- **Zero-cost linear capability security** (`cap.io`, `cap.fs`, `cap.net`)
- **Hardware-native ARM64 / x86-64 codegen** (`nuw`/`nsw`/`noalias` -> Apple Silicon NEON SIMD + ARMv8.1 `casal` atomics + auto-generated C `.h` & Python `ctypes` bindings)

---

## Architecture

1. **Layer 1 — Spec Firewall (`spec_firewall.py`)**
   * **`ail audit-spec`**: Non-vacuity (`SAT(pre)`) + Specification Mutation Testing (*SpecMut*) + universal uniqueness (`UNSAT(pre && y1 != y2 && Spec(y1) && Spec(y2))`) across `u64`, `i64`, dependent `struct`, and `enum` domains.
   * **`ail diff-specs`**: Differential autoformalization (*Clover*) extracting concrete distinguishing witnesses (`SAT(Spec_A != Spec_B)`) and conservation violations before implementation.
2. **Layer 2 — Dense Linear, Dependent-Struct & Algebraic `enum` Frontend (`parser.py`, `ownership.py`)**
   * Accepts `.ail` S-expressions (bare top-level declarations or optional `(module <name> ...)`) **or** binary `.ail.pb` `ModuleProto` ASTs.
   * **Signed & Unsigned Refinements**: `u64[lo..hi]` and `i64[lo..hi]` (`MIN_I64`, `MAX_I64`, `MAX`), strict signed/unsigned separation with checked `(to_i64 x)` and `(to_u64 x)` casts.
   * **Dependent Algebraic Structs & Sum Types**: `(struct Quote ...)`, `(enum SettleOutcome (Filled ...) (Partial ...) (Rejected ...) (Cancelled))`, `(variant ...)`, `(is_variant ...)`, and exhaustive `(match ...)` with `E_NON_EXHAUSTIVE_MATCH`, `E_DUPLICATE_MATCH_ARM`, and `E_ENUM_INVARIANT_FAILED` diagnostics.
   * **Linear Capabilities (0-bit runtime erasure)**: Single-use linear tokens for flushed console I/O (`cap.io`), local log append (`cap.fs`), and `127.0.0.1` loopback UDP telemetry (`cap.net` with Z3-verified unprivileged ports `[1024..65535]`), plus non-aliasing `mut_slice` borrows.
3. **Layer 3 — Stratified Multi-Solver Verifier (`intervals.py`, `bitwuzla_tier.py`, `verifier.py`)**
   * **Tier 0**: Microsecond forward Interval Abstract Interpretation (`[lo, hi]`) including `variant` / `is_variant` / `match` propagation.
   * **Tier 1**: Witness-sliced 64-bit `QF_BV` islands solved in **Bitwuzla** (`&`, `|`, `^`, `<<`, `>>`, `~`).
   * **Tier 2**: **Z3** arithmetic verifier proving zero `u64`/`i64` overflow/underflow, zero `MIN_I64 / -1` traps, exact C/LLVM truncation-toward-zero (`sdiv`/`srem`), dependent struct/enum invariants, path-guarded conditional active-variant equality, $O(1)$ inductive `fold`/`map_inplace` loops, and sharded `atomic_protocol` CAS conservation.
4. **Layer 4 — Native Silicon Backend (`codegen_llvm.py`)**
   * Emits SSA LLVM IR with proven `nuw`, `nsw`, `ptr noalias`, and `switch i64` tagged-union dispatch (`insertvalue`/`extractvalue`), `fastcc` intra-AIL aggregate calls, flushed `io.done` (`fflush(NULL)`), and portable C-ABI wrappers (`.h` `typedef enum`/`struct` & `ctypes.Structure` `_bindings.py`).
5. **Autonomous Repair & Benchmark Suite (`agent_loop.py`, `lang_bench.py`, `llm_bench.py`)**
   * **`ail repair`**: Closed-loop Protobuf diagnosis & AST synthesis engine (`RepairSession`).
   * **`ail bench-langs`**: Empirical cross-language comparison (AIL v0.3 vs `rustc -C opt-level=3` vs `clang -O3 -shared` vs Python) for token density (`o200k_base` & `.ail.pb` bytes), compile+verify wall time, Apple Silicon `ns/op`, and 5-bug static firewall checks.
   * **`ail bench-llm`**: Blind Spec-to-Silicon benchmark harness scoring generated code through verification, `SpecMut`, LLVM `.dylib` compilation, and native test execution.

---

## Empirical Benchmarks (Apple Silicon)

### 1. AIL v0.3 vs. Rust / C / Python ([human_vs_ail.md](file:///Users/nunoribeiro/repos/ailang/benchmarks/results/human_vs_ail.md))
- **Compile + Verify Wall Time:** AIL (`check` + `audit-spec` + LLVM `-O3` `.dylib`): **414.03 ms** | Rust (`rustc -C opt-level=3`): **433.92 ms** | C (`clang -O3 -shared`): **123.78 ms**
- **5-Kernel Token Density (`o200k_base`) & Native Latency (`ns/op`):** AIL totaled **466 tokens** vs Rust **498** (winning cleanly on algebraic/dependent kernels `settle_outcome_dispatch`: **90 vs 136** and `quote_net_mid`: **91 vs 117**), matching/outperforming C & Rust native `ns/op` (**0.92–181.58 ns/op** vs Python **121.78–55866.46 ns/op**).
- **Static Bug Firewall (Zero Execution):** AIL caught **5/5** subtle bugs (`E_U64_OVERFLOW`, `E_I64_OVERFLOW`, `E_SPEC_MUTANT_SURVIVED`, `E_STRUCT_INVARIANT_FAILED`, `E_NON_EXHAUSTIVE_MATCH`), whereas `rustc -O3`, `clang -Wall -Wextra -Werror`, and `py_compile` caught **0/5**.

### 2. Blind Subagent Spec-to-Silicon Evaluation ([live_llm_spec_to_silicon.md](file:///Users/nunoribeiro/repos/ailang/benchmarks/results/live_llm_spec_to_silicon.md))
- **Turn-1 Verified Pass Rate:** **6/6** (100.0%) across 6 zero-tool blind `blind_ail_coder` subagents (`clamped_bps_rebate`, `signed_sensor_step`, `dependent_window_span`, `enum_ticket_payout`, `folded_energy_sum`, `sandboxed_beacon`), averaging **123.0 AIL tokens** (`o200k_base`) in **2455.5 ms** total verification+compile+execution time.

---

## Quickstart CLI Commands

```bash
# 1. Verify algebraic sum types, dependent structs, and Z3 + Bitwuzla proofs
uv run ail check examples/sum_type_settlement.ail

# 2. Audit specifications against vacuity and mutant survival (SpecMut)
uv run ail audit-spec examples/sum_type_settlement.ail

# 3. Run closed-loop autonomous repair on a multi-bug AI draft & compile verified native .dylib
uv run ail repair examples/broken_agent_draft.ail -o build/ --write-fixed build/fixed.ail --write-ast build/fixed.ail.pb

# 4. Build native SIMD shared library (.dylib/.so) + C header + Python ctypes bindings
uv run ail build --lib --require-tight-specs examples/sum_type_settlement.ail -o build/

# 5. Run empirical Rust / C / Python vs AIL benchmark
uv run ail bench-langs -o build/bench_langs --markdown-out benchmarks/results/human_vs_ail.md

# 6. Run the full end-to-end test suite (17/17 passing)
uv run pytest -v
```
