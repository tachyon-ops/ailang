# AIL (`ailang` v0.2 Discovery) — Protobuf-Native Verified Compiler & Autonomous Repair Stack for AI Agents

`ailang` is a 5-component programming language, stratified formal verifier, closed-loop agent repair harness, and LLVM native compiler designed from first principles around **AI agent economics**:
- **High semantic density** (spanned S-expressions & zero-syntax-error binary `ModuleProto` ASTs)
- **Lossless Protocol Buffer IPC** (`uint64` / `int64` varints without IEEE-754 $2^{53}$ precision loss)
- **Millisecond stratified formal verification** (Interval Abstract Interpretation + Bitwuzla `QF_BV(64)` + Z3 `Int`)
- **Zero-cost linear capability security** (`cap.io`, `cap.fs`, `cap.net`)
- **Hardware-native ARM64 / x86-64 codegen** (`nuw`/`nsw`/`noalias` -> Apple Silicon NEON SIMD + ARMv8.1 `casal` atomics + auto-generated C & Python `ctypes` bindings)

---

## Architecture

1. **Layer 1 — Spec Firewall (`spec_firewall.py`)**
   * **`ail audit-spec`**: Non-vacuity (`SAT(pre)`) + Specification Mutation Testing (*SpecMut*) + universal uniqueness (`UNSAT(pre && y1 != y2 && Spec(y1) && Spec(y2))`) across both unsigned `u64` and signed `i64` domains.
   * **`ail diff-specs`**: Differential autoformalization (*Clover*) extracting concrete distinguishing witnesses (`SAT(Spec_A != Spec_B)`) and conservation violations before implementation.
2. **Layer 2 — Dense Linear, Signed & Dependent-Struct Frontend (`parser.py`, `ownership.py`)**
   * Accepts `.ail` S-expressions **or** binary `.ail.pb` `ModuleProto` ASTs.
   * **Signed & Unsigned Refinements**: `u64[lo..hi]` and `i64[lo..hi]` (`MIN_I64`, `MAX_I64`, `MAX`), strict signed/unsigned separation with checked `(to_i64 x)` and `(to_u64 x)` casts.
   * **Dependent Algebraic Structs**: `(struct Quote ((bid u64[0..10^9]) (ask u64[bid..10^9]) (pnl_adj i64[-50000..50000])))`, `(make Quote ...)`, and `(field q ask)` where later fields can depend directly on earlier fields.
   * **Linear Capabilities (0-bit runtime erasure)**: Single-use linear tokens for console (`cap.io`), local log append (`cap.fs`), and `127.0.0.1` loopback UDP telemetry (`cap.net` with Z3-verified unprivileged ports `[1024..65535]`), plus non-aliasing `mut_slice` borrows.
3. **Layer 3 — Stratified Multi-Solver Verifier (`intervals.py`, `bitwuzla_tier.py`, `verifier.py`)**
   * **Tier 0**: Microsecond forward signed/unsigned Interval Abstract Interpretation (`[lo, hi]`).
   * **Tier 1**: Witness-sliced 64-bit `QF_BV` islands solved in **Bitwuzla** (`&`, `|`, `^`, `<<`, `>>`, `~`).
   * **Tier 2**: **Z3** arithmetic verifier proving zero `u64`/`i64` overflow/underflow, zero `MIN_I64 / -1` division traps, exact C/LLVM truncation-toward-zero (`sdiv`/`srem`), dependent struct invariants, $O(1)$ inductive `fold`/`map_inplace` loops, and sharded `atomic_protocol` CAS conservation.
4. **Layer 4 — Native Silicon Backend (`codegen_llvm.py`)**
   * Emits SSA LLVM IR with proven `nuw`, `nsw`, and `ptr noalias` flags, plus zero-overhead `fastcc` SSA struct helpers for intra-AIL calls and portable C-ABI wrappers (`typedef struct` in `.h` and `ctypes.Structure` in `_bindings.py`).
5. **Closed-Loop Protobuf Self-Repair Harness (`agent_loop.py` / `ail repair`)**
   * Multi-turn autonomous repair loop operating over `ail.v1.CompilerResponse`, `ModuleProto`, and `RepairSession` Protocol Buffer messages (deterministic counterexample-guided AST synthesis engine + pluggable Gemini / custom LLM callback).

---

## Quickstart CLI Commands

```bash
# 1. Verify ownership, linear capabilities, dependent structs, and 64-bit Z3 + Bitwuzla proofs
uv run ail check examples/signed_struct_quote.ail

# 2. Audit specifications against vacuity and mutant survival (SpecMut)
uv run ail audit-spec examples/signed_struct_quote.ail

# 3. Run closed-loop autonomous repair on a multi-bug AI draft & compile verified native .dylib
uv run ail repair examples/broken_agent_draft.ail -o build/ --write-fixed build/fixed.ail --write-ast build/fixed.ail.pb

# 4. Build native SIMD shared library (.dylib/.so) + C header + Python ctypes.Structure bindings
uv run ail build --lib --require-tight-specs examples/signed_struct_quote.ail -o build/

# 5. Verify, compile, and run capability-sandboxed standalone executable (`cap.io` + `cap.fs` + `cap.net`)
AIL_FS_OUT=/tmp/ail_sandbox.log uv run ail run examples/capability_sandbox_cli.ail -o build/

# 6. Run the full end-to-end test suite
uv run pytest -v
```
