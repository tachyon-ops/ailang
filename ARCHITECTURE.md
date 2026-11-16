# AIL (`ailang`) v1.1.0 Architecture

## End-to-End Compiler & Verification Pipeline

1. **Parsing & Module/Type Expansion (`parser.py`, `modules.py`)**
   - Tokenizes S-expressions with exact source `Span`s and decodes `.ail.pb` protobuf ASTs (`proto/ail_agent.proto`).
   - Resolves `(import "...")` stdlib and relative modules, flattens constants `(const ...)`, folds constant expressions, and expands `(type AliasName <TypeSpec>)` aliases uniformly across structs, enums, signatures, `fold` accumulators, and `mut_bytes`.

2. **Ownership, Refinement & Type Checking (`ownership.py`)**
   - Tracks linear capabilities (`cap.io`, `cap.fs`, `cap.net`) and enforces strict single-use move semantics (`E_LINEAR_USE_AFTER_MOVE`, `E_LINEAR_UNCONSUMED`).
   - Enforces non-aliasing on `mut_slice` and `mut_bytes` call arguments (`E_ALIASING_VIOLATION`) and permits safe immutable borrow coercion (`mut_bytes` -> `bytes`).
   - Validates nested `struct`/`enum` type declarations (`type_order` topological emission), `make`/`field`/`variant`/`is_variant`/`match` exhaustiveness, aggregate `==`/`!=`, `(mul_div_u64 a b denom)`, `(mul_div_ceil_u64 a b denom)`, little/big-endian byte readers, and bounds/range-checked byte writers.

3. **3-Tier Formal Verification (`intervals.py`, `bitwuzla_tier.py`, `verifier.py`)**
   - **Tier 0 (`intervals.py`)**: Fast sound integer interval abstract interpretation discharging safe `+`, `-`, `*`, `/`, `%`, bitwise, `mul_div_u64`, `mul_div_ceil_u64`, and byte reader/writer bounds in microseconds.
   - **Tier 1 (`bitwuzla_tier.py`)**: Exact `QF_BV(64)` bitvector SMT verification for bitwise shifts and masks.
   - **Tier 2 (`verifier.py`)**: Dependent-refinement Z3 verification across unbounded integer arithmetic + uninterpreted byte-array axioms + guarded nested ADT invariants (`Implies`), plus `O1` inductive loop verification (`fold` and `map_inplace`). Returns concrete counterexamples on failure.

4. **Layer-1 Spec Firewall & Closed-Loop Repair (`spec_firewall.py`, `agent_loop.py`)**
   - **`SpecMut` & `Clover`**: Verifies precondition satisfiability (non-vacuity) and kills 6 canonical adversarial postcondition mutants to prove specification tightness across scalar, struct, and nested-enum-consuming kernels.
   - **Deterministic Repair**: Rewrites common bug classes (e.g. non-literal `(/ (* a b) den)` -> `(mul_div_u64 a b den)`) and iterates verification automatically.

5. **4-Target Code Generation (`multi_target.py`)**
   - **`codegen_llvm.py`**: Native LLVM IR compiled via `clang` into host shared/executable binaries + C ABI header + Python `ctypes` bindings (`_ail_flatten_slots` for nested ADTs, `bytearray`/`memoryview` buffers for `mut_bytes`, LLVM `i128` for `mul_div_*`).
   - **`codegen_wasm.py`**: Zero-dependency hand-encoded W3C WebAssembly 1.0 binary (`i64.store8/16/32`, pure-64-bit `__ail_mul_div_u64` 128-bit helper, inline-slotted nested struct/enum linear-memory marshaling) + ESM `.mjs` wrapper + `.d.ts` definitions.
   - **`codegen_c.py`**: Strictly warning-free (`-std=c11 -Wall -Wextra -Werror`) C11 source + header (topological structs/enums, recursive `_c_zero_init`, `__SIZEOF_INT128__` + pure-`uint64_t` fallback for `wasm32-freestanding` targets).
   - **`codegen_rust.py`**: `#![no_std] #![forbid(unsafe_code)]` Rust crate (Cargo crate + `.rlib`, `&[u8]`/`&mut [u8]` safe slicing with `&mut *buf`/`&*buf` reborrows, `u128` widening math, nested `Copy, Clone, Debug, PartialEq, Eq` structs and enums).

6. **4-Target Differential Fuzzing & Tooling (`diff_fuzz.py`, `cli.py`, `mcp_server.py`, `web_server.py`)**
   - **`diff_fuzz.py`**: Generates dependent boundary + PRNG test vectors per exported `fn` and compares `native` vs `wasm` vs `c` vs `rust` return values and `mut_bytes`/`mut_slice` mutations bit-for-bit.
   - **`web_server.py` & `web/`**: Local HTTP playground + static site bundle exporter (`ail studio --export-static`) running real compiled `.wasm` kernels directly in the browser.
   - **`integrations/dogfood-gateway/`**: End-to-end Rust workspace + WASM artifacts demonstrating verified `"MRNT"` wire framing, token-bucket rate limiting, and 128-bit fee calculation.
