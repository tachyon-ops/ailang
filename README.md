# AIL (`ailang`) v1.1.0 — Formally Verified Multi-Target Kernel Language

**AIL** is an AI-native systems programming language, 3-tier formal verifier (Intervals + Bitwuzla `QF_BV(64)` + Z3), specification tightness auditor (`SpecMut` & `Clover`), deterministic repair engine, and multi-target ahead-of-time compiler targeting **Native LLVM**, **WebAssembly 1.0**, **strict ISO C11**, and **`#![no_std] #![forbid(unsafe_code)]` Rust**.

## What's New in v1.1.0

- **128-bit Widening Intermediate Math**: Built-in `(mul_div_u64 a b denom)` (floor) and `(mul_div_ceil_u64 a b denom)` (ceil) compute exact \(\lfloor ab / d \rfloor\) and \(\lceil ab / d \rceil\) without 64-bit intermediate multiplication overflow, compiled to LLVM `i128`, portable pure-64-bit WASM, `__SIZEOF_INT128__` + pure-64-bit C11 fallback (`wasm32-freestanding` safe), and `#![no_std]` Rust `u128`.
- **Bidirectional Zero-Copy Wire Codecs**: Little-endian readers (`read_u16_le`, `read_u32_le`, `read_u64_le`), mutable length-indexed byte slices `(mut_bytes len_var)` with non-aliasing enforcement (`E_ALIASING_VIOLATION`) and `mut_bytes -> bytes` borrow coercion, and bounds/value-checked writers (`write_byte`, `write_u{16,32,64}_{be,le}`), plus the 5th stdlib module **`stdlib/wire`**.
- **Type Aliases & Nested Algebraic Data Types**: `(type AliasName <TypeSpec>)` aliases across imports, arbitrarily nested `struct`/`enum` fields (structs in structs, structs in enums, enums in structs/enums), and structural `==`/`!=` aggregate equality.
- **4-Target Differential Fuzzing**: `ail fuzz`, Python API `run_differential_fuzz()`, and 6th MCP tool `ail_fuzz_targets` verify bit-exact agreement across Native LLVM, WebAssembly, ISO C11, and `#![no_std]` Rust.
- **Static Web Studio Export & Packaging**: `ail studio --export-static <dir>` bundles Web Studio v1.1 (`7` presets including `wire_codec_v1_1` with `mut_bytes` browser WASM execution) for static hosting, plus self-hosted `uv build` & Pages workflows.
- **Real Rust Integration Showcase**: Self-contained Cargo workspace in `integrations/dogfood-gateway/` running a verified RPC edge gateway (`"MRNT"` frame codec, token-bucket rate limiter, and 128-bit bps fee metering).

## Quick Start

```bash
uv sync --extra dev

# Inspect all 5 verified stdlib modules
uv run ail stdlib

# Verify & audit specs on v1.1 wire codec example
uv run ail check examples/wire_codec_v1_1.ail
uv run ail audit-spec examples/wire_codec_v1_1.ail

# Compile to Native LLVM, WebAssembly 1.0, ISO C11, and #![no_std] Rust
uv run ail build --target all examples/wire_codec_v1_1.ail -o build/wire_v1_1

# Run 4-target differential fuzzing
uv run ail fuzz examples/wire_codec_v1_1.ail -o build/fuzz_wire --cases 50

# Launch interactive Web Studio or export standalone static site
uv run ail studio --port 8765
uv run ail studio --export-static build/site

# Run pytest suite & Rust dogfood gateway tests
uv run pytest -v
cargo test --manifest-path integrations/dogfood-gateway/Cargo.toml
```

## Verified Standard Library (5 Modules)

| Module | Purpose | Highlights |
| :--- | :--- | :--- |
| `stdlib/bits` | Bitwise byte & word helpers | `low_byte`, `pack_u32_pair`, `unpack_hi32`, `unpack_lo32`, `mask_bits_u64` |
| `stdlib/finance` | Overflow-safe financial math | `mul_bps_floor`, `mul_bps_wide_u64`, `mul_bps_ceil_u64`, `net_after_bps_fee`, `Quote2Way` |
| `stdlib/math` | Checked integer & widening ops | `midpoint_u64`, `sat_add_u64`, `sat_sub_u64`, `clamp_*`, `wide_mul_div_floor`, `wide_mul_div_ceil` |
| `stdlib/parse` | Bounds-checked big-endian readers | `has_ail_magic`, `frame_version_byte`, `frame_payload_len_u16` |
| `stdlib/wire` | Bidirectional wire header & LE codecs | `write_ail_magic`, `encode_ail_frame_header`, `read_payload_u32_le`, `read_payload_u64_le`, `write_payload_u64_le` |

## MCP Server (6 Tools via `ail-mcp`)

Run `uv run ail-mcp` (stdio JSON-RPC 2.0) to expose:
1. `ail_check_and_prove` — Interval + Bitwuzla + Z3 formal verification with counterexample witnesses.
2. `ail_audit_spec` — Non-vacuity, `SpecMut` specification tightness auditing, and `Clover` disambiguation.
3. `ail_repair_code` — Deterministic closed-loop counterexample repair.
4. `ail_compile_target` — Multi-target build (`native`, `wasm`, `c`, `rust`, `all`) with `--require-tight-specs`.
5. `ail_stdlib_catalog` — Inspect verified standard library modules and signatures.
6. `ail_fuzz_targets` — 4-target differential fuzzing across compiled Native, WASM, C11, and Rust artifacts.

## Repository Layout

- `src/ailang/` — Front-end (`parser.py`, `modules.py`, `ownership.py`), verifiers (`intervals.py`, `bitwuzla_tier.py`, `verifier.py`, `spec_firewall.py`, `agent_loop.py`), codegens (`codegen_llvm.py`, `codegen_wasm.py`, `codegen_c.py`, `codegen_rust.py`, `multi_target.py`), `diff_fuzz.py`, `cli.py`, `mcp_server.py`, `web_server.py`, `stdlib/*.ail`.
- `web/` — Standalone AIL v1.1 Web Studio (`index.html`, `styles.css`, `app.js`, `demos.json`).
- `examples/` — Verified reference modules (`signed_quote.ail`, `sum_type_settlement.ail`, `defi_waterfall_v1.ail`, `wire_frame_parser.ail`, `simd_halving.ail`, `broken_agent_draft.ail`, `wire_codec_v1_1.ail`).
- `integrations/dogfood-gateway/` — Self-contained Rust + WASM RPC edge gateway showcase.
- `integrations/antigravity-plugin/` — Antigravity IDE plugin (`ailang-mcp`, `ailang` skill, `ail-kernel-synthesizer` agent).
- `tests/` — Pytest end-to-end verification, multi-target parity, MCP, Web Studio, expressiveness, differential fuzzing, and distribution test suites.
