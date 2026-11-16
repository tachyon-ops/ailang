# Dogfood RPC Edge Gateway (`integrations/dogfood-gateway`)

Self-contained Rust workspace + WebAssembly artifacts demonstrating real AIL v1.1 integration.

## Verified Kernel Features (`kernels/gateway_kernel.ail`)

- `(type ...)` aliases (`MilliBps`, `TokenCount`) and cross-module stdlib imports (`stdlib/finance`, `stdlib/wire`).
- Nested ADT (`BucketState` embedded inside `RateDecision::Allowed`).
- 128-bit widening arithmetic (`mul_div_u64`, `mul_bps_ceil_u64`) for overflow-free high-notional fee calculation (`10^18` wei * `25` bps).
- Zero-copy bidirectional `"MRNT"` wire frame codec (`bytes` decode + `mut_bytes` write_byte / write_u16_be / write_u32_le / write_u64_le / read_u*_le).
- Proved with Z3/Bitwuzla and SpecMut (`--require-tight-specs`).

## Regenerate Verified Artifacts & Run Tests

```bash
uv run ail build --target rust --require-tight-specs integrations/dogfood-gateway/kernels/gateway_kernel.ail -o integrations/dogfood-gateway/crates/ail_gateway_kernel
uv run ail build --target wasm --require-tight-specs integrations/dogfood-gateway/kernels/gateway_kernel.ail -o integrations/dogfood-gateway/wasm
cargo test --manifest-path integrations/dogfood-gateway/Cargo.toml
```
