# AIL v0.3 vs. Rust / C / Python — Empirical Verification, Token Density & Apple Silicon Benchmark

- **Compile + Verify Wall Time:** AIL (`check` + `audit-spec` + LLVM `-O3` `.dylib`): **414.03 ms** | Rust (`rustc -C opt-level=3`): **433.92 ms** | C (`clang -O3 -shared`): **123.78 ms**

## 1. Per-Kernel Agent Token Density (`o200k_base`) & Apple Silicon Latency (`ns/op`)

| Kernel | AIL Tokens (`.ail.pb` B) | Rust Tokens | C Tokens | Python Tokens | AIL `ns/op` | Rust `ns/op` | C `ns/op` | Python `ns/op` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `midpoint_u64` | **71** (698 B) | 48 | 46 | 45 | **1.47** | 1.83 | 1.38 | 220.79 |
| `settle_fee_net` | **127** (1087 B) | 112 | 96 | 59 | **1.80** | 4.15 | 5.81 | 273.59 |
| `halve_bonus_simd` | **87** (621 B) | 85 | 85 | 58 | **181.58** | 182.98 | 181.35 | 55866.46 |
| `quote_net_mid` | **91** (795 B) | 117 | 100 | 79 | **0.92** | 1.82 | 1.83 | 185.61 |
| `settle_outcome_dispatch` | **90** (811 B) | 136 | 93 | 47 | **1.02** | 2.08 | 2.27 | 121.78 |
| **Total (5 Kernels)** | **466** | **498** | **420** | **288** | — | — | — | — |

## 2. 5-Bug Static Compiler Firewall Matrix (Zero Execution / Caught at Compile Time)

| Subtle Bug Class | AIL (`v0.3`) | Rust (`rustc -O3`) | C (`clang -Wall -Wextra -Werror`) | Python (`py_compile`) | AIL Diagnostic |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `u64_midpoint_2pow63_overflow` | **CAUGHT** | missed | missed | missed | `E_U64_OVERFLOW` |
| `i64_min_div_neg1_trap` | **CAUGHT** | missed | missed | missed | `E_I64_OVERFLOW` |
| `spec_gaming_zero_mutant` | **CAUGHT** | missed | missed | missed | `E_SPEC_MUTANT_SURVIVED` |
| `inverted_dependent_quote_struct` | **CAUGHT** | missed | missed | missed | `E_STRUCT_INVARIANT_FAILED` |
| `non_exhaustive_enum_and_cap_leak` | **CAUGHT** | missed | missed | missed | `E_NON_EXHAUSTIVE_MATCH` |
