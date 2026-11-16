---
name: defi-verified-math-pack
description: >-
  Formally verify and synthesize overflow-proof DeFi, Solana/EVM, DEX, and
  fintech math kernels using Z3, Bitwuzla, and AIL. Covers ERC-4626 inflation-safe
  vault share rounding, constant-product AMM swaps, basis-points fee waterfalls,
  and overflow-free mul_div, compiling directly to safe #![no_std] Rust, ISO C11,
  and WebAssembly.
---

# DeFi & Fintech Verified Math Synthesizer

Eliminate rounding-direction exploits, ERC-4626 share-inflation attacks, `u64`
intermediate multiplication overflows, and tranche conservation bugs before any
code hits production or audit.

## Included Verified Assets

- `scripts/verify_defi_invariants.py` — Standalone Z3 economic invariant checker
  (`uv run --with z3-solver scripts/verify_defi_invariants.py ...`) that proves:
  1. **Round-trip value non-extraction** (`redeem(deposit(assets)) <= assets`)
  2. **Mint-withdraw solvency** (`withdraw_shares_ceil(assets) >= deposit_shares_floor(assets)`)
  3. **Tranche / fee split conservation** (`protocol_fee + lp_fee + net_out == gross`)
  4. **64-bit intermediate overflow freedom** across full domain bounds
- `references/erc4626_vault_shares.ail` — Proven ERC-4626 virtual-offset vault
  accounting (`convert_to_shares_floor`, `convert_to_assets_floor`,
  `preview_mint_assets_ceil`, `preview_withdraw_shares_ceil`) with 100% `SpecMut`
  mutant kill rate.
- `references/amm_cpsmm_swap.ail` — Proven constant-product (`x * y = k`) swap
  output kernel with basis-point fee deduction, protocol fee split, and minimum
  output slippage settlement enum.

## Mandatory DeFi Math Rules

### 1. Rounding Direction Matrix (Vault / Protocol Solvency)
Never guess `floor` vs `ceil`. Every conversion MUST round in favor of the pool/vault:

| Operation | Input | Output | Required Rounding | Formula (`a * b / c`, `c >= 1`) |
|---|---|---|---|---|
| `deposit` (`convertToShares`) | `assets` | `shares` | **Floor** (fewer shares minted) | `(a * b) / c` |
| `redeem` (`convertToAssets`) | `shares` | `assets` | **Floor** (fewer assets paid out) | `(a * b) / c` |
| `mint` (`previewMint`) | `shares` | `assets` | **Ceil** (more assets pulled in) | `a == 0 || b == 0 ? 0 : 1 + ((a * b - 1) / c)` |
| `withdraw` (`previewWithdraw`) | `assets` | `shares` | **Ceil** (more shares burned) | `a == 0 || b == 0 ? 0 : 1 + ((a * b - 1) / c)` |

### 2. ERC-4626 Donation / First-Depositor Inflation Defense
Always include non-zero virtual shares (`VIRTUAL_SHARES >= 1`) and virtual assets
(`VIRTUAL_ASSETS >= 1`) in conversion denominators:
- `effective_supply = total_supply + VIRTUAL_SHARES`
- `effective_assets = total_assets + VIRTUAL_ASSETS`

This guarantees strict positivity of denominators (eliminating `E_DIV_ZERO`) and
bounds attacker dilution loss.

### 3. Overflow-Free `u64` `mul_div` Decomposition
On 64-bit targets (`u64::MAX = 18_446_744_073_709_551_615`), `(* amount rate)`
overflows whenever `amount * rate > 2^64 - 1`, even if the final quotient fits in `u64`.
- If `amount <= 10^14` and `bps <= 10_000`, `amount * bps <= 10^18 < 2^64 - 1` (safe direct multiply).
- For larger bounds where `b < c`, decompose exact floor `mul_div(a, b, c)` without
  intermediate overflow as:
  ```lisp
  (+ (* (/ a c) b) (/ (* (% a c) b) c))
  ```

## Execution Workflow

1. **Run Standalone Economic Invariant Proof First**
   ```bash
   uv run --with z3-solver scripts/verify_defi_invariants.py --suite all
   ```
   When designing a custom vault, fee waterfall, or bonding curve, pass `--custom-json`
   or inspect the counterexample witness if any solvency invariant fails.

2. **Synthesize `.ail` Kernel Starting from `references/`**
   Adapt `references/erc4626_vault_shares.ail` or `references/amm_cpsmm_swap.ail`
   to the target domain bounds and fee caps.

3. **Verify & Audit Tightness**
   ```bash
   uvx --from git+https://github.com/tachyon-ops/ailang.git ail check your_kernel.ail
   uvx --from git+https://github.com/tachyon-ops/ailang.git ail audit-spec your_kernel.ail
   ```
   Require `STATUS_VERIFIED` and `100%` `SpecMut` mutant kill rate.

4. **Compile to Production Target (`rust`, `c`, `wasm`, `llvm`)**
   ```bash
   uvx --from git+https://github.com/tachyon-ops/ailang.git ail build \
     --target rust --require-tight-specs your_kernel.ail -o build/defi_crate
   ```
   Drop the generated `#![no_std] #![forbid(unsafe_code)]` Rust module directly
   into Solana Anchor/Pinocchio programs, CosmWasm contracts, Rollup provers, or
   C11/WASM matching engines.
