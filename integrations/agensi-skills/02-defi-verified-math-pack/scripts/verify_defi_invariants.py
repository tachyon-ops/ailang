#!/usr/bin/env python3
"""Standalone Z3 DeFi Economic Invariant Prover.

Verifies ERC-4626 vault solvency (no-free-money deposit->redeem round-trip,
mint/withdraw rounding duality), basis-points fee waterfall conservation, and
constant-product AMM reserve depletion bounds over unbounded integers & u64 ranges.

Run via:
  uv run --with z3-solver scripts/verify_defi_invariants.py --suite all
"""

from __future__ import annotations
import argparse
import json
import sys
import z3

U64_MAX = (1 << 64) - 1


def z3_div_floor(num: z3.ArithRef, den: z3.ArithRef) -> z3.ArithRef:
    """Exact floor division for non-negative num and positive den in Z3."""
    return num / den


def z3_div_ceil(num: z3.ArithRef, den: z3.ArithRef) -> z3.ArithRef:
    """Exact ceiling division for non-negative num and positive den in Z3."""
    return z3.If(num == 0, z3.IntVal(0), 1 + ((num - 1) / den))


def prove_claim(name: str, preconditions: list[z3.BoolRef], claim: z3.BoolRef, vars_map: dict[str, z3.ArithRef]) -> dict:
    s = z3.Solver()
    s.set("timeout", 5000)
    s.add(*preconditions)
    s.add(z3.Not(claim))
    res = s.check()
    if res == z3.unsat:
        return {"invariant": name, "status": "PROVEN", "counterexample": None}
    if res == z3.sat:
        m = s.model()
        witness = {k: int(str(m.evaluate(v, model_completion=True))) for k, v in vars_map.items()}
        return {"invariant": name, "status": "VIOLATED", "counterexample": witness}
    return {"invariant": name, "status": "UNKNOWN_TIMEOUT", "counterexample": None}


def run_erc4626_suite(max_tvl: int, virtual_assets: int, virtual_shares: int) -> list[dict]:
    assets = z3.Int("assets")
    shares = z3.Int("shares")
    total_assets = z3.Int("total_assets")
    total_supply = z3.Int("total_supply")

    max_supply = max_tvl * max(1, virtual_shares)
    pre = [
        assets >= 0,
        assets <= max_tvl,
        shares >= 0,
        shares <= max_supply,
        total_assets >= 0,
        total_assets <= max_tvl,
        total_supply >= 0,
        total_supply <= max_supply,
    ]
    eff_assets = total_assets + virtual_assets
    eff_supply = total_supply + virtual_shares

    minted_shares = z3_div_floor(assets * eff_supply, eff_assets)
    # After deposit of `assets`, vault has `total_assets + assets` and `total_supply + minted_shares`
    redeemed_assets = z3_div_floor(
        minted_shares * (eff_assets + assets),
        eff_supply + minted_shares,
    )

    preview_mint_assets = z3_div_ceil(shares * eff_assets, eff_supply)
    preview_withdraw_shares = z3_div_ceil(assets * eff_supply, eff_assets)

    vmap = {
        "assets": assets,
        "shares": shares,
        "total_assets": total_assets,
        "total_supply": total_supply,
    }

    return [
        prove_claim(
            "erc4626_no_free_money_deposit_redeem_roundtrip",
            pre,
            redeemed_assets <= assets,
            vmap,
        ),
        prove_claim(
            "erc4626_withdraw_burns_at_least_deposit_shares",
            pre,
            preview_withdraw_shares >= minted_shares,
            vmap,
        ),
        prove_claim(
            "erc4626_mint_pulls_at_least_redeem_assets",
            pre,
            preview_mint_assets >= z3_div_floor(shares * eff_assets, eff_supply),
            vmap,
        ),
        prove_claim(
            "erc4626_u64_intermediate_product_no_overflow",
            pre,
            z3.And(
                assets * eff_supply <= U64_MAX,
                shares * eff_assets <= U64_MAX,
            ),
            vmap,
        ),
    ]


def run_amm_and_waterfall_suite(max_reserve: int) -> list[dict]:
    amount_in = z3.Int("amount_in")
    res_in = z3.Int("reserve_in")
    res_out = z3.Int("reserve_out")
    fee_bps = z3.Int("fee_bps")
    proto_cut_bps = z3.Int("proto_cut_bps")

    pre = [
        amount_in >= 0,
        amount_in <= max_reserve,
        res_in >= 1,
        res_in <= max_reserve,
        res_out >= 1,
        res_out <= max_reserve,
        fee_bps >= 0,
        fee_bps <= 300,
        proto_cut_bps >= 0,
        proto_cut_bps <= 5000,
    ]

    total_fee = z3_div_floor(amount_in * fee_bps, 10000)
    proto_fee = z3_div_floor(total_fee * proto_cut_bps, 10000)
    lp_fee = total_fee - proto_fee
    net_in = amount_in - total_fee
    amount_out = z3_div_floor(res_out * net_in, res_in + net_in)

    # Post-swap constant product k' >= k check
    new_k = (res_in + net_in) * (res_out - amount_out)
    old_k = res_in * res_out

    vmap = {
        "amount_in": amount_in,
        "reserve_in": res_in,
        "reserve_out": res_out,
        "fee_bps": fee_bps,
        "proto_cut_bps": proto_cut_bps,
    }

    return [
        prove_claim(
            "fee_split_exact_conservation",
            pre,
            proto_fee + lp_fee + net_in == amount_in,
            vmap,
        ),
        prove_claim(
            "cpsmm_never_drains_entire_output_reserve",
            pre,
            z3.And(amount_out >= 0, amount_out < res_out),
            vmap,
        ),
        prove_claim(
            "cpsmm_k_invariant_non_decreasing",
            pre,
            new_k >= old_k,
            vmap,
        ),
        prove_claim(
            "cpsmm_u64_intermediate_product_no_overflow",
            pre,
            res_out * net_in <= U64_MAX,
            vmap,
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Prove DeFi economic and u64 arithmetic invariants with Z3.")
    parser.add_argument("--suite", choices=["erc4626", "amm", "all"], default="all")
    parser.add_argument("--max-tvl", type=int, default=100_000_000)
    parser.add_argument("--virtual-assets", type=int, default=1)
    parser.add_argument("--virtual-shares", type=int, default=1000)
    args = parser.parse_args()

    results: list[dict] = []
    if args.suite in ("erc4626", "all"):
        results.extend(run_erc4626_suite(args.max_tvl, args.virtual_assets, args.virtual_shares))
    if args.suite in ("amm", "all"):
        results.extend(run_amm_and_waterfall_suite(args.max_tvl))

    all_ok = all(r["status"] == "PROVEN" for r in results)
    report = {
        "overall_status": "VERIFIED" if all_ok else "FAILED",
        "total_invariants": len(results),
        "proven_count": sum(1 for r in results if r["status"] == "PROVEN"),
        "results": results,
    }
    print(json.dumps(report, indent=2))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
