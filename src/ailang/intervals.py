"""Tier 0: Sound Signed/Unsigned Interval Abstract Interpretation `[lo, hi]` (v0.2)."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any

from ailang.diagnostics import I64_MAX, I64_MIN, U64_MAX
from ailang.parser import SNode


@dataclass(frozen=True)
class Interval:
    lo: int
    hi: int


def parse_range_raw(tspec_raw: Any) -> tuple[Any, Any]:
    if tspec_raw == "u64":
        return 0, "MAX"
    if tspec_raw == "i64":
        return "MIN_I64", "MAX_I64"
    if isinstance(tspec_raw, list) and len(tspec_raw) == 3 and tspec_raw[0] in ("u64_range", "i64_range"):
        return tspec_raw[1], tspec_raw[2]
    return 0, "MAX"


def _trunc_div_int(a: int, b: int) -> int:
    q = abs(a) // abs(b)
    return -q if (a < 0) ^ (b < 0) else q


def eval_interval(
    node: SNode | Any,
    env: dict[str, Interval],
    fn_ret_ranges: dict[str, tuple[list[str], Any, Any]] | None = None,
) -> Interval:
    raw = node.raw() if isinstance(node, SNode) else node
    if isinstance(raw, int):
        return Interval(raw, raw)
    if isinstance(raw, str):
        if raw == "MAX":
            return Interval(U64_MAX, U64_MAX)
        if raw == "MIN_I64":
            return Interval(I64_MIN, I64_MIN)
        if raw == "MAX_I64":
            return Interval(I64_MAX, I64_MAX)
        return env.get(raw, Interval(I64_MIN, U64_MAX))
    if not isinstance(raw, list) or not raw:
        return Interval(I64_MIN, U64_MAX)

    op = raw[0]
    if op == "let":
        nenv = dict(env)
        for bname, bexpr in raw[1]:
            if isinstance(bexpr, list) and bexpr and bexpr[0] == "make":
                # Track struct literal fields if needed
                nenv[bname] = Interval(0, 0)
            else:
                nenv[bname] = eval_interval(bexpr, nenv, fn_ret_ranges)
        return eval_interval(raw[2], nenv, fn_ret_ranges)
    if op == "if":
        t = eval_interval(raw[2], env, fn_ret_ranges)
        f = eval_interval(raw[3], env, fn_ret_ranges)
        return Interval(min(t.lo, f.lo), max(t.hi, f.hi))
    if op in ("to_i64", "to_u64"):
        return eval_interval(raw[1], env, fn_ret_ranges)
    if op == "field":
        if isinstance(raw[1], str):
            return env.get(f"{raw[1]}__field__{raw[2]}", Interval(I64_MIN, U64_MAX))
        return Interval(I64_MIN, U64_MAX)
    if op == "make":
        return Interval(0, 0)
    if op in ("variant", "is_variant"):
        return Interval(0, 1 if op == "is_variant" else 0)
    if op == "match":
        scrut = raw[1]
        arms = raw[2:]
        arm_ivs: list[Interval] = []
        for arm in arms:
            pat, arm_body = arm[0], arm[1]
            arm_env = dict(env)
            if isinstance(pat, list) and pat:
                vname = str(pat[0])
                for fidx, bname in enumerate(pat[1:]):
                    if isinstance(scrut, str) and f"{scrut}__enum__{vname}__{fidx}" in env:
                        arm_env[str(bname)] = env[f"{scrut}__enum__{vname}__{fidx}"]
                    elif isinstance(scrut, list) and len(scrut) >= 3 and scrut[0] == "variant" and str(scrut[2]) == vname and 3 + fidx < len(scrut):
                        arm_env[str(bname)] = eval_interval(scrut[3 + fidx], env, fn_ret_ranges)
            arm_ivs.append(eval_interval(arm_body, arm_env, fn_ret_ranges))
        return Interval(min(iv.lo for iv in arm_ivs), max(iv.hi for iv in arm_ivs))
    if op == "~":
        a = eval_interval(raw[1], env, fn_ret_ranges)
        if a.lo == a.hi and a.lo >= 0:
            v = (~a.lo) & U64_MAX
            return Interval(v, v)
        return Interval(I64_MIN, U64_MAX)
    if op == "get":
        return env.get(f"{raw[1]}__elem", Interval(0, U64_MAX))
    if op == "byte_at":
        return Interval(0, 255)
    if op in ("read_u16_be", "read_u16_le"):
        return Interval(0, 65535)
    if op in ("read_u32_be", "read_u32_le"):
        return Interval(0, 4294967295)
    if op in ("read_u64_be", "read_u64_le"):
        return Interval(0, U64_MAX)
    if op == "bytes_eq4":
        return Interval(0, 1)
    if op == "write_byte":
        return Interval(1, 1)
    if op in ("write_u16_be", "write_u16_le"):
        return Interval(2, 2)
    if op in ("write_u32_be", "write_u32_le"):
        return Interval(4, 4)
    if op in ("write_u64_be", "write_u64_le"):
        return Interval(8, 8)
    if op in ("io.print_u64", "io.print_i64", "fs.write_u64", "fs.write_i64", "fs.close", "net.loopback_send_u64", "net.close"):
        return Interval(0, 0)
    if op == "io.done":
        return eval_interval(raw[2], env, fn_ret_ranges)
    if op == "fold":
        _, (ivar, bound_e), (_, _, acc_t), _ = raw
        b_iv = eval_interval(bound_e, env, fn_ret_ranges)
        lo_e, hi_e = parse_range_raw(acc_t)
        exit_env = dict(env, **{ivar: b_iv})
        return Interval(
            eval_interval(lo_e, exit_env, fn_ret_ranges).lo,
            eval_interval(hi_e, exit_env, fn_ret_ranges).hi,
        )
    if op == "call":
        callee = raw[1]
        if fn_ret_ranges and callee in fn_ret_ranges:
            pnames, rlo_e, rhi_e = fn_ret_ranges[callee]
            cenv = {pn: eval_interval(arg, env, fn_ret_ranges) for pn, arg in zip(pnames, raw[2:])}
            return Interval(
                eval_interval(rlo_e, cenv, fn_ret_ranges).lo,
                eval_interval(rhi_e, cenv, fn_ret_ranges).hi,
            )
        return Interval(I64_MIN, U64_MAX)

    args = [eval_interval(a, env, fn_ret_ranges) for a in raw[1:]]
    if op == "+":
        return Interval(args[0].lo + args[1].lo, args[0].hi + args[1].hi)
    if op == "-":
        return Interval(args[0].lo - args[1].hi, args[0].hi - args[1].lo)
    if op == "*":
        prods = (
            args[0].lo * args[1].lo,
            args[0].lo * args[1].hi,
            args[0].hi * args[1].lo,
            args[0].hi * args[1].hi,
        )
        return Interval(min(prods), max(prods))
    if op == "/":
        if args[1].lo > 0 or args[1].hi < 0:
            quots = (
                _trunc_div_int(args[0].lo, args[1].lo),
                _trunc_div_int(args[0].lo, args[1].hi),
                _trunc_div_int(args[0].hi, args[1].lo),
                _trunc_div_int(args[0].hi, args[1].hi),
            )
            return Interval(min(quots), max(quots))
        return Interval(I64_MIN, U64_MAX)
    if op == "%":
        if args[1].lo > 0 and args[0].lo >= 0:
            return Interval(0, min(args[0].hi, args[1].hi - 1))
        if args[1].lo > 0 or args[1].hi < 0:
            max_mod = max(abs(args[1].lo), abs(args[1].hi)) - 1
            return Interval(-max_mod, max_mod)
        return Interval(I64_MIN, U64_MAX)
    if op == "min":
        return Interval(min(args[0].lo, args[1].lo), min(args[0].hi, args[1].hi))
    if op == "max":
        return Interval(max(args[0].lo, args[1].lo), max(args[0].hi, args[1].hi))
    if op == "mul_div_u64":
        if args[0].lo >= 0 and args[1].lo >= 0 and args[2].lo > 0:
            return Interval((args[0].lo * args[1].lo) // args[2].hi, (args[0].hi * args[1].hi) // args[2].lo)
        return Interval(0, U64_MAX)
    if op == "mul_div_ceil_u64":
        if args[0].lo >= 0 and args[1].lo >= 0 and args[2].lo > 0:
            lo_q = (args[0].lo * args[1].lo + args[2].hi - 1) // args[2].hi
            hi_q = (args[0].hi * args[1].hi + args[2].lo - 1) // args[2].lo
            return Interval(lo_q, hi_q)
        return Interval(0, U64_MAX)
    if op == "&":
        if args[0].lo >= 0 and args[1].lo >= 0:
            return Interval(0, min(args[0].hi, args[1].hi))
        return Interval(I64_MIN, U64_MAX)
    if op == "|":
        if args[0].lo >= 0 and args[1].lo >= 0:
            hi_bits = 1 << max(args[0].hi.bit_length(), args[1].hi.bit_length())
            return Interval(max(args[0].lo, args[1].lo), min(U64_MAX, hi_bits - 1))
        return Interval(I64_MIN, U64_MAX)
    if op == "^":
        if args[0].lo >= 0 and args[1].lo >= 0:
            hi_bits = 1 << max(args[0].hi.bit_length(), args[1].hi.bit_length())
            return Interval(0, min(U64_MAX, hi_bits - 1))
        return Interval(I64_MIN, U64_MAX)
    if op == ">>":
        if 0 <= args[1].lo and args[1].hi < 64:
            return Interval(args[0].lo >> args[1].hi, args[0].hi >> args[1].lo)
        return Interval(I64_MIN, U64_MAX)
    if op == "<<":
        if args[0].lo >= 0 and 0 <= args[1].lo and args[1].hi < 64:
            return Interval(args[0].lo << args[1].lo, args[0].hi << args[1].hi)
        return Interval(I64_MIN, U64_MAX)
    return Interval(I64_MIN, U64_MAX)
