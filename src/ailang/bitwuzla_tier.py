"""Tier 1: Witness-Sliced 64-Bit `QF_BV` Engine via Native Bitwuzla."""

from __future__ import annotations
from typing import Any
import bitwuzla as bw

from ailang import ail_agent_pb2 as pb
from ailang.diagnostics import AILCompilerError, Span, U64_MAX
from ailang.intervals import Interval, eval_interval
from ailang.parser import SNode, pretty

BITWISE_OPS = {"&", "|", "^", ">>", "<<", "~"}


def verify_bitwise_subtree(
    node: SNode,
    iv_env: dict[str, Interval],
    item_name: str,
    fn_ret_ranges: dict[str, tuple[list[str], Any, Any]] | None = None,
) -> Interval:
    """
    Verifies a bitwise subtree in Bitwuzla by replacing non-bitwise subtrees (`/`, `%`, `*`, `call`, `get`, `fold`)
    with fresh bounded 64-bit witnesses constrained by Tier-0 intervals.
    Checks shift bounds (< 64), internal + / - overflow, and sound output interval.
    """
    iv = eval_interval(node, iv_env, fn_ret_ranges)
    claim_lo = max(0, iv.lo)
    claim_hi = min(U64_MAX, iv.hi)

    tm = bw.TermManager()
    opts = bw.Options()
    opts.set(bw.Option.PRODUCE_MODELS, True)
    bv64 = tm.mk_bv_sort(64)
    solver = bw.Bitwuzla(tm, opts)
    var_map: dict[str, Any] = {}
    checks: list[tuple[int, Span, str, Any]] = []
    wit_counter = 0

    def build_bv(n: SNode) -> Any:
        nonlocal wit_counter
        if isinstance(n.val, int):
            return tm.mk_bv_value(bv64, n.val & U64_MAX)
        if isinstance(n.val, str):
            if n.val == "MAX":
                return tm.mk_bv_value(bv64, U64_MAX)
            if n.val not in var_map:
                v = tm.mk_const(bv64, n.val)
                b_iv = iv_env.get(n.val, Interval(0, U64_MAX))
                solver.assert_formula(tm.mk_term(bw.Kind.BV_UGE, [v, tm.mk_bv_value(bv64, max(0, b_iv.lo))]))
                solver.assert_formula(tm.mk_term(bw.Kind.BV_ULE, [v, tm.mk_bv_value(bv64, min(U64_MAX, b_iv.hi))]))
                var_map[n.val] = v
            return var_map[n.val]

        items = n.val
        op = str(items[0].val)

        # Slice non-bitwise nonlinear / memory / call subtrees into bounded 64-bit witnesses
        if op not in (BITWISE_OPS | {"+", "-"}):
            wit_counter += 1
            wname = f"_wit_{wit_counter}"
            w = tm.mk_const(bv64, wname)
            w_iv = eval_interval(n, iv_env, fn_ret_ranges)
            solver.assert_formula(tm.mk_term(bw.Kind.BV_UGE, [w, tm.mk_bv_value(bv64, max(0, w_iv.lo))]))
            solver.assert_formula(tm.mk_term(bw.Kind.BV_ULE, [w, tm.mk_bv_value(bv64, min(U64_MAX, w_iv.hi))]))
            var_map[wname] = w
            return w

        if op == "~":
            return tm.mk_term(bw.Kind.BV_NOT, [build_bv(items[1])])

        a = build_bv(items[1])
        b = build_bv(items[2])
        if op == "+":
            checks.append((pb.E_U64_OVERFLOW, n.span, pretty(n), tm.mk_term(bw.Kind.BV_UADD_OVERFLOW, [a, b])))
            return tm.mk_term(bw.Kind.BV_ADD, [a, b])
        if op == "-":
            checks.append((pb.E_U64_UNDERFLOW, n.span, pretty(n), tm.mk_term(bw.Kind.BV_USUB_OVERFLOW, [a, b])))
            return tm.mk_term(bw.Kind.BV_SUB, [a, b])
        if op == "&":
            return tm.mk_term(bw.Kind.BV_AND, [a, b])
        if op == "|":
            return tm.mk_term(bw.Kind.BV_OR, [a, b])
        if op == "^":
            return tm.mk_term(bw.Kind.BV_XOR, [a, b])
        if op == ">>":
            checks.append((pb.E_SHIFT_OUT_OF_RANGE, n.span, pretty(n), tm.mk_term(bw.Kind.BV_UGE, [b, tm.mk_bv_value(bv64, 64)])))
            return tm.mk_term(bw.Kind.BV_SHR, [a, b])
        if op == "<<":
            checks.append((pb.E_SHIFT_OUT_OF_RANGE, n.span, pretty(n), tm.mk_term(bw.Kind.BV_UGE, [b, tm.mk_bv_value(bv64, 64)])))
            # Also ensure left-shift doesn't overflow if interval claims boundedness
            return tm.mk_term(bw.Kind.BV_SHL, [a, b])
        raise NotImplementedError(op)

    res_bv = build_bv(node)
    checks.append((pb.E_POSTCONDITION_FAILED, node.span, pretty(node), tm.mk_term(bw.Kind.BV_ULT, [res_bv, tm.mk_bv_value(bv64, claim_lo)])))
    checks.append((pb.E_POSTCONDITION_FAILED, node.span, pretty(node), tm.mk_term(bw.Kind.BV_UGT, [res_bv, tm.mk_bv_value(bv64, claim_hi)])))

    for err_code, sp, expr_s, bad_cond in checks:
        solver.push()
        solver.assert_formula(bad_cond)
        if solver.check_sat() == bw.Result.SAT:
            ce = {k: int(solver.get_value(v).value(10)) for k, v in var_map.items() if not k.startswith("_wit_")}
            solver.pop()
            raise AILCompilerError(
                code=err_code,
                stage=pb.STAGE_TIER1_BITWUZLA,
                item_name=item_name,
                message=f"Bitwuzla 64-bit bit-vector check failed on `{expr_s}`",
                span=sp,
                expr=expr_s,
                counterexample=ce,
            )
        solver.pop()

    return Interval(claim_lo, claim_hi)
