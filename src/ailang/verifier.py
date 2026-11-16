"""Tier 2: Stratified Z3 Verifier v0.2 (`u64`, `i64`, Dependent `struct`, `cap.io`/`fs`/`net`, `fold`, `atomic_cas`)."""

from __future__ import annotations
from dataclasses import dataclass, field
import time
from typing import Any
import z3

from ailang import ail_agent_pb2 as pb
from ailang.bitwuzla_tier import BITWISE_OPS, verify_bitwise_subtree
from ailang.diagnostics import AILCompilerError, I64_MAX, I64_MIN, Span, U64_MAX
from ailang.intervals import Interval, eval_interval
from ailang.ownership import EnumDef, LINEAR_CAPS, ModuleTypeEnv, StructDef, check_module_ownership_v2
from ailang.parser import SNode, pretty

Z3Value = z3.ExprRef | dict[str, Any]

BYTES_SORT = z3.DeclareSort("Bytes")
Z3_BYTE_AT = z3.Function("ail_byte_at", BYTES_SORT, z3.IntSort(), z3.IntSort())
Z3_READ_U16_BE = z3.Function("ail_read_u16_be", BYTES_SORT, z3.IntSort(), z3.IntSort())
Z3_READ_U32_BE = z3.Function("ail_read_u32_be", BYTES_SORT, z3.IntSort(), z3.IntSort())
Z3_READ_U64_BE = z3.Function("ail_read_u64_be", BYTES_SORT, z3.IntSort(), z3.IntSort())
Z3_READ_U16_LE = z3.Function("ail_read_u16_le", BYTES_SORT, z3.IntSort(), z3.IntSort())
Z3_READ_U32_LE = z3.Function("ail_read_u32_le", BYTES_SORT, z3.IntSort(), z3.IntSort())
Z3_READ_U64_LE = z3.Function("ail_read_u64_le", BYTES_SORT, z3.IntSort(), z3.IntSort())
Z3_BYTES_EQ4 = z3.Function(
    "ail_bytes_eq4",
    BYTES_SORT,
    z3.IntSort(),
    z3.IntSort(),
    z3.IntSort(),
    z3.IntSort(),
    z3.IntSort(),
    z3.IntSort(),
)

BYTES_OP_SPECS: dict[str, tuple[int, int, z3.FuncDeclRef]] = {
    "byte_at": (1, 255, Z3_BYTE_AT),
    "read_u16_be": (2, 65535, Z3_READ_U16_BE),
    "read_u32_be": (4, 4294967295, Z3_READ_U32_BE),
    "read_u64_be": (8, U64_MAX, Z3_READ_U64_BE),
    "read_u16_le": (2, 65535, Z3_READ_U16_LE),
    "read_u32_le": (4, 4294967295, Z3_READ_U32_LE),
    "read_u64_le": (8, U64_MAX, Z3_READ_U64_LE),
    "bytes_eq4": (4, 1, Z3_BYTES_EQ4),
}

BYTES_WRITE_SPECS: dict[str, tuple[int, int]] = {
    "write_byte": (1, 255),
    "write_u16_be": (2, 65535),
    "write_u16_le": (2, 65535),
    "write_u32_be": (4, 4294967295),
    "write_u32_le": (4, 4294967295),
    "write_u64_be": (8, U64_MAX),
    "write_u64_le": (8, U64_MAX),
}


@dataclass
class SpecDeclInfo:
    name: str
    params: list[str]
    body: SNode


@dataclass
class FnContractInfo:
    name: str
    params: list[tuple[str, str, SNode, SNode]]  # (pname, pkind, lo_node, hi_node)
    ret_name: str
    ret_kind: str
    ret_lo: SNode
    ret_hi: SNode
    ensures: list[SNode]
    bytes_len_params: dict[str, str] = field(default_factory=dict)


@dataclass
class AtomicProtoInfo:
    name: str
    fields: list[str]
    invariant: SNode
    steps: dict[str, tuple[list[tuple[str, SNode, SNode]], list[SNode], Span]]


def _extract_range_nodes(tspec: SNode) -> tuple[SNode, SNode]:
    raw = tspec.raw()
    if raw == "u64" or (isinstance(raw, str) and raw in LINEAR_CAPS):
        return SNode(0, tspec.span), SNode("MAX", tspec.span)
    if raw == "i64":
        return SNode("MIN_I64", tspec.span), SNode("MAX_I64", tspec.span)
    if isinstance(tspec.val, list) and len(tspec.val) == 3 and tspec.val[0].val in ("u64_range", "i64_range"):
        return tspec.val[1], tspec.val[2]
    return SNode(0, tspec.span), SNode("MAX", tspec.span)


def _extract_ret_spec(
    ret_node: SNode,
    structs: dict[str, StructDef] | None = None,
    enums: dict[str, EnumDef] | None = None,
) -> tuple[str, SNode, SNode, list[SNode]]:
    raw = ret_node.raw()
    if isinstance(raw, str) and (
        raw in LINEAR_CAPS or raw in ("u64", "i64") or (structs and raw in structs) or (enums and raw in enums)
    ):
        lo_n, hi_n = _extract_range_nodes(ret_node)
        return "_ret", lo_n, hi_n, []
    if isinstance(raw, list) and raw and raw[0] in ("u64_range", "i64_range"):
        lo_n, hi_n = _extract_range_nodes(ret_node)
        return "_ret", lo_n, hi_n, []
    assert isinstance(ret_node.val, list) and len(ret_node.val) >= 2
    rname = str(ret_node.val[0].val)
    lo_n, hi_n = _extract_range_nodes(ret_node.val[1])
    return rname, lo_n, hi_n, ret_node.val[2:]


def _z3_trunc_div(a: z3.ArithRef, b: z3.ArithRef) -> z3.ArithRef:
    """Exact C / LLVM `sdiv` truncation-toward-zero semantics on signed integers."""
    return z3.If(
        a >= 0,
        z3.If(b > 0, a / b, -(a / (-b))),
        z3.If(b > 0, -((-a) / b), (-a) / (-b)),
    )


def _z3_trunc_rem(a: z3.ArithRef, b: z3.ArithRef) -> z3.ArithRef:
    return a - b * _z3_trunc_div(a, b)


def _z3_ite_val(cond: z3.BoolRef, t_val: Any, f_val: Any) -> Any:
    if isinstance(t_val, str):
        return t_val
    if isinstance(t_val, dict) and isinstance(f_val, dict):
        return {k: _z3_ite_val(cond, t_val[k], f_val[k]) for k in t_val}
    return z3.If(cond, t_val, f_val)


def _z3_val_eq(v1: Any, v2: Any) -> z3.BoolRef:
    if isinstance(v1, dict) and isinstance(v2, dict):
        return _z3_dict_eq(v1, v2)
    return v1 == v2


def _z3_dict_eq(d1: dict[str, Any], d2: dict[str, Any]) -> z3.BoolRef:
    if "__tag__" in d1:
        tag1, tag2 = d1["__tag__"], d2["__tag__"]
        eqs: list[z3.BoolRef] = [tag1 == tag2]
        for k in d1:
            if k not in ("__tag__", "__enum__"):
                t_idx = int(k.split(":", 1)[0])
                eqs.append(z3.Implies(tag1 == t_idx, _z3_val_eq(d1[k], d2[k])))
        return z3.And(*eqs)
    return z3.And(*[_z3_val_eq(d1[k], d2[k]) for k in d1])


class ModuleVerifier:
    def __init__(self, tenv: ModuleTypeEnv | None = None) -> None:
        self.tenv = tenv
        self.specs: dict[str, SpecDeclInfo] = {}
        self.fn_contracts: dict[str, FnContractInfo] = {}
        self.fn_ret_ranges: dict[str, tuple[list[str], Any, Any]] = {}
        self.protocols: dict[str, AtomicProtoInfo] = {}
        self.wit_id = 0
        self._uf_axioms: list[z3.BoolRef] = []

    def fresh_int(self, prefix: str) -> z3.ArithRef:
        self.wit_id += 1
        return z3.Int(f"{prefix}_{self.wit_id}")

    def _z3_zero_for_kind(self, kind: str) -> Z3Value:
        if kind in ("u64", "i64"):
            return z3.IntVal(0)
        assert self.tenv is not None
        if kind.startswith("struct:"):
            sdef = self.tenv.structs[kind.split(":", 1)[1]]
            return {fd.name: self._z3_zero_for_kind(fd.kind) for fd in sdef.fields}
        if kind.startswith("enum:"):
            ename = kind.split(":", 1)[1]
            edef = self.tenv.enums[ename]
            edict: dict[str, Any] = {"__enum__": ename, "__tag__": z3.IntVal(0)}
            for v in edef.variants:
                for i, fd in enumerate(v.fields):
                    edict[f"{v.tag}:{v.name}.{i}"] = self._z3_zero_for_kind(fd.kind)
            return edict
        return z3.IntVal(0)

    def make_symbolic_value(
        self,
        prefix: str,
        kind: str,
        constraints_out: list[z3.BoolRef],
        z3_scope: dict[str, Z3Value],
        scalar_vars_out: dict[str, z3.ArithRef] | None = None,
        *,
        type_node: SNode | None = None,
        fresh_sym: bool = False,
        guard_cond: z3.BoolRef | None = None,
        iv_env_out: dict[str, Interval] | None = None,
        iv_prefix: str = "",
        iv_scope: dict[str, Interval] | None = None,
    ) -> Z3Value:
        assert self.tenv is not None

        def add_guarded(cond: z3.BoolRef) -> None:
            constraints_out.append(z3.Implies(guard_cond, cond) if guard_cond is not None else cond)

        if kind in ("u64", "i64"):
            sym = self.fresh_int(prefix) if fresh_sym else z3.Int(prefix)
            hw_lo, hw_hi = (I64_MIN, I64_MAX) if kind == "i64" else (0, U64_MAX)
            constraints_out.extend([sym >= hw_lo, sym <= hw_hi])
            if type_node is not None:
                lo_n, hi_n = _extract_range_nodes(type_node)
                lo_v = self.eval_pure_spec(lo_n, z3_scope)
                hi_v = self.eval_pure_spec(hi_n, z3_scope)
                add_guarded(z3.And(sym >= lo_v, sym <= hi_v))
                if iv_env_out is not None and iv_prefix:
                    cur_ivs = iv_scope if iv_scope is not None else {}
                    lo_i = eval_interval(lo_n, cur_ivs, self.fn_ret_ranges).lo
                    hi_i = eval_interval(hi_n, cur_ivs, self.fn_ret_ranges).hi
                    iv_env_out[iv_prefix] = Interval(max(hw_lo, lo_i), min(hw_hi, hi_i))
            if scalar_vars_out is not None:
                scalar_vars_out[prefix] = sym
            return sym

        if kind.startswith("struct:"):
            sname = kind.split(":", 1)[1]
            sdef = self.tenv.structs[sname]
            fdict: dict[str, Any] = {}
            local_z3 = dict(z3_scope)
            local_iv = dict(iv_scope) if iv_scope is not None else {}
            for fd in sdef.fields:
                f_iv_key = f"{iv_prefix}__field__{fd.name}" if iv_prefix else ""
                fv = self.make_symbolic_value(
                    f"{prefix}.{fd.name}",
                    fd.kind,
                    constraints_out,
                    local_z3,
                    scalar_vars_out,
                    type_node=fd.type_node,
                    fresh_sym=fresh_sym,
                    guard_cond=guard_cond,
                    iv_env_out=iv_env_out,
                    iv_prefix=f_iv_key,
                    iv_scope=local_iv,
                )
                fdict[fd.name] = fv
                local_z3[fd.name] = fv
                if iv_env_out is not None and f_iv_key in iv_env_out:
                    local_iv[fd.name] = iv_env_out[f_iv_key]
            return fdict

        if kind.startswith("enum:"):
            ename = kind.split(":", 1)[1]
            edef = self.tenv.enums[ename]
            edict: dict[str, Any] = {"__enum__": ename}
            tag_name = f"{prefix}.__tag__"
            tag_v = self.fresh_int(f"{prefix}_tag") if fresh_sym else z3.Int(tag_name)
            constraints_out.extend([tag_v >= 0, tag_v < len(edef.variants)])
            edict["__tag__"] = tag_v
            if scalar_vars_out is not None:
                scalar_vars_out[tag_name] = tag_v
            for vdef in edef.variants:
                local_z3 = dict(z3_scope)
                local_iv = dict(iv_scope) if iv_scope is not None else {}
                v_guard = (tag_v == vdef.tag) if guard_cond is None else z3.And(guard_cond, tag_v == vdef.tag)
                for fidx, fd in enumerate(vdef.fields):
                    f_iv_key = f"{iv_prefix}__enum__{vdef.name}__{fidx}" if iv_prefix else ""
                    fv = self.make_symbolic_value(
                        f"{prefix}.{vdef.name}.{fd.name}",
                        fd.kind,
                        constraints_out,
                        local_z3,
                        scalar_vars_out,
                        type_node=fd.type_node,
                        fresh_sym=fresh_sym,
                        guard_cond=v_guard,
                        iv_env_out=iv_env_out,
                        iv_prefix=f_iv_key,
                        iv_scope=local_iv,
                    )
                    edict[f"{vdef.tag}:{vdef.name}.{fidx}"] = fv
                    local_z3[fd.name] = fv
                    if iv_env_out is not None and f_iv_key in iv_env_out:
                        local_iv[fd.name] = iv_env_out[f_iv_key]
            return edict

        return self.fresh_int(prefix) if fresh_sym else z3.Int(prefix)

    def _apply_bytes_uf(self, op: str, buf_sym: Any, idx_v: z3.ArithRef, items: list[SNode]) -> z3.ArithRef:
        _, max_val, uf = BYTES_OP_SPECS[op]
        if op == "bytes_eq4":
            lits = [z3.IntVal(int(a.val)) for a in items[3:7]]
            res = uf(buf_sym, idx_v, *lits)
        else:
            res = uf(buf_sym, idx_v)
        assert isinstance(res, z3.ArithRef)
        self._uf_axioms.append(z3.And(res >= 0, res <= max_val))
        return res

    def eval_pure_spec(self, node: SNode, z3_env: dict[str, Z3Value]) -> Z3Value:
        if isinstance(node.val, int):
            return z3.IntVal(node.val)
        if isinstance(node.val, str):
            if node.val == "MAX":
                return z3.IntVal(U64_MAX)
            if node.val == "MIN_I64":
                return z3.IntVal(I64_MIN)
            if node.val == "MAX_I64":
                return z3.IntVal(I64_MAX)
            if node.val not in z3_env:
                raise AILCompilerError(pb.E_UNBOUND_SYMBOL, pb.STAGE_TIER2_Z3, "<spec>", f"Unbound symbol `{node.val}` in contract", node.span, node.val)
            return z3_env[node.val]

        items = node.val
        op = str(items[0].val)
        if op == "let":
            nenv = dict(z3_env)
            for b in items[1].val:
                nenv[str(b.val[0].val)] = self.eval_pure_spec(b.val[1], nenv)
            return self.eval_pure_spec(items[2], nenv)
        if op == "if":
            c = self.eval_pure_spec(items[1], z3_env)
            t = self.eval_pure_spec(items[2], z3_env)
            f = self.eval_pure_spec(items[3], z3_env)
            return _z3_ite_val(c, t, f)
        if op in ("to_i64", "to_u64"):
            return self.eval_pure_spec(items[1], z3_env)
        if op == "make":
            sname = str(items[1].val)
            assert self.tenv is not None and sname in self.tenv.structs
            sdef = self.tenv.structs[sname]
            return {fd.name: self.eval_pure_spec(arg, z3_env) for fd, arg in zip(sdef.fields, items[2:])}
        if op == "field":
            sv = self.eval_pure_spec(items[1], z3_env)
            fname = str(items[2].val)
            assert isinstance(sv, dict)
            return sv[fname]
        if op == "variant":
            ename = str(items[1].val)
            vname = str(items[2].val)
            assert self.tenv is not None and ename in self.tenv.enums
            edef = self.tenv.enums[ename]
            vdef = edef.get_variant(vname)
            assert vdef is not None
            edict: dict[str, Any] = {"__enum__": ename, "__tag__": z3.IntVal(vdef.tag)}
            for v in edef.variants:
                for i, fd in enumerate(v.fields):
                    edict[f"{v.tag}:{v.name}.{i}"] = self._z3_zero_for_kind(fd.kind)
            for i, arg in enumerate(items[3:]):
                edict[f"{vdef.tag}:{vdef.name}.{i}"] = self.eval_pure_spec(arg, z3_env)
            return edict
        if op == "is_variant":
            sv = self.eval_pure_spec(items[1], z3_env)
            assert isinstance(sv, dict)
            ename = sv.get("__enum__") or self._node_kind(items[1]).split(":", 1)[1]
            vname = str(items[2].val)
            assert self.tenv is not None and ename in self.tenv.enums
            vdef = self.tenv.enums[ename].get_variant(vname)
            assert vdef is not None
            return sv["__tag__"] == vdef.tag
        if op == "match":
            scrut_n = items[1]
            sv = self.eval_pure_spec(scrut_n, z3_env)
            assert isinstance(sv, dict)
            tag_e = sv["__tag__"]
            ename = sv.get("__enum__") or self._node_kind(scrut_n).split(":", 1)[1]
            assert self.tenv is not None and ename in self.tenv.enums
            edef = self.tenv.enums[ename]
            seen_tags: list[int] = []
            arm_pairs: list[tuple[z3.BoolRef, Z3Value]] = []
            for arm in items[2:]:
                pat, arm_body = arm.val[0], arm.val[1]
                arm_env = dict(z3_env)
                if isinstance(pat.val, str) and pat.val == "_":
                    arm_cond = z3.And(*[tag_e != t for t in seen_tags]) if seen_tags else z3.BoolVal(True)
                else:
                    vname = str(pat.val[0].val)
                    vdef = edef.get_variant(vname)
                    assert vdef is not None
                    seen_tags.append(vdef.tag)
                    arm_cond = tag_e == vdef.tag
                    for i, bnode in enumerate(pat.val[1:]):
                        arm_env[str(bnode.val)] = sv[f"{vdef.tag}:{vdef.name}.{i}"]
                arm_pairs.append((arm_cond, self.eval_pure_spec(arm_body, arm_env)))
            res_val = arm_pairs[-1][1]
            for ac, av in reversed(arm_pairs[:-1]):
                res_val = _z3_ite_val(ac, av, res_val)
            return res_val
        if op in self.specs:
            sp = self.specs[op]
            senv = {pn: self.eval_pure_spec(arg, z3_env) for pn, arg in zip(sp.params, items[1:])}
            return self.eval_pure_spec(sp.body, senv)
        if op in BYTES_OP_SPECS:
            buf_sym = self.eval_pure_spec(items[1], z3_env)
            idx_v = self.eval_pure_spec(items[2], z3_env)
            assert isinstance(idx_v, z3.ArithRef)
            return self._apply_bytes_uf(op, buf_sym, idx_v, items)
        if op not in (
            "+",
            "-",
            "*",
            "/",
            "%",
            "trunc_div",
            "trunc_rem",
            "mul_div_u64",
            "mul_div_ceil_u64",
            ">>",
            "min",
            "max",
            "==",
            "!=",
            "<",
            "<=",
            ">",
            ">=",
            "and",
            "or",
            "not",
        ):
            raise NotImplementedError(f"Unsupported pure spec operator `{op}`")

        args: list[Any] = [self.eval_pure_spec(a, z3_env) for a in items[1:]]
        if op == "+":
            return args[0] + args[1]
        if op == "-":
            return args[0] - args[1]
        if op == "*":
            return args[0] * args[1]
        if op == "mul_div_u64":
            return (args[0] * args[1]) / args[2]
        if op == "mul_div_ceil_u64":
            return z3.If(z3.Or(args[0] == 0, args[1] == 0), z3.IntVal(0), ((args[0] * args[1] - 1) / args[2]) + 1)
        if op == "/":
            if self.tenv and self.tenv.expr_types.get(id(node)) == "i64":
                return _z3_trunc_div(args[0], args[1])
            return args[0] / args[1]
        if op == "%":
            if self.tenv and self.tenv.expr_types.get(id(node)) == "i64":
                return _z3_trunc_rem(args[0], args[1])
            return args[0] % args[1]
        if op == "trunc_div":
            return _z3_trunc_div(args[0], args[1])
        if op == "trunc_rem":
            return _z3_trunc_rem(args[0], args[1])
        if op == ">>":
            if isinstance(items[2].val, int):
                return args[0] / z3.IntVal(1 << items[2].val)
        if op == "min":
            return z3.If(args[0] <= args[1], args[0], args[1])
        if op == "max":
            return z3.If(args[0] >= args[1], args[0], args[1])
        if op in ("==", "!=", "<", "<=", ">", ">="):
            if op in ("==", "!=") and isinstance(args[0], dict) and isinstance(args[1], dict):
                eq_ref = _z3_dict_eq(args[0], args[1])
                return eq_ref if op == "==" else z3.Not(eq_ref)
            return {
                "==": lambda x, y: x == y,
                "!=": lambda x, y: x != y,
                "<": lambda x, y: x < y,
                "<=": lambda x, y: x <= y,
                ">": lambda x, y: x > y,
                ">=": lambda x, y: x >= y,
            }[op](args[0], args[1])
        if op == "and":
            return z3.And(*args)
        if op == "or":
            return z3.Or(*args)
        if op == "not":
            return z3.Not(args[0])
        raise NotImplementedError(f"Unsupported pure spec operator `{op}`")

    def _node_kind(self, node: SNode) -> str:
        if self.tenv and id(node) in self.tenv.expr_types:
            k = self.tenv.expr_types[id(node)]
            return "u64" if k == "lit_pos" else k
        if isinstance(node.val, int) and node.val < 0:
            return "i64"
        return "u64"

    def verify_function_like(self, form: SNode, is_main: bool = False) -> pb.FunctionProofStats:
        assert self.tenv is not None
        t0 = time.perf_counter()
        items = form.val
        name = "main" if is_main else str(items[1].val)
        params_node = items[1] if is_main else items[2]
        ret_node = items[2] if is_main else items[3]
        body_node = items[3] if is_main else items[4]

        stats = pb.FunctionProofStats(item_name=name, verified=False)
        self._uf_axioms = []
        axioms: list[z3.BoolRef] = []
        assumptions: list[z3.BoolRef] = []
        z3_env: dict[str, Z3Value] = {}
        scalar_vars_for_ce: dict[str, z3.ArithRef] = {}
        iv_env: dict[str, Interval] = {}
        slice_lengths: dict[str, z3.ArithRef] = {}
        slice_elem_bounds: dict[str, tuple[str, SNode, SNode]] = {}
        bytes_lengths: dict[str, tuple[str, z3.ArithRef]] = {}
        bytes_len_params: dict[str, str] = {}

        def check_z3(
            code: int,
            sp: Span,
            expr_s: str,
            msg: str,
            guard: z3.BoolRef,
            cond: z3.BoolRef,
            cur_env: dict[str, Z3Value],
            extra_assumptions: list[z3.BoolRef] | None = None,
        ) -> None:
            stats.tier2_z3_queries += 1
            s = z3.Solver()
            s.set("timeout", 4000)
            s.add(*assumptions, *(extra_assumptions or []), *axioms, *self._uf_axioms, guard, z3.Not(cond))
            res = s.check()
            if res != z3.unsat:
                ce: dict[str, int] = {}
                if res == z3.sat:
                    m = s.model()
                    for k, v in scalar_vars_for_ce.items():
                        ce[k] = m.eval(v, model_completion=True).as_long()
                    for k, v in cur_env.items():
                        if not k.startswith("_") and isinstance(v, z3.ArithRef) and k not in ce:
                            ce[k] = m.eval(v, model_completion=True).as_long()
                raise AILCompilerError(code, pb.STAGE_TIER2_Z3, name, msg, sp, expr_s, ce)

        param_contracts: list[tuple[str, str, SNode, SNode]] = []
        sig = self.tenv.sigs[name]

        for p, pk in zip(params_node.val, sig.param_kinds):
            pname = str(p.val[0].val)
            pspec = p.val[1]
            if pk in LINEAR_CAPS:
                z3_env[f"_{pname}"] = z3.IntVal(0)
                iv_env[pname] = Interval(0, 0)
                param_contracts.append((pname, pk, SNode(0, p.span), SNode(0, p.span)))
            elif pk in ("slice", "mut_slice"):
                len_var = str(pspec.val[1].val)
                elem_t = pspec.val[2]
                elem_k = "i64" if (elem_t.raw() == "i64" or (isinstance(elem_t.raw(), list) and elem_t.raw()[0] == "i64_range")) else "u64"
                elo_n, ehi_n = _extract_range_nodes(elem_t)
                len_z3 = z3_env[len_var]
                assert isinstance(len_z3, z3.ArithRef)
                slice_lengths[pname] = len_z3
                slice_elem_bounds[pname] = (elem_k, elo_n, ehi_n)
                iv_env[f"{pname}__elem"] = Interval(
                    eval_interval(elo_n, iv_env, self.fn_ret_ranges).lo,
                    eval_interval(ehi_n, iv_env, self.fn_ret_ranges).hi,
                )
                param_contracts.append((pname, pk, elo_n, ehi_n))
            elif pk in ("bytes", "mut_bytes"):
                len_var = str(pspec.val[1].val)
                len_z3 = z3_env[len_var]
                assert isinstance(len_z3, z3.ArithRef)
                bytes_lengths[pname] = (len_var, len_z3)
                bytes_len_params[pname] = len_var
                z3_env[pname] = z3.Const(f"__bytes_{pname}", BYTES_SORT)
                param_contracts.append((pname, pk, SNode(0, p.span), SNode("MAX", p.span)))
            elif pk == "atomic_u64":
                param_contracts.append((pname, pk, SNode(0, p.span), SNode("MAX", p.span)))
            elif pk.startswith(("struct:", "enum:")):
                z3_env[pname] = self.make_symbolic_value(
                    pname,
                    pk,
                    assumptions,
                    z3_env,
                    scalar_vars_for_ce,
                    fresh_sym=False,
                    iv_env_out=iv_env,
                    iv_prefix=pname,
                    iv_scope=iv_env,
                )
                param_contracts.append((pname, pk, SNode(0, p.span), SNode(0, p.span)))
            else:
                lo_n, hi_n = _extract_range_nodes(pspec)
                sym = z3.Int(pname)
                hw_lo, hw_hi = (I64_MIN, I64_MAX) if pk == "i64" else (0, U64_MAX)
                lo_v = self.eval_pure_spec(lo_n, z3_env)
                hi_v = self.eval_pure_spec(hi_n, z3_env)
                assumptions.extend([sym >= hw_lo, sym <= hw_hi, sym >= lo_v, sym <= hi_v])
                z3_env[pname] = sym
                scalar_vars_for_ce[pname] = sym
                iv_env[pname] = Interval(
                    eval_interval(lo_n, iv_env, self.fn_ret_ranges).lo,
                    eval_interval(hi_n, iv_env, self.fn_ret_ranges).hi,
                )
                param_contracts.append((pname, pk, lo_n, hi_n))

        def eval_checked(
            n: SNode,
            cur_z3: dict[str, Z3Value],
            cur_iv: dict[str, Interval],
            cur_extra: list[z3.BoolRef],
            guard: z3.BoolRef,
        ) -> Z3Value:
            nk = self._node_kind(n)
            if isinstance(n.val, int):
                if nk == "i64":
                    if n.val < I64_MIN or n.val > I64_MAX:
                        raise AILCompilerError(pb.E_I64_OVERFLOW, pb.STAGE_TIER0_INTERVAL, name, f"Signed literal {n.val} outside i64", n.span, str(n.val))
                else:
                    if n.val < 0 or n.val > U64_MAX:
                        raise AILCompilerError(pb.E_U64_OVERFLOW, pb.STAGE_TIER0_INTERVAL, name, f"Unsigned literal {n.val} outside u64", n.span, str(n.val))
                return z3.IntVal(n.val)

            if isinstance(n.val, str):
                if n.val == "MAX":
                    return z3.IntVal(U64_MAX)
                if n.val == "MIN_I64":
                    return z3.IntVal(I64_MIN)
                if n.val == "MAX_I64":
                    return z3.IntVal(I64_MAX)
                return cur_z3.get(n.val, z3.IntVal(0))

            sub = n.val
            op = str(sub[0].val)

            if op == "let":
                nz = dict(cur_z3)
                niv = dict(cur_iv)
                for b in sub[1].val:
                    bk = str(b.val[0].val)
                    bval = eval_checked(b.val[1], nz, niv, cur_extra, guard)
                    nz[bk] = bval
                    if isinstance(bval, dict):
                        bk_kind = self._node_kind(b.val[1])
                        if bk_kind.startswith("enum:"):
                            edef = self.tenv.enums[bk_kind.split(":", 1)[1]]
                            for vdef in edef.variants:
                                l_iv = dict(niv)
                                for fidx, fd in enumerate(vdef.fields):
                                    if fd.kind not in ("u64", "i64"):
                                        continue
                                    flo_n, fhi_n = _extract_range_nodes(fd.type_node)
                                    hw_lo, hw_hi = (I64_MIN, I64_MAX) if fd.kind == "i64" else (0, U64_MAX)
                                    fiv = Interval(
                                        max(hw_lo, eval_interval(flo_n, l_iv, self.fn_ret_ranges).lo),
                                        min(hw_hi, eval_interval(fhi_n, l_iv, self.fn_ret_ranges).hi),
                                    )
                                    l_iv[fd.name] = fiv
                                    niv[f"{bk}__enum__{vdef.name}__{fidx}"] = fiv
                        else:
                            for fnm in bval:
                                niv[f"{bk}__field__{fnm}"] = Interval(I64_MIN, U64_MAX)
                    else:
                        niv[bk] = eval_interval(b.val[1], niv, self.fn_ret_ranges)
                return eval_checked(sub[2], nz, niv, cur_extra, guard)

            if op == "if":
                c = eval_checked(sub[1], cur_z3, cur_iv, cur_extra, guard)
                assert isinstance(c, z3.BoolRef)
                tv = eval_checked(sub[2], cur_z3, cur_iv, cur_extra, z3.And(guard, c))
                fv = eval_checked(sub[3], cur_z3, cur_iv, cur_extra, z3.And(guard, z3.Not(c)))
                return _z3_ite_val(c, tv, fv)

            if op == "to_i64":
                av = eval_checked(sub[1], cur_z3, cur_iv, cur_extra, guard)
                assert isinstance(av, z3.ArithRef)
                a_iv = eval_interval(sub[1], cur_iv, self.fn_ret_ranges)
                if a_iv.hi <= I64_MAX:
                    stats.tier0_interval_discharged += 1
                else:
                    check_z3(pb.E_I64_OVERFLOW, n.span, pretty(n), "`(to_i64 ...)` input can exceed `MAX_I64`", guard, av <= I64_MAX, cur_z3, cur_extra)
                return av

            if op == "to_u64":
                av = eval_checked(sub[1], cur_z3, cur_iv, cur_extra, guard)
                assert isinstance(av, z3.ArithRef)
                a_iv = eval_interval(sub[1], cur_iv, self.fn_ret_ranges)
                if a_iv.lo >= 0:
                    stats.tier0_interval_discharged += 1
                else:
                    check_z3(pb.E_U64_UNDERFLOW, n.span, pretty(n), "`(to_u64 ...)` input can be negative", guard, av >= 0, cur_z3, cur_extra)
                return av

            if op == "make":
                sname = str(sub[1].val)
                sdef = self.tenv.structs[sname]
                built: dict[str, Any] = {}
                field_scope = dict(cur_z3)
                for fd, arg_n in zip(sdef.fields, sub[2:]):
                    fv = eval_checked(arg_n, cur_z3, cur_iv, cur_extra, guard)
                    if fd.kind in ("u64", "i64"):
                        assert isinstance(fv, z3.ArithRef)
                        flo_n, fhi_n = _extract_range_nodes(fd.type_node)
                        flo_v = self.eval_pure_spec(flo_n, field_scope)
                        fhi_v = self.eval_pure_spec(fhi_n, field_scope)
                        check_z3(
                            pb.E_STRUCT_INVARIANT_FAILED,
                            arg_n.span,
                            pretty(n),
                            f"Struct `{sname}` field `{fd.name}` violates dependent refinement `{pretty(fd.type_node)}`",
                            guard,
                            z3.And(fv >= flo_v, fv <= fhi_v),
                            cur_z3,
                            cur_extra,
                        )
                    built[fd.name] = fv
                    field_scope[fd.name] = fv
                return built

            if op == "field":
                sv = eval_checked(sub[1], cur_z3, cur_iv, cur_extra, guard)
                assert isinstance(sv, dict)
                return sv[str(sub[2].val)]

            if op == "variant":
                ename = str(sub[1].val)
                vname = str(sub[2].val)
                edef = self.tenv.enums[ename]
                vdef = edef.get_variant(vname)
                assert vdef is not None
                built_e: dict[str, Any] = {"__enum__": ename, "__tag__": z3.IntVal(vdef.tag)}
                for v in edef.variants:
                    for i, fd in enumerate(v.fields):
                        built_e[f"{v.tag}:{v.name}.{i}"] = self._z3_zero_for_kind(fd.kind)
                fscope = dict(cur_z3)
                for i, (fd, arg_n) in enumerate(zip(vdef.fields, sub[3:])):
                    fv = eval_checked(arg_n, cur_z3, cur_iv, cur_extra, guard)
                    if fd.kind in ("u64", "i64"):
                        assert isinstance(fv, z3.ArithRef)
                        flo_n, fhi_n = _extract_range_nodes(fd.type_node)
                        flo_v = self.eval_pure_spec(flo_n, fscope)
                        fhi_v = self.eval_pure_spec(fhi_n, fscope)
                        check_z3(
                            pb.E_ENUM_INVARIANT_FAILED,
                            arg_n.span,
                            pretty(n),
                            f"Enum `{ename}.{vname}` field `{fd.name}` violates dependent refinement `{pretty(fd.type_node)}`",
                            guard,
                            z3.And(fv >= flo_v, fv <= fhi_v),
                            cur_z3,
                            cur_extra,
                        )
                    built_e[f"{vdef.tag}:{vdef.name}.{i}"] = fv
                    fscope[fd.name] = fv
                return built_e

            if op == "is_variant":
                sv = eval_checked(sub[1], cur_z3, cur_iv, cur_extra, guard)
                assert isinstance(sv, dict)
                ename = sv.get("__enum__") or self._node_kind(sub[1]).split(":", 1)[1]
                vdef = self.tenv.enums[ename].get_variant(str(sub[2].val))
                assert vdef is not None
                return sv["__tag__"] == vdef.tag

            if op == "match":
                scrut_n = sub[1]
                sv = eval_checked(scrut_n, cur_z3, cur_iv, cur_extra, guard)
                assert isinstance(sv, dict)
                tag_e = sv["__tag__"]
                ename = sv.get("__enum__") or self._node_kind(scrut_n).split(":", 1)[1]
                edef = self.tenv.enums[ename]
                seen_tags: list[int] = []
                arm_pairs: list[tuple[z3.BoolRef, Z3Value]] = []
                scrut_name = scrut_n.val if isinstance(scrut_n.val, str) else None

                for arm in sub[2:]:
                    pat, arm_body = arm.val[0], arm.val[1]
                    arm_z3 = dict(cur_z3)
                    arm_iv = dict(cur_iv)
                    if isinstance(pat.val, str) and pat.val == "_":
                        arm_cond = z3.And(*[tag_e != t for t in seen_tags]) if seen_tags else z3.BoolVal(True)
                    else:
                        vname = str(pat.val[0].val)
                        vdef = edef.get_variant(vname)
                        assert vdef is not None
                        seen_tags.append(vdef.tag)
                        arm_cond = tag_e == vdef.tag
                        for fidx, (bnode, fd) in enumerate(zip(pat.val[1:], vdef.fields)):
                            bname = str(bnode.val)
                            arm_z3[bname] = sv[f"{vdef.tag}:{vdef.name}.{fidx}"]
                            if fd.kind in ("u64", "i64"):
                                iv_key = f"{scrut_name}__enum__{vdef.name}__{fidx}" if scrut_name else ""
                                if iv_key and iv_key in cur_iv:
                                    fiv = cur_iv[iv_key]
                                else:
                                    flo_n, fhi_n = _extract_range_nodes(fd.type_node)
                                    hw_lo, hw_hi = (I64_MIN, I64_MAX) if fd.kind == "i64" else (0, U64_MAX)
                                    fiv = Interval(
                                        max(hw_lo, eval_interval(flo_n, arm_iv, self.fn_ret_ranges).lo),
                                        min(hw_hi, eval_interval(fhi_n, arm_iv, self.fn_ret_ranges).hi),
                                    )
                                arm_iv[bname] = fiv
                    arm_val = eval_checked(arm_body, arm_z3, arm_iv, cur_extra, z3.And(guard, arm_cond))
                    arm_pairs.append((arm_cond, arm_val))

                res_val = arm_pairs[-1][1]
                for ac, av in reversed(arm_pairs[:-1]):
                    res_val = _z3_ite_val(ac, av, res_val)
                return res_val

            if op in ("io.print_u64", "io.print_i64", "fs.write_u64", "fs.write_i64"):
                _ = eval_checked(sub[2], cur_z3, cur_iv, cur_extra, guard)
                return z3.IntVal(0)
            if op in ("fs.close", "net.close"):
                return z3.IntVal(0)
            if op == "net.loopback_send_u64":
                port_v = eval_checked(sub[2], cur_z3, cur_iv, cur_extra, guard)
                _ = eval_checked(sub[3], cur_z3, cur_iv, cur_extra, guard)
                assert isinstance(port_v, z3.ArithRef)
                check_z3(
                    pb.E_PRECONDITION_FAILED,
                    sub[2].span,
                    pretty(n),
                    "Loopback UDP port must be an unprivileged valid port in `[1024..65535]`",
                    guard,
                    z3.And(port_v >= 1024, port_v <= 65535),
                    cur_z3,
                    cur_extra,
                )
                return z3.IntVal(0)
            if op == "io.done":
                return eval_checked(sub[2], cur_z3, cur_iv, cur_extra, guard)

            if op == "get":
                buf_name = str(sub[1].val)
                idx_v = eval_checked(sub[2], cur_z3, cur_iv, cur_extra, guard)
                assert isinstance(idx_v, z3.ArithRef)
                len_v = slice_lengths[buf_name]
                check_z3(
                    pb.E_SLICE_OUT_OF_BOUNDS,
                    n.span,
                    pretty(n),
                    f"Slice index `{pretty(sub[2])}` may exceed `{buf_name}` length",
                    guard,
                    z3.And(idx_v >= 0, idx_v < len_v),
                    cur_z3,
                    cur_extra,
                )
                elem = self.fresh_int(f"_{buf_name}_elem")
                elem_k, elo_n, ehi_n = slice_elem_bounds[buf_name]
                hw_lo, hw_hi = (I64_MIN, I64_MAX) if elem_k == "i64" else (0, U64_MAX)
                elo_v = self.eval_pure_spec(elo_n, cur_z3)
                ehi_v = self.eval_pure_spec(ehi_n, cur_z3)
                axioms.extend([elem >= hw_lo, elem <= hw_hi, elem >= elo_v, elem <= ehi_v])
                return elem

            if op in BYTES_OP_SPECS:
                buf_name = str(sub[1].val)
                idx_v = eval_checked(sub[2], cur_z3, cur_iv, cur_extra, guard)
                assert isinstance(idx_v, z3.ArithRef)
                len_var, len_v = bytes_lengths[buf_name]
                width, _, _ = BYTES_OP_SPECS[op]
                check_z3(
                    pb.E_OUT_OF_BOUNDS,
                    n.span,
                    pretty(n),
                    f"`{op}` access at `{pretty(sub[2])}` (+{width} bytes) may exceed `{buf_name}` length `{len_var}`",
                    guard,
                    z3.And(idx_v >= 0, idx_v + width <= len_v),
                    cur_z3,
                    cur_extra,
                )
                return self._apply_bytes_uf(op, cur_z3[buf_name], idx_v, sub)

            if op in BYTES_WRITE_SPECS:
                buf_name = str(sub[1].val)
                idx_v = eval_checked(sub[2], cur_z3, cur_iv, cur_extra, guard)
                val_v = eval_checked(sub[3], cur_z3, cur_iv, cur_extra, guard)
                assert isinstance(idx_v, z3.ArithRef) and isinstance(val_v, z3.ArithRef)
                len_var, len_v = bytes_lengths[buf_name]
                width, max_val = BYTES_WRITE_SPECS[op]
                check_z3(
                    pb.E_OUT_OF_BOUNDS,
                    n.span,
                    pretty(n),
                    f"`{op}` write at `{pretty(sub[2])}` (+{width} bytes) may exceed `{buf_name}` length `{len_var}`",
                    guard,
                    z3.And(idx_v >= 0, idx_v + width <= len_v),
                    cur_z3,
                    cur_extra,
                )
                if max_val < U64_MAX:
                    val_iv = eval_interval(sub[3], cur_iv, self.fn_ret_ranges)
                    if 0 <= val_iv.lo and val_iv.hi <= max_val:
                        stats.tier0_interval_discharged += 1
                    else:
                        check_z3(
                            pb.E_PRECONDITION_FAILED,
                            sub[3].span,
                            pretty(n),
                            f"`{op}` value `{pretty(sub[3])}` may exceed `[0..{max_val}]`",
                            guard,
                            z3.And(val_v >= 0, val_v <= max_val),
                            cur_z3,
                            cur_extra,
                        )
                return z3.IntVal(width)

            if op == "fold":
                stats.o1_loop_steps += 1
                ivar = str(sub[1].val[0].val)
                bound_n = sub[1].val[1]
                avar = str(sub[2].val[0].val)
                init_n = sub[2].val[1]
                acc_t_node = sub[2].val[2]
                acc_is_i64 = acc_t_node.raw() == "i64" or (isinstance(acc_t_node.raw(), list) and acc_t_node.raw()[0] == "i64_range")
                acc_hw_lo, acc_hw_hi = (I64_MIN, I64_MAX) if acc_is_i64 else (0, U64_MAX)
                acc_lo_n, acc_hi_n = _extract_range_nodes(acc_t_node)
                step_n = sub[3]

                bound_v = eval_checked(bound_n, cur_z3, cur_iv, cur_extra, guard)
                init_v = eval_checked(init_n, cur_z3, cur_iv, cur_extra, guard)
                assert isinstance(bound_v, z3.ArithRef) and isinstance(init_v, z3.ArithRef)

                base_env = dict(cur_z3, **{ivar: z3.IntVal(0), avar: init_v})
                blo = self.eval_pure_spec(acc_lo_n, base_env)
                bhi = self.eval_pure_spec(acc_hi_n, base_env)
                check_z3(
                    pb.E_LOOP_BASE_FAILED,
                    sub[2].span,
                    pretty(sub[2]),
                    f"Initial `fold` accumulator fails `{pretty(acc_t_node)}` at `{ivar} = 0`",
                    guard,
                    z3.And(init_v >= blo, init_v <= bhi),
                    cur_z3,
                    cur_extra,
                )

                sym_i = z3.Int(ivar)
                sym_acc = z3.Int(avar)
                step_z3 = dict(cur_z3, **{ivar: sym_i, avar: sym_acc})
                b_iv = eval_interval(bound_n, cur_iv, self.fn_ret_ranges)
                step_iv = dict(cur_iv, **{ivar: Interval(0, max(0, b_iv.hi - 1))})
                acc_lo_min = eval_interval(acc_lo_n, dict(cur_iv, **{ivar: Interval(0, b_iv.hi)}), self.fn_ret_ranges).lo
                acc_hi_max = eval_interval(acc_hi_n, dict(cur_iv, **{ivar: Interval(0, b_iv.hi)}), self.fn_ret_ranges).hi
                step_iv[avar] = Interval(max(acc_hw_lo, acc_lo_min), min(acc_hw_hi, acc_hi_max))

                alo_i = self.eval_pure_spec(acc_lo_n, step_z3)
                ahi_i = self.eval_pure_spec(acc_hi_n, step_z3)
                ind_extra = list(cur_extra) + [
                    sym_i >= 0,
                    sym_i < bound_v,
                    sym_acc >= acc_hw_lo,
                    sym_acc <= acc_hw_hi,
                    sym_acc >= alo_i,
                    sym_acc <= ahi_i,
                ]
                next_acc = eval_checked(step_n, step_z3, step_iv, ind_extra, guard)
                assert isinstance(next_acc, z3.ArithRef)
                next_env = dict(step_z3, **{ivar: sym_i + 1, avar: next_acc})
                alo_next = self.eval_pure_spec(acc_lo_n, next_env)
                ahi_next = self.eval_pure_spec(acc_hi_n, next_env)
                check_z3(
                    pb.E_LOOP_STEP_FAILED,
                    step_n.span,
                    pretty(step_n),
                    f"Inductive `fold` step violates `{pretty(acc_t_node)}` at `{ivar} + 1`",
                    guard,
                    z3.And(next_acc >= alo_next, next_acc <= ahi_next, next_acc >= acc_hw_lo, next_acc <= acc_hw_hi),
                    step_z3,
                    ind_extra,
                )

                out_acc = self.fresh_int("_fold_out")
                exit_env = dict(cur_z3, **{ivar: bound_v, avar: out_acc})
                flo = self.eval_pure_spec(acc_lo_n, exit_env)
                fhi = self.eval_pure_spec(acc_hi_n, exit_env)
                axioms.extend([out_acc >= acc_hw_lo, out_acc <= acc_hw_hi, out_acc >= flo, out_acc <= fhi])
                return out_acc

            if op == "call":
                callee = str(sub[1].val)
                if callee not in self.fn_contracts:
                    return z3.IntVal(0)
                fc = self.fn_contracts[callee]
                callee_env: dict[str, Z3Value] = {}
                for (pname, pkind, plo_n, phi_n), arg_node in zip(fc.params, sub[2:]):
                    if pkind in ("slice", "mut_slice", "atomic_u64") or pkind in LINEAR_CAPS:
                        continue
                    if pkind in ("bytes", "mut_bytes"):
                        arg_buf_name = str(arg_node.val)
                        actual_len_var, actual_len_v = bytes_lengths[arg_buf_name]
                        callee_len_var = fc.bytes_len_params[pname]
                        passed_len_v = callee_env[callee_len_var]
                        assert isinstance(passed_len_v, z3.ArithRef)
                        check_z3(
                            pb.E_OUT_OF_BOUNDS,
                            arg_node.span,
                            pretty(n),
                            f"Passed byte slice length `{callee_len_var}` for `{pname}` in call to `{callee}` may exceed `{arg_buf_name}` length `{actual_len_var}`",
                            guard,
                            passed_len_v <= actual_len_v,
                            cur_z3,
                            cur_extra,
                        )
                        callee_env[pname] = cur_z3[arg_buf_name]
                        continue
                    av = eval_checked(arg_node, cur_z3, cur_iv, cur_extra, guard)
                    callee_env[pname] = av
                    if not pkind.startswith(("struct:", "enum:")):
                        assert isinstance(av, z3.ArithRef)
                        plo_v = self.eval_pure_spec(plo_n, callee_env)
                        phi_v = self.eval_pure_spec(phi_n, callee_env)
                        check_z3(
                            pb.E_PRECONDITION_FAILED,
                            arg_node.span,
                            pretty(n),
                            f"Argument `{pname}` to `{callee}` may violate precondition `[{pretty(plo_n)}..{pretty(phi_n)}]`",
                            guard,
                            z3.And(av >= plo_v, av <= phi_v),
                            cur_z3,
                            cur_extra,
                        )
                if fc.ret_kind.startswith(("struct:", "enum:")):
                    rdict = self.make_symbolic_value(
                        f"_{callee}_ret",
                        fc.ret_kind,
                        axioms,
                        callee_env,
                        None,
                        fresh_sym=True,
                    )
                    callee_env[fc.ret_name] = rdict
                    for ens in fc.ensures:
                        axioms.append(self.eval_pure_spec(ens, callee_env))
                    return rdict

                call_ret = self.fresh_int(f"_{callee}_ret")
                callee_env[fc.ret_name] = call_ret
                hw_lo, hw_hi = (I64_MIN, I64_MAX) if fc.ret_kind == "i64" else (0, U64_MAX)
                rlo_v = self.eval_pure_spec(fc.ret_lo, callee_env)
                rhi_v = self.eval_pure_spec(fc.ret_hi, callee_env)
                axioms.extend([call_ret >= hw_lo, call_ret <= hw_hi, call_ret >= rlo_v, call_ret <= rhi_v])
                for ens in fc.ensures:
                    axioms.append(self.eval_pure_spec(ens, callee_env))
                return call_ret

            if op in BITWISE_OPS:
                if nk == "u64":
                    stats.tier1_bitwuzla_queries += 1
                    bw_iv = verify_bitwise_subtree(n, cur_iv, name, self.fn_ret_ranges)
                    if op == ">>" and isinstance(sub[2].val, int) and 0 <= sub[2].val < 64:
                        lhs = eval_checked(sub[1], cur_z3, cur_iv, cur_extra, guard)
                        assert isinstance(lhs, z3.ArithRef)
                        return lhs / z3.IntVal(1 << sub[2].val)
                    bw_args = [eval_checked(a, cur_z3, cur_iv, cur_extra, guard) for a in sub[1:]]
                    bw_wit = self.fresh_int("_bv_out")
                    axioms.extend([bw_wit >= bw_iv.lo, bw_wit <= bw_iv.hi])
                    if op == "&":
                        lhs, rhs = bw_args[0], bw_args[1]
                        assert isinstance(lhs, z3.ArithRef) and isinstance(rhs, z3.ArithRef)
                        axioms.extend([bw_wit <= lhs, bw_wit <= rhs])
                    elif op == "|":
                        lhs, rhs = bw_args[0], bw_args[1]
                        assert isinstance(lhs, z3.ArithRef) and isinstance(rhs, z3.ArithRef)
                        axioms.extend([bw_wit >= lhs, bw_wit >= rhs])
                    return bw_wit
                else:
                    # Signed shift range check
                    bw_args = [eval_checked(a, cur_z3, cur_iv, cur_extra, guard) for a in sub[1:]]
                    if op in (">>", "<<"):
                        lhs, rhs = bw_args[0], bw_args[1]
                        assert isinstance(lhs, z3.ArithRef) and isinstance(rhs, z3.ArithRef)
                        check_z3(pb.E_SHIFT_OUT_OF_RANGE, n.span, pretty(n), "Shift count outside [0..63]", guard, z3.And(rhs >= 0, rhs < 64), cur_z3, cur_extra)
                        if op == ">>" and isinstance(sub[2].val, int):
                            return lhs / z3.IntVal(1 << sub[2].val)
                    bw_wit = self.fresh_int("_ibv_out")
                    axioms.extend([bw_wit >= I64_MIN, bw_wit <= I64_MAX])
                    return bw_wit

            args: list[Any] = [eval_checked(a, cur_z3, cur_iv, cur_extra, guard) for a in sub[1:]]
            iv = eval_interval(n, cur_iv, self.fn_ret_ranges)
            is_signed = nk == "i64"

            if op == "+":
                res = args[0] + args[1]
                if is_signed:
                    if iv.lo >= I64_MIN and iv.hi <= I64_MAX:
                        stats.tier0_interval_discharged += 1
                    else:
                        check_z3(pb.E_I64_OVERFLOW, n.span, pretty(n), "64-bit signed addition overflow", guard, z3.And(res >= I64_MIN, res <= I64_MAX), cur_z3, cur_extra)
                else:
                    if iv.hi <= U64_MAX:
                        stats.tier0_interval_discharged += 1
                    else:
                        check_z3(pb.E_U64_OVERFLOW, n.span, pretty(n), "64-bit unsigned addition overflow", guard, res <= U64_MAX, cur_z3, cur_extra)
                return res

            if op == "-":
                res = args[0] - args[1]
                if is_signed:
                    if iv.lo >= I64_MIN and iv.hi <= I64_MAX:
                        stats.tier0_interval_discharged += 1
                    else:
                        check_z3(pb.E_I64_OVERFLOW, n.span, pretty(n), "64-bit signed subtraction overflow", guard, z3.And(res >= I64_MIN, res <= I64_MAX), cur_z3, cur_extra)
                else:
                    if iv.lo >= 0:
                        stats.tier0_interval_discharged += 1
                    else:
                        check_z3(pb.E_U64_UNDERFLOW, n.span, pretty(n), "64-bit unsigned subtraction underflow", guard, res >= 0, cur_z3, cur_extra)
                return res

            if op == "*":
                res = args[0] * args[1]
                if is_signed:
                    if iv.lo >= I64_MIN and iv.hi <= I64_MAX:
                        stats.tier0_interval_discharged += 1
                    else:
                        check_z3(pb.E_I64_OVERFLOW, n.span, pretty(n), "64-bit signed multiplication overflow", guard, z3.And(res >= I64_MIN, res <= I64_MAX), cur_z3, cur_extra)
                else:
                    if iv.hi <= U64_MAX:
                        stats.tier0_interval_discharged += 1
                    else:
                        check_z3(pb.E_U64_OVERFLOW, n.span, pretty(n), "64-bit unsigned multiplication overflow", guard, res <= U64_MAX, cur_z3, cur_extra)
                return res

            if op in ("/", "%"):
                rhs_iv = eval_interval(sub[2], cur_iv, self.fn_ret_ranges)
                if rhs_iv.lo > 0 or rhs_iv.hi < 0:
                    stats.tier0_interval_discharged += 1
                else:
                    check_z3(pb.E_DIV_BY_ZERO, n.span, pretty(n), "Division or modulo by zero", guard, args[1] != 0, cur_z3, cur_extra)
                if is_signed:
                    if op == "/":
                        check_z3(
                            pb.E_I64_OVERFLOW,
                            n.span,
                            pretty(n),
                            "Signed division `MIN_I64 / -1` overflows 64-bit two's complement",
                            guard,
                            z3.Not(z3.And(args[0] == I64_MIN, args[1] == -1)),
                            cur_z3,
                            cur_extra,
                        )
                        return _z3_trunc_div(args[0], args[1])
                    return _z3_trunc_rem(args[0], args[1])
                return args[0] / args[1] if op == "/" else args[0] % args[1]

            if op == "min":
                return z3.If(args[0] <= args[1], args[0], args[1])
            if op == "max":
                return z3.If(args[0] >= args[1], args[0], args[1])
            if op in ("mul_div_u64", "mul_div_ceil_u64"):
                a_v, b_v, d_v = args[0], args[1], args[2]
                d_iv = eval_interval(sub[3], cur_iv, self.fn_ret_ranges)
                if d_iv.lo > 0:
                    stats.tier0_interval_discharged += 1
                else:
                    check_z3(
                        pb.E_DIV_BY_ZERO,
                        sub[3].span,
                        pretty(n),
                        f"`{op}` divisor `{pretty(sub[3])}` may be zero",
                        guard,
                        d_v > 0,
                        cur_z3,
                        cur_extra,
                    )
                if op == "mul_div_u64":
                    res = (a_v * b_v) / d_v
                else:
                    res = z3.If(z3.Or(a_v == 0, b_v == 0), z3.IntVal(0), ((a_v * b_v - 1) / d_v) + 1)
                if iv.lo >= 0 and iv.hi <= U64_MAX:
                    stats.tier0_interval_discharged += 1
                else:
                    check_z3(
                        pb.E_U64_OVERFLOW,
                        n.span,
                        pretty(n),
                        f"64-bit unsigned `{op}` quotient exceeds U64_MAX",
                        guard,
                        z3.And(res >= 0, res <= U64_MAX),
                        cur_z3,
                        cur_extra,
                    )
                return res
            if op in ("==", "!=", "<", "<=", ">", ">="):
                if op in ("==", "!=") and isinstance(args[0], dict) and isinstance(args[1], dict):
                    eq_ref = _z3_dict_eq(args[0], args[1])
                    return eq_ref if op == "==" else z3.Not(eq_ref)
                return {
                    "==": lambda x, y: x == y,
                    "!=": lambda x, y: x != y,
                    "<": lambda x, y: x < y,
                    "<=": lambda x, y: x <= y,
                    ">": lambda x, y: x > y,
                    ">=": lambda x, y: x >= y,
                }[op](args[0], args[1])
            if op == "and":
                return z3.And(*args)
            if op == "or":
                return z3.Or(*args)
            if op == "not":
                return z3.Not(args[0])
            raise NotImplementedError(op)

        out_val = eval_checked(body_node, z3_env, iv_env, [], z3.BoolVal(True))
        rname, rlo_n, rhi_n, ensures_list = _extract_ret_spec(ret_node, self.tenv.structs, self.tenv.enums)
        if sig.ret_kind not in LINEAR_CAPS:
            renv = dict(z3_env, **{rname: out_val})
            if not sig.ret_kind.startswith(("struct:", "enum:")):
                assert isinstance(out_val, z3.ArithRef)
                rlo_v = self.eval_pure_spec(rlo_n, renv)
                rhi_v = self.eval_pure_spec(rhi_n, renv)
                check_z3(
                    pb.E_POSTCONDITION_FAILED,
                    ret_node.span,
                    pretty(ret_node),
                    f"Return value violates range `[{pretty(rlo_n)}..{pretty(rhi_n)}]`",
                    z3.BoolVal(True),
                    z3.And(out_val >= rlo_v, out_val <= rhi_v),
                    z3_env,
                )
            for ens in ensures_list:
                ec = self.eval_pure_spec(ens, renv)
                assert isinstance(ec, z3.BoolRef)
                check_z3(
                    pb.E_POSTCONDITION_FAILED,
                    ens.span,
                    pretty(ens),
                    f"Postcondition `{pretty(ens)}` failed",
                    z3.BoolVal(True),
                    ec,
                    z3_env,
                )

        if not is_main:
            self.fn_contracts[name] = FnContractInfo(
                name,
                param_contracts,
                rname,
                sig.ret_kind,
                rlo_n,
                rhi_n,
                ensures_list,
                bytes_len_params,
            )
            if not sig.ret_kind.startswith(("struct:", "enum:")):
                self.fn_ret_ranges[name] = ([p[0] for p in param_contracts], rlo_n.raw(), rhi_n.raw())

        stats.verified = True
        stats.elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return stats

    def verify_map_inplace(self, form: SNode) -> pb.FunctionProofStats:
        t0 = time.perf_counter()
        items = form.val
        name = str(items[1].val)
        params_node, ret_node, elem_vars, body_node = items[2], items[3], items[4], items[5]
        elem_var = str(elem_vars.val[0].val)

        synth_params: list[SNode] = []
        elem_type_node: SNode | None = None
        for p in params_node.val:
            pspec = p.val[1]
            praw = pspec.raw()
            if isinstance(praw, list) and praw[0] == "mut_slice":
                elem_type_node = pspec.val[2]
            else:
                synth_params.append(p)
        assert elem_type_node is not None
        synth_params.append(SNode([SNode(elem_var, elem_vars.span), elem_type_node], elem_vars.span))
        synth_fn = SNode(
            [SNode("fn", form.span), SNode(name, items[1].span), SNode(synth_params, params_node.span), ret_node, body_node],
            form.span,
        )
        # Re-run ownership on synth_fn alongside existing structs/enums/specs so expr_types has scalar type tags
        sub_tenv = check_module_ownership_v2([f for f in getattr(self, "_all_forms", []) if str(f.val[0].val) in ("struct", "enum", "spec")] + [synth_fn])
        old_tenv = self.tenv
        assert old_tenv is not None
        sub_tenv.sigs.update({k: v for k, v in old_tenv.sigs.items() if k != name})
        self.tenv = sub_tenv
        try:
            st = self.verify_function_like(synth_fn, is_main=False)
        finally:
            self.tenv = old_tenv
        st.o1_loop_steps += 1
        st.elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return st

    def verify_atomic_protocol(self, form: SNode) -> pb.FunctionProofStats:
        t0 = time.perf_counter()
        items = form.val
        pname = str(items[1].val)
        fields_node = items[2]
        inv_node = items[3]
        step_nodes = items[4:]

        stats = pb.FunctionProofStats(item_name=pname, verified=False)
        field_names = [str(f.val[0].val) for f in fields_node.val]
        steps_dict: dict[str, tuple[list[tuple[str, SNode, SNode]], list[SNode], Span]] = {}

        for sn in step_nodes:
            sname = str(sn.val[1].val)
            sparams_n = sn.val[2]
            next_tuple_n = sn.val[3]

            env: dict[str, Z3Value] = {}
            pre: list[z3.BoolRef] = []
            for fnm in field_names:
                v = z3.Int(fnm)
                pre.extend([v >= 0, v <= U64_MAX])
                env[fnm] = v
            inv_pre = self.eval_pure_spec(inv_node, env)
            assert isinstance(inv_pre, z3.BoolRef)
            pre.append(inv_pre)

            sparam_specs: list[tuple[str, SNode, SNode]] = []
            for sp in sparams_n.val:
                sp_name = str(sp.val[0].val)
                lo_n, hi_n = _extract_range_nodes(sp.val[1])
                sv = z3.Int(sp_name)
                pre.extend([sv >= 0, sv <= U64_MAX, sv >= self.eval_pure_spec(lo_n, env), sv <= self.eval_pure_spec(hi_n, env)])
                env[sp_name] = sv
                sparam_specs.append((sp_name, lo_n, hi_n))

            next_exprs = next_tuple_n.val
            next_env: dict[str, Z3Value] = {}
            bounds_ok: list[z3.BoolRef] = []
            for fnm, ne in zip(field_names, next_exprs):
                nv = self.eval_pure_spec(ne, env)
                assert isinstance(nv, z3.ArithRef)
                next_env[fnm] = nv
                bounds_ok.extend([nv >= 0, nv <= U64_MAX])

            inv_after = self.eval_pure_spec(inv_node, next_env)
            assert isinstance(inv_after, z3.BoolRef)
            stats.tier2_z3_queries += 1
            s = z3.Solver()
            s.set("timeout", 4000)
            s.add(*pre, z3.Not(z3.And(*bounds_ok, inv_after)))
            res = s.check()
            if res != z3.unsat:
                ce = {}
                if res == z3.sat:
                    m = s.model()
                    ce = {k: m.eval(v, model_completion=True).as_long() for k, v in env.items() if isinstance(v, z3.ArithRef)}
                raise AILCompilerError(
                    pb.E_ATOMIC_INVARIANT_FAILED,
                    pb.STAGE_TIER2_Z3,
                    f"{pname}.{sname}",
                    f"Concurrent atomic step `{sname}` violates sharded protocol `{pname}` invariant or overflows u64",
                    sn.span,
                    pretty(sn),
                    ce,
                )
            steps_dict[sname] = (sparam_specs, next_exprs, sn.span)

        self.protocols[pname] = AtomicProtoInfo(pname, field_names, inv_node, steps_dict)
        stats.verified = True
        stats.elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return stats

    def verify_module(self, forms: list[SNode]) -> list[pb.FunctionProofStats]:
        self._all_forms = forms
        if self.tenv is None:
            self.tenv = check_module_ownership_v2(forms)
        out: list[pb.FunctionProofStats] = []
        for form in forms:
            head = str(form.val[0].val)
            if head in ("struct", "enum"):
                continue
            if head == "spec":
                sname = str(form.val[1].val)
                pnames = [str(p.val[0].val) for p in form.val[2].val]
                self.specs[sname] = SpecDeclInfo(sname, pnames, form.val[3])
            elif head == "fn":
                out.append(self.verify_function_like(form, is_main=False))
            elif head == "main":
                out.append(self.verify_function_like(form, is_main=True))
            elif head == "map_inplace":
                out.append(self.verify_map_inplace(form))
            elif head == "atomic_protocol":
                out.append(self.verify_atomic_protocol(form))
            elif head == "atomic_cas":
                t0 = time.perf_counter()
                cname = str(form.val[1].val)
                pname = str(form.val[2].val)
                sname = str(form.val[3].val)
                if pname not in self.protocols or sname not in self.protocols[pname].steps:
                    raise AILCompilerError(pb.E_UNBOUND_SYMBOL, pb.STAGE_TIER2_Z3, cname, f"Unknown protocol step `{pname}.{sname}`", form.span, pretty(form))
                out.append(pb.FunctionProofStats(item_name=cname, verified=True, elapsed_ms=(time.perf_counter() - t0) * 1000.0))
        return out
