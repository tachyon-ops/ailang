"""ISO C11 Backend: Strictly Warning-Free C11 + C ABI Header Code Generator."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import platform
import re
import subprocess

from ailang.diagnostics import I64_MAX, I64_MIN, U64_MAX
from ailang.ownership import (
    EnumDef,
    LINEAR_CAPS,
    ModuleTypeEnv,
    StructDef,
    check_module_ownership_v2,
    kind_u64_slots,
)
from ailang.parser import SNode

_C11_KEYWORDS = frozenset(
    {
        "auto",
        "break",
        "case",
        "char",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extern",
        "float",
        "for",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "register",
        "restrict",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "struct",
        "switch",
        "typedef",
        "union",
        "unsigned",
        "void",
        "volatile",
        "while",
        "_Alignas",
        "_Alignof",
        "_Atomic",
        "_Bool",
        "_Complex",
        "_Generic",
        "_Imaginary",
        "_Noreturn",
        "_Static_assert",
        "_Thread_local",
        "bool",
        "true",
        "false",
    }
)


@dataclass(frozen=True)
class CArtifacts:
    c_source_path: str
    c_header_path: str
    shared_lib_path: str


@dataclass
class _CExport:
    name: str
    ret_c: str
    params_c: list[tuple[str, str]]


def _slice_elem_is_i64(pspec: SNode) -> bool:
    elem_raw = pspec.val[2].raw()
    return elem_raw == "i64" or (isinstance(elem_raw, list) and bool(elem_raw) and elem_raw[0] == "i64_range")


def _safe_c_ident(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"v_{cleaned}"
    if cleaned in _C11_KEYWORDS:
        cleaned = f"{cleaned}_v"
    return cleaned


def _c_value_type(kind: str) -> str:
    if kind == "i64":
        return "int64_t"
    if kind == "bool":
        return "bool"
    if kind.startswith("struct:"):
        return kind.split(":", 1)[1]
    if kind.startswith("enum:"):
        return kind.split(":", 1)[1]
    return "uint64_t"


def _c_zero_init(kind: str, structs: dict[str, StructDef] | None = None) -> str:
    if kind == "i64":
        return "INT64_C(0)"
    if kind == "bool":
        return "false"
    if kind.startswith("struct:") and structs is not None:
        sdef = structs[kind.split(":", 1)[1]]
        inits = ", ".join(_c_zero_init(fd.kind, structs) for fd in sdef.fields) or "UINT64_C(0)"
        return f"{{ {inits} }}"
    if kind.startswith(("struct:", "enum:")):
        return "{ 0 }"
    return "UINT64_C(0)"


def _format_int_lit(val: int, kind: str) -> str:
    if kind == "i64":
        if val == I64_MIN:
            return "INT64_MIN"
        if val == I64_MAX:
            return "INT64_MAX"
        return f"INT64_C({val})"
    if val == U64_MAX:
        return "UINT64_MAX"
    return f"UINT64_C({val})"


def _has_aggregate_boundary(ret_kind: str, param_kinds: list[str]) -> bool:
    return ret_kind.startswith(("struct:", "enum:")) or any(
        pk.startswith(("struct:", "enum:")) for pk in param_kinds
    )


class CFunctionEmitter:
    """Statement-lowering ISO C11 emitter for a single AIL function or body."""

    def __init__(
        self,
        tenv: ModuleTypeEnv,
        var_kinds: dict[str, str],
        slice_elem_kinds: dict[str, str],
        consts: dict[str, tuple[str, int]],
        used_helpers: set[str],
        used_locals: set[str],
    ) -> None:
        self.tenv = tenv
        self.var_kinds = dict(var_kinds)
        self.slice_elem_kinds = dict(slice_elem_kinds)
        self.consts = consts
        self.used_helpers = used_helpers
        self.used_locals = set(used_locals)
        self.tmp_counter = 0
        self.lines: list[str] = []
        self.uses_io = False
        self.uses_fs = False
        self.uses_net = False
        self.uses_bool = False

    def fresh_tmp(self, prefix: str = "ail_t") -> str:
        while True:
            self.tmp_counter += 1
            cand = f"{prefix}{self.tmp_counter}"
            if cand not in self.used_locals:
                self.used_locals.add(cand)
                return cand

    def bind_local(self, ail_name: str) -> str:
        base = _safe_c_ident(ail_name)
        if base not in self.used_locals and not base.startswith("ail_"):
            self.used_locals.add(base)
            return base
        idx = 1
        while f"{base}_{idx}" in self.used_locals:
            idx += 1
        cand = f"{base}_{idx}"
        self.used_locals.add(cand)
        return cand

    def _raw_kind(self, node: SNode) -> str:
        if id(node) in self.tenv.expr_types:
            return self.tenv.expr_types[id(node)]
        if isinstance(node.val, int):
            return "i64" if node.val < 0 else "lit_pos"
        if isinstance(node.val, str):
            if node.val == "MAX":
                return "u64"
            if node.val in ("MIN_I64", "MAX_I64"):
                return "i64"
            if node.val in self.var_kinds:
                return self.var_kinds[node.val]
            if node.val in self.consts:
                return self.consts[node.val][0]
        return "u64"

    def _node_kind(self, node: SNode) -> str:
        rk = self._raw_kind(node)
        return "u64" if rk == "lit_pos" else rk

    def _use(self, helper: str) -> str:
        self.used_helpers.add(helper)
        return helper

    def _emit_c_flatten_slots(self, expr: str, kind: str, indent: str) -> list[str]:
        if kind == "u64":
            return [expr]
        if kind == "i64":
            return [f"(uint64_t)({expr})"]
        if kind.startswith("struct:"):
            sname = kind.split(":", 1)[1]
            sdef = self.tenv.structs[sname]
            tmp_s = self.fresh_tmp("ail_fl")
            self.lines.append(f"{indent}{sname} {tmp_s} = {expr};")
            out: list[str] = []
            for fd in sdef.fields:
                out.extend(self._emit_c_flatten_slots(f"{tmp_s}.{fd.name}", fd.kind, indent))
            return out or ["UINT64_C(0)"]
        if kind.startswith("enum:"):
            ename = kind.split(":", 1)[1]
            edef = self.tenv.enums[ename]
            tmp_e = self.fresh_tmp("ail_fl")
            self.lines.append(f"{indent}{ename} {tmp_e} = {expr};")
            nslots = edef.max_payload_slots(self.tenv.structs, self.tenv.enums)
            return [f"{tmp_e}.tag", *[f"{tmp_e}._p{i}" for i in range(nslots)]]
        return [expr]

    def _emit_c_unflatten(
        self,
        slots: list[str],
        kind: str,
        offset: int = 0,
        indent: str = "    ",
    ) -> tuple[str, int]:
        if kind == "u64":
            return slots[offset], offset + 1
        if kind == "i64":
            return f"{self._use('ail_u64_to_i64')}({slots[offset]})", offset + 1
        if kind.startswith("struct:"):
            sname = kind.split(":", 1)[1]
            sdef = self.tenv.structs[sname]
            cur_off = offset
            fexprs: list[str] = []
            for fd in sdef.fields:
                fe, cur_off = self._emit_c_unflatten(slots, fd.kind, cur_off, indent)
                fexprs.append(fe)
            s_var = self.fresh_tmp("ail_uf")
            init_s = ", ".join(fexprs) if fexprs else "UINT64_C(0)"
            self.lines.append(f"{indent}{sname} {s_var} = {{ {init_s} }};")
            return s_var, cur_off
        if kind.startswith("enum:"):
            ename = kind.split(":", 1)[1]
            edef = self.tenv.enums[ename]
            nslots = edef.max_payload_slots(self.tenv.structs, self.tenv.enums)
            e_var = self.fresh_tmp("ail_uf")
            self.lines.append(f"{indent}{ename} {e_var} = {{ 0 }};")
            self.lines.append(f"{indent}{e_var}.tag = {slots[offset]};")
            for i in range(nslots):
                self.lines.append(f"{indent}{e_var}._p{i} = {slots[offset + 1 + i]};")
            return e_var, offset + 1 + nslots
        return slots[offset], offset + 1

    def _emit_into(self, target_var: str, node: SNode, env: dict[str, str], target_kind: str, indent: str) -> None:
        val = self.emit_expr(node, env, target_kind=target_kind, indent=indent)
        if val:
            self.lines.append(f"{indent}{target_var} = {val};")

    def emit_expr(
        self,
        node: SNode,
        env: dict[str, str],
        target_kind: str | None = None,
        indent: str = "    ",
    ) -> str:
        nk = self._node_kind(node)
        eff_kind = target_kind if target_kind is not None else nk

        if isinstance(node.val, int):
            lit_kind = eff_kind if (eff_kind in ("i64", "u64") and (node.val < 0 or eff_kind == "i64")) else nk
            return _format_int_lit(node.val, lit_kind)

        if isinstance(node.val, str):
            sym = node.val
            if sym == "MAX":
                return "UINT64_MAX"
            if sym == "MIN_I64":
                return "INT64_MIN"
            if sym == "MAX_I64":
                return "INT64_MAX"
            if sym in self.consts and sym not in env:
                ck, cval = self.consts[sym]
                return _format_int_lit(cval, eff_kind if eff_kind in ("i64", "u64") else ck)
            return env.get(sym, "")

        items = node.val
        op = str(items[0].val)

        if op == "let":
            nenv = dict(env)
            saved_vk = dict(self.var_kinds)
            try:
                if nk in LINEAR_CAPS:
                    self.lines.append(f"{indent}{{")
                    for b in items[1].val:
                        self._emit_let_binding(b, nenv, indent + "    ")
                    _ = self.emit_expr(items[2], nenv, target_kind=nk, indent=indent + "    ")
                    self.lines.append(f"{indent}}}")
                    return ""
                if nk == "bool":
                    self.uses_bool = True
                res_var = self.fresh_tmp()
                res_ty = _c_value_type(nk)
                self.lines.append(f"{indent}{res_ty} {res_var} = {_c_zero_init(nk, self.tenv.structs)};")
                self.lines.append(f"{indent}{{")
                for b in items[1].val:
                    self._emit_let_binding(b, nenv, indent + "    ")
                self._emit_into(res_var, items[2], nenv, eff_kind, indent + "    ")
                self.lines.append(f"{indent}}}")
                return res_var
            finally:
                self.var_kinds = saved_vk

        if op == "if":
            cond_expr = self.emit_expr(items[1], env, target_kind="bool", indent=indent)
            self.uses_bool = True
            cond_var = self.fresh_tmp("ail_c")
            self.lines.append(f"{indent}bool {cond_var} = {cond_expr};")
            if nk in LINEAR_CAPS:
                self.lines.append(f"{indent}if ({cond_var}) {{")
                _ = self.emit_expr(items[2], env, target_kind=nk, indent=indent + "    ")
                self.lines.append(f"{indent}}} else {{")
                _ = self.emit_expr(items[3], env, target_kind=nk, indent=indent + "    ")
                self.lines.append(f"{indent}}}")
                return ""
            res_var = self.fresh_tmp()
            res_ty = _c_value_type(nk)
            self.lines.append(f"{indent}{res_ty} {res_var} = {_c_zero_init(nk, self.tenv.structs)};")
            self.lines.append(f"{indent}if ({cond_var}) {{")
            self._emit_into(res_var, items[2], env, eff_kind, indent + "    ")
            self.lines.append(f"{indent}}} else {{")
            self._emit_into(res_var, items[3], env, eff_kind, indent + "    ")
            self.lines.append(f"{indent}}}")
            return res_var

        if op == "to_i64":
            arg_n = items[1]
            if isinstance(arg_n.val, int) and 0 <= arg_n.val <= I64_MAX:
                return _format_int_lit(arg_n.val, "i64")
            av = self.emit_expr(arg_n, env, target_kind="u64", indent=indent)
            return f"{self._use('ail_u64_to_i64')}({av})"

        if op == "to_u64":
            arg_n = items[1]
            if isinstance(arg_n.val, int) and arg_n.val >= 0:
                return _format_int_lit(arg_n.val, "u64")
            arg_k = "i64" if self._raw_kind(arg_n) == "i64" else "u64"
            av = self.emit_expr(arg_n, env, target_kind=arg_k, indent=indent)
            return f"(uint64_t)({av})"

        if op == "make":
            sname = str(items[1].val)
            sdef = self.tenv.structs[sname]
            fvals = [self.emit_expr(fa, env, target_kind=fd.kind, indent=indent) for fa, fd in zip(items[2:], sdef.fields)]
            s_var = self.fresh_tmp()
            self.lines.append(f"{indent}{sname} {s_var} = {{ {', '.join(fvals)} }};")
            return s_var

        if op == "field":
            sv = self.emit_expr(items[1], env, indent=indent)
            fname = str(items[2].val)
            return f"{sv}.{fname}"

        if op == "variant":
            ename = str(items[1].val)
            vname = str(items[2].val)
            edef = self.tenv.enums[ename]
            vdef = edef.get_variant(vname)
            assert vdef is not None
            e_var = self.fresh_tmp()
            self.lines.append(f"{indent}{ename} {e_var} = {{ 0 }};")
            self.lines.append(f"{indent}{e_var}.tag = UINT64_C({vdef.tag});")
            slot_idx = 0
            for arg_n, fd in zip(items[3:], vdef.fields):
                av = self.emit_expr(arg_n, env, target_kind=fd.kind, indent=indent)
                for slot_e in self._emit_c_flatten_slots(av, fd.kind, indent=indent):
                    self.lines.append(f"{indent}{e_var}._p{slot_idx} = {slot_e};")
                    slot_idx += 1
            return e_var

        if op == "is_variant":
            sv_node = items[1]
            ename = self._node_kind(sv_node).split(":", 1)[1]
            vdef = self.tenv.enums[ename].get_variant(str(items[2].val))
            assert vdef is not None
            sv = self.emit_expr(sv_node, env, indent=indent)
            return f"({sv}.tag == UINT64_C({vdef.tag}))"

        if op == "match":
            scrut_n = items[1]
            ename = self._node_kind(scrut_n).split(":", 1)[1]
            edef = self.tenv.enums[ename]
            scrut_expr = self.emit_expr(scrut_n, env, indent=indent)
            scrut_var = self.fresh_tmp("ail_scrut")
            self.lines.append(f"{indent}{ename} {scrut_var} = {scrut_expr};")

            is_cap = nk in LINEAR_CAPS
            res_var = ""
            if not is_cap:
                if nk == "bool":
                    self.uses_bool = True
                res_var = self.fresh_tmp()
                self.lines.append(f"{indent}{_c_value_type(nk)} {res_var} = {_c_zero_init(nk, self.tenv.structs)};")

            arms = items[2:]
            has_wildcard = any(isinstance(arm.val[0].val, str) and arm.val[0].val == "_" for arm in arms)
            self.lines.append(f"{indent}switch ({scrut_var}.tag) {{")
            for idx, arm in enumerate(arms):
                pat, arm_body = arm.val[0], arm.val[1]
                is_wild = isinstance(pat.val, str) and pat.val == "_"
                is_last = idx == len(arms) - 1
                if is_wild:
                    self.lines.append(f"{indent}    default: {{")
                else:
                    vname = str(pat.val[0].val)
                    vdef = edef.get_variant(vname)
                    assert vdef is not None
                    self.lines.append(f"{indent}    case UINT64_C({vdef.tag}):")
                    if is_last and not has_wildcard:
                        self.lines.append(f"{indent}    default:")
                    self.lines[-1] = self.lines[-1] + " {"
                arm_env = dict(env)
                saved_vk = dict(self.var_kinds)
                try:
                    if not is_wild:
                        vdef = edef.get_variant(str(pat.val[0].val))
                        assert vdef is not None
                        slot_off = 0
                        for bnode, fd in zip(pat.val[1:], vdef.fields):
                            bname = str(bnode.val)
                            c_bname = self.bind_local(bname)
                            self.var_kinds[bname] = fd.kind
                            arm_env[bname] = c_bname
                            needed = kind_u64_slots(fd.kind, self.tenv.structs, self.tenv.enums)
                            slots = [f"{scrut_var}._p{slot_off + i}" for i in range(needed)]
                            slot_off += needed
                            val_expr, _ = self._emit_c_unflatten(slots, fd.kind, 0, indent + "        ")
                            self.lines.append(f"{indent}        {_c_value_type(fd.kind)} {c_bname} = {val_expr};")
                            self.lines.append(f"{indent}        (void){c_bname};")
                    if is_cap:
                        _ = self.emit_expr(arm_body, arm_env, target_kind=nk, indent=indent + "        ")
                    else:
                        self._emit_into(res_var, arm_body, arm_env, eff_kind, indent + "        ")
                finally:
                    self.var_kinds = saved_vk
                self.lines.append(f"{indent}        break;")
                self.lines.append(f"{indent}    }}")
            self.lines.append(f"{indent}}}")
            return res_var

        if op == "io.print_u64":
            self.uses_io = True
            _ = self.emit_expr(items[1], env, indent=indent)
            val = self.emit_expr(items[2], env, target_kind="u64", indent=indent)
            self.lines.append(f'{indent}printf("%llu\\n", (unsigned long long)({val}));')
            return ""

        if op == "io.print_i64":
            self.uses_io = True
            _ = self.emit_expr(items[1], env, indent=indent)
            val = self.emit_expr(items[2], env, target_kind="i64", indent=indent)
            self.lines.append(f'{indent}printf("%lld\\n", (long long)({val}));')
            return ""

        if op == "io.done":
            self.uses_io = True
            _ = self.emit_expr(items[1], env, indent=indent)
            ret_v = self.emit_expr(items[2], env, target_kind=eff_kind, indent=indent)
            self.lines.append(f"{indent}fflush(NULL);")
            return ret_v

        if op == "fs.write_u64":
            self.uses_fs = True
            _ = self.emit_expr(items[1], env, indent=indent)
            val = self.emit_expr(items[2], env, target_kind="u64", indent=indent)
            self.lines.append(f"{indent}{self._use('ail_fs_write_u64')}({val});")
            return ""

        if op == "fs.write_i64":
            self.uses_fs = True
            _ = self.emit_expr(items[1], env, indent=indent)
            val = self.emit_expr(items[2], env, target_kind="i64", indent=indent)
            self.lines.append(f"{indent}{self._use('ail_fs_write_i64')}({val});")
            return ""

        if op in ("fs.close", "net.close"):
            _ = self.emit_expr(items[1], env, indent=indent)
            return "UINT64_C(0)"

        if op == "net.loopback_send_u64":
            self.uses_net = True
            _ = self.emit_expr(items[1], env, indent=indent)
            port_v = self.emit_expr(items[2], env, target_kind="u64", indent=indent)
            payload_v = self.emit_expr(items[3], env, target_kind="u64", indent=indent)
            self.lines.append(f"{indent}{self._use('ail_net_loopback_u64')}({port_v}, {payload_v});")
            return ""

        if op == "get":
            buf_name = str(items[1].val)
            buf_c = env[buf_name]
            idx_v = self.emit_expr(items[2], env, target_kind="u64", indent=indent)
            el_kind = self.slice_elem_kinds.get(buf_name, "u64")
            elem_expr = f"{buf_c}[{idx_v}]"
            if el_kind == "i64" and eff_kind == "u64":
                return f"(uint64_t)({elem_expr})"
            if el_kind == "u64" and eff_kind == "i64":
                return f"{self._use('ail_u64_to_i64')}({elem_expr})"
            return elem_expr

        if op == "byte_at":
            buf_c = self.emit_expr(items[1], env, indent=indent)
            idx_v = self.emit_expr(items[2], env, target_kind="u64", indent=indent)
            return f"(uint64_t)({buf_c}[{idx_v}])"

        if op == "read_u16_be":
            buf_c = self.emit_expr(items[1], env, indent=indent)
            idx_v = self.emit_expr(items[2], env, target_kind="u64", indent=indent)
            return f"{self._use('ail_read_u16_be')}({buf_c}, {idx_v})"

        if op == "read_u32_be":
            buf_c = self.emit_expr(items[1], env, indent=indent)
            idx_v = self.emit_expr(items[2], env, target_kind="u64", indent=indent)
            return f"{self._use('ail_read_u32_be')}({buf_c}, {idx_v})"

        if op == "read_u64_be":
            buf_c = self.emit_expr(items[1], env, indent=indent)
            idx_v = self.emit_expr(items[2], env, target_kind="u64", indent=indent)
            return f"{self._use('ail_read_u64_be')}({buf_c}, {idx_v})"

        if op in ("read_u16_le", "read_u32_le", "read_u64_le"):
            buf_c = self.emit_expr(items[1], env, indent=indent)
            idx_v = self.emit_expr(items[2], env, target_kind="u64", indent=indent)
            return f"{self._use(f'ail_{op}')}({buf_c}, {idx_v})"

        if op in ("write_byte", "write_u16_be", "write_u32_be", "write_u64_be", "write_u16_le", "write_u32_le", "write_u64_le"):
            buf_c = self.emit_expr(items[1], env, indent=indent)
            idx_v = self.emit_expr(items[2], env, target_kind="u64", indent=indent)
            val_v = self.emit_expr(items[3], env, target_kind="u64", indent=indent)
            return f"{self._use(f'ail_{op}')}({buf_c}, {idx_v}, {val_v})"

        if op in ("mul_div_u64", "mul_div_ceil_u64"):
            a_v = self.emit_expr(items[1], env, target_kind="u64", indent=indent)
            b_v = self.emit_expr(items[2], env, target_kind="u64", indent=indent)
            d_v = self.emit_expr(items[3], env, target_kind="u64", indent=indent)
            return f"{self._use(f'ail_{op}')}({a_v}, {b_v}, {d_v})"

        if op == "bytes_eq4":
            buf_c = self.emit_expr(items[1], env, indent=indent)
            idx_v = self.emit_expr(items[2], env, target_kind="u64", indent=indent)
            bvals = [self.emit_expr(b, env, target_kind="u64", indent=indent) for b in items[3:7]]
            b_args = ", ".join(f"(uint8_t)({bv})" for bv in bvals)
            return f"{self._use('ail_bytes_eq4')}({buf_c}, {idx_v}, {b_args})"

        if op == "fold":
            ivar = str(items[1].val[0].val)
            bound_v = self.emit_expr(items[1].val[1], env, target_kind="u64", indent=indent)
            avar = str(items[2].val[0].val)
            init_v = self.emit_expr(items[2].val[1], env, target_kind=nk, indent=indent)

            acc_var = self.fresh_tmp("ail_acc")
            bound_var = self.fresh_tmp("ail_n")
            iter_var = self.fresh_tmp("ail_i")
            acc_ty = _c_value_type(nk)

            self.lines.append(f"{indent}{acc_ty} {acc_var} = {init_v};")
            self.lines.append(f"{indent}uint64_t {bound_var} = {bound_v};")
            self.lines.append(
                f"{indent}for (uint64_t {iter_var} = UINT64_C(0); {iter_var} < {bound_var}; ++{iter_var}) {{"
            )
            c_ivar = self.bind_local(ivar)
            c_avar = self.bind_local(avar)
            saved_vk = dict(self.var_kinds)
            try:
                self.var_kinds[ivar] = "u64"
                self.var_kinds[avar] = nk
                self.lines.append(f"{indent}    uint64_t {c_ivar} = {iter_var};")
                self.lines.append(f"{indent}    (void){c_ivar};")
                self.lines.append(f"{indent}    {acc_ty} {c_avar} = {acc_var};")
                self.lines.append(f"{indent}    (void){c_avar};")
                step_env = dict(env, **{ivar: c_ivar, avar: c_avar})
                self._emit_into(acc_var, items[3], step_env, nk, indent + "    ")
            finally:
                self.var_kinds = saved_vk
            self.lines.append(f"{indent}}}")
            return acc_var

        if op == "call":
            callee = str(items[1].val)
            sig = self.tenv.sigs[callee]
            use_impl = sig.kind == "fn" and _has_aggregate_boundary(sig.ret_kind, sig.param_kinds)
            c_callee = f"ail_impl_{callee}" if use_impl else callee

            c_args: list[str] = []
            for arg_node, pk in zip(items[2:], sig.param_kinds):
                if pk in LINEAR_CAPS:
                    _ = self.emit_expr(arg_node, env, indent=indent)
                    continue
                c_args.append(self.emit_expr(arg_node, env, target_kind=pk, indent=indent))

            arg_str = ", ".join(c_args)
            if sig.kind == "map_inplace" or sig.ret_kind in LINEAR_CAPS:
                self.lines.append(f"{indent}{c_callee}({arg_str});")
                return ""
            ret_ty = _c_value_type(sig.ret_kind)
            call_var = self.fresh_tmp()
            self.lines.append(f"{indent}{ret_ty} {call_var} = {c_callee}({arg_str});")
            return call_var

        if op == "~":
            av = self.emit_expr(items[1], env, target_kind=nk, indent=indent)
            if nk == "i64":
                return f"{self._use('ail_bitnot_i64')}({av})"
            return f"(~({av}))"

        if op in ("==", "!=", "<", "<=", ">", ">="):
            self.uses_bool = True
            rk1 = self._raw_kind(items[1])
            rk2 = self._raw_kind(items[2])
            if rk1.startswith("struct:") and rk2.startswith("struct:") and op in ("==", "!="):
                sname = rk1.split(":", 1)[1]
                av = self.emit_expr(items[1], env, indent=indent)
                bv = self.emit_expr(items[2], env, indent=indent)
                eq_call = f"{self._use(f'ail_eq_{sname}')}({av}, {bv})"
                return eq_call if op == "==" else f"(!{eq_call})"
            if rk1.startswith("enum:") and rk2.startswith("enum:") and op in ("==", "!="):
                ename = rk1.split(":", 1)[1]
                av = self.emit_expr(items[1], env, indent=indent)
                bv = self.emit_expr(items[2], env, indent=indent)
                eq_call = f"{self._use(f'ail_eq_{ename}')}({av}, {bv})"
                return eq_call if op == "==" else f"(!{eq_call})"

            cmp_kind = "i64" if (rk1 == "i64" or rk2 == "i64") else ("bool" if rk1 == "bool" else "u64")
            av = self.emit_expr(items[1], env, target_kind=cmp_kind, indent=indent)
            bv = self.emit_expr(items[2], env, target_kind=cmp_kind, indent=indent)
            return f"({av} {op} {bv})"

        if op in ("and", "or"):
            self.uses_bool = True
            c_op = " && " if op == "and" else " || "
            parts = [self.emit_expr(a, env, target_kind="bool", indent=indent) for a in items[1:]]
            return f"({c_op.join(parts)})"

        if op == "not":
            self.uses_bool = True
            av = self.emit_expr(items[1], env, target_kind="bool", indent=indent)
            return f"(!({av}))"

        if op in (">>", "<<"):
            av = self.emit_expr(items[1], env, target_kind=nk, indent=indent)
            bv = self.emit_expr(items[2], env, target_kind="u64", indent=indent)
            if nk == "i64":
                helper = "ail_ashr_i64" if op == ">>" else "ail_shl_i64"
                return f"{self._use(helper)}({av}, {bv})"
            return f"({av} {op} {bv})"

        av = self.emit_expr(items[1], env, target_kind=nk, indent=indent)
        bv = self.emit_expr(items[2], env, target_kind=nk, indent=indent)
        is_signed = nk == "i64"

        if op in ("min", "max"):
            helper = f"ail_{op}_{'i64' if is_signed else 'u64'}"
            return f"{self._use(helper)}({av}, {bv})"

        if is_signed:
            signed_helpers = {
                "+": "ail_add_i64",
                "-": "ail_sub_i64",
                "*": "ail_mul_i64",
                "&": "ail_bitand_i64",
                "|": "ail_bitor_i64",
                "^": "ail_bitxor_i64",
            }
            if op in signed_helpers:
                return f"{self._use(signed_helpers[op])}({av}, {bv})"
            if op in ("/", "%"):
                return f"({av} {op} {bv})"

        if op in ("+", "-", "*", "/", "%", "&", "|", "^"):
            return f"({av} {op} {bv})"

        raise NotImplementedError(f"Unsupported AIL operator in C11 backend: `{op}`")

    def _emit_let_binding(self, binding: SNode, nenv: dict[str, str], indent: str) -> None:
        bname = str(binding.val[0].val)
        rhs = binding.val[1]
        bk = self._node_kind(rhs)
        if bk in LINEAR_CAPS:
            _ = self.emit_expr(rhs, nenv, target_kind=bk, indent=indent)
            self.var_kinds[bname] = bk
            return
        if bk == "bool":
            self.uses_bool = True
        rval = self.emit_expr(rhs, nenv, target_kind=bk, indent=indent)
        c_bname = self.bind_local(bname)
        self.var_kinds[bname] = bk
        nenv[bname] = c_bname
        self.lines.append(f"{indent}{_c_value_type(bk)} {c_bname} = {rval};")
        self.lines.append(f"{indent}(void){c_bname};")


def _c_slot_eq_expr(
    a_prefix: str,
    b_prefix: str,
    offset: int,
    kind: str,
    structs: dict[str, StructDef],
    enums: dict[str, EnumDef],
) -> tuple[str, int]:
    if kind in ("u64", "i64"):
        return f"({a_prefix}{offset} == {b_prefix}{offset})", offset + 1
    if kind.startswith("struct:"):
        sdef = structs[kind.split(":", 1)[1]]
        cur_off = offset
        parts: list[str] = []
        for fd in sdef.fields:
            fe, cur_off = _c_slot_eq_expr(a_prefix, b_prefix, cur_off, fd.kind, structs, enums)
            parts.append(fe)
        return (f"({' && '.join(parts)})" if parts else "true"), cur_off
    if kind.startswith("enum:"):
        edef = enums[kind.split(":", 1)[1]]
        tag_eq = f"({a_prefix}{offset} == {b_prefix}{offset})"
        v_parts = [tag_eq]
        for vdef in edef.variants:
            if not vdef.fields:
                continue
            cur_off = offset + 1
            f_parts: list[str] = []
            for fd in vdef.fields:
                fe, cur_off = _c_slot_eq_expr(a_prefix, b_prefix, cur_off, fd.kind, structs, enums)
                f_parts.append(fe)
            v_parts.append(f"({a_prefix}{offset} != UINT64_C({vdef.tag}) || ({' && '.join(f_parts)}))")
        return f"({' && '.join(v_parts)})", offset + 1 + edef.max_payload_slots(structs, enums)
    return f"({a_prefix}{offset} == {b_prefix}{offset})", offset + 1


def _emit_c_helpers(
    used_helpers: set[str],
    structs: dict[str, StructDef],
    enums: dict[str, EnumDef],
    type_order: list[tuple[str, str]],
    uses_io: bool,
    uses_fs: bool,
    uses_net: bool,
) -> list[str]:
    expanded = set(used_helpers)
    if expanded & {"ail_mul_div_u64", "ail_mul_div_ceil_u64"}:
        expanded.add("ail_mul_div_u64_core")
    changed = True
    while changed:
        changed = False
        for sname, sdef in structs.items():
            if f"ail_eq_{sname}" in expanded:
                for fd in sdef.fields:
                    if fd.kind.startswith(("struct:", "enum:")):
                        dep = f"ail_eq_{fd.kind.split(':', 1)[1]}"
                        if dep not in expanded:
                            expanded.add(dep)
                            changed = True
    if expanded & {
        "ail_add_i64",
        "ail_sub_i64",
        "ail_mul_i64",
        "ail_shl_i64",
        "ail_ashr_i64",
        "ail_bitand_i64",
        "ail_bitor_i64",
        "ail_bitxor_i64",
        "ail_bitnot_i64",
    }:
        expanded.add("ail_u64_to_i64")

    lines: list[str] = []
    if "ail_u64_to_i64" in expanded:
        lines.extend(
            [
                "static inline int64_t ail_u64_to_i64(uint64_t u) {",
                "    union { uint64_t u; int64_t i; } conv;",
                "    conv.u = u;",
                "    return conv.i;",
                "}",
                "",
            ]
        )
    if "ail_min_u64" in expanded:
        lines.extend(["static inline uint64_t ail_min_u64(uint64_t a, uint64_t b) { return a < b ? a : b; }", ""])
    if "ail_max_u64" in expanded:
        lines.extend(["static inline uint64_t ail_max_u64(uint64_t a, uint64_t b) { return a > b ? a : b; }", ""])
    if "ail_min_i64" in expanded:
        lines.extend(["static inline int64_t ail_min_i64(int64_t a, int64_t b) { return a < b ? a : b; }", ""])
    if "ail_max_i64" in expanded:
        lines.extend(["static inline int64_t ail_max_i64(int64_t a, int64_t b) { return a > b ? a : b; }", ""])

    for name, c_op in (("ail_add_i64", "+"), ("ail_sub_i64", "-"), ("ail_mul_i64", "*")):
        if name in expanded:
            lines.extend(
                [
                    f"static inline int64_t {name}(int64_t a, int64_t b) {{",
                    f"    return ail_u64_to_i64((uint64_t)a {c_op} (uint64_t)b);",
                    "}",
                    "",
                ]
            )
    for name, c_op in (("ail_bitand_i64", "&"), ("ail_bitor_i64", "|"), ("ail_bitxor_i64", "^")):
        if name in expanded:
            lines.extend(
                [
                    f"static inline int64_t {name}(int64_t a, int64_t b) {{",
                    f"    return ail_u64_to_i64((uint64_t)a {c_op} (uint64_t)b);",
                    "}",
                    "",
                ]
            )
    if "ail_bitnot_i64" in expanded:
        lines.extend(
            [
                "static inline int64_t ail_bitnot_i64(int64_t a) {",
                "    return ail_u64_to_i64(~((uint64_t)a));",
                "}",
                "",
            ]
        )
    if "ail_shl_i64" in expanded:
        lines.extend(
            [
                "static inline int64_t ail_shl_i64(int64_t a, uint64_t b) {",
                "    return ail_u64_to_i64((uint64_t)a << (b & UINT64_C(63)));",
                "}",
                "",
            ]
        )
    if "ail_ashr_i64" in expanded:
        lines.extend(
            [
                "static inline int64_t ail_ashr_i64(int64_t a, uint64_t b) {",
                "    uint64_t s = b & UINT64_C(63);",
                "    uint64_t ua = (uint64_t)a;",
                "    if (a >= INT64_C(0)) {",
                "        return ail_u64_to_i64(ua >> s);",
                "    }",
                "    return ail_u64_to_i64(~((~ua) >> s));",
                "}",
                "",
            ]
        )
    if "ail_read_u16_be" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_read_u16_be(const uint8_t* buf, uint64_t idx) {",
                "    return ((uint64_t)buf[idx] << 8)",
                "         | (uint64_t)buf[idx + UINT64_C(1)];",
                "}",
                "",
            ]
        )
    if "ail_read_u32_be" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_read_u32_be(const uint8_t* buf, uint64_t idx) {",
                "    return ((uint64_t)buf[idx] << 24)",
                "         | ((uint64_t)buf[idx + UINT64_C(1)] << 16)",
                "         | ((uint64_t)buf[idx + UINT64_C(2)] << 8)",
                "         | (uint64_t)buf[idx + UINT64_C(3)];",
                "}",
                "",
            ]
        )
    if "ail_read_u64_be" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_read_u64_be(const uint8_t* buf, uint64_t idx) {",
                "    return ((uint64_t)buf[idx] << 56)",
                "         | ((uint64_t)buf[idx + UINT64_C(1)] << 48)",
                "         | ((uint64_t)buf[idx + UINT64_C(2)] << 40)",
                "         | ((uint64_t)buf[idx + UINT64_C(3)] << 32)",
                "         | ((uint64_t)buf[idx + UINT64_C(4)] << 24)",
                "         | ((uint64_t)buf[idx + UINT64_C(5)] << 16)",
                "         | ((uint64_t)buf[idx + UINT64_C(6)] << 8)",
                "         | (uint64_t)buf[idx + UINT64_C(7)];",
                "}",
                "",
            ]
        )
    if "ail_bytes_eq4" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_bytes_eq4(",
                "    const uint8_t* buf, uint64_t idx,",
                "    uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3",
                ") {",
                "    return (buf[idx] == b0",
                "         && buf[idx + UINT64_C(1)] == b1",
                "         && buf[idx + UINT64_C(2)] == b2",
                "         && buf[idx + UINT64_C(3)] == b3) ? UINT64_C(1) : UINT64_C(0);",
                "}",
                "",
            ]
        )
    if "ail_read_u16_le" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_read_u16_le(const uint8_t* buf, uint64_t idx) {",
                "    return (uint64_t)buf[idx]",
                "         | ((uint64_t)buf[idx + UINT64_C(1)] << 8);",
                "}",
                "",
            ]
        )
    if "ail_read_u32_le" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_read_u32_le(const uint8_t* buf, uint64_t idx) {",
                "    return (uint64_t)buf[idx]",
                "         | ((uint64_t)buf[idx + UINT64_C(1)] << 8)",
                "         | ((uint64_t)buf[idx + UINT64_C(2)] << 16)",
                "         | ((uint64_t)buf[idx + UINT64_C(3)] << 24);",
                "}",
                "",
            ]
        )
    if "ail_read_u64_le" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_read_u64_le(const uint8_t* buf, uint64_t idx) {",
                "    return (uint64_t)buf[idx]",
                "         | ((uint64_t)buf[idx + UINT64_C(1)] << 8)",
                "         | ((uint64_t)buf[idx + UINT64_C(2)] << 16)",
                "         | ((uint64_t)buf[idx + UINT64_C(3)] << 24)",
                "         | ((uint64_t)buf[idx + UINT64_C(4)] << 32)",
                "         | ((uint64_t)buf[idx + UINT64_C(5)] << 40)",
                "         | ((uint64_t)buf[idx + UINT64_C(6)] << 48)",
                "         | ((uint64_t)buf[idx + UINT64_C(7)] << 56);",
                "}",
                "",
            ]
        )
    if "ail_write_byte" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_write_byte(uint8_t* buf, uint64_t idx, uint64_t val) {",
                "    buf[idx] = (uint8_t)val;",
                "    return UINT64_C(1);",
                "}",
                "",
            ]
        )
    if "ail_write_u16_be" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_write_u16_be(uint8_t* buf, uint64_t idx, uint64_t val) {",
                "    buf[idx] = (uint8_t)(val >> 8);",
                "    buf[idx + UINT64_C(1)] = (uint8_t)val;",
                "    return UINT64_C(2);",
                "}",
                "",
            ]
        )
    if "ail_write_u16_le" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_write_u16_le(uint8_t* buf, uint64_t idx, uint64_t val) {",
                "    buf[idx] = (uint8_t)val;",
                "    buf[idx + UINT64_C(1)] = (uint8_t)(val >> 8);",
                "    return UINT64_C(2);",
                "}",
                "",
            ]
        )
    if "ail_write_u32_be" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_write_u32_be(uint8_t* buf, uint64_t idx, uint64_t val) {",
                "    buf[idx] = (uint8_t)(val >> 24);",
                "    buf[idx + UINT64_C(1)] = (uint8_t)(val >> 16);",
                "    buf[idx + UINT64_C(2)] = (uint8_t)(val >> 8);",
                "    buf[idx + UINT64_C(3)] = (uint8_t)val;",
                "    return UINT64_C(4);",
                "}",
                "",
            ]
        )
    if "ail_write_u32_le" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_write_u32_le(uint8_t* buf, uint64_t idx, uint64_t val) {",
                "    buf[idx] = (uint8_t)val;",
                "    buf[idx + UINT64_C(1)] = (uint8_t)(val >> 8);",
                "    buf[idx + UINT64_C(2)] = (uint8_t)(val >> 16);",
                "    buf[idx + UINT64_C(3)] = (uint8_t)(val >> 24);",
                "    return UINT64_C(4);",
                "}",
                "",
            ]
        )
    if "ail_write_u64_be" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_write_u64_be(uint8_t* buf, uint64_t idx, uint64_t val) {",
                "    buf[idx] = (uint8_t)(val >> 56);",
                "    buf[idx + UINT64_C(1)] = (uint8_t)(val >> 48);",
                "    buf[idx + UINT64_C(2)] = (uint8_t)(val >> 40);",
                "    buf[idx + UINT64_C(3)] = (uint8_t)(val >> 32);",
                "    buf[idx + UINT64_C(4)] = (uint8_t)(val >> 24);",
                "    buf[idx + UINT64_C(5)] = (uint8_t)(val >> 16);",
                "    buf[idx + UINT64_C(6)] = (uint8_t)(val >> 8);",
                "    buf[idx + UINT64_C(7)] = (uint8_t)val;",
                "    return UINT64_C(8);",
                "}",
                "",
            ]
        )
    if "ail_write_u64_le" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_write_u64_le(uint8_t* buf, uint64_t idx, uint64_t val) {",
                "    buf[idx] = (uint8_t)val;",
                "    buf[idx + UINT64_C(1)] = (uint8_t)(val >> 8);",
                "    buf[idx + UINT64_C(2)] = (uint8_t)(val >> 16);",
                "    buf[idx + UINT64_C(3)] = (uint8_t)(val >> 24);",
                "    buf[idx + UINT64_C(4)] = (uint8_t)(val >> 32);",
                "    buf[idx + UINT64_C(5)] = (uint8_t)(val >> 40);",
                "    buf[idx + UINT64_C(6)] = (uint8_t)(val >> 48);",
                "    buf[idx + UINT64_C(7)] = (uint8_t)(val >> 56);",
                "    return UINT64_C(8);",
                "}",
                "",
            ]
        )
    if "ail_mul_div_u64_core" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_mul_div_u64_core(uint64_t a, uint64_t b, uint64_t d, int is_ceil) {",
                "#if defined(__SIZEOF_INT128__)",
                "    __extension__ unsigned __int128 num = ((__extension__ (unsigned __int128)a)) * ((__extension__ (unsigned __int128)b));",
                "    if (is_ceil) {",
                "        num += (__extension__ (unsigned __int128)(d - UINT64_C(1)));",
                "    }",
                "    return (uint64_t)(num / (__extension__ (unsigned __int128)d));",
                "#else",
                "    uint64_t a_lo = a & UINT64_C(0xFFFFFFFF);",
                "    uint64_t a_hi = a >> 32;",
                "    uint64_t b_lo = b & UINT64_C(0xFFFFFFFF);",
                "    uint64_t b_hi = b >> 32;",
                "    uint64_t p0 = a_lo * b_lo;",
                "    uint64_t p1 = a_lo * b_hi;",
                "    uint64_t p2 = a_hi * b_lo;",
                "    uint64_t p3 = a_hi * b_hi;",
                "    uint64_t mid = (p0 >> 32) + (p1 & UINT64_C(0xFFFFFFFF)) + (p2 & UINT64_C(0xFFFFFFFF));",
                "    uint64_t lo = (p0 & UINT64_C(0xFFFFFFFF)) | (mid << 32);",
                "    uint64_t hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);",
                "    if (is_ceil) {",
                "        uint64_t nlo = lo + (d - UINT64_C(1));",
                "        if (nlo < lo) {",
                "            hi += UINT64_C(1);",
                "        }",
                "        lo = nlo;",
                "    }",
                "    if (hi == UINT64_C(0)) {",
                "        return lo / d;",
                "    }",
                "    uint64_t rem = hi % d;",
                "    uint64_t quot = UINT64_C(0);",
                "    for (uint32_t step = 0U; step < 64U; ++step) {",
                "        uint64_t msb = rem >> 63;",
                "        rem = (rem << 1) | (lo >> 63);",
                "        lo <<= 1;",
                "        quot <<= 1;",
                "        if (msb != UINT64_C(0) || rem >= d) {",
                "            rem -= d;",
                "            quot |= UINT64_C(1);",
                "        }",
                "    }",
                "    return quot;",
                "#endif",
                "}",
                "",
            ]
        )
    if "ail_mul_div_u64" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_mul_div_u64(uint64_t a, uint64_t b, uint64_t d) {",
                "    return ail_mul_div_u64_core(a, b, d, 0);",
                "}",
                "",
            ]
        )
    if "ail_mul_div_ceil_u64" in expanded:
        lines.extend(
            [
                "static inline uint64_t ail_mul_div_ceil_u64(uint64_t a, uint64_t b, uint64_t d) {",
                "    return ail_mul_div_u64_core(a, b, d, 1);",
                "}",
                "",
            ]
        )
    order = type_order or ([("struct", s) for s in structs] + [("enum", e) for e in enums])
    for tkind, tname in order:
        if tkind == "struct" and tname in structs and f"ail_eq_{tname}" in expanded:
            sdef = structs[tname]
            parts: list[str] = []
            for fd in sdef.fields:
                if fd.kind.startswith(("struct:", "enum:")):
                    sub_name = fd.kind.split(":", 1)[1]
                    parts.append(f"ail_eq_{sub_name}(a.{fd.name}, b.{fd.name})")
                else:
                    parts.append(f"(a.{fd.name} == b.{fd.name})")
            cond = " && ".join(parts) if parts else "true"
            lines.extend(
                [
                    f"static inline bool ail_eq_{tname}({tname} a, {tname} b) {{",
                    f"    return {cond};",
                    "}",
                    "",
                ]
            )
        elif tkind == "enum" and tname in enums and f"ail_eq_{tname}" in expanded:
            edef = enums[tname]
            lines.extend(
                [
                    f"static inline bool ail_eq_{tname}({tname} a, {tname} b) {{",
                    "    if (a.tag != b.tag) {",
                    "        return false;",
                    "    }",
                    "    switch (a.tag) {",
                ]
            )
            for vdef in edef.variants:
                lines.append(f"        case UINT64_C({vdef.tag}):")
                if not vdef.fields:
                    lines.append("            return true;")
                else:
                    cur_off = 0
                    v_conds: list[str] = []
                    for fd in vdef.fields:
                        fe, cur_off = _c_slot_eq_expr("a._p", "b._p", cur_off, fd.kind, structs, enums)
                        v_conds.append(fe)
                    lines.append(f"            return {' && '.join(v_conds)};")
            lines.extend(["        default:", "            return false;", "    }", "}", ""])
    if uses_fs and "ail_fs_write_u64" in expanded:
        lines.extend(
            [
                "static void ail_fs_write_u64(uint64_t val) {",
                '    const char* path = getenv("AIL_FS_OUT");',
                "    if (!path || path[0] == '\\0') {",
                '        path = "ail_fs_out.log";',
                "    }",
                '    FILE* fp = fopen(path, "a");',
                "    if (fp != NULL) {",
                '        fprintf(fp, "%llu\\n", (unsigned long long)val);',
                "        fclose(fp);",
                "    }",
                "}",
                "",
            ]
        )
    if uses_fs and "ail_fs_write_i64" in expanded:
        lines.extend(
            [
                "static void ail_fs_write_i64(int64_t val) {",
                '    const char* path = getenv("AIL_FS_OUT");',
                "    if (!path || path[0] == '\\0') {",
                '        path = "ail_fs_out.log";',
                "    }",
                '    FILE* fp = fopen(path, "a");',
                "    if (fp != NULL) {",
                '        fprintf(fp, "%lld\\n", (long long)val);',
                "        fclose(fp);",
                "    }",
                "}",
                "",
            ]
        )
    if uses_net and "ail_net_loopback_u64" in expanded:
        lines.extend(
            [
                "static void ail_net_loopback_u64(uint64_t port, uint64_t payload) {",
                "    int fd = socket(AF_INET, SOCK_DGRAM, 0);",
                "    if (fd < 0) {",
                "        return;",
                "    }",
                "    struct sockaddr_in addr;",
                "    memset(&addr, 0, sizeof(addr));",
                "    addr.sin_family = AF_INET;",
                "    addr.sin_port = htons((uint16_t)port);",
                "    addr.sin_addr.s_addr = htonl(UINT32_C(0x7F000001));",
                "    (void)sendto(fd, &payload, sizeof(payload), 0,",
                "                 (const struct sockaddr*)&addr, (socklen_t)sizeof(addr));",
                "    close(fd);",
                "}",
                "",
            ]
        )
    _ = uses_io
    return lines


def _generate_c_header_text(
    module_name: str,
    exports: list[_CExport],
    structs: dict[str, StructDef],
    enums: dict[str, EnumDef],
    uses_atomic: bool,
    type_order: list[tuple[str, str]] | None = None,
) -> str:
    guard = f"AIL_{re.sub(r'[^A-Za-z0-9_]', '_', module_name).upper()}_H"
    lines = [
        "/* Auto-generated by ailang v1.1 — Formally Verified ISO C11 Header */",
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        "#include <stdint.h>",
    ]
    if uses_atomic:
        lines.append("#include <stdatomic.h>")
    lines.extend(
        [
            "",
            "#ifdef __cplusplus",
            'extern "C" {',
            "#endif",
            "",
        ]
    )
    order = type_order or ([("struct", s) for s in structs] + [("enum", e) for e in enums])
    for tkind, tname in order:
        if tkind == "struct" and tname in structs:
            sdef = structs[tname]
            lines.append("typedef struct {")
            if not sdef.fields:
                lines.append("    uint64_t _dummy;")
            else:
                for fd in sdef.fields:
                    lines.append(f"    {_c_value_type(fd.kind)} {fd.name};")
            lines.append(f"}} {sdef.name};")
            lines.append("")
        elif tkind == "enum" and tname in enums:
            edef = enums[tname]
            lines.append("typedef enum {")
            for vdef in edef.variants:
                lines.append(f"    {edef.name}_{vdef.name} = {vdef.tag},")
            lines.append(f"}} {edef.name}_Tag;")
            lines.append("")
            lines.append("typedef struct {")
            lines.append("    uint64_t tag;")
            for p_idx in range(edef.max_payload_slots(structs, enums)):
                lines.append(f"    uint64_t _p{p_idx};")
            lines.append(f"}} {edef.name};")
            lines.append("")
    for ex in exports:
        p_str = ", ".join(f"{ty} {nm}" for ty, nm in ex.params_c) or "void"
        lines.append(f"{ex.ret_c} {ex.name}({p_str});")
    lines.extend(["", "#ifdef __cplusplus", "}", "#endif", "", f"#endif /* {guard} */", ""])
    return "\n".join(lines)


def _c_param_decl(
    pname: str,
    c_pname: str,
    pk: str,
    pspec: SNode,
    for_header: bool,
) -> tuple[str, str]:
    """Return `(c_type, elem_kind)` for a parameter in `.h` or `.c`."""
    _ = pname
    restrict = "" if for_header else " restrict"
    if pk == "slice":
        is_i64 = _slice_elem_is_i64(pspec)
        el = "i64" if is_i64 else "u64"
        base = "const int64_t*" if is_i64 else "const uint64_t*"
        return f"{base}{restrict}", el
    if pk == "mut_slice":
        is_i64 = _slice_elem_is_i64(pspec)
        el = "i64" if is_i64 else "u64"
        base = "int64_t*" if is_i64 else "uint64_t*"
        return f"{base}{restrict}", el
    if pk == "bytes":
        return f"const uint8_t*{restrict}", "u64"
    if pk == "mut_bytes":
        return f"uint8_t*{restrict}", "u64"
    if pk == "atomic_u64":
        return "_Atomic uint64_t*", "u64"
    if pk.startswith("struct:"):
        sname = pk.split(":", 1)[1]
        return f"const {sname}*", "u64"
    if pk.startswith("enum:"):
        ename = pk.split(":", 1)[1]
        return f"const {ename}*", "u64"
    if pk == "i64":
        return "int64_t", "i64"
    return "uint64_t", "u64"


def _emit_c_module(
    forms: list[SNode],
    tenv: ModuleTypeEnv,
    module_name: str,
    header_filename: str,
) -> tuple[str, str]:
    consts: dict[str, tuple[str, int]] = {}
    proto_steps: dict[tuple[str, str], tuple[str, list[tuple[str, SNode]], SNode]] = {}

    for form in forms:
        if not isinstance(form.val, list) or not form.val:
            continue
        head = str(form.val[0].val)
        if head == "const" and len(form.val) == 4 and isinstance(form.val[3].val, int):
            ck = "i64" if str(form.val[2].val) == "i64" else "u64"
            consts[str(form.val[1].val)] = (ck, int(form.val[3].val))
        elif head == "atomic_protocol":
            pname = str(form.val[1].val)
            f0 = str(form.val[2].val[0].val[0].val)
            for sn in form.val[4:]:
                sname = str(sn.val[1].val)
                sparams = [(str(sp.val[0].val), sp.val[1]) for sp in sn.val[2].val]
                next_f0 = sn.val[3].val[0]
                proto_steps[(pname, sname)] = (f0, sparams, next_f0)

    exports: list[_CExport] = []
    fn_blocks: list[str] = []
    impl_protos: list[str] = []
    used_helpers: set[str] = set()
    any_io = False
    any_fs = False
    any_net = False
    any_atomic = False
    any_bool = False

    for form in forms:
        if not isinstance(form.val, list) or not form.val:
            continue
        head = str(form.val[0].val)
        if head in ("spec", "struct", "enum", "atomic_protocol", "import", "const"):
            continue

        if head == "fn":
            name = str(form.val[1].val)
            params_n, _, body_n = form.val[2], form.val[3], form.val[4]
            sig = tenv.sigs[name]

            var_kinds: dict[str, str] = {}
            slice_elem_kinds: dict[str, str] = {}
            c_env: dict[str, str] = {}
            used_locals: set[str] = set()
            h_params: list[tuple[str, str]] = []
            c_abi_params: list[tuple[str, str]] = []
            val_params: list[tuple[str, str]] = []
            has_agg = _has_aggregate_boundary(sig.ret_kind, sig.param_kinds)

            for p, pk in zip(params_n.val, sig.param_kinds):
                pname = str(p.val[0].val)
                var_kinds[pname] = pk
                if pk in LINEAR_CAPS:
                    continue
                if pk == "atomic_u64":
                    any_atomic = True
                c_pname = _safe_c_ident(pname)
                while c_pname in used_locals:
                    c_pname = f"{c_pname}_p"
                used_locals.add(c_pname)
                c_env[pname] = c_pname

                h_ty, el_k = _c_param_decl(pname, c_pname, pk, p.val[1], for_header=True)
                c_ty, _ = _c_param_decl(pname, c_pname, pk, p.val[1], for_header=False)
                if pk in ("slice", "mut_slice"):
                    slice_elem_kinds[pname] = el_k
                h_params.append((h_ty, c_pname))
                c_abi_params.append((c_ty, c_pname))
                val_params.append((_c_value_type(pk) if pk.startswith(("struct:", "enum:")) else c_ty, c_pname))

            em = CFunctionEmitter(tenv, var_kinds, slice_elem_kinds, consts, used_helpers, used_locals)
            ret_target = sig.ret_kind if sig.ret_kind not in LINEAR_CAPS else None
            ret_expr = em.emit_expr(body_n, c_env, target_kind=ret_target)

            any_io = any_io or em.uses_io
            any_fs = any_fs or em.uses_fs
            any_net = any_net or em.uses_net
            any_bool = any_bool or em.uses_bool

            if not has_agg:
                ret_c = "void" if sig.ret_kind in LINEAR_CAPS else _c_value_type(sig.ret_kind)
                exports.append(_CExport(name, ret_c, h_params))
                p_sig = ", ".join(f"{ty} {nm}" for ty, nm in c_abi_params) or "void"
                fn_blocks.append(f"{ret_c} {name}({p_sig}) {{")
                for _, c_pname in c_abi_params:
                    fn_blocks.append(f"    (void){c_pname};")
                fn_blocks.extend(em.lines)
                if sig.ret_kind in LINEAR_CAPS:
                    fn_blocks.append("}")
                else:
                    fn_blocks.append(f"    return {ret_expr};")
                    fn_blocks.append("}")
                fn_blocks.append("")
            else:
                # 1. Pure value-based internal helper matching LLVM fastcc intra-module calls
                val_ret_c = "void" if sig.ret_kind in LINEAR_CAPS else _c_value_type(sig.ret_kind)
                val_p_sig = ", ".join(f"{ty} {nm}" for ty, nm in val_params) or "void"
                impl_name = f"ail_impl_{name}"
                impl_protos.append(f"static inline {val_ret_c} {impl_name}({val_p_sig});")
                fn_blocks.append(f"static inline {val_ret_c} {impl_name}({val_p_sig}) {{")
                for _, c_pname in val_params:
                    fn_blocks.append(f"    (void){c_pname};")
                fn_blocks.extend(em.lines)
                if sig.ret_kind in LINEAR_CAPS:
                    fn_blocks.append("}")
                else:
                    fn_blocks.append(f"    return {ret_expr};")
                    fn_blocks.append("}")
                fn_blocks.append("")

                # 2. Portable C-ABI wrapper matching codegen_llvm.py `.h` ABI
                call_args: list[str] = []
                for p, pk in zip(params_n.val, sig.param_kinds):
                    if pk in LINEAR_CAPS:
                        continue
                    c_pname = c_env[str(p.val[0].val)]
                    call_args.append(f"*{c_pname}" if pk.startswith(("struct:", "enum:")) else c_pname)

                if sig.ret_kind.startswith(("struct:", "enum:")):
                    ret_sname = sig.ret_kind.split(":", 1)[1]
                    out_param = "ail_out"
                    h_full = [*h_params, (f"{ret_sname}*", "_out")]
                    c_full = [*c_abi_params, (f"{ret_sname}*", out_param)]
                    exports.append(_CExport(name, "void", h_full))
                    p_sig = ", ".join(f"{ty} {nm}" for ty, nm in c_full) or "void"
                    fn_blocks.append(f"void {name}({p_sig}) {{")
                    fn_blocks.append(f"    *{out_param} = {impl_name}({', '.join(call_args)});")
                    fn_blocks.append("}")
                elif sig.ret_kind in LINEAR_CAPS:
                    exports.append(_CExport(name, "void", h_params))
                    p_sig = ", ".join(f"{ty} {nm}" for ty, nm in c_abi_params) or "void"
                    fn_blocks.append(f"void {name}({p_sig}) {{")
                    fn_blocks.append(f"    {impl_name}({', '.join(call_args)});")
                    fn_blocks.append("}")
                else:
                    ret_c = _c_value_type(sig.ret_kind)
                    exports.append(_CExport(name, ret_c, h_params))
                    p_sig = ", ".join(f"{ty} {nm}" for ty, nm in c_abi_params) or "void"
                    fn_blocks.append(f"{ret_c} {name}({p_sig}) {{")
                    fn_blocks.append(f"    return {impl_name}({', '.join(call_args)});")
                    fn_blocks.append("}")
                fn_blocks.append("")

        elif head == "map_inplace":
            name = str(form.val[1].val)
            params_n, _, elem_vars, body_n = form.val[2], form.val[3], form.val[4], form.val[5]
            elem_var = str(elem_vars.val[0].val)
            sig = tenv.sigs[name]

            var_kinds = {}
            slice_elem_kinds = {}
            c_env = {}
            used_locals = set()
            h_params = []
            c_abi_params = []
            buf_c = ""
            len_c = ""
            elem_k = "u64"

            for p, pk in zip(params_n.val, sig.param_kinds):
                pname = str(p.val[0].val)
                var_kinds[pname] = pk
                if pk in LINEAR_CAPS:
                    continue
                c_pname = _safe_c_ident(pname)
                while c_pname in used_locals:
                    c_pname = f"{c_pname}_p"
                used_locals.add(c_pname)
                c_env[pname] = c_pname

                h_ty, el_k = _c_param_decl(pname, c_pname, pk, p.val[1], for_header=True)
                c_ty, _ = _c_param_decl(pname, c_pname, pk, p.val[1], for_header=False)
                h_params.append((h_ty, c_pname))
                c_abi_params.append((c_ty, c_pname))
                if pk == "mut_slice":
                    buf_c = c_pname
                    len_ail = str(p.val[1].val[1].val)
                    len_c = c_env[len_ail]
                    elem_k = el_k
                    slice_elem_kinds[pname] = el_k

            var_kinds[elem_var] = elem_k
            em = CFunctionEmitter(tenv, var_kinds, slice_elem_kinds, consts, used_helpers, used_locals)
            c_elem = em.bind_local(elem_var)
            c_env[elem_var] = c_elem
            iter_var = em.fresh_tmp("ail_i")
            elem_cty = _c_value_type(elem_k)

            exports.append(_CExport(name, "void", h_params))
            p_sig = ", ".join(f"{ty} {nm}" for ty, nm in c_abi_params) or "void"
            fn_blocks.append(f"void {name}({p_sig}) {{")
            for _, c_pname in c_abi_params:
                fn_blocks.append(f"    (void){c_pname};")
            fn_blocks.append(f"    for (uint64_t {iter_var} = UINT64_C(0); {iter_var} < {len_c}; ++{iter_var}) {{")
            fn_blocks.append(f"        {elem_cty} {c_elem} = {buf_c}[{iter_var}];")
            fn_blocks.append(f"        (void){c_elem};")
            step_expr = em.emit_expr(body_n, c_env, target_kind=elem_k, indent="        ")
            fn_blocks.extend(em.lines)
            fn_blocks.append(f"        {buf_c}[{iter_var}] = {step_expr};")
            fn_blocks.append("    }")
            fn_blocks.append("}")
            fn_blocks.append("")

            any_io = any_io or em.uses_io
            any_fs = any_fs or em.uses_fs
            any_net = any_net or em.uses_net
            any_bool = any_bool or em.uses_bool

        elif head == "atomic_cas":
            any_atomic = True
            name = str(form.val[1].val)
            pname = str(form.val[2].val)
            sname = str(form.val[3].val)
            params_n = form.val[4]
            ptr_name = str(params_n.val[0].val[0].val)
            c_ptr = _safe_c_ident(ptr_name)

            f0_name, sparams, next_f0_node = proto_steps[(pname, sname)]
            used_locals = {c_ptr}
            h_params = [("_Atomic uint64_t*", c_ptr)]
            c_abi_params = [("_Atomic uint64_t*", c_ptr)]
            cas_env: dict[str, str] = {}
            var_kinds = {f0_name: "u64"}

            arg_c_names: list[str] = []
            for p_node in params_n.val[1:]:
                aname = str(p_node.val[0].val)
                c_aname = _safe_c_ident(aname)
                while c_aname in used_locals:
                    c_aname = f"{c_aname}_p"
                used_locals.add(c_aname)
                h_params.append(("uint64_t", c_aname))
                c_abi_params.append(("uint64_t", c_aname))
                var_kinds[aname] = "u64"
                cas_env[aname] = c_aname
                arg_c_names.append(c_aname)

            obs_var = "ail_obs"
            while obs_var in used_locals:
                obs_var = f"{obs_var}_v"
            used_locals.add(obs_var)
            cas_env[f0_name] = obs_var

            for (sp_name, _), c_aname in zip(sparams, arg_c_names):
                var_kinds[sp_name] = "u64"
                cas_env[sp_name] = c_aname

            em_guard = CFunctionEmitter(tenv, var_kinds, {}, consts, used_helpers, used_locals)
            guard_parts: list[str] = []
            for (sp_name, sp_ty), c_aname in zip(sparams, arg_c_names):
                raw_t = sp_ty.raw()
                if isinstance(raw_t, list) and len(raw_t) == 3 and raw_t[0] == "u64_range":
                    lo_n, hi_n = sp_ty.val[1], sp_ty.val[2]
                    if lo_n.raw() != 0:
                        lo_e = em_guard.emit_expr(lo_n, cas_env, target_kind="u64")
                        guard_parts.append(f"({lo_e} <= {c_aname})")
                    if hi_n.raw() != "MAX":
                        hi_e = em_guard.emit_expr(hi_n, cas_env, target_kind="u64")
                        guard_parts.append(f"({c_aname} <= {hi_e})")
            guard_expr = " && ".join(guard_parts) if guard_parts else "true"
            if guard_expr == "true":
                any_bool = True

            em_step = CFunctionEmitter(tenv, var_kinds, {}, consts, used_helpers, em_guard.used_locals)
            desired_expr = em_step.emit_expr(next_f0_node, cas_env, target_kind="u64", indent="        ")
            any_bool = any_bool or em_guard.uses_bool or em_step.uses_bool

            exports.append(_CExport(name, "uint64_t", h_params))
            p_sig = ", ".join(f"{ty} {nm}" for ty, nm in c_abi_params)
            fn_blocks.append(f"uint64_t {name}({p_sig}) {{")
            for _, nm in c_abi_params:
                fn_blocks.append(f"    (void){nm};")
            fn_blocks.append(f"    uint64_t {obs_var} = atomic_load_explicit({c_ptr}, memory_order_relaxed);")
            fn_blocks.extend(em_guard.lines)
            fn_blocks.append(f"    while ({guard_expr}) {{")
            fn_blocks.extend(em_step.lines)
            fn_blocks.append(f"        uint64_t ail_desired = {desired_expr};")
            fn_blocks.append(
                f"        if (atomic_compare_exchange_weak_explicit({c_ptr}, &{obs_var}, ail_desired, "
                "memory_order_acq_rel, memory_order_relaxed)) {"
            )
            fn_blocks.append("            return UINT64_C(1);")
            fn_blocks.append("        }")
            fn_blocks.append("    }")
            fn_blocks.append("    return UINT64_C(0);")
            fn_blocks.append("}")
            fn_blocks.append("")

        elif head == "main":
            body_n = form.val[3]
            sig = tenv.sigs["main"]
            em = CFunctionEmitter(tenv, {}, {}, consts, used_helpers, set())
            ret_target = sig.ret_kind if sig.ret_kind not in LINEAR_CAPS else "u64"
            ret_expr = em.emit_expr(body_n, {}, target_kind=ret_target)
            any_io = any_io or em.uses_io
            any_fs = any_fs or em.uses_fs
            any_net = any_net or em.uses_net
            any_bool = any_bool or em.uses_bool

            fn_blocks.append("int main(void) {")
            fn_blocks.extend(em.lines)
            if sig.ret_kind in LINEAR_CAPS:
                fn_blocks.append("    return 0;")
            else:
                fn_blocks.append(f"    return (int)({ret_expr});")
            fn_blocks.append("}")
            fn_blocks.append("")

    if any_bool or any(f"ail_eq_{s}" in used_helpers for s in tenv.structs) or any(f"ail_eq_{e}" in used_helpers for e in tenv.enums):
        any_bool = True

    c_preamble = [f"/* Auto-generated by ailang v1.1 — Verified ISO C11 Module ({module_name}) */"]
    if any_net:
        c_preamble.extend(
            [
                "#if !defined(_POSIX_C_SOURCE)",
                "#define _POSIX_C_SOURCE 200809L",
                "#endif",
            ]
        )
    c_preamble.append(f'#include "{header_filename}"')
    if any_bool:
        c_preamble.append("#include <stdbool.h>")
    if any_io or any_fs:
        c_preamble.append("#include <stdio.h>")
    if any_fs:
        c_preamble.append("#include <stdlib.h>")
    if any_net:
        c_preamble.extend(
            [
                "#include <string.h>",
                "#include <sys/types.h>",
                "#include <sys/socket.h>",
                "#include <netinet/in.h>",
                "#include <unistd.h>",
            ]
        )
    c_preamble.append("")

    helper_lines = _emit_c_helpers(used_helpers, tenv.structs, tenv.enums, tenv.type_order, any_io, any_fs, any_net)
    if impl_protos:
        impl_protos.append("")

    h_text = _generate_c_header_text(module_name, exports, tenv.structs, tenv.enums, any_atomic, tenv.type_order)
    c_text = "\n".join(c_preamble + helper_lines + impl_protos + fn_blocks)
    return h_text, c_text


def compile_to_c(
    forms: list[SNode],
    tenv: ModuleTypeEnv,
    out_dir: Path,
    module_name: str = "ail_mod",
    compile_shared: bool = True,
) -> CArtifacts:
    """Compile verified AIL forms and ModuleTypeEnv into strictly warning-free ISO C11 (`.h` + `.c` + optional shared lib)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    effective_tenv = tenv if tenv is not None else check_module_ownership_v2(forms)

    h_path = out_dir / f"{module_name}.h"
    c_path = out_dir / f"{module_name}.c"
    h_text, c_text = _emit_c_module(forms, effective_tenv, module_name, h_path.name)
    h_path.write_text(h_text)
    c_path.write_text(c_text)

    shared_lib_path = ""
    if compile_shared:
        ext = ".dylib" if platform.system() == "Darwin" else ".so"
        lib_path = out_dir / f"lib{module_name}{ext}"
        subprocess.run(
            [
                "clang",
                "-std=c11",
                "-O3",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-shared",
                "-fPIC",
                str(c_path),
                "-o",
                str(lib_path),
            ],
            check=True,
        )
        shared_lib_path = str(lib_path)

    return CArtifacts(
        c_source_path=str(c_path),
        c_header_path=str(h_path),
        shared_lib_path=shared_lib_path,
    )
