"""Layer 4 Safe Rust Target Backend: `#![no_std]` + `#![forbid(unsafe_code)]` Standalone Cargo Crate Emitter."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shutil
import subprocess

from ailang import ail_agent_pb2 as pb
from ailang.diagnostics import AILCompilerError, I64_MAX, I64_MIN, U64_MAX
from ailang.ownership import LINEAR_CAPS, EnumDef, ModuleTypeEnv, StructDef, check_module_ownership_v2
from ailang.parser import SNode, pretty


@dataclass(frozen=True)
class RustArtifacts:
    crate_dir: str
    lib_rs_path: str
    cargo_toml_path: str
    rlib_path: str


_RUST_KEYWORDS = {
    "as",
    "break",
    "const",
    "continue",
    "else",
    "enum",
    "extern",
    "false",
    "fn",
    "for",
    "if",
    "impl",
    "in",
    "let",
    "loop",
    "match",
    "mod",
    "move",
    "mut",
    "pub",
    "ref",
    "return",
    "static",
    "struct",
    "trait",
    "true",
    "type",
    "unsafe",
    "use",
    "where",
    "while",
    "async",
    "await",
    "dyn",
    "abstract",
    "become",
    "box",
    "do",
    "final",
    "macro",
    "override",
    "priv",
    "typeof",
    "unsized",
    "virtual",
    "yield",
    "try",
}

_RUST_NON_RAW_KEYWORDS = {"self", "super", "crate", "Self"}

_CAP_INTRINSICS = {
    "io.print_u64",
    "io.print_i64",
    "io.done",
    "fs.write_u64",
    "fs.write_i64",
    "fs.close",
    "net.loopback_send_u64",
    "net.close",
}


def _sanitize_crate_name(module_name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", module_name)
    if not cleaned:
        return "ail_mod"
    if cleaned[0].isdigit():
        cleaned = f"ail_{cleaned}"
    if cleaned in _RUST_KEYWORDS or cleaned in _RUST_NON_RAW_KEYWORDS:
        cleaned = f"ail_{cleaned}"
    return cleaned


def _rust_ident(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not cleaned:
        return "ail_ident"
    if cleaned[0].isdigit():
        cleaned = f"ail_{cleaned}"
    if cleaned in _RUST_NON_RAW_KEYWORDS:
        return f"ail_{cleaned}"
    if cleaned in _RUST_KEYWORDS:
        return f"r#{cleaned}"
    return cleaned


def _slice_elem_is_i64(pspec: SNode) -> bool:
    elem_raw = pspec.val[2].raw()
    return elem_raw == "i64" or (isinstance(elem_raw, list) and bool(elem_raw) and elem_raw[0] == "i64_range")


def _rust_type_for_kind(kind: str, is_i64_slice: bool = False) -> str:
    if kind == "u64":
        return "u64"
    if kind == "i64":
        return "i64"
    if kind == "bool":
        return "bool"
    if kind == "bytes":
        return "&[u8]"
    if kind == "slice":
        return "&[i64]" if is_i64_slice else "&[u64]"
    if kind == "mut_slice":
        return "&mut [i64]" if is_i64_slice else "&mut [u64]"
    if kind == "atomic_u64":
        return "&core::sync::atomic::AtomicU64"
    if kind.startswith("struct:"):
        return _rust_ident(kind.split(":", 1)[1])
    if kind.startswith("enum:"):
        return _rust_ident(kind.split(":", 1)[1])
    if kind in LINEAR_CAPS or kind == "void":
        return "()"
    return "u64"


def _node_uses_caps(node: SNode) -> bool:
    if not isinstance(node.val, list) or not node.val:
        return False
    op = node.val[0].val
    if isinstance(op, str) and op in _CAP_INTRINSICS:
        return True
    return any(_node_uses_caps(ch) for ch in node.val)


def _node_calls(node: SNode, out: set[str]) -> None:
    if not isinstance(node.val, list) or not node.val:
        return
    if node.val[0].val == "call" and len(node.val) >= 2 and isinstance(node.val[1].val, str):
        out.add(node.val[1].val)
    for ch in node.val:
        _node_calls(ch, out)


def _compute_cap_functions(forms: list[SNode], tenv: ModuleTypeEnv) -> set[str]:
    cap_fns: set[str] = set()
    call_graph: dict[str, set[str]] = {}

    for form in forms:
        if not isinstance(form.val, list) or not form.val:
            continue
        head = str(form.val[0].val)
        if head not in ("fn", "main"):
            continue
        name = "main" if head == "main" else str(form.val[1].val)
        body_n = form.val[3] if head == "main" else form.val[4]
        sig = tenv.sigs.get(name)
        direct_cap = False
        if sig is not None:
            if sig.ret_kind in LINEAR_CAPS or any(pk in LINEAR_CAPS for pk in sig.param_kinds):
                direct_cap = True
        if _node_uses_caps(body_n):
            direct_cap = True
        if direct_cap:
            cap_fns.add(name)
        callees: set[str] = set()
        _node_calls(body_n, callees)
        call_graph[name] = callees

    changed = True
    while changed:
        changed = False
        for fname, callees in call_graph.items():
            if fname not in cap_fns and any(c in cap_fns for c in callees):
                cap_fns.add(fname)
                changed = True
    return cap_fns


def _format_int_lit(val: int, target_kind: str) -> tuple[str, bool]:
    if target_kind == "i64":
        if val == I64_MIN:
            return "i64::MIN", True
        if val == I64_MAX:
            return "i64::MAX", True
        if val < 0:
            return f"{val}i64", False
        return f"{val}i64", True
    if val == U64_MAX:
        return "u64::MAX", True
    if val < 0:
        return f"{val}i64", False
    return f"{val}u64", True


def _atom(expr_tuple: tuple[str, bool]) -> str:
    code, is_atomic = expr_tuple
    return code if is_atomic else f"({code})"


class RustExprEmitter:
    def __init__(
        self,
        tenv: ModuleTypeEnv,
        var_kinds: dict[str, str],
        slice_i64_vars: set[str],
        cap_fns: set[str],
    ) -> None:
        self.tenv = tenv
        self.var_kinds = dict(var_kinds)
        self.slice_i64_vars = set(slice_i64_vars)
        self.cap_fns = cap_fns
        self.used_helpers: set[str] = set()
        self.counter = 0

    def _fresh(self, prefix: str) -> str:
        self.counter += 1
        return f"__ail_{prefix}_{self.counter}"

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
            return self.var_kinds.get(node.val, "u64")
        items = node.val
        if not items or not isinstance(items[0].val, str):
            return "u64"
        op = items[0].val
        if op == "let":
            return self._raw_kind(items[2])
        if op == "if":
            k1 = self._raw_kind(items[2])
            k2 = self._raw_kind(items[3])
            return k1 if k1 != "lit_pos" else k2
        if op == "to_i64":
            return "i64"
        if op == "to_u64":
            return "u64"
        if op == "make":
            return f"struct:{items[1].val}"
        if op == "field":
            sk = self._node_kind(items[1])
            sname = sk.split(":", 1)[1]
            found = self.tenv.structs[sname].get_field(str(items[2].val))
            return found[1].kind if found else "u64"
        if op == "variant":
            return f"enum:{items[1].val}"
        if op in ("is_variant", "==", "!=", "<", "<=", ">", ">=", "and", "or", "not"):
            return "bool"
        if op == "match":
            for arm in items[2:]:
                ak = self._raw_kind(arm.val[1])
                if ak != "lit_pos":
                    return ak
            return "u64"
        if op == "get":
            bname = str(items[1].val)
            return "i64" if bname in self.slice_i64_vars else "u64"
        if op in ("byte_at", "read_u16_be", "read_u32_be", "read_u64_be", "bytes_eq4"):
            return "u64"
        if op == "fold":
            acc_t = items[2].val[2].raw()
            if acc_t == "i64" or (isinstance(acc_t, list) and acc_t and acc_t[0] == "i64_range"):
                return "i64"
            if isinstance(acc_t, str) and acc_t in self.tenv.structs:
                return f"struct:{acc_t}"
            return "u64"
        if op == "call":
            sig = self.tenv.sigs.get(str(items[1].val))
            return sig.ret_kind if sig else "u64"
        if op in ("io.print_u64", "io.print_i64"):
            return "cap.io"
        if op in ("fs.write_u64", "fs.write_i64"):
            return "cap.fs"
        if op == "net.loopback_send_u64":
            return "cap.net"
        if op in ("io.done", "fs.close", "net.close"):
            return "u64"
        if op == "~":
            return self._node_kind(items[1])
        if op in (">>", "<<"):
            return self._node_kind(items[1])
        if op in ("+", "-", "*", "/", "%", "min", "max", "&", "|", "^"):
            k1 = self._raw_kind(items[1])
            k2 = self._raw_kind(items[2])
            if k1 == "i64" or k2 == "i64":
                return "i64"
            return "u64"
        return "u64"

    def _node_kind(self, node: SNode) -> str:
        rk = self._raw_kind(node)
        return "u64" if rk == "lit_pos" else rk

    def _emit_let_lines(self, node: SNode, expected_kind: str, indent: str) -> tuple[list[str], str]:
        """Emit a `let` chain as indented statement lines plus trailing tail expression."""
        lines: list[str] = []
        old_kinds = dict(self.var_kinds)
        old_i64_slices = set(self.slice_i64_vars)
        try:
            for b in node.val[1].val:
                raw_name = str(b.val[0].val)
                bname = _rust_ident(raw_name)
                bexpr = b.val[1]
                bk = self._node_kind(bexpr)
                b_code, _ = self.emit_expr(bexpr, bk, indent)
                if bk in LINEAR_CAPS:
                    lines.append(f"{indent}let {bname}: () = {b_code};")
                else:
                    b_ty = _rust_type_for_kind(bk, is_i64_slice=(raw_name in self.slice_i64_vars))
                    lines.append(f"{indent}let {bname}: {b_ty} = {b_code};")
                self.var_kinds[raw_name] = bk
            tail_code, _ = self.emit_expr(node.val[2], expected_kind, indent)
            return lines, tail_code
        finally:
            self.var_kinds = old_kinds
            self.slice_i64_vars = old_i64_slices

    def emit_fn_body(self, body: SNode, ret_kind: str, indent: str = "    ") -> list[str]:
        if isinstance(body.val, list) and body.val and body.val[0].val == "let":
            lines, tail = self._emit_let_lines(body, ret_kind, indent)
            if ret_kind in LINEAR_CAPS or ret_kind == "void":
                if tail != "()":
                    lines.append(f"{indent}{tail};")
            else:
                lines.append(f"{indent}{tail}")
            return lines
        code, _ = self.emit_expr(body, ret_kind, indent)
        if ret_kind in LINEAR_CAPS or ret_kind == "void":
            if code == "()":
                return []
            if code.startswith("{") and code.endswith("}"):
                return [f"{indent}{code}"]
            return [f"{indent}{code};"]
        return [f"{indent}{code}"]

    def emit_expr(self, node: SNode, expected_kind: str | None = None, indent: str = "    ") -> tuple[str, bool]:
        if isinstance(node.val, int):
            tk = expected_kind if expected_kind in ("u64", "i64") else ("i64" if node.val < 0 else "u64")
            return _format_int_lit(node.val, tk)

        if isinstance(node.val, str):
            sym = node.val
            if sym == "MAX":
                return "u64::MAX", True
            if sym == "MIN_I64":
                return "i64::MIN", True
            if sym == "MAX_I64":
                return "i64::MAX", True
            if self.var_kinds.get(sym) in LINEAR_CAPS:
                return "()", True
            return _rust_ident(sym), True

        items = node.val
        op = str(items[0].val)
        nk = self._node_kind(node)
        eff_k = expected_kind if (expected_kind in ("u64", "i64") and self._raw_kind(node) == "lit_pos") else nk

        if op == "let":
            inner_indent = indent + "    "
            lines, tail = self._emit_let_lines(node, eff_k, inner_indent)
            body_s = "\n".join([*lines, f"{inner_indent}{tail}"])
            return f"{{\n{body_s}\n{indent}}}", False

        if op == "if":
            cond_s, _ = self.emit_expr(items[1], "bool", indent)
            branch_k = expected_kind if expected_kind in ("u64", "i64") else eff_k
            inner_indent = indent + "    "
            then_s, _ = self.emit_expr(items[2], branch_k, inner_indent)
            else_s, _ = self.emit_expr(items[3], branch_k, inner_indent)
            return f"if {cond_s} {{\n{inner_indent}{then_s}\n{indent}}} else {{\n{inner_indent}{else_s}\n{indent}}}", False

        if op == "to_i64":
            arg_n = items[1]
            rk = self._raw_kind(arg_n)
            if rk == "i64":
                return self.emit_expr(arg_n, "i64", indent)
            if isinstance(arg_n.val, int):
                return _format_int_lit(arg_n.val, "i64")
            arg_t = self.emit_expr(arg_n, "u64", indent)
            return f"{_atom(arg_t)} as i64", False

        if op == "to_u64":
            arg_n = items[1]
            rk = self._raw_kind(arg_n)
            if rk == "u64":
                return self.emit_expr(arg_n, "u64", indent)
            if rk == "lit_pos" and isinstance(arg_n.val, int):
                return _format_int_lit(arg_n.val, "u64")
            arg_t = self.emit_expr(arg_n, "i64", indent)
            return f"{_atom(arg_t)} as u64", False

        if op == "make":
            sname = str(items[1].val)
            sdef = self.tenv.structs[sname]
            parts: list[str] = []
            for fd, arg_n in zip(sdef.fields, items[2:]):
                val_s, _ = self.emit_expr(arg_n, fd.kind, indent)
                parts.append(f"{_rust_ident(fd.name)}: {val_s}")
            return f"{_rust_ident(sname)} {{ {', '.join(parts)} }}", True

        if op == "field":
            sv_t = self.emit_expr(items[1], None, indent)
            fname = _rust_ident(str(items[2].val))
            return f"{_atom(sv_t)}.{fname}", True

        if op == "variant":
            ename = str(items[1].val)
            vname = str(items[2].val)
            vdef = self.tenv.enums[ename].get_variant(vname)
            assert vdef is not None
            if not vdef.fields:
                return f"{_rust_ident(ename)}::{_rust_ident(vname)}", True
            vargs = [self.emit_expr(arg_n, fd.kind, indent)[0] for fd, arg_n in zip(vdef.fields, items[3:])]
            return f"{_rust_ident(ename)}::{_rust_ident(vname)}({', '.join(vargs)})", True

        if op == "is_variant":
            ename = self._node_kind(items[1]).split(":", 1)[1]
            vname = str(items[2].val)
            vdef = self.tenv.enums[ename].get_variant(vname)
            assert vdef is not None
            scrut_s, _ = self.emit_expr(items[1], f"enum:{ename}", indent)
            pat = f"{_rust_ident(ename)}::{_rust_ident(vname)}"
            if vdef.fields:
                pat += "(..)"
            return f"matches!({scrut_s}, {pat})", True

        if op == "match":
            scrut_n = items[1]
            ename = self._node_kind(scrut_n).split(":", 1)[1]
            edef = self.tenv.enums[ename]
            scrut_s, _ = self.emit_expr(scrut_n, f"enum:{ename}", indent)
            arm_k = expected_kind if expected_kind in ("u64", "i64") else eff_k
            inner_indent = indent + "    "
            arm_lines: list[str] = []
            for arm in items[2:]:
                pat, arm_body = arm.val[0], arm.val[1]
                old_kinds = dict(self.var_kinds)
                try:
                    if isinstance(pat.val, str) and pat.val == "_":
                        pat_s = "_"
                    else:
                        vname = str(pat.val[0].val)
                        vdef = edef.get_variant(vname)
                        assert vdef is not None
                        if not vdef.fields:
                            pat_s = f"{_rust_ident(ename)}::{_rust_ident(vname)}"
                        else:
                            bnames: list[str] = []
                            for bnode, fd in zip(pat.val[1:], vdef.fields):
                                raw_b = str(bnode.val)
                                self.var_kinds[raw_b] = fd.kind
                                bnames.append(_rust_ident(raw_b))
                            pat_s = f"{_rust_ident(ename)}::{_rust_ident(vname)}({', '.join(bnames)})"
                    body_s, _ = self.emit_expr(arm_body, arm_k, inner_indent + "    ")
                    arm_lines.append(f"{inner_indent}{pat_s} => {body_s},")
                finally:
                    self.var_kinds = old_kinds
            joined = "\n".join(arm_lines)
            return f"match {scrut_s} {{\n{joined}\n{indent}}}", False

        if op in _CAP_INTRINSICS:
            cap_expr = items[1]
            has_side_effect_cap = isinstance(cap_expr.val, list)
            inner_indent = indent + "    "
            stmts: list[str] = []
            if has_side_effect_cap:
                cap_s, _ = self.emit_expr(cap_expr, None, inner_indent)
                if cap_s != "()":
                    stmts.append(f"{inner_indent}let _ = {cap_s};")
            if op == "io.print_u64":
                val_s, _ = self.emit_expr(items[2], "u64", inner_indent)
                stmts.append(f"{inner_indent}caps.io_print_u64({val_s});")
                return self._block_or_stmt(stmts, None, indent), False
            if op == "io.print_i64":
                val_s, _ = self.emit_expr(items[2], "i64", inner_indent)
                stmts.append(f"{inner_indent}caps.io_print_i64({val_s});")
                return self._block_or_stmt(stmts, None, indent), False
            if op == "io.done":
                ret_k = eff_k if eff_k in ("u64", "i64") else "u64"
                ret_ty = _rust_type_for_kind(ret_k)
                ret_s, _ = self.emit_expr(items[2], ret_k, inner_indent)
                tmp_r = self._fresh("ret")
                stmts.append(f"{inner_indent}let {tmp_r}: {ret_ty} = {ret_s};")
                stmts.append(f"{inner_indent}caps.io_done();")
                return self._block_or_stmt(stmts, tmp_r, indent), False
            if op == "fs.write_u64":
                val_s, _ = self.emit_expr(items[2], "u64", inner_indent)
                stmts.append(f"{inner_indent}caps.fs_write_u64({val_s});")
                return self._block_or_stmt(stmts, None, indent), False
            if op == "fs.write_i64":
                val_s, _ = self.emit_expr(items[2], "i64", inner_indent)
                stmts.append(f"{inner_indent}caps.fs_write_i64({val_s});")
                return self._block_or_stmt(stmts, None, indent), False
            if op == "fs.close":
                stmts.append(f"{inner_indent}caps.fs_close();")
                return self._block_or_stmt(stmts, "0u64", indent), False
            if op == "net.loopback_send_u64":
                port_s, _ = self.emit_expr(items[2], "u64", inner_indent)
                payload_s, _ = self.emit_expr(items[3], "u64", inner_indent)
                stmts.append(f"{inner_indent}caps.net_loopback_send_u64({port_s}, {payload_s});")
                return self._block_or_stmt(stmts, None, indent), False
            if op == "net.close":
                stmts.append(f"{inner_indent}caps.net_close();")
                return self._block_or_stmt(stmts, "0u64", indent), False

        if op == "get":
            buf_raw = str(items[1].val)
            buf_rs = _rust_ident(buf_raw)
            idx_s, _ = self.emit_expr(items[2], "u64", indent)
            if buf_raw in self.slice_i64_vars:
                self.used_helpers.add("slice_get_i64")
                return f"ail_slice_get_i64({buf_rs}, {idx_s})", True
            self.used_helpers.add("slice_get_u64")
            return f"ail_slice_get_u64({buf_rs}, {idx_s})", True

        if op == "byte_at":
            self.used_helpers.add("byte_at")
            buf_s, _ = self.emit_expr(items[1], "bytes", indent)
            idx_s, _ = self.emit_expr(items[2], "u64", indent)
            return f"ail_byte_at({buf_s}, {idx_s})", True

        if op == "read_u16_be":
            self.used_helpers.add("read_u16_be")
            buf_s, _ = self.emit_expr(items[1], "bytes", indent)
            idx_s, _ = self.emit_expr(items[2], "u64", indent)
            return f"ail_read_u16_be({buf_s}, {idx_s})", True

        if op == "read_u32_be":
            self.used_helpers.add("read_u32_be")
            buf_s, _ = self.emit_expr(items[1], "bytes", indent)
            idx_s, _ = self.emit_expr(items[2], "u64", indent)
            return f"ail_read_u32_be({buf_s}, {idx_s})", True

        if op == "read_u64_be":
            self.used_helpers.add("read_u64_be")
            buf_s, _ = self.emit_expr(items[1], "bytes", indent)
            idx_s, _ = self.emit_expr(items[2], "u64", indent)
            return f"ail_read_u64_be({buf_s}, {idx_s})", True

        if op == "bytes_eq4":
            self.used_helpers.add("bytes_eq4")
            buf_s, _ = self.emit_expr(items[1], "bytes", indent)
            idx_s, _ = self.emit_expr(items[2], "u64", indent)
            b_args: list[str] = []
            for b_node in items[3:7]:
                if isinstance(b_node.val, int) and 0 <= b_node.val <= 255:
                    b_args.append(f"{b_node.val}u8")
                else:
                    b_t = self.emit_expr(b_node, "u64", indent)
                    b_args.append(f"({_atom(b_t)} & 255u64) as u8")
            return f"ail_bytes_eq4({buf_s}, {idx_s}, {', '.join(b_args)})", True

        if op == "fold":
            raw_ivar = str(items[1].val[0].val)
            raw_avar = str(items[2].val[0].val)
            ivar = _rust_ident(raw_ivar)
            avar = _rust_ident(raw_avar)
            acc_t_raw = items[2].val[2].raw()
            if acc_t_raw == "i64" or (isinstance(acc_t_raw, list) and acc_t_raw and acc_t_raw[0] == "i64_range"):
                acc_k = "i64"
            elif isinstance(acc_t_raw, str) and acc_t_raw in self.tenv.structs:
                acc_k = f"struct:{acc_t_raw}"
            elif isinstance(acc_t_raw, str) and acc_t_raw in self.tenv.enums:
                acc_k = f"enum:{acc_t_raw}"
            else:
                acc_k = "u64"
            acc_ty = _rust_type_for_kind(acc_k)
            inner_indent = indent + "    "
            bound_s, _ = self.emit_expr(items[1].val[1], "u64", inner_indent)
            init_s, _ = self.emit_expr(items[2].val[1], acc_k, inner_indent)
            bound_tmp = self._fresh("fold_bound")

            old_kinds = dict(self.var_kinds)
            try:
                self.var_kinds[raw_ivar] = "u64"
                self.var_kinds[raw_avar] = acc_k
                step_s, _ = self.emit_expr(items[3], acc_k, inner_indent + "    ")
            finally:
                self.var_kinds = old_kinds

            return (
                f"{{\n"
                f"{inner_indent}let {bound_tmp}: u64 = {bound_s};\n"
                f"{inner_indent}let mut {avar}: {acc_ty} = {init_s};\n"
                f"{inner_indent}for {ivar} in 0u64..{bound_tmp} {{\n"
                f"{inner_indent}    {avar} = {step_s};\n"
                f"{inner_indent}}}\n"
                f"{inner_indent}{avar}\n"
                f"{indent}}}"
            ), False

        if op == "call":
            callee = str(items[1].val)
            sig = self.tenv.sigs[callee]
            inner_indent = indent + "    "
            cap_prefixes: list[str] = []
            call_args: list[str] = ["caps"] if callee in self.cap_fns else []
            for arg_node, pk in zip(items[2:], sig.param_kinds):
                if pk in LINEAR_CAPS:
                    if isinstance(arg_node.val, list):
                        cap_s, _ = self.emit_expr(arg_node, None, inner_indent)
                        if cap_s != "()":
                            cap_prefixes.append(f"{inner_indent}let _ = {cap_s};")
                    continue
                if pk == "slice" and isinstance(arg_node.val, str) and self.var_kinds.get(arg_node.val) == "mut_slice":
                    call_args.append(f"&*{_rust_ident(arg_node.val)}")
                elif pk == "mut_slice" and isinstance(arg_node.val, str):
                    call_args.append(f"&mut *{_rust_ident(arg_node.val)}")
                else:
                    arg_indent = inner_indent if cap_prefixes else indent
                    arg_s, _ = self.emit_expr(arg_node, pk, arg_indent)
                    call_args.append(arg_s)
            call_code = f"{_rust_ident(callee)}({', '.join(call_args)})"
            if cap_prefixes:
                return "{\n" + "\n".join(cap_prefixes) + f"\n{inner_indent}{call_code}\n{indent}}}", False
            return call_code, True

        if op == "~":
            a_t = self.emit_expr(items[1], eff_k, indent)
            return f"!{_atom(a_t)}", False

        if op in ("==", "!=", "<", "<=", ">", ">="):
            k1 = self._raw_kind(items[1])
            k2 = self._raw_kind(items[2])
            if k1 == "i64" or k2 == "i64":
                cmp_k = "i64"
            elif k1.startswith(("struct:", "enum:")):
                cmp_k = k1
            else:
                cmp_k = "u64"
            lhs_t = self.emit_expr(items[1], cmp_k, indent)
            rhs_t = self.emit_expr(items[2], cmp_k, indent)
            return f"{_atom(lhs_t)} {op} {_atom(rhs_t)}", False

        if op == "not":
            arg_t = self.emit_expr(items[1], "bool", indent)
            return f"!{_atom(arg_t)}", False

        if op in ("and", "or"):
            rop = " && " if op == "and" else " || "
            if len(items) == 2:
                return self.emit_expr(items[1], "bool", indent)
            parts = [_atom(self.emit_expr(a, "bool", indent)) for a in items[1:]]
            return rop.join(parts), False

        if op in (">>", "<<"):
            lhs_t = self.emit_expr(items[1], eff_k, indent)
            rhs_t = self.emit_expr(items[2], "u64", indent)
            method = "wrapping_shr" if op == ">>" else "wrapping_shl"
            return f"{_atom(lhs_t)}.{method}({_atom(rhs_t)} as u32)", True

        lhs_t = self.emit_expr(items[1], eff_k, indent)
        rhs_t = self.emit_expr(items[2], eff_k, indent)
        lhs_s = _atom(lhs_t)
        rhs_raw = rhs_t[0]

        if op == "+":
            return f"{lhs_s}.wrapping_add({rhs_raw})", True
        if op == "-":
            return f"{lhs_s}.wrapping_sub({rhs_raw})", True
        if op == "*":
            return f"{lhs_s}.wrapping_mul({rhs_raw})", True
        if op == "/":
            return f"{lhs_s}.checked_div({rhs_raw}).unwrap_or(0)", True
        if op == "%":
            return f"{lhs_s}.checked_rem({rhs_raw}).unwrap_or(0)", True
        if op == "min":
            return f"{lhs_s}.min({rhs_raw})", True
        if op == "max":
            return f"{lhs_s}.max({rhs_raw})", True
        if op in ("&", "|", "^"):
            return f"{lhs_s} {op} {_atom(rhs_t)}", False

        raise AILCompilerError(
            pb.E_SYNTAX,
            pb.STAGE_LLVM_CODEGEN,
            "<rust>",
            f"Unsupported operator `{op}` in Rust backend",
            node.span,
            pretty(node),
        )

    @staticmethod
    def _block_or_stmt(stmts: list[str], tail: str | None, indent: str) -> str:
        inner_indent = indent + "    "
        all_lines = list(stmts)
        if tail is not None:
            all_lines.append(f"{inner_indent}{tail}")
        return "{\n" + "\n".join(all_lines) + f"\n{indent}}}"


def _emit_rust_helpers(used: set[str]) -> list[str]:
    helpers: list[str] = []
    if "slice_get_u64" in used:
        helpers.append(
            "#[inline]\n"
            "fn ail_slice_get_u64(buf: &[u64], idx: u64) -> u64 {\n"
            "    match usize::try_from(idx) {\n"
            "        Ok(i) => match buf.get(i) {\n"
            "            Some(&v) => v,\n"
            "            None => 0,\n"
            "        },\n"
            "        Err(_) => 0,\n"
            "    }\n"
            "}\n"
        )
    if "slice_get_i64" in used:
        helpers.append(
            "#[inline]\n"
            "fn ail_slice_get_i64(buf: &[i64], idx: u64) -> i64 {\n"
            "    match usize::try_from(idx) {\n"
            "        Ok(i) => match buf.get(i) {\n"
            "            Some(&v) => v,\n"
            "            None => 0,\n"
            "        },\n"
            "        Err(_) => 0,\n"
            "    }\n"
            "}\n"
        )
    if "byte_at" in used:
        helpers.append(
            "#[inline]\n"
            "fn ail_byte_at(buf: &[u8], idx: u64) -> u64 {\n"
            "    match usize::try_from(idx) {\n"
            "        Ok(i) => match buf.get(i) {\n"
            "            Some(&b) => b as u64,\n"
            "            None => 0,\n"
            "        },\n"
            "        Err(_) => 0,\n"
            "    }\n"
            "}\n"
        )
    if "read_u16_be" in used:
        helpers.append(
            "#[inline]\n"
            "fn ail_read_u16_be(buf: &[u8], idx: u64) -> u64 {\n"
            "    if let Ok(i) = usize::try_from(idx) {\n"
            "        if let Some(end) = i.checked_add(2) {\n"
            "            if let Some(sub) = buf.get(i..end) {\n"
            "                if let Ok(arr) = <[u8; 2]>::try_from(sub) {\n"
            "                    return u16::from_be_bytes(arr) as u64;\n"
            "                }\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "    0\n"
            "}\n"
        )
    if "read_u32_be" in used:
        helpers.append(
            "#[inline]\n"
            "fn ail_read_u32_be(buf: &[u8], idx: u64) -> u64 {\n"
            "    if let Ok(i) = usize::try_from(idx) {\n"
            "        if let Some(end) = i.checked_add(4) {\n"
            "            if let Some(sub) = buf.get(i..end) {\n"
            "                if let Ok(arr) = <[u8; 4]>::try_from(sub) {\n"
            "                    return u32::from_be_bytes(arr) as u64;\n"
            "                }\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "    0\n"
            "}\n"
        )
    if "read_u64_be" in used:
        helpers.append(
            "#[inline]\n"
            "fn ail_read_u64_be(buf: &[u8], idx: u64) -> u64 {\n"
            "    if let Ok(i) = usize::try_from(idx) {\n"
            "        if let Some(end) = i.checked_add(8) {\n"
            "            if let Some(sub) = buf.get(i..end) {\n"
            "                if let Ok(arr) = <[u8; 8]>::try_from(sub) {\n"
            "                    return u64::from_be_bytes(arr);\n"
            "                }\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "    0\n"
            "}\n"
        )
    if "bytes_eq4" in used:
        helpers.append(
            "#[inline]\n"
            "fn ail_bytes_eq4(buf: &[u8], idx: u64, b0: u8, b1: u8, b2: u8, b3: u8) -> u64 {\n"
            "    if let Ok(i) = usize::try_from(idx) {\n"
            "        if let Some(end) = i.checked_add(4) {\n"
            "            if let Some(sub) = buf.get(i..end) {\n"
            "                return if sub == [b0, b1, b2, b3] { 1 } else { 0 };\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "    0\n"
            "}\n"
        )
    return helpers


def _extract_range_pair(tspec: SNode) -> tuple[SNode, SNode]:
    raw = tspec.raw()
    if raw == "u64":
        return SNode(0, tspec.span), SNode("MAX", tspec.span)
    if raw == "i64":
        return SNode("MIN_I64", tspec.span), SNode("MAX_I64", tspec.span)
    if isinstance(tspec.val, list) and len(tspec.val) == 3 and tspec.val[0].val in ("u64_range", "i64_range"):
        return tspec.val[1], tspec.val[2]
    return SNode(0, tspec.span), SNode("MAX", tspec.span)


def emit_rust_source(forms: list[SNode], tenv: ModuleTypeEnv) -> str:
    cap_fns = _compute_cap_functions(forms, tenv)
    used_helpers: set[str] = set()

    struct_blocks: list[str] = []
    for sdef in tenv.structs.values():
        fields_rs = [
            f"    pub {_rust_ident(fd.name)}: {'i64' if fd.kind == 'i64' else 'u64'},"
            for fd in sdef.fields
        ]
        struct_blocks.append(
            "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n"
            f"pub struct {_rust_ident(sdef.name)} {{\n"
            + "\n".join(fields_rs)
            + "\n}\n"
        )

    enum_blocks: list[str] = []
    for edef in tenv.enums.values():
        variants_rs: list[str] = []
        for vdef in edef.variants:
            if not vdef.fields:
                variants_rs.append(f"    {_rust_ident(vdef.name)},")
            else:
                ftypes = ", ".join("i64" if fd.kind == "i64" else "u64" for fd in vdef.fields)
                variants_rs.append(f"    {_rust_ident(vdef.name)}({ftypes}),")
        enum_blocks.append(
            "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n"
            f"pub enum {_rust_ident(edef.name)} {{\n"
            + "\n".join(variants_rs)
            + "\n}\n"
        )

    # Collect atomic_protocol step transitions: (pname, sname) -> (f0_name, sparam_specs, next_f0_node)
    proto_steps: dict[tuple[str, str], tuple[str, list[tuple[str, str, SNode, SNode]], SNode]] = {}
    for form in forms:
        if isinstance(form.val, list) and form.val and str(form.val[0].val) == "atomic_protocol":
            pname = str(form.val[1].val)
            f0_name = str(form.val[2].val[0].val[0].val)
            for sn in form.val[4:]:
                sname = str(sn.val[1].val)
                sparams: list[tuple[str, str, SNode, SNode]] = []
                for sp in sn.val[2].val:
                    sp_name = str(sp.val[0].val)
                    sp_raw = sp.val[1].raw()
                    sp_kind = "i64" if (sp_raw == "i64" or (isinstance(sp_raw, list) and sp_raw and sp_raw[0] == "i64_range")) else "u64"
                    lo_n, hi_n = _extract_range_pair(sp.val[1])
                    sparams.append((sp_name, sp_kind, lo_n, hi_n))
                next_f0 = sn.val[3].val[0]
                proto_steps[(pname, sname)] = (f0_name, sparams, next_f0)

    fn_blocks: list[str] = []
    for form in forms:
        if not isinstance(form.val, list) or not form.val:
            continue
        head = str(form.val[0].val)
        if head in ("spec", "struct", "enum", "atomic_protocol", "const"):
            continue

        if head in ("fn", "main"):
            is_main = head == "main"
            name = "main" if is_main else str(form.val[1].val)
            rust_fn_name = "ail_main" if is_main else _rust_ident(name)
            params_n = form.val[1] if is_main else form.val[2]
            body_n = form.val[3] if is_main else form.val[4]
            sig = tenv.sigs[name]

            var_kinds: dict[str, str] = {}
            slice_i64_vars: set[str] = set()
            rs_params: list[str] = []
            if name in cap_fns:
                rs_params.append("caps: &mut C")

            for p, pk in zip(params_n.val, sig.param_kinds):
                pname = str(p.val[0].val)
                var_kinds[pname] = pk
                if pk in LINEAR_CAPS:
                    continue
                is_i64_sl = pk in ("slice", "mut_slice") and _slice_elem_is_i64(p.val[1])
                if is_i64_sl:
                    slice_i64_vars.add(pname)
                rs_params.append(f"{_rust_ident(pname)}: {_rust_type_for_kind(pk, is_i64_slice=is_i64_sl)}")

            generics = "<C: AilHostCaps + ?Sized>" if name in cap_fns else ""
            ret_str = "" if sig.ret_kind in LINEAR_CAPS else f" -> {_rust_type_for_kind(sig.ret_kind)}"

            em = RustExprEmitter(tenv, var_kinds, slice_i64_vars, cap_fns)
            body_lines = em.emit_fn_body(body_n, sig.ret_kind, indent="    ")
            used_helpers.update(em.used_helpers)

            fn_blocks.append(
                f"pub fn {rust_fn_name}{generics}({', '.join(rs_params)}){ret_str} {{\n"
                + ("\n".join(body_lines) + "\n" if body_lines else "")
                + "}\n"
            )

        elif head == "map_inplace":
            name = str(form.val[1].val)
            params_n, _, elem_vars, body_n = form.val[2], form.val[3], form.val[4], form.val[5]
            raw_elem_var = str(elem_vars.val[0].val)
            elem_var = _rust_ident(raw_elem_var)
            sig = tenv.sigs[name]

            var_kinds: dict[str, str] = {}
            slice_i64_vars: set[str] = set()
            rs_params: list[str] = []
            mut_buf_name = ""
            len_name = ""
            elem_k = "u64"

            for p, pk in zip(params_n.val, sig.param_kinds):
                pname = str(p.val[0].val)
                var_kinds[pname] = pk
                is_i64_sl = pk in ("slice", "mut_slice") and _slice_elem_is_i64(p.val[1])
                if is_i64_sl:
                    slice_i64_vars.add(pname)
                if pk == "mut_slice":
                    mut_buf_name = _rust_ident(pname)
                    len_name = _rust_ident(str(p.val[1].val[1].val))
                    elem_k = "i64" if is_i64_sl else "u64"
                rs_params.append(f"{_rust_ident(pname)}: {_rust_type_for_kind(pk, is_i64_slice=is_i64_sl)}")

            var_kinds[raw_elem_var] = elem_k
            em = RustExprEmitter(tenv, var_kinds, slice_i64_vars, cap_fns)
            step_s, _ = em.emit_expr(body_n, elem_k, indent="        ")
            used_helpers.update(em.used_helpers)

            fn_blocks.append(
                f"pub fn {_rust_ident(name)}({', '.join(rs_params)}) {{\n"
                f"    let __ail_limit: usize = usize::try_from({len_name}).unwrap_or({mut_buf_name}.len()).min({mut_buf_name}.len());\n"
                f"    for __ail_slot in {mut_buf_name}.iter_mut().take(__ail_limit) {{\n"
                f"        let {elem_var}: {elem_k} = *__ail_slot;\n"
                f"        *__ail_slot = {step_s};\n"
                f"    }}\n"
                f"}}\n"
            )

        elif head == "atomic_cas":
            name = str(form.val[1].val)
            pname = str(form.val[2].val)
            sname = str(form.val[3].val)
            params_n = form.val[4]
            sig = tenv.sigs[name]

            rs_params: list[str] = []
            ptr_rs = _rust_ident(str(params_n.val[0].val[0].val))
            scalar_param_rs: list[str] = []
            for p, pk in zip(params_n.val, sig.param_kinds):
                pn = str(p.val[0].val)
                rs_params.append(f"{_rust_ident(pn)}: {_rust_type_for_kind(pk)}")
                if pk != "atomic_u64":
                    scalar_param_rs.append(_rust_ident(pn))

            f0_name, sparams, next_f0_node = proto_steps[(pname, sname)]
            step_var_kinds: dict[str, str] = {f0_name: "u64"}
            guard_parts: list[str] = []
            em_step = RustExprEmitter(tenv, step_var_kinds, set(), cap_fns)

            # Map protocol f0 -> "__ail_obs" and step params -> atomic_cas scalar args
            # Note: evaluate guard expressions using step variable names bound in Rust
            guard_bindings: list[str] = []
            for idx_sp, (sp_name, sp_kind, lo_n, hi_n) in enumerate(sparams):
                step_var_kinds[sp_name] = sp_kind
                if idx_sp < len(scalar_param_rs) and _rust_ident(sp_name) != scalar_param_rs[idx_sp]:
                    guard_bindings.append(f"        let {_rust_ident(sp_name)}: {sp_kind} = {scalar_param_rs[idx_sp]};")

            em_step.var_kinds = dict(step_var_kinds)
            obs_bind = f"        let {_rust_ident(f0_name)}: u64 = __ail_obs;"
            for sp_name, sp_kind, lo_n, hi_n in sparams:
                sp_rs = _rust_ident(sp_name)
                if not (sp_kind == "u64" and lo_n.val == 0):
                    lo_t = em_step.emit_expr(lo_n, sp_kind, "        ")
                    guard_parts.append(f"{sp_rs} >= {_atom(lo_t)}")
                if not (sp_kind == "u64" and hi_n.val == "MAX") and not (sp_kind == "i64" and hi_n.val == "MAX_I64"):
                    hi_t = em_step.emit_expr(hi_n, sp_kind, "        ")
                    guard_parts.append(f"{sp_rs} <= {_atom(hi_t)}")

            desired_s, _ = em_step.emit_expr(next_f0_node, "u64", "        ")
            used_helpers.update(em_step.used_helpers)
            guard_lines = [obs_bind, *guard_bindings]
            guard_block = ""
            if guard_parts:
                guard_cond = " && ".join(guard_parts)
                guard_block = (
                    f"        if !({guard_cond}) {{\n"
                    f"            return 0u64;\n"
                    f"        }}\n"
                )
            fn_blocks.append(
                f"pub fn {_rust_ident(name)}({', '.join(rs_params)}) -> u64 {{\n"
                f"    let mut __ail_obs: u64 = {ptr_rs}.load(core::sync::atomic::Ordering::Relaxed);\n"
                f"    loop {{\n"
                + "\n".join(guard_lines)
                + "\n"
                + guard_block
                + f"        let __ail_desired: u64 = {desired_s};\n"
                f"        match {ptr_rs}.compare_exchange_weak(\n"
                f"            __ail_obs,\n"
                f"            __ail_desired,\n"
                f"            core::sync::atomic::Ordering::AcqRel,\n"
                f"            core::sync::atomic::Ordering::Relaxed,\n"
                f"        ) {{\n"
                f"            Ok(_) => return 1u64,\n"
                f"            Err(__ail_actual) => __ail_obs = __ail_actual,\n"
                f"        }}\n"
                f"    }}\n"
                f"}}\n"
            )

    sections: list[str] = [
        "// Auto-generated by ailang — Formally Verified #![no_std] #![forbid(unsafe_code)] Rust Target",
        "#![no_std]",
        "#![forbid(unsafe_code)]",
        "#![allow(dead_code, non_camel_case_types, non_snake_case, unused_variables)]",
        "",
    ]

    if cap_fns:
        sections.append(
            "pub trait AilHostCaps {\n"
            "    fn io_print_u64(&mut self, _val: u64) {}\n"
            "    fn io_print_i64(&mut self, _val: i64) {}\n"
            "    fn io_done(&mut self) {}\n"
            "    fn fs_write_u64(&mut self, _val: u64) {}\n"
            "    fn fs_write_i64(&mut self, _val: i64) {}\n"
            "    fn fs_close(&mut self) {}\n"
            "    fn net_loopback_send_u64(&mut self, _port: u64, _payload: u64) {}\n"
            "    fn net_close(&mut self) {}\n"
            "}\n"
        )

    sections.extend(_emit_rust_helpers(used_helpers))
    sections.extend(struct_blocks)
    sections.extend(enum_blocks)
    sections.extend(fn_blocks)
    return "\n".join(sections).rstrip() + "\n"


def compile_to_rust(
    forms: list[SNode],
    tenv: ModuleTypeEnv,
    out_dir: Path,
    module_name: str = "ail_mod",
    verify_rustc: bool = True,
) -> RustArtifacts:
    out_dir = Path(out_dir)
    src_dir = out_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)

    if tenv is None:
        tenv = check_module_ownership_v2(forms)

    crate_name = _sanitize_crate_name(module_name)
    cargo_toml_path = out_dir / "Cargo.toml"
    lib_rs_path = src_dir / "lib.rs"
    rlib_file = out_dir / f"lib{crate_name}.rlib"

    cargo_toml = (
        "[package]\n"
        f'name = "{crate_name}"\n'
        'version = "0.1.0"\n'
        'edition = "2021"\n\n'
        "[lib]\n"
        f'name = "{crate_name}"\n'
        'path = "src/lib.rs"\n'
        'crate-type = ["rlib"]\n'
    )
    cargo_toml_path.write_text(cargo_toml)

    lib_rs = emit_rust_source(forms, tenv)
    lib_rs_path.write_text(lib_rs)

    rlib_out = ""
    if verify_rustc:
        rustc_bin = shutil.which("rustc") or str(Path.home() / ".cargo" / "bin" / "rustc")
        proc = subprocess.run(
            [
                rustc_bin,
                "--edition",
                "2021",
                "--crate-type",
                "rlib",
                "--crate-name",
                crate_name,
                "-O",
                "-D",
                "warnings",
                str(lib_rs_path),
                "-o",
                str(rlib_file),
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"rustc verification failed for {lib_rs_path}:\n{proc.stderr.strip() or proc.stdout.strip()}"
            )
        rlib_out = str(rlib_file)

    return RustArtifacts(
        crate_dir=str(out_dir),
        lib_rs_path=str(lib_rs_path),
        cargo_toml_path=str(cargo_toml_path),
        rlib_path=rlib_out,
    )
