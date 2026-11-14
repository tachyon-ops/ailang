"""Static Ownership, Signed/Unsigned Type Safety, Dependent Structs, and Linear Capabilities (`cap.io`, `cap.fs`, `cap.net`)."""

from __future__ import annotations
from dataclasses import dataclass, field

from ailang import ail_agent_pb2 as pb
from ailang.diagnostics import AILCompilerError, Span
from ailang.parser import SNode, pretty

LINEAR_CAPS = {"cap.io", "cap.fs", "cap.net"}


@dataclass
class StructFieldDef:
    name: str
    kind: str  # "u64" | "i64"
    type_node: SNode


@dataclass
class StructDef:
    name: str
    fields: list[StructFieldDef]
    span: Span

    def get_field(self, fname: str) -> tuple[int, StructFieldDef] | None:
        for idx, f in enumerate(self.fields):
            if f.name == fname:
                return idx, f
        return None


@dataclass
class FnSig:
    name: str
    kind: str  # "spec" | "fn" | "map_inplace" | "atomic_cas" | "main"
    param_kinds: list[str]
    ret_kind: str = "u64"


@dataclass
class ModuleTypeEnv:
    sigs: dict[str, FnSig] = field(default_factory=dict)
    structs: dict[str, StructDef] = field(default_factory=dict)
    expr_types: dict[int, str] = field(default_factory=dict)  # id(SNode) -> resolved scalar/struct kind


def _classify_type(tspec: SNode, structs: dict[str, StructDef], allow_math_int: bool, item_name: str) -> str:
    raw = tspec.raw()
    if raw == "u64" or (isinstance(raw, list) and raw and raw[0] == "u64_range"):
        return "u64"
    if raw == "i64" or (isinstance(raw, list) and raw and raw[0] == "i64_range"):
        return "i64"
    if isinstance(raw, str) and raw in LINEAR_CAPS:
        return raw
    if isinstance(raw, str) and raw in structs:
        return f"struct:{raw}"
    if raw == "int":
        if not allow_math_int:
            raise AILCompilerError(
                pb.E_TYPE_MISMATCH,
                pb.STAGE_OWNERSHIP,
                item_name,
                "Unbounded `int` is restricted to `(spec ...)` declarations; runtime functions must use `u64` or `i64`.",
                tspec.span,
                pretty(tspec),
            )
        return "int"
    if isinstance(raw, list) and len(raw) == 3 and raw[0] in ("slice", "mut_slice"):
        return raw[0]
    if isinstance(raw, list) and len(raw) == 2 and raw[0] == "atomic" and raw[1] == "u64":
        return "atomic_u64"
    raise AILCompilerError(
        pb.E_TYPE_MISMATCH,
        pb.STAGE_OWNERSHIP,
        item_name,
        f"Invalid type `{pretty(tspec)}`",
        tspec.span,
        pretty(tspec),
    )


def _extract_ret_kind(ret_node: SNode, structs: dict[str, StructDef], item_name: str) -> str:
    raw = ret_node.raw()
    if isinstance(raw, str) and (raw in LINEAR_CAPS or raw in ("u64", "i64") or raw in structs):
        return _classify_type(ret_node, structs, False, item_name)
    if isinstance(raw, list) and raw and raw[0] in ("u64_range", "i64_range"):
        return "u64" if raw[0] == "u64_range" else "i64"
    if isinstance(ret_node.val, list) and len(ret_node.val) >= 2:
        return _classify_type(ret_node.val[1], structs, False, item_name)
    raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, item_name, f"Invalid return spec `{pretty(ret_node)}`", ret_node.span)


def _unify_numeric(k1: str, k2: str, span: Span, item_name: str, expr_s: str) -> str:
    if k1 == "int" or k2 == "int":
        return "int"
    if k1 == k2:
        return "u64" if k1 == "lit_pos" else k1
    if k1 == "lit_pos" and k2 in ("u64", "i64"):
        return k2
    if k2 == "lit_pos" and k1 in ("u64", "i64"):
        return k1
    raise AILCompilerError(
        pb.E_TYPE_MISMATCH,
        pb.STAGE_OWNERSHIP,
        item_name,
        f"Cannot mix `{k1}` and `{k2}` without explicit `(to_i64 ...)` or `(to_u64 ...)` cast.",
        span,
        expr_s,
    )


def _compatible_arg(actual: str, expected: str) -> bool:
    if actual == expected:
        return True
    if actual == "lit_pos" and expected in ("u64", "i64", "int"):
        return True
    if expected == "int" and actual in ("u64", "i64", "lit_pos"):
        return True
    return False


@dataclass
class LinearScope:
    item_name: str
    var_kinds: dict[str, str] = field(default_factory=dict)
    linear_alive: dict[str, Span] = field(default_factory=dict)
    linear_consumed: set[str] = field(default_factory=set)

    def bind(self, name: str, kind: str, span: Span) -> None:
        resolved = "u64" if kind == "lit_pos" else kind
        self.var_kinds[name] = resolved
        if resolved in LINEAR_CAPS:
            self.linear_alive[name] = span

    def consume_linear(self, name: str, expected_cap: str | None, use_span: Span, expr_str: str) -> str:
        if name in self.linear_consumed:
            raise AILCompilerError(
                pb.E_LINEAR_USE_AFTER_MOVE,
                pb.STAGE_OWNERSHIP,
                self.item_name,
                f"Linear capability `{name}` was already consumed and cannot be reused.",
                use_span,
                expr_str,
            )
        if name not in self.linear_alive:
            raise AILCompilerError(
                pb.E_CAPABILITY_MISSING,
                pb.STAGE_OWNERSHIP,
                self.item_name,
                f"`{name}` is not a live linear capability token.",
                use_span,
                expr_str,
            )
        actual_cap = self.var_kinds[name]
        if expected_cap and actual_cap != expected_cap:
            raise AILCompilerError(
                pb.E_CAPABILITY_MISSING,
                pb.STAGE_OWNERSHIP,
                self.item_name,
                f"Expected `{expected_cap}`, but `{name}` has capability type `{actual_cap}`.",
                use_span,
                expr_str,
            )
        del self.linear_alive[name]
        self.linear_consumed.add(name)
        return actual_cap

    def clone_for_branch(self) -> LinearScope:
        return LinearScope(
            item_name=self.item_name,
            var_kinds=dict(self.var_kinds),
            linear_alive=dict(self.linear_alive),
            linear_consumed=set(self.linear_consumed),
        )


def _check_expr(node: SNode, scope: LinearScope, tenv: ModuleTypeEnv, in_spec: bool) -> str:
    def record(k: str) -> str:
        tenv.expr_types[id(node)] = k
        return k

    if isinstance(node.val, int):
        if in_spec:
            return record("int")
        return record("lit_pos" if node.val >= 0 else "i64")

    if isinstance(node.val, str):
        sym = node.val
        if sym == "MAX":
            return record("int" if in_spec else "u64")
        if sym in ("MIN_I64", "MAX_I64"):
            return record("int" if in_spec else "i64")
        if sym not in scope.var_kinds:
            raise AILCompilerError(pb.E_UNBOUND_SYMBOL, pb.STAGE_OWNERSHIP, scope.item_name, f"Unbound variable `{sym}`", node.span, sym)
        k = scope.var_kinds[sym]
        if k in LINEAR_CAPS:
            scope.consume_linear(sym, k, node.span, sym)
        return record(k)

    items = node.val
    if not items or not isinstance(items[0].val, str):
        raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, scope.item_name, "Expected operator symbol", node.span, pretty(node))
    op = items[0].val

    if op == "let":
        if len(items) != 3 or not isinstance(items[1].val, list):
            raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, scope.item_name, "Malformed `let`", node.span, pretty(node))
        for b in items[1].val:
            if not isinstance(b.val, list) or len(b.val) != 2 or not isinstance(b.val[0].val, str):
                raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, scope.item_name, "Malformed `let` binding", b.span, pretty(b))
            bname = b.val[0].val
            bk = _check_expr(b.val[1], scope, tenv, in_spec)
            scope.bind(bname, bk, b.span)
        return record(_check_expr(items[2], scope, tenv, in_spec))

    if op == "if":
        if len(items) != 4:
            raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, scope.item_name, "`if` expects 3 arguments", node.span, pretty(node))
        _check_expr(items[1], scope, tenv, in_spec)
        s_then = scope.clone_for_branch()
        s_else = scope.clone_for_branch()
        kt = _check_expr(items[2], s_then, tenv, in_spec)
        ke = _check_expr(items[3], s_else, tenv, in_spec)
        if set(s_then.linear_alive.keys()) != set(s_else.linear_alive.keys()):
            raise AILCompilerError(
                pb.E_LINEAR_UNCONSUMED,
                pb.STAGE_OWNERSHIP,
                scope.item_name,
                "Branches of `if` must consume identical linear capabilities.",
                node.span,
                pretty(node),
            )
        scope.linear_alive = s_then.linear_alive
        scope.linear_consumed = s_then.linear_consumed | s_else.linear_consumed
        if kt.startswith("struct:") or kt in LINEAR_CAPS:
            if kt != ke:
                raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, f"Branch type mismatch `{kt}` vs `{ke}`", node.span, pretty(node))
            return record(kt)
        return record(_unify_numeric(kt, ke, node.span, scope.item_name, pretty(node)))

    if op in ("to_i64", "to_u64"):
        if len(items) != 2:
            raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, scope.item_name, f"`{op}` expects 1 argument", node.span, pretty(node))
        ak = _check_expr(items[1], scope, tenv, in_spec)
        if in_spec:
            return record("int")
        if op == "to_i64" and ak not in ("u64", "lit_pos"):
            raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, "`to_i64` expects a `u64` argument", items[1].span, pretty(node))
        if op == "to_u64" and ak not in ("i64", "lit_pos"):
            raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, "`to_u64` expects an `i64` argument", items[1].span, pretty(node))
        return record("i64" if op == "to_i64" else "u64")

    # Algebraic Structs: `(make StructName f1 f2 ...)` and `(field s fname)`
    if op == "make":
        if len(items) < 2 or not isinstance(items[1].val, str):
            raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, scope.item_name, "Expected `(make StructName args...)`", node.span, pretty(node))
        sname = items[1].val
        if sname not in tenv.structs:
            raise AILCompilerError(pb.E_UNBOUND_SYMBOL, pb.STAGE_OWNERSHIP, scope.item_name, f"Unknown struct `{sname}`", items[1].span, pretty(node))
        sdef = tenv.structs[sname]
        fargs = items[2:]
        if len(fargs) != len(sdef.fields):
            raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, f"`{sname}` has {len(sdef.fields)} fields, got {len(fargs)}", node.span, pretty(node))
        for fa, fd in zip(fargs, sdef.fields):
            ak = _check_expr(fa, scope, tenv, in_spec)
            if not _compatible_arg(ak, fd.kind):
                raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, f"Field `{fd.name}` expects `{fd.kind}`, got `{ak}`", fa.span, pretty(node))
        return record(f"struct:{sname}")

    if op == "field":
        if len(items) != 3 or not isinstance(items[2].val, str):
            raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, scope.item_name, "Expected `(field struct_expr field_name)`", node.span, pretty(node))
        sk = _check_expr(items[1], scope, tenv, in_spec)
        if not sk.startswith("struct:"):
            raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, f"Cannot access field on non-struct `{sk}`", items[1].span, pretty(node))
        sname = sk.split(":", 1)[1]
        fname = items[2].val
        found = tenv.structs[sname].get_field(fname)
        if not found:
            raise AILCompilerError(pb.E_UNBOUND_SYMBOL, pb.STAGE_OWNERSHIP, scope.item_name, f"Struct `{sname}` has no field `{fname}`", items[2].span, pretty(node))
        return record("int" if in_spec else found[1].kind)

    # Capability-gated I/O, Filesystem (`cap.fs`), and Local Loopback Network (`cap.net`) Intrinsics
    cap_intrinsics: dict[str, tuple[str, list[str], str]] = {
        "io.print_u64": ("cap.io", ["u64"], "cap.io"),
        "io.print_i64": ("cap.io", ["i64"], "cap.io"),
        "io.done": ("cap.io", ["u64"], "u64"),
        "fs.write_u64": ("cap.fs", ["u64"], "cap.fs"),
        "fs.write_i64": ("cap.fs", ["i64"], "cap.fs"),
        "fs.close": ("cap.fs", [], "u64"),
        "net.loopback_send_u64": ("cap.net", ["u64", "u64"], "cap.net"),
        "net.close": ("cap.net", [], "u64"),
    }
    if op in cap_intrinsics:
        req_cap, val_types, ret_t = cap_intrinsics[op]
        if in_spec:
            raise AILCompilerError(pb.E_CAPABILITY_MISSING, pb.STAGE_OWNERSHIP, scope.item_name, f"Cannot invoke `{op}` inside `(spec ...)`", node.span, pretty(node))
        if len(items) != 2 + len(val_types):
            raise AILCompilerError(pb.E_CAPABILITY_MISSING, pb.STAGE_OWNERSHIP, scope.item_name, f"`{op}` expects `{req_cap}` + {len(val_types)} value arg(s)", node.span, pretty(node))
        tok_node = items[1]
        if isinstance(tok_node.val, str) and tok_node.val in scope.var_kinds:
            scope.consume_linear(tok_node.val, req_cap, tok_node.span, pretty(node))
            tenv.expr_types[id(tok_node)] = req_cap
        else:
            tk = _check_expr(tok_node, scope, tenv, in_spec)
            if tk != req_cap:
                raise AILCompilerError(pb.E_CAPABILITY_MISSING, pb.STAGE_OWNERSHIP, scope.item_name, f"`{op}` requires `{req_cap}`, got `{tk}`", tok_node.span, pretty(node))
        for arg_n, vt in zip(items[2:], val_types):
            ak = _check_expr(arg_n, scope, tenv, in_spec)
            if not _compatible_arg(ak, vt):
                raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, f"`{op}` expects `{vt}`, got `{ak}`", arg_n.span, pretty(node))
        return record(ret_t)

    if op == "get":
        if len(items) != 3 or not isinstance(items[1].val, str):
            raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, scope.item_name, "Expected `(get slice_var idx)`", node.span, pretty(node))
        buf_name = items[1].val
        if scope.var_kinds.get(buf_name) not in ("slice", "mut_slice"):
            raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, f"`{buf_name}` is not a slice", items[1].span, pretty(node))
        ik = _check_expr(items[2], scope, tenv, in_spec)
        if not _compatible_arg(ik, "u64"):
            raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, "Slice index must be `u64`", items[2].span, pretty(node))
        return record("u64")

    if op == "fold":
        idx_pair, acc_triple, step_node = items[1], items[2], items[3]
        assert isinstance(idx_pair.val, list) and isinstance(acc_triple.val, list)
        ivar = str(idx_pair.val[0].val)
        avar = str(acc_triple.val[0].val)
        acc_kind = _classify_type(acc_triple.val[2], tenv.structs, False, scope.item_name)
        bk = _check_expr(idx_pair.val[1], scope, tenv, in_spec)
        if not _compatible_arg(bk, "u64"):
            raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, "`fold` bound must be `u64`", idx_pair.span, pretty(node))
        ik = _check_expr(acc_triple.val[1], scope, tenv, in_spec)
        if not _compatible_arg(ik, acc_kind):
            raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, f"`fold` init does not match `{acc_kind}`", acc_triple.span, pretty(node))
        body_scope = scope.clone_for_branch()
        body_scope.bind(ivar, "u64", idx_pair.span)
        body_scope.bind(avar, acc_kind, acc_triple.span)
        sk = _check_expr(step_node, body_scope, tenv, in_spec)
        if not _compatible_arg(sk, acc_kind):
            raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, f"`fold` step returns `{sk}`, expected `{acc_kind}`", step_node.span, pretty(node))
        if set(body_scope.linear_alive.keys()) != set(scope.linear_alive.keys()):
            raise AILCompilerError(pb.E_LINEAR_USE_AFTER_MOVE, pb.STAGE_OWNERSHIP, scope.item_name, "Cannot consume outer linear capabilities inside `fold`", step_node.span, pretty(node))
        return record(acc_kind)

    if op == "call":
        if len(items) < 2 or not isinstance(items[1].val, str):
            raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, scope.item_name, "Expected `(call fn_name args...)`", node.span, pretty(node))
        callee = items[1].val
        if callee not in tenv.sigs:
            raise AILCompilerError(pb.E_UNBOUND_SYMBOL, pb.STAGE_OWNERSHIP, scope.item_name, f"Unknown function `{callee}`", items[1].span, pretty(node))
        sig = tenv.sigs[callee]
        if sig.kind == "spec" and not in_spec:
            raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, f"`(spec {callee} ...)` cannot execute at runtime", items[1].span, pretty(node))
        call_args = items[2:]
        if len(call_args) != len(sig.param_kinds):
            raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, f"`{callee}` expects {len(sig.param_kinds)} args, got {len(call_args)}", node.span, pretty(node))
        seen_slices: set[str] = set()
        has_mut = False
        for arg_node, expected_k in zip(call_args, sig.param_kinds):
            if expected_k in ("slice", "mut_slice"):
                if not isinstance(arg_node.val, str):
                    raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, "Slice argument must be a variable", arg_node.span, pretty(arg_node))
                sname = arg_node.val
                actual_k = scope.var_kinds.get(sname)
                if expected_k == "mut_slice" and actual_k != "mut_slice":
                    raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, f"`{sname}` is not a `mut_slice`", arg_node.span, pretty(arg_node))
                if sname in seen_slices and (expected_k == "mut_slice" or has_mut):
                    raise AILCompilerError(pb.E_ALIASING_VIOLATION, pb.STAGE_OWNERSHIP, scope.item_name, f"Mutable slice aliasing forbidden on `{sname}`", arg_node.span, pretty(node))
                if expected_k == "mut_slice":
                    has_mut = True
                seen_slices.add(sname)
            elif expected_k in LINEAR_CAPS:
                ak = _check_expr(arg_node, scope, tenv, in_spec)
                if ak != expected_k:
                    raise AILCompilerError(pb.E_CAPABILITY_MISSING, pb.STAGE_OWNERSHIP, scope.item_name, f"`{callee}` requires `{expected_k}`", arg_node.span, pretty(node))
            else:
                ak = _check_expr(arg_node, scope, tenv, in_spec)
                if not _compatible_arg(ak, expected_k):
                    raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, f"Argument to `{callee}` has type `{ak}`, expected `{expected_k}`", arg_node.span, pretty(node))
        return record(sig.ret_kind)

    if op in tenv.sigs and tenv.sigs[op].kind == "spec":
        if not in_spec:
            raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, f"Spec `{op}` cannot execute at runtime", node.span, pretty(node))
        for a in items[1:]:
            _check_expr(a, scope, tenv, in_spec=True)
        return record("int")

    if op == "~":
        ak = _check_expr(items[1], scope, tenv, in_spec)
        return record("int" if in_spec else ("u64" if ak == "lit_pos" else ak))

    if op in (">>", "<<"):
        lk = _check_expr(items[1], scope, tenv, in_spec)
        rk = _check_expr(items[2], scope, tenv, in_spec)
        if not in_spec and not _compatible_arg(rk, "u64"):
            raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, "Shift count must be `u64`", items[2].span, pretty(node))
        return record("int" if in_spec else ("u64" if lk == "lit_pos" else lk))

    if op in ("trunc_div", "trunc_rem"):
        if not in_spec:
            raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, scope.item_name, f"`{op}` is a `(spec ...)` operator; use `/` or `%` in runtime code", node.span, pretty(node))
        _check_expr(items[1], scope, tenv, in_spec=True)
        _check_expr(items[2], scope, tenv, in_spec=True)
        return record("int")

    if op in ("+", "-", "*", "/", "%", "min", "max", "&", "|", "^"):
        k1 = _check_expr(items[1], scope, tenv, in_spec)
        k2 = _check_expr(items[2], scope, tenv, in_spec)
        if in_spec:
            return record("int")
        return record(_unify_numeric(k1, k2, node.span, scope.item_name, pretty(node)))

    if op in ("==", "!=", "<", "<=", ">", ">="):
        k1 = _check_expr(items[1], scope, tenv, in_spec)
        k2 = _check_expr(items[2], scope, tenv, in_spec)
        if not in_spec:
            _unify_numeric(k1, k2, node.span, scope.item_name, pretty(node))
        return record("bool")

    if op in ("and", "or", "not"):
        for a in items[1:]:
            _check_expr(a, scope, tenv, in_spec)
        return record("bool")

    raise AILCompilerError(pb.E_UNBOUND_SYMBOL, pb.STAGE_OWNERSHIP, scope.item_name, f"Unknown operator or function `{op}`", items[0].span, pretty(node))


def check_module_ownership_v2(forms: list[SNode]) -> ModuleTypeEnv:
    tenv = ModuleTypeEnv()
    protocols: set[str] = set()

    for form in forms:
        assert isinstance(form.val, list)
        head = str(form.val[0].val)

        if head == "struct":
            sname = str(form.val[1].val)
            fields_node = form.val[2]
            assert isinstance(fields_node.val, list)
            fdefs: list[StructFieldDef] = []
            for f in fields_node.val:
                fname = str(f.val[0].val)
                fk = _classify_type(f.val[1], tenv.structs, False, sname)
                if fk not in ("u64", "i64"):
                    raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, sname, "Struct fields in v0.2 must be `u64` or `i64` refinements", f.span, pretty(f))
                fdefs.append(StructFieldDef(fname, fk, f.val[1]))
            tenv.structs[sname] = StructDef(sname, fdefs, form.span)
            continue

        if head == "atomic_protocol":
            protocols.add(str(form.val[1].val))
            continue

        if head in ("spec", "fn", "main"):
            name = "main" if head == "main" else str(form.val[1].val)
            params_node = form.val[1] if head == "main" else form.val[2]
            ret_node = form.val[2] if head == "main" else (None if head == "spec" else form.val[3])
            body_node = form.val[3] if head in ("spec", "main") else form.val[4]

            scope = LinearScope(item_name=name)
            pkinds: list[str] = []
            for p in params_node.val:
                pname = str(p.val[0].val)
                pk = _classify_type(p.val[1], tenv.structs, allow_math_int=(head == "spec"), item_name=name)
                pkinds.append(pk)
                scope.bind(pname, pk, p.span)

            rk = "int" if head == "spec" else _extract_ret_kind(ret_node, tenv.structs, name)
            tenv.sigs[name] = FnSig(name=name, kind=head, param_kinds=pkinds, ret_kind=rk)

            out_k = _check_expr(body_node, scope, tenv, in_spec=(head == "spec"))
            if head != "spec" and not _compatible_arg(out_k, rk):
                raise AILCompilerError(pb.E_TYPE_MISMATCH, pb.STAGE_OWNERSHIP, name, f"Body returns `{out_k}`, expected `{rk}`", body_node.span, pretty(body_node))
            if scope.linear_alive:
                leaked = next(iter(scope.linear_alive.keys()))
                raise AILCompilerError(pb.E_LINEAR_UNCONSUMED, pb.STAGE_OWNERSHIP, name, f"Linear capability `{leaked}` was never consumed before scope exit.", scope.linear_alive[leaked])

        elif head == "map_inplace":
            name = str(form.val[1].val)
            params_node, ret_node, elem_vars, body_node = form.val[2], form.val[3], form.val[4], form.val[5]
            scope = LinearScope(item_name=name)
            pkinds = []
            elem_k = "u64"
            for p in params_node.val:
                pname = str(p.val[0].val)
                pk = _classify_type(p.val[1], tenv.structs, False, name)
                pkinds.append(pk)
                scope.bind(pname, pk, p.span)
                if pk == "mut_slice":
                    elem_k = _classify_type(p.val[1].val[2], tenv.structs, False, name)
            tenv.sigs[name] = FnSig(name=name, kind="map_inplace", param_kinds=pkinds, ret_kind="void")
            scope.bind(str(elem_vars.val[0].val), elem_k, elem_vars.span)
            _check_expr(body_node, scope, tenv, in_spec=False)

        elif head == "atomic_cas":
            name = str(form.val[1].val)
            proto_name = str(form.val[2].val)
            if proto_name not in protocols:
                raise AILCompilerError(pb.E_UNBOUND_SYMBOL, pb.STAGE_OWNERSHIP, name, f"Unknown `atomic_protocol` `{proto_name}`", form.val[2].span)
            pkinds = [_classify_type(p.val[1], tenv.structs, False, name) for p in form.val[4].val]
            tenv.sigs[name] = FnSig(name=name, kind="atomic_cas", param_kinds=pkinds, ret_kind="u64")
        else:
            raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, "<module>", f"Unknown top-level declaration `{head}`", form.span, pretty(form))

    return tenv


def check_module_ownership(forms: list[SNode]) -> dict[str, FnSig]:
    """Backward-compatible helper returning sigs."""
    return check_module_ownership_v2(forms).sigs
