"""Module Loader, Import Resolver (`E_IMPORT_CYCLE` + Diamond Deduplication), and `(const ...)` Folder."""

from __future__ import annotations
from pathlib import Path

from ailang import ail_agent_pb2 as pb
from ailang.diagnostics import AILCompilerError, I64_MAX, I64_MIN, Span, U64_MAX
from ailang.parser import SNode, load_ail_path, parse_source, pretty

PKG_DIR = Path(__file__).resolve().parent
STDLIB_DIR = PKG_DIR / "stdlib"


def list_stdlib_modules() -> list[Path]:
    """Return sorted paths to built-in verified stdlib `.ail` modules."""
    if not STDLIB_DIR.is_dir():
        return []
    return sorted(STDLIB_DIR.glob("*.ail"))


def _unquote_import_target(raw_tok: str) -> str:
    if len(raw_tok) >= 2 and raw_tok[0] == '"' and raw_tok[-1] == '"':
        inner = raw_tok[1:-1]
        return inner.replace('\\"', '"').replace("\\\\", "\\")
    return raw_tok


def _resolve_import_path(
    raw_target: str,
    cur_dir: Path,
    search_dirs: list[Path],
    span: Span,
    expr_s: str,
) -> Path:
    target = _unquote_import_target(raw_target).strip()
    if not target:
        raise AILCompilerError(
            pb.E_SYNTAX,
            pb.STAGE_PARSE,
            "<import>",
            "Empty `(import ...)` module path",
            span,
            expr_s,
        )

    candidates = [target] if target.endswith((".ail", ".pb")) else [target, f"{target}.ail", f"{target}.ail.pb"]
    target_path = Path(target)
    if target_path.is_absolute():
        for cand in candidates:
            cp = Path(cand)
            if cp.is_file():
                return cp.resolve()
    else:
        for base in [cur_dir, *search_dirs, PKG_DIR]:
            for cand in candidates:
                cp = base / cand
                if cp.is_file():
                    return cp.resolve()

    raise AILCompilerError(
        pb.E_UNBOUND_SYMBOL,
        pb.STAGE_PARSE,
        "<import>",
        f"Cannot resolve imported module `{target}`",
        span,
        expr_s,
    )


def _eval_const_decl(form: SNode, consts: dict[str, int]) -> tuple[str, int]:
    items = form.val
    if not isinstance(items, list) or len(items) != 4 or not isinstance(items[1].val, str):
        raise AILCompilerError(
            pb.E_SYNTAX,
            pb.STAGE_PARSE,
            "<const>",
            "Expected `(const NAME u64|i64 <int_lit>)`",
            form.span,
            pretty(form),
        )
    cname = items[1].val
    ctype = items[2].raw()
    if ctype not in ("u64", "i64"):
        raise AILCompilerError(
            pb.E_TYPE_MISMATCH,
            pb.STAGE_PARSE,
            cname,
            f"Constant `{cname}` type must be `u64` or `i64`, got `{pretty(items[2])}`",
            items[2].span,
            pretty(form),
        )

    val_node = items[3]
    if isinstance(val_node.val, int):
        val = val_node.val
    elif isinstance(val_node.val, str):
        if val_node.val == "MAX":
            val = U64_MAX
        elif val_node.val == "MAX_I64":
            val = I64_MAX
        elif val_node.val == "MIN_I64":
            val = I64_MIN
        elif val_node.val in consts:
            val = consts[val_node.val]
        else:
            raise AILCompilerError(
                pb.E_UNBOUND_SYMBOL,
                pb.STAGE_PARSE,
                cname,
                f"Constant `{cname}` value must be an integer literal, got `{pretty(val_node)}`",
                val_node.span,
                pretty(form),
            )
    else:
        raise AILCompilerError(
            pb.E_SYNTAX,
            pb.STAGE_PARSE,
            cname,
            f"Constant `{cname}` value must be an integer literal, got `{pretty(val_node)}`",
            val_node.span,
            pretty(form),
        )

    if ctype == "u64":
        if val < 0:
            raise AILCompilerError(
                pb.E_U64_UNDERFLOW,
                pb.STAGE_PARSE,
                cname,
                f"`u64` constant `{cname}` cannot be negative ({val})",
                val_node.span,
                pretty(form),
            )
        if val > U64_MAX:
            raise AILCompilerError(
                pb.E_U64_OVERFLOW,
                pb.STAGE_PARSE,
                cname,
                f"`u64` constant `{cname}` exceeds MAX ({val})",
                val_node.span,
                pretty(form),
            )
    else:
        if val < I64_MIN or val > I64_MAX:
            raise AILCompilerError(
                pb.E_I64_OVERFLOW,
                pb.STAGE_PARSE,
                cname,
                f"`i64` constant `{cname}` outside [MIN_I64..MAX_I64] ({val})",
                val_node.span,
                pretty(form),
            )
    return cname, val


def _subst_expr(node: SNode, consts: dict[str, int], shadowed: set[str]) -> SNode:
    if not consts:
        return node
    if isinstance(node.val, int):
        return node
    if isinstance(node.val, str):
        if node.val in consts and node.val not in shadowed:
            return SNode(consts[node.val], node.span)
        return node

    items = node.val
    if not items:
        return node
    head = items[0].val
    if not isinstance(head, str):
        return SNode([_subst_expr(ch, consts, shadowed) for ch in items], node.span)

    if head in ("u64_range", "i64_range") and len(items) == 3:
        return SNode(
            [items[0], _subst_expr(items[1], consts, shadowed), _subst_expr(items[2], consts, shadowed)],
            node.span,
        )

    if head == "let" and len(items) == 3 and isinstance(items[1].val, list):
        cur_sh = set(shadowed)
        new_binds: list[SNode] = []
        for b in items[1].val:
            if isinstance(b.val, list) and len(b.val) == 2 and isinstance(b.val[0].val, str):
                rhs = _subst_expr(b.val[1], consts, cur_sh)
                cur_sh.add(b.val[0].val)
                new_binds.append(SNode([b.val[0], rhs], b.span))
            else:
                new_binds.append(_subst_expr(b, consts, cur_sh))
        return SNode([items[0], SNode(new_binds, items[1].span), _subst_expr(items[2], consts, cur_sh)], node.span)

    if head == "fold" and len(items) == 4 and isinstance(items[1].val, list) and isinstance(items[2].val, list):
        idx_pair, acc_triple, step_n = items[1], items[2], items[3]
        if len(idx_pair.val) == 2 and len(acc_triple.val) == 3 and isinstance(idx_pair.val[0].val, str) and isinstance(acc_triple.val[0].val, str):
            ivar = idx_pair.val[0].val
            avar = acc_triple.val[0].val
            bound_s = _subst_expr(idx_pair.val[1], consts, shadowed)
            init_s = _subst_expr(acc_triple.val[1], consts, shadowed)
            acc_t_s = _subst_expr(acc_triple.val[2], consts, shadowed | {ivar})
            step_s = _subst_expr(step_n, consts, shadowed | {ivar, avar})
            return SNode(
                [
                    items[0],
                    SNode([idx_pair.val[0], bound_s], idx_pair.span),
                    SNode([acc_triple.val[0], init_s, acc_t_s], acc_triple.span),
                    step_s,
                ],
                node.span,
            )

    if head == "match" and len(items) >= 3:
        scrut_s = _subst_expr(items[1], consts, shadowed)
        new_arms: list[SNode] = []
        for arm in items[2:]:
            if isinstance(arm.val, list) and len(arm.val) == 2:
                pat, arm_body = arm.val[0], arm.val[1]
                arm_sh = set(shadowed)
                if isinstance(pat.val, list) and len(pat.val) >= 2:
                    for b in pat.val[1:]:
                        if isinstance(b.val, str):
                            arm_sh.add(b.val)
                new_arms.append(SNode([pat, _subst_expr(arm_body, consts, arm_sh)], arm.span))
            else:
                new_arms.append(_subst_expr(arm, consts, shadowed))
        return SNode([items[0], scrut_s, *new_arms], node.span)

    if head in ("call", "make") and len(items) >= 2:
        return SNode([items[0], items[1], *[_subst_expr(a, consts, shadowed) for a in items[2:]]], node.span)

    if head in ("field", "is_variant") and len(items) == 3:
        return SNode([items[0], _subst_expr(items[1], consts, shadowed), items[2]], node.span)

    if head == "variant" and len(items) >= 3:
        return SNode([items[0], items[1], items[2], *[_subst_expr(a, consts, shadowed) for a in items[3:]]], node.span)

    return SNode([items[0], *[_subst_expr(ch, consts, shadowed) for ch in items[1:]]], node.span)


def _subst_params(params_node: SNode, consts: dict[str, int], shadowed: set[str]) -> tuple[SNode, set[str]]:
    cur_sh = set(shadowed)
    if not isinstance(params_node.val, list):
        return params_node, cur_sh
    new_params: list[SNode] = []
    for p in params_node.val:
        if isinstance(p.val, list) and len(p.val) == 2 and isinstance(p.val[0].val, str):
            ptype_s = _subst_expr(p.val[1], consts, cur_sh)
            cur_sh.add(p.val[0].val)
            new_params.append(SNode([p.val[0], ptype_s], p.span))
        else:
            new_params.append(_subst_expr(p, consts, cur_sh))
    return SNode(new_params, params_node.span), cur_sh


def _subst_ret(ret_node: SNode, consts: dict[str, int], shadowed: set[str]) -> SNode:
    raw = ret_node.raw()
    if isinstance(raw, list) and raw and raw[0] not in ("u64_range", "i64_range", "slice", "mut_slice", "atomic", "bytes"):
        if isinstance(ret_node.val, list) and len(ret_node.val) >= 2 and isinstance(ret_node.val[0].val, str):
            rname = ret_node.val[0].val
            rtype_s = _subst_expr(ret_node.val[1], consts, shadowed)
            ret_sh = shadowed | {rname}
            ens_s = [_subst_expr(e, consts, ret_sh) for e in ret_node.val[2:]]
            return SNode([ret_node.val[0], rtype_s, *ens_s], ret_node.span)
    return _subst_expr(ret_node, consts, shadowed)


def _subst_top_form(form: SNode, consts: dict[str, int]) -> SNode:
    if not consts or not isinstance(form.val, list) or not form.val or not isinstance(form.val[0].val, str):
        return form
    head = form.val[0].val

    if head == "struct" and len(form.val) == 3 and isinstance(form.val[2].val, list):
        cur_sh: set[str] = set()
        new_fields: list[SNode] = []
        for fld in form.val[2].val:
            if isinstance(fld.val, list) and len(fld.val) == 2 and isinstance(fld.val[0].val, str):
                ft_s = _subst_expr(fld.val[1], consts, cur_sh)
                cur_sh.add(fld.val[0].val)
                new_fields.append(SNode([fld.val[0], ft_s], fld.span))
            else:
                new_fields.append(_subst_expr(fld, consts, cur_sh))
        return SNode([form.val[0], form.val[1], SNode(new_fields, form.val[2].span)], form.span)

    if head == "enum" and len(form.val) >= 3:
        new_variants: list[SNode] = []
        for vform in form.val[2:]:
            if isinstance(vform.val, list) and vform.val:
                cur_sh = set()
                new_flds: list[SNode] = []
                for fld in vform.val[1:]:
                    if isinstance(fld.val, list) and len(fld.val) == 2 and isinstance(fld.val[0].val, str):
                        ft_s = _subst_expr(fld.val[1], consts, cur_sh)
                        cur_sh.add(fld.val[0].val)
                        new_flds.append(SNode([fld.val[0], ft_s], fld.span))
                    else:
                        new_flds.append(_subst_expr(fld, consts, cur_sh))
                new_variants.append(SNode([vform.val[0], *new_flds], vform.span))
            else:
                new_variants.append(vform)
        return SNode([form.val[0], form.val[1], *new_variants], form.span)

    if head == "spec" and len(form.val) == 4:
        p_s, sh = _subst_params(form.val[2], consts, set())
        b_s = _subst_expr(form.val[3], consts, sh)
        return SNode([form.val[0], form.val[1], p_s, b_s], form.span)

    if head == "fn" and len(form.val) == 5:
        p_s, sh = _subst_params(form.val[2], consts, set())
        r_s = _subst_ret(form.val[3], consts, sh)
        b_s = _subst_expr(form.val[4], consts, sh)
        return SNode([form.val[0], form.val[1], p_s, r_s, b_s], form.span)

    if head == "main" and len(form.val) == 4:
        p_s, sh = _subst_params(form.val[1], consts, set())
        r_s = _subst_ret(form.val[2], consts, sh)
        b_s = _subst_expr(form.val[3], consts, sh)
        return SNode([form.val[0], p_s, r_s, b_s], form.span)

    if head == "map_inplace" and len(form.val) == 6:
        p_s, sh = _subst_params(form.val[2], consts, set())
        r_s = _subst_ret(form.val[3], consts, sh)
        elem_sh = set(sh)
        if isinstance(form.val[4].val, list):
            for ev in form.val[4].val:
                if isinstance(ev.val, str):
                    elem_sh.add(ev.val)
        b_s = _subst_expr(form.val[5], consts, elem_sh)
        return SNode([form.val[0], form.val[1], p_s, r_s, form.val[4], b_s], form.span)

    if head == "atomic_protocol" and len(form.val) >= 5:
        f_s, f_sh = _subst_params(form.val[2], consts, set())
        inv_s = _subst_expr(form.val[3], consts, f_sh)
        new_steps: list[SNode] = []
        for sn in form.val[4:]:
            if isinstance(sn.val, list) and len(sn.val) == 4:
                sp_s, sp_sh = _subst_params(sn.val[2], consts, f_sh)
                nx_s = _subst_expr(sn.val[3], consts, sp_sh)
                new_steps.append(SNode([sn.val[0], sn.val[1], sp_s, nx_s], sn.span))
            else:
                new_steps.append(_subst_expr(sn, consts, f_sh))
        return SNode([form.val[0], form.val[1], f_s, inv_s, *new_steps], form.span)

    if head == "atomic_cas" and len(form.val) == 5:
        p_s, _ = _subst_params(form.val[4], consts, set())
        return SNode([form.val[0], form.val[1], form.val[2], form.val[3], p_s], form.span)

    return _subst_expr(form, consts, set())


def load_ail_module_with_imports(
    path_or_src: Path | str,
    search_dirs: list[Path] | None = None,
) -> list[SNode]:
    """
    Loads an `.ail` / `.ail.pb` file or source string, recursively resolving `(import "...")`
    declarations, detecting cycles (`E_IMPORT_CYCLE`), deduplicating diamond imports, and folding
    `(const NAME u64|i64 <int_lit>)` constants across subsequent declarations.
    """
    extra_dirs = [d.resolve() for d in (search_dirs or [])]
    visiting: list[Path] = []
    visited: set[Path] = set()
    module_consts: dict[Path, dict[str, int]] = {}
    out_forms: list[SNode] = []

    def process_forms(forms: list[SNode], cur_dir: Path) -> dict[str, int]:
        local_consts: dict[str, int] = {}
        for form in forms:
            if not isinstance(form.val, list) or not form.val or not isinstance(form.val[0].val, str):
                raise AILCompilerError(
                    pb.E_SYNTAX,
                    pb.STAGE_PARSE,
                    "<module>",
                    "Top-level item must be a declaration list",
                    form.span,
                    pretty(form),
                )
            head = form.val[0].val
            if head == "import":
                if len(form.val) != 2 or not isinstance(form.val[1].val, str):
                    raise AILCompilerError(
                        pb.E_SYNTAX,
                        pb.STAGE_PARSE,
                        "<import>",
                        'Expected `(import "path/to/module")`',
                        form.span,
                        pretty(form),
                    )
                imp_path = _resolve_import_path(form.val[1].val, cur_dir, extra_dirs, form.span, pretty(form))
                if imp_path in visiting:
                    idx = visiting.index(imp_path)
                    cycle = " -> ".join([p.name for p in [*visiting[idx:], imp_path]])
                    raise AILCompilerError(
                        pb.E_IMPORT_CYCLE,
                        pb.STAGE_PARSE,
                        imp_path.stem,
                        f"Circular import detected: {cycle}",
                        form.span,
                        pretty(form),
                    )
                if imp_path in visited:
                    local_consts.update(module_consts.get(imp_path, {}))
                    continue
                dep_consts = load_file(imp_path)
                local_consts.update(dep_consts)
                continue

            if head == "const":
                cname, cval = _eval_const_decl(form, local_consts)
                local_consts[cname] = cval
                continue

            out_forms.append(_subst_top_form(form, local_consts))
        return local_consts

    def load_file(mod_path: Path) -> dict[str, int]:
        visiting.append(mod_path)
        try:
            raw_forms = load_ail_path(mod_path)
            consts = process_forms(raw_forms, mod_path.parent)
        finally:
            visiting.pop()
        visited.add(mod_path)
        module_consts[mod_path] = consts
        return consts

    if isinstance(path_or_src, Path):
        load_file(path_or_src.resolve())
    elif isinstance(path_or_src, str) and "\n" not in path_or_src and "(" not in path_or_src:
        cand = Path(path_or_src)
        if cand.is_file():
            load_file(cand.resolve())
        else:
            process_forms(parse_source(path_or_src), Path.cwd())
    else:
        process_forms(parse_source(str(path_or_src)), Path.cwd())

    return out_forms
