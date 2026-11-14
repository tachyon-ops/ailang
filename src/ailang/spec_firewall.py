"""Layer 1 Spec Firewall: Specification Mutation Auditor (`SpecMut`) & Differential Disambiguator (`Clover`) v0.2."""

from __future__ import annotations
import time
import z3

from ailang import ail_agent_pb2 as pb
from ailang.diagnostics import (
    I64_MAX,
    I64_MIN,
    U64_MAX,
    ce_bindings_to_dict,
    dict_to_ce_bindings,
    make_diagnostic,
)
from ailang.ownership import LINEAR_CAPS, ModuleTypeEnv, check_module_ownership_v2
from ailang.parser import SNode, pretty
from ailang.verifier import ModuleVerifier, SpecDeclInfo, _extract_range_nodes, _extract_ret_spec


def _to_u64_wire(val: int) -> int:
    return val & U64_MAX


def audit_module_specifications(
    forms: list[SNode],
    tenv: ModuleTypeEnv | None = None,
) -> tuple[list[pb.SpecAuditItem], list[pb.Diagnostic]]:
    if tenv is None:
        tenv = check_module_ownership_v2(forms)
    mv = ModuleVerifier(tenv)
    audits: list[pb.SpecAuditItem] = []
    diags: list[pb.Diagnostic] = []

    for form in forms:
        head = str(form.val[0].val)
        if head == "spec":
            sname = str(form.val[1].val)
            pnames = [str(p.val[0].val) for p in form.val[2].val]
            mv.specs[sname] = SpecDeclInfo(sname, pnames, form.val[3])
            continue

        if head in ("struct", "enum"):
            continue
        if head != "fn":
            continue

        fn_name = str(form.val[1].val)
        sig = tenv.sigs[fn_name]
        params_node, ret_node, body_node = form.val[2], form.val[3], form.val[4]

        # Audit pure scalar functions (`u64` / `i64` return, scalar/struct/enum inputs without slices or linear caps)
        if sig.ret_kind in LINEAR_CAPS or sig.ret_kind.startswith(("struct:", "enum:")):
            continue
        if any(pk in ("slice", "mut_slice", "atomic_u64") or pk in LINEAR_CAPS for pk in sig.param_kinds):
            continue

        t0 = time.perf_counter()
        env: dict[str, z3.ArithRef | dict[str, z3.ArithRef]] = {}
        scalar_vars: dict[str, z3.ArithRef] = {}
        scalar_param_names: list[str] = []
        pre: list[z3.BoolRef] = []

        for p, pk in zip(params_node.val, sig.param_kinds):
            pname = str(p.val[0].val)
            if pk.startswith("struct:"):
                sname = pk.split(":", 1)[1]
                sdef = tenv.structs[sname]
                fdict: dict[str, z3.ArithRef] = {}
                fscope = dict(env)
                for fd in sdef.fields:
                    fv = z3.Int(f"{pname}.{fd.name}")
                    flo_n, fhi_n = _extract_range_nodes(fd.type_node)
                    hw_lo, hw_hi = (I64_MIN, I64_MAX) if fd.kind == "i64" else (0, U64_MAX)
                    pre.extend([fv >= hw_lo, fv <= hw_hi, fv >= mv.eval_pure_spec(flo_n, fscope), fv <= mv.eval_pure_spec(fhi_n, fscope)])
                    fdict[fd.name] = fv
                    fscope[fd.name] = fv
                    scalar_vars[f"{pname}.{fd.name}"] = fv
                env[pname] = fdict
            elif pk.startswith("enum:"):
                ename = pk.split(":", 1)[1]
                edef = tenv.enums[ename]
                edict: dict[str, z3.ArithRef] = {}
                tag_v = z3.Int(f"{pname}.__tag__")
                pre.extend([tag_v >= 0, tag_v < len(edef.variants)])
                edict["__tag__"] = tag_v
                scalar_vars[f"{pname}.__tag__"] = tag_v
                for vdef in edef.variants:
                    vscope = dict(env)
                    for fidx, fd in enumerate(vdef.fields):
                        fv = z3.Int(f"{pname}.{vdef.name}.{fd.name}")
                        flo_n, fhi_n = _extract_range_nodes(fd.type_node)
                        hw_lo, hw_hi = (I64_MIN, I64_MAX) if fd.kind == "i64" else (0, U64_MAX)
                        pre.extend(
                            [
                                fv >= hw_lo,
                                fv <= hw_hi,
                                z3.Implies(tag_v == vdef.tag, z3.And(fv >= mv.eval_pure_spec(flo_n, vscope), fv <= mv.eval_pure_spec(fhi_n, vscope))),
                            ]
                        )
                        edict[f"{vdef.tag}:{vdef.name}.{fidx}"] = fv
                        vscope[fd.name] = fv
                        scalar_vars[f"{pname}.{vdef.name}.{fd.name}"] = fv
                env[pname] = edict
            else:
                lo_n, hi_n = _extract_range_nodes(p.val[1])
                v = z3.Int(pname)
                hw_lo, hw_hi = (I64_MIN, I64_MAX) if pk == "i64" else (0, U64_MAX)
                pre.extend([v >= hw_lo, v <= hw_hi, v >= mv.eval_pure_spec(lo_n, env), v <= mv.eval_pure_spec(hi_n, env)])
                env[pname] = v
                scalar_vars[pname] = v
                scalar_param_names.append(pname)

        # Gate 1: Non-vacuity check
        s_vac = z3.Solver()
        s_vac.set("timeout", 4000)
        s_vac.add(*pre)
        non_vacuous = s_vac.check() == z3.sat
        if not non_vacuous:
            diags.append(
                make_diagnostic(
                    pb.E_SPEC_VACUOUS,
                    pb.STAGE_SPEC_FIREWALL,
                    fn_name,
                    f"Preconditions of `{fn_name}` are vacuously false (`UNSAT`).",
                    params_node.span,
                    pretty(params_node),
                )
            )
            audits.append(
                pb.SpecAuditItem(
                    fn_name=fn_name,
                    non_vacuous=False,
                    uniquely_tight=False,
                    elapsed_ms=(time.perf_counter() - t0) * 1000.0,
                )
            )
            continue

        try:
            ref_val = mv.eval_pure_spec(body_node, env)
            assert isinstance(ref_val, z3.ArithRef)
            ref_out = ref_val
            ref_extra: list[z3.BoolRef] = []
        except (NotImplementedError, AssertionError):
            ref_out = z3.Int("_verified_ref_out")
            ref_extra = []

        rname, rlo_n, rhi_n, ensures_list = _extract_ret_spec(ret_node, tenv.structs, tenv.enums)
        ret_hw_lo, ret_hw_hi = (I64_MIN, I64_MAX) if sig.ret_kind == "i64" else (0, U64_MAX)

        def spec_holds_for(cand: z3.ArithRef) -> z3.BoolRef:
            renv = dict(env, **{rname: cand})
            clauses = [
                cand >= ret_hw_lo,
                cand <= ret_hw_hi,
                cand >= mv.eval_pure_spec(rlo_n, renv),
                cand <= mv.eval_pure_spec(rhi_n, renv),
            ]
            for ens in ensures_list:
                ec = mv.eval_pure_spec(ens, renv)
                assert isinstance(ec, z3.BoolRef)
                clauses.append(ec)
            return z3.And(*clauses)

        if str(ref_out) == "_verified_ref_out":
            ref_extra.append(spec_holds_for(ref_out))

        # Gate 2: Synthesize canonical adversarial mutants
        rlo_eval = mv.eval_pure_spec(rlo_n, dict(env, **{rname: ref_out}))
        assert isinstance(rlo_eval, z3.ArithRef)
        mutants: list[tuple[str, str, z3.ArithRef]] = [
            ("zero_const", "0", z3.IntVal(0)),
            ("plus_one_drift", "(+ out 1)", ref_out + 1),
            ("minus_one_drift", "(- out 1)", ref_out - 1),
            ("lower_bound_const", pretty(rlo_n), rlo_eval),
        ]
        if scalar_param_names:
            p0 = scalar_param_names[0]
            p_last = scalar_param_names[-1]
            v0 = env[p0]
            v_last = env[p_last]
            assert isinstance(v0, z3.ArithRef) and isinstance(v_last, z3.ArithRef)
            mutants.append(("first_arg_identity", p0, v0))
            mutants.append(("last_arg_identity", p_last, v_last))

        surviving: list[pb.SurvivingMutant] = []
        killed = 0
        for mkind, mexpr_s, mexpr in mutants:
            s = z3.Solver()
            s.set("timeout", 4000)
            s.add(*pre, *ref_extra, mexpr != ref_out, spec_holds_for(mexpr))
            if s.check() == z3.sat:
                m = s.model()
                ce = {vn: m.eval(vv, model_completion=True).as_long() for vn, vv in scalar_vars.items()}
                m_out = _to_u64_wire(m.eval(mexpr, model_completion=True).as_long())
                r_out = _to_u64_wire(m.eval(ref_out, model_completion=True).as_long())
                surviving.append(
                    pb.SurvivingMutant(
                        mutant_kind=mkind,
                        mutant_expr=mexpr_s,
                        witness=dict_to_ce_bindings(ce),
                        mutant_output=m_out,
                        reference_output=r_out,
                    )
                )
            else:
                killed += 1

        # Gate 3: Universal uniqueness check (can ANY two distinct outputs satisfy the spec?)
        out_1 = z3.Int("_spec_out_1")
        out_2 = z3.Int("_spec_out_2")
        s_uniq = z3.Solver()
        s_uniq.set("timeout", 4000)
        s_uniq.add(*pre, out_1 != out_2, spec_holds_for(out_1), spec_holds_for(out_2))
        uniquely_tight = s_uniq.check() == z3.unsat

        dt = (time.perf_counter() - t0) * 1000.0
        item = pb.SpecAuditItem(
            fn_name=fn_name,
            non_vacuous=non_vacuous,
            uniquely_tight=uniquely_tight,
            mutants_tested=len(mutants),
            mutants_killed=killed,
            elapsed_ms=dt,
            surviving_mutants=surviving,
        )
        audits.append(item)

        if surviving or not uniquely_tight:
            first_ce = {vn: 0 for vn in scalar_vars}
            if surviving:
                first_ce = ce_bindings_to_dict(list(surviving[0].witness))
            diags.append(
                make_diagnostic(
                    pb.E_SPEC_MUTANT_SURVIVED,
                    pb.STAGE_SPEC_FIREWALL,
                    fn_name,
                    f"Under-constrained specification on `{fn_name}`: {len(surviving)}/{len(mutants)} buggy mutants survived.",
                    ret_node.span,
                    pretty(ret_node),
                    first_ce,
                )
            )

    return audits, diags


def diff_candidate_modules(forms_a: list[SNode], forms_b: list[SNode]) -> tuple[list[pb.SpecDiscrepancy], list[pb.Diagnostic]]:
    """Compares candidate autoformalizations (`spec` or `fn`) across two modules via Z3 equivalence."""
    tenv_a = check_module_ownership_v2(forms_a)
    tenv_b = check_module_ownership_v2(forms_b)
    mv_a = ModuleVerifier(tenv_a)
    mv_b = ModuleVerifier(tenv_b)
    fns_a: dict[str, SNode] = {}
    fns_b: dict[str, SNode] = {}

    for fa in forms_a:
        h = str(fa.val[0].val)
        if h in ("spec", "fn"):
            nm = str(fa.val[1].val)
            if h == "spec":
                mv_a.specs[nm] = SpecDeclInfo(nm, [str(p.val[0].val) for p in fa.val[2].val], fa.val[3])
            fns_a[nm] = fa

    for fb in forms_b:
        h = str(fb.val[0].val)
        if h in ("spec", "fn"):
            nm = str(fb.val[1].val)
            if h == "spec":
                mv_b.specs[nm] = SpecDeclInfo(nm, [str(p.val[0].val) for p in fb.val[2].val], fb.val[3])
            fns_b[nm] = fb

    diffs: list[pb.SpecDiscrepancy] = []
    diags: list[pb.Diagnostic] = []

    for nm in sorted(set(fns_a.keys()) & set(fns_b.keys())):
        t0 = time.perf_counter()
        fa, fb = fns_a[nm], fns_b[nm]
        head = str(fa.val[0].val)
        params_a = fa.val[2].val
        body_a = fa.val[3] if head == "spec" else fa.val[4]
        body_b = fb.val[3] if str(fb.val[0].val) == "spec" else fb.val[4]

        env: dict[str, z3.ArithRef] = {}
        pre: list[z3.BoolRef] = []
        pnames: list[str] = []
        for p in params_a:
            pname = str(p.val[0].val)
            v = z3.Int(pname)
            raw_t = p.val[1].raw()
            if raw_t == "int":
                pre.extend([v >= 0, v <= 1_000_000_000])
            else:
                is_i64 = raw_t == "i64" or (isinstance(raw_t, list) and raw_t and raw_t[0] == "i64_range")
                hw_lo, hw_hi = (I64_MIN, I64_MAX) if is_i64 else (0, U64_MAX)
                lo_n, hi_n = _extract_range_nodes(p.val[1])
                pre.extend([v >= hw_lo, v <= hw_hi, v >= mv_a.eval_pure_spec(lo_n, env), v <= mv_a.eval_pure_spec(hi_n, env)])
            env[pname] = v
            pnames.append(pname)

        out_a = mv_a.eval_pure_spec(body_a, env)
        out_b = mv_b.eval_pure_spec(body_b, env)
        assert isinstance(out_a, z3.ArithRef) and isinstance(out_b, z3.ArithRef)

        s = z3.Solver()
        s.set("timeout", 4000)
        s.add(*pre, out_a != out_b)
        res = s.check()
        dt = (time.perf_counter() - t0) * 1000.0

        if res == z3.unsat:
            diffs.append(pb.SpecDiscrepancy(fn_name=nm, equivalent=True, elapsed_ms=dt))
        else:
            m = s.model()
            ce = {pn: m.eval(env[pn], model_completion=True).as_long() for pn in pnames}
            va = m.eval(out_a, model_completion=True).as_long()
            vb = m.eval(out_b, model_completion=True).as_long()
            p0_val = ce[pnames[0]] if pnames else 0
            viol_a = bool(pnames and va > p0_val)
            viol_b = bool(pnames and vb > p0_val)
            question = (
                f"On edge input {ce}, Candidate A yields {va} while Candidate B yields {vb}. Which behavior matches your intent?"
            )
            diffs.append(
                pb.SpecDiscrepancy(
                    fn_name=nm,
                    equivalent=False,
                    elapsed_ms=dt,
                    distinguishing_input=dict_to_ce_bindings(ce),
                    spec_a_output=va,
                    spec_b_output=vb,
                    spec_a_violates_conservation=viol_a,
                    spec_b_violates_conservation=viol_b,
                    clarification_question=question,
                )
            )
            diags.append(
                make_diagnostic(
                    pb.E_SPEC_AMBIGUITY,
                    pb.STAGE_SPEC_FIREWALL,
                    nm,
                    question,
                    fa.span,
                    pretty(fa),
                    ce,
                )
            )

    return diffs, diags
