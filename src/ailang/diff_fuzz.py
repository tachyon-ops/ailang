"""Track 2: 4-Target Differential Fuzzing Engine (`native` vs `wasm` vs `c` vs `rust`)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import importlib.util
import json
from pathlib import Path
import random
import subprocess
import tempfile
import time
from typing import Any

from ailang.diagnostics import I64_MAX, I64_MIN, U64_MAX
from ailang.modules import load_ail_module_with_imports
from ailang.multi_target import build_multi_target
from ailang.ownership import LINEAR_CAPS, ModuleTypeEnv, check_module_ownership_v2, kind_u64_slots
from ailang.parser import SNode, parse_source
from ailang.verifier import ModuleVerifier, _extract_range_nodes


MAX_FUZZ_BUF_LEN = 64


@dataclass
class FnFuzzSummary:
    fn_name: str
    cases_executed: int
    mismatches: int
    skipped_reason: str = ""


@dataclass
class DiffFuzzReport:
    stem: str
    seed: int
    cases_per_fn: int
    total_executions: int
    mismatches: int
    functions: list[FnFuzzSummary] = field(default_factory=list)
    first_mismatch: dict[str, Any] | None = None
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "stem": self.stem,
            "seed": self.seed,
            "cases_per_fn": self.cases_per_fn,
            "total_executions": self.total_executions,
            "mismatches": self.mismatches,
            "functions": [asdict(f) for f in self.functions],
            "first_mismatch": self.first_mismatch,
            "elapsed_ms": round(self.elapsed_ms, 2),
        }


def _eval_concrete_int(node: SNode, env: dict[str, Any]) -> int:
    if isinstance(node.val, int):
        return node.val
    if isinstance(node.val, str):
        if node.val == "MAX":
            return U64_MAX
        if node.val == "MAX_I64":
            return I64_MAX
        if node.val == "MIN_I64":
            return I64_MIN
        v = env.get(node.val, 0)
        return int(v) if isinstance(v, int) else 0
    items = node.val
    op = str(items[0].val)
    if op == "field":
        sv = env.get(items[1].val if isinstance(items[1].val, str) else "")
        if isinstance(sv, dict):
            val = sv.get("fields", sv).get(str(items[2].val), 0)
            return int(val) if isinstance(val, int) else 0
        return 0
    if op == "if":
        cond = _eval_concrete_int(items[1], env)
        return _eval_concrete_int(items[2], env) if cond else _eval_concrete_int(items[3], env)
    if op in ("+", "-", "*", "/", "%", "min", "max", "&", "|", "^", "<<", ">>", "==", "!=", "<", "<=", ">", ">="):
        a = _eval_concrete_int(items[1], env)
        b = _eval_concrete_int(items[2], env)
        if op == "+":
            return a + b
        if op == "-":
            return a - b
        if op == "*":
            return a * b
        if op == "/":
            return a // b if b > 0 else 0
        if op == "%":
            return a % b if b > 0 else 0
        if op == "min":
            return min(a, b)
        if op == "max":
            return max(a, b)
        if op == "&":
            return a & b
        if op == "|":
            return a | b
        if op == "^":
            return a ^ b
        if op == "<<":
            return a << min(max(b, 0), 63)
        if op == ">>":
            return a >> min(max(b, 0), 63)
        if op == "==":
            return 1 if a == b else 0
        if op == "!=":
            return 1 if a != b else 0
        if op == "<":
            return 1 if a < b else 0
        if op == "<=":
            return 1 if a <= b else 0
        if op == ">":
            return 1 if a > b else 0
        if op == ">=":
            return 1 if a >= b else 0
    return 0


def _pick_int_in_range(rng: random.Random, case_idx: int, lo: int, hi: int, *, cap_len: bool = False) -> int:
    if lo > hi:
        return lo
    if cap_len and (hi - lo) > MAX_FUZZ_BUF_LEN:
        hi = min(hi, max(lo, MAX_FUZZ_BUF_LEN))
    if case_idx == 0:
        return lo
    if case_idx == 1:
        return hi
    if case_idx == 2:
        return lo + (hi - lo) // 2
    if case_idx == 3:
        return min(hi, lo + 1)
    if case_idx == 4:
        return max(lo, hi - 1)
    if case_idx == 5 and hi >= (1 << 32) >= lo:
        return 1 << 32
    if case_idx == 6 and hi >= (1 << 63) >= lo:
        return 1 << 63
    if (hi - lo) > 1_000_000 and rng.random() < 0.25:
        anchor = rng.choice([lo, hi, lo + (hi - lo) // 2, 1 << 31, 1 << 32, 1 << 63])
        if lo <= anchor <= hi:
            delta = rng.randint(-min(1024, anchor - lo), min(1024, hi - anchor))
            return anchor + delta
    return rng.randint(lo, hi)


def _gen_value(
    rng: random.Random,
    case_idx: int,
    kind: str,
    tspec: SNode,
    tenv: ModuleTypeEnv,
    env: dict[str, Any],
    *,
    cap_len: bool = False,
) -> Any:
    if kind in ("u64", "i64"):
        hw_lo, hw_hi = (I64_MIN, I64_MAX) if kind == "i64" else (0, U64_MAX)
        lo_n, hi_n = _extract_range_nodes(tspec)
        lo = max(hw_lo, _eval_concrete_int(lo_n, env))
        hi = min(hw_hi, _eval_concrete_int(hi_n, env))
        return _pick_int_in_range(rng, case_idx, lo, hi, cap_len=cap_len)

    if kind.startswith("struct:"):
        sname = kind.split(":", 1)[1]
        sdef = tenv.structs[sname]
        local_env = dict(env)
        fields_out: dict[str, Any] = {}
        for fd in sdef.fields:
            v = _gen_value(rng, case_idx, fd.kind, fd.type_node, tenv, local_env)
            fields_out[fd.name] = v
            local_env[fd.name] = v
        return {"__struct__": sname, "fields": fields_out}

    if kind.startswith("enum:"):
        ename = kind.split(":", 1)[1]
        edef = tenv.enums[ename]
        vdef = edef.variants[case_idx % len(edef.variants)] if case_idx < len(edef.variants) * 3 else rng.choice(edef.variants)
        local_env = dict(env)
        fields_out: list[Any] = []
        for fd in vdef.fields:
            v = _gen_value(rng, case_idx, fd.kind, fd.type_node, tenv, local_env)
            fields_out.append(v)
            local_env[fd.name] = v
        return {"__enum__": ename, "tag": vdef.tag, "variant": vdef.name, "fields": fields_out}

    if kind in ("bytes", "mut_bytes"):
        len_var = str(tspec.val[1].val)
        n = max(0, min(int(env.get(len_var, 0)), MAX_FUZZ_BUF_LEN))
        if n == 0:
            return []
        if kind == "bytes" and case_idx % 4 == 1 and n >= 5:
            head = [65, 73, 76, 49, 1]
            return head + [rng.randint(0, 255) for _ in range(n - len(head))]
        if kind == "bytes" and case_idx % 4 == 2 and n >= 4:
            head = [77, 82, 78, 84]
            return head + [rng.randint(0, 255) for _ in range(n - len(head))]
        return [rng.randint(0, 255) for _ in range(n)]

    if kind in ("slice", "mut_slice"):
        len_var = str(tspec.val[1].val)
        elem_t = tspec.val[2]
        elem_raw = elem_t.raw()
        elem_k = "i64" if (elem_raw == "i64" or (isinstance(elem_raw, list) and elem_raw and elem_raw[0] == "i64_range")) else "u64"
        n = max(0, min(int(env.get(len_var, 0)), MAX_FUZZ_BUF_LEN))
        return [_gen_value(rng, case_idx + i, elem_k, elem_t, tenv, env) for i in range(n)]

    return 0


def _decode_slots(kind: str, slots: list[int], off: int, tenv: ModuleTypeEnv) -> tuple[Any, int]:
    if kind == "u64":
        return str(slots[off] & U64_MAX), off + 1
    if kind == "i64":
        raw = slots[off] & U64_MAX
        return str(raw - (1 << 64) if raw >= (1 << 63) else raw), off + 1
    if kind.startswith("struct:"):
        sname = kind.split(":", 1)[1]
        out: dict[str, Any] = {}
        cur = off
        for fd in tenv.structs[sname].fields:
            val, cur = _decode_slots(fd.kind, slots, cur, tenv)
            out[fd.name] = val
        return {"__struct__": sname, "fields": out}, cur
    if kind.startswith("enum:"):
        ename = kind.split(":", 1)[1]
        edef = tenv.enums[ename]
        tag = int(slots[off])
        vdef = edef.variants[tag]
        fields: list[Any] = []
        cur = off + 1
        for fd in vdef.fields:
            val, cur = _decode_slots(fd.kind, slots, cur, tenv)
            fields.append(val)
        return {"__enum__": ename, "variant": vdef.name, "fields": fields}, off + 1 + edef.max_payload_slots(tenv.structs, tenv.enums)
    return str(slots[off]), off + 1


def _decode_ctype_result(obj: Any, kind: str, tenv: ModuleTypeEnv) -> Any:
    if kind == "u64":
        return str(int(obj) & U64_MAX)
    if kind == "i64":
        raw = int(obj) & U64_MAX
        return str(raw - (1 << 64) if raw >= (1 << 63) else raw)
    if kind.startswith("struct:"):
        sname = kind.split(":", 1)[1]
        return {
            "__struct__": sname,
            "fields": {
                fd.name: _decode_ctype_result(getattr(obj, fd.name), fd.kind, tenv)
                for fd in tenv.structs[sname].fields
            },
        }
    if kind.startswith("enum:"):
        ename = kind.split(":", 1)[1]
        edef = tenv.enums[ename]
        slots = [int(obj.tag)] + [int(getattr(obj, f"_p{i}")) for i in range(edef.max_payload_slots(tenv.structs, tenv.enums))]
        decoded, _ = _decode_slots(kind, slots, 0, tenv)
        return decoded
    return str(obj)


def _encode_ctype_arg(val: Any, kind: str, mod: Any, tspec: SNode, tenv: ModuleTypeEnv) -> Any:
    if kind in ("u64", "i64"):
        return int(val)
    if kind == "bytes":
        return bytes(val)
    if kind == "mut_bytes":
        return bytearray(val)
    if kind in ("slice", "mut_slice"):
        import ctypes

        elem_raw = tspec.val[2].raw()
        is_i64 = elem_raw == "i64" or (isinstance(elem_raw, list) and elem_raw and elem_raw[0] == "i64_range")
        c_ty = ctypes.c_int64 if is_i64 else ctypes.c_uint64
        arr = (c_ty * len(val))(*val)
        return arr
    if kind.startswith("struct:"):
        sname = kind.split(":", 1)[1]
        cls = getattr(mod, sname)
        sdef = tenv.structs[sname]
        kwargs = {
            fd.name: _encode_ctype_arg(val["fields"][fd.name], fd.kind, mod, fd.type_node, tenv)
            for fd in sdef.fields
        }
        return cls(**kwargs)
    if kind.startswith("enum:"):
        ename = kind.split(":", 1)[1]
        cls = getattr(mod, ename)
        edef = tenv.enums[ename]
        vdef = edef.get_variant(val["variant"])
        assert vdef is not None
        args = [
            _encode_ctype_arg(av, fd.kind, mod, fd.type_node, tenv)
            for av, fd in zip(val["fields"], vdef.fields)
        ]
        return getattr(cls, vdef.name)(*args)
    return val


def _run_ctype_batch(
    mod: Any,
    fn_name: str,
    params_meta: list[tuple[str, str, SNode]],
    ret_kind: str,
    cases_inputs: list[list[Any]],
    tenv: ModuleTypeEnv,
) -> list[dict[str, Any]]:
    fn = getattr(mod, fn_name)
    results: list[dict[str, Any]] = []
    for raw_args in cases_inputs:
        c_args: list[Any] = []
        mut_indices: list[tuple[int, str]] = []
        for idx, (val, (_, pk, pspec)) in enumerate(zip(raw_args, params_meta)):
            c_arg = _encode_ctype_arg(val, pk, mod, pspec, tenv)
            c_args.append(c_arg)
            if pk in ("mut_bytes", "mut_slice"):
                mut_indices.append((idx, pk))
        ret_raw = fn(*c_args)
        mut_out = {}
        for idx, pk in mut_indices:
            if pk == "mut_bytes":
                mut_out[str(idx)] = list(c_args[idx])
            else:
                mut_out[str(idx)] = [str(int(x)) for x in c_args[idx]]
        results.append({"ret": _decode_ctype_result(ret_raw, ret_kind, tenv), "mut": mut_out})
    return results


def _canonicalize_wasm_val(val: Any, kind: str, tenv: ModuleTypeEnv) -> Any:
    if kind in ("u64", "i64"):
        return str(int(val))
    if kind.startswith("struct:"):
        sname = kind.split(":", 1)[1]
        sdef = tenv.structs[sname]
        return {
            "__struct__": sname,
            "fields": {
                fd.name: _canonicalize_wasm_val(val[fd.name], fd.kind, tenv)
                for fd in sdef.fields
            },
        }
    if kind.startswith("enum:"):
        ename = kind.split(":", 1)[1]
        edef = tenv.enums[ename]
        vdef = edef.get_variant(str(val["variant"]))
        assert vdef is not None
        return {
            "__enum__": ename,
            "variant": vdef.name,
            "fields": [
                _canonicalize_wasm_val(fv, fd.kind, tenv)
                for fv, fd in zip(val["fields"], vdef.fields)
            ],
        }
    return str(val)


def _run_wasm_batch(
    wasm_mjs: Path,
    fn_specs: list[tuple[str, list[tuple[str, str, SNode]], str, list[list[Any]]]],
    tenv: ModuleTypeEnv,
) -> dict[str, list[dict[str, Any]]]:
    payload: list[dict[str, Any]] = []
    for fn_name, params_meta, _ret_kind, cases_inputs in fn_specs:
        payload.append(
            {
                "fn": fn_name,
                "params": [pk for _, pk, _ in params_meta],
                "cases": [
                    [[_json_encode_val(v) for v in case_args]][0]
                    for case_args in cases_inputs
                ],
            }
        )

    driver_js = f"""
import * as w from {json.dumps(str(wasm_mjs.resolve()))};

const specs = {json.dumps(payload)};

function buildArg(val, kind) {{
  if (kind === "u64" || kind === "i64") return BigInt(val);
  if (kind === "bytes" || kind === "mut_bytes") return new Uint8Array(val);
  if (kind === "slice" || kind === "mut_slice") return val.map((x) => BigInt(x));
  if (kind.startsWith("struct:")) {{
    const out = {{}};
    for (const [k, v] of Object.entries(val.fields)) out[k] = buildArg(v, val.fieldKinds[k]);
    return out;
  }}
  if (kind.startsWith("enum:")) {{
    return {{
      tag: Number(val.tag),
      variant: val.variant,
      fields: val.fields.map((f, i) => buildArg(f, val.fieldKinds[i])),
    }};
  }}
  return val;
}}

function normOut(v) {{
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "number") return String(v);
  if (Array.isArray(v)) return v.map(normOut);
  if (v && typeof v === "object") {{
    if (typeof v.tag === "number" && typeof v.variant === "string" && Array.isArray(v.fields)) {{
      return {{ variant: v.variant, fields: v.fields.map(normOut) }};
    }}
    const out = {{}};
    for (const k of Object.keys(v)) out[k] = normOut(v[k]);
    return out;
  }}
  return String(v);
}}

const results = {{}};
for (const sp of specs) {{
  const fn = w[sp.fn];
  const rows = [];
  for (const rawArgs of sp.cases) {{
    const jsArgs = rawArgs.map((a, i) => buildArg(a, sp.params[i]));
    const ret = fn(...jsArgs);
    const mut = {{}};
    for (let i = 0; i < sp.params.length; i++) {{
      if (sp.params[i] === "mut_bytes") mut[String(i)] = Array.from(jsArgs[i]);
      else if (sp.params[i] === "mut_slice") mut[String(i)] = Array.from(jsArgs[i], (x) => BigInt(x).toString());
    }}
    rows.push({{ ret: normOut(ret), mut }});
  }}
  results[sp.fn] = rows;
}}
console.log(JSON.stringify(results));
"""
    raw_out = subprocess.check_output(["node", "--input-type=module", "-e", driver_js], text=True)
    parsed = json.loads(raw_out)
    final: dict[str, list[dict[str, Any]]] = {}
    for fn_name, _, ret_kind, _ in fn_specs:
        rows = []
        for row in parsed[fn_name]:
            rows.append({"ret": _canonicalize_wasm_val(row["ret"], ret_kind, tenv), "mut": row["mut"]})
        final[fn_name] = rows
    return final


def _json_encode_val(v: Any) -> Any:
    if isinstance(v, list):
        return [str(x) if isinstance(x, int) and abs(x) > (1 << 52) else x for x in v]
    if isinstance(v, dict):
        if "__struct__" in v:
            # Field kinds are looked up separately if nested; encode recursively
            return {
                "__struct__": v["__struct__"],
                "fields": {k: _json_encode_val(fv) for k, fv in v["fields"].items()},
                "_flat_type": "struct",
            }
        if "__enum__" in v:
            return {
                "__enum__": v["__enum__"],
                "tag": v["tag"],
                "variant": v["variant"],
                "fields": [_json_encode_val(fv) for fv in v["fields"]],
            }
    if isinstance(v, int):
        return str(v)
    return v


def _attach_kinds_for_wasm(v: Any, kind: str, tenv: ModuleTypeEnv) -> Any:
    if kind.startswith("struct:"):
        sname = kind.split(":", 1)[1]
        sdef = tenv.structs[sname]
        return {
            "__struct__": sname,
            "fields": {fd.name: _attach_kinds_for_wasm(v["fields"][fd.name], fd.kind, tenv) for fd in sdef.fields},
            "fieldKinds": {fd.name: fd.kind for fd in sdef.fields},
        }
    if kind.startswith("enum:"):
        ename = kind.split(":", 1)[1]
        edef = tenv.enums[ename]
        vdef = edef.get_variant(v["variant"])
        assert vdef is not None
        return {
            "__enum__": ename,
            "tag": v["tag"],
            "variant": v["variant"],
            "fields": [_attach_kinds_for_wasm(fv, fd.kind, tenv) for fv, fd in zip(v["fields"], vdef.fields)],
            "fieldKinds": [fd.kind for fd in vdef.fields],
        }
    if kind in ("bytes", "mut_bytes"):
        return list(v)
    if kind in ("slice", "mut_slice"):
        return [str(x) for x in v]
    return str(v)


def _run_wasm_batch_typed(
    wasm_mjs: Path,
    fn_specs: list[tuple[str, list[tuple[str, str, SNode]], str, list[list[Any]]]],
    tenv: ModuleTypeEnv,
) -> dict[str, list[dict[str, Any]]]:
    payload: list[dict[str, Any]] = []
    for fn_name, params_meta, _ret_kind, cases_inputs in fn_specs:
        payload.append(
            {
                "fn": fn_name,
                "params": [pk for _, pk, _ in params_meta],
                "cases": [
                    [_attach_kinds_for_wasm(val, pk, tenv) for val, (_, pk, _) in zip(case_args, params_meta)]
                    for case_args in cases_inputs
                ],
            }
        )

    driver_js = f"""
import * as w from {json.dumps(str(wasm_mjs.resolve()))};

const specs = {json.dumps(payload)};

function buildArg(val, kind) {{
  if (kind === "u64" || kind === "i64") return BigInt(val);
  if (kind === "bytes" || kind === "mut_bytes") return new Uint8Array(val);
  if (kind === "slice" || kind === "mut_slice") return val.map((x) => BigInt(x));
  if (kind.startsWith("struct:")) {{
    const out = {{}};
    for (const [k, v] of Object.entries(val.fields)) out[k] = buildArg(v, val.fieldKinds[k]);
    return out;
  }}
  if (kind.startsWith("enum:")) {{
    return {{
      tag: Number(val.tag),
      variant: val.variant,
      fields: val.fields.map((f, i) => buildArg(f, val.fieldKinds[i])),
    }};
  }}
  return val;
}}

function normOut(v) {{
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "number") return String(v);
  if (Array.isArray(v)) return v.map(normOut);
  if (v && typeof v === "object") {{
    if (typeof v.tag === "number" && typeof v.variant === "string" && Array.isArray(v.fields)) {{
      return {{ variant: v.variant, fields: v.fields.map(normOut) }};
    }}
    const out = {{}};
    for (const k of Object.keys(v)) out[k] = normOut(v[k]);
    return out;
  }}
  return String(v);
}}

const results = {{}};
for (const sp of specs) {{
  const fn = w[sp.fn];
  const rows = [];
  for (const rawArgs of sp.cases) {{
    const jsArgs = rawArgs.map((a, i) => buildArg(a, sp.params[i]));
    const ret = fn(...jsArgs);
    const mut = {{}};
    for (let i = 0; i < sp.params.length; i++) {{
      if (sp.params[i] === "mut_bytes") mut[String(i)] = Array.from(jsArgs[i]);
      else if (sp.params[i] === "mut_slice") mut[String(i)] = Array.from(jsArgs[i], (x) => BigInt(x).toString());
    }}
    rows.push({{ ret: normOut(ret), mut }});
  }}
  results[sp.fn] = rows;
}}
console.log(JSON.stringify(results));
"""
    raw_out = subprocess.check_output(["node", "--input-type=module", "-e", driver_js], text=True)
    parsed = json.loads(raw_out)
    final: dict[str, list[dict[str, Any]]] = {}
    for fn_name, _, ret_kind, _ in fn_specs:
        final[fn_name] = [
            {"ret": _canonicalize_wasm_val(row["ret"], ret_kind, tenv), "mut": row["mut"]}
            for row in parsed[fn_name]
        ]
    return final


def _rust_val_expr(val: Any, kind: str, tenv: ModuleTypeEnv) -> str:
    if kind == "u64":
        return f"{int(val)}u64"
    if kind == "i64":
        v = int(val)
        return "i64::MIN" if v == I64_MIN else f"{v}i64"
    if kind.startswith("struct:"):
        sname = kind.split(":", 1)[1]
        sdef = tenv.structs[sname]
        flds = ", ".join(f"{fd.name}: {_rust_val_expr(val['fields'][fd.name], fd.kind, tenv)}" for fd in sdef.fields)
        return f"ail::{sname} {{ {flds} }}"
    if kind.startswith("enum:"):
        ename = kind.split(":", 1)[1]
        edef = tenv.enums[ename]
        vdef = edef.get_variant(val["variant"])
        assert vdef is not None
        if not vdef.fields:
            return f"ail::{ename}::{vdef.name}"
        args = ", ".join(_rust_val_expr(fv, fd.kind, tenv) for fv, fd in zip(val["fields"], vdef.fields))
        return f"ail::{ename}::{vdef.name}({args})"
    if kind in ("bytes", "mut_bytes"):
        elems = ", ".join(f"{int(b)}u8" for b in val)
        return f"[{elems}]"
    if kind in ("slice", "mut_slice"):
        return "[" + ", ".join(str(int(x)) for x in val) + "]"
    return "0u64"


def _rust_emit_print_ret(expr: str, kind: str, tenv: ModuleTypeEnv, lines: list[str], indent: str = "        ") -> None:
    if kind in ("u64", "i64"):
        lines.append(f'{indent}print!("\\"{{}}\\"", {expr});')
    elif kind.startswith("struct:"):
        sname = kind.split(":", 1)[1]
        sdef = tenv.structs[sname]
        lines.append(f'{indent}wr("{{\\"__struct__\\":\\"{sname}\\",\\"fields\\":{{");')
        for i, fd in enumerate(sdef.fields):
            if i > 0:
                lines.append(f'{indent}wr(",");')
            lines.append(f'{indent}wr("\\"{fd.name}\\":");')
            _rust_emit_print_ret(f"{expr}.{fd.name}", fd.kind, tenv, lines, indent)
        lines.append(f'{indent}wr("}}}}");')
    elif kind.startswith("enum:"):
        ename = kind.split(":", 1)[1]
        edef = tenv.enums[ename]
        lines.append(f"{indent}match {expr} {{")
        for vdef in edef.variants:
            if vdef.fields:
                bvars = ", ".join(f"_f{i}" for i in range(len(vdef.fields)))
                lines.append(f"{indent}    ail::{ename}::{vdef.name}({bvars}) => {{")
            else:
                lines.append(f"{indent}    ail::{ename}::{vdef.name} => {{")
            lines.append(f'{indent}        wr("{{\\"__enum__\\":\\"{ename}\\",\\"variant\\":\\"{vdef.name}\\",\\"fields\\":[");')
            for i, fd in enumerate(vdef.fields):
                if i > 0:
                    lines.append(f'{indent}        wr(",");')
                _rust_emit_print_ret(f"_f{i}", fd.kind, tenv, lines, indent + "        ")
            lines.append(f'{indent}        wr("]}}");')
            lines.append(f"{indent}    }}")
        lines.append(f"{indent}}}")


def _run_rust_batch(
    rust_rlib: Path,
    work_dir: Path,
    fn_specs: list[tuple[str, list[tuple[str, str, SNode]], str, list[list[Any]]]],
    tenv: ModuleTypeEnv,
) -> dict[str, list[dict[str, Any]]]:
    rs_lines: list[str] = [
        "#![allow(unused_mut, unused_variables, non_snake_case)]",
        "extern crate ail_mod as ail;",
        "use std::io::Write;",
        'fn wr(s: &str) { let _ = std::io::stdout().write_all(s.as_bytes()); }',
        "",
    ]
    for fidx, (fn_name, params_meta, ret_kind, cases_inputs) in enumerate(fn_specs):
        rs_lines.append(f"fn run_fn_{fidx}() {{")
        rs_lines.append('    wr("[");')
        for cidx, case_args in enumerate(cases_inputs):
            if cidx > 0:
                rs_lines.append('    wr(",");')
            rs_lines.append("    {")
            call_args: list[str] = []
            mut_locals: list[tuple[int, str, str]] = []
            for pidx, (val, (_, pk, pspec)) in enumerate(zip(case_args, params_meta)):
                vname = f"arg_{pidx}"
                if pk == "bytes":
                    rs_lines.append(f"        let {vname}: &[u8] = &{_rust_val_expr(val, pk, tenv)};")
                    call_args.append(vname)
                elif pk == "mut_bytes":
                    rs_lines.append(f"        let mut {vname}_arr: [u8; {len(val)}] = {_rust_val_expr(val, pk, tenv)};")
                    call_args.append(f"&mut {vname}_arr")
                    mut_locals.append((pidx, pk, f"{vname}_arr"))
                elif pk in ("slice", "mut_slice"):
                    elem_raw = pspec.val[2].raw()
                    r_elem = "i64" if (elem_raw == "i64" or (isinstance(elem_raw, list) and elem_raw and elem_raw[0] == "i64_range")) else "u64"
                    arr_lit = "[" + ", ".join(
                        ("i64::MIN" if (r_elem == "i64" and x == I64_MIN) else f"{int(x)}{r_elem}")
                        for x in val
                    ) + "]"
                    if pk == "slice":
                        rs_lines.append(f"        let {vname}: &[{r_elem}] = &{arr_lit};")
                        call_args.append(vname)
                    else:
                        rs_lines.append(f"        let mut {vname}_arr: [{r_elem}; {len(val)}] = {arr_lit};")
                        call_args.append(f"&mut {vname}_arr")
                        mut_locals.append((pidx, pk, f"{vname}_arr"))
                else:
                    rs_lines.append(f"        let {vname} = {_rust_val_expr(val, pk, tenv)};")
                    call_args.append(vname)
            rs_lines.append(f"        let _ret = ail::{fn_name}({', '.join(call_args)});")
            rs_lines.append('        wr("{\\"ret\\":");')
            _rust_emit_print_ret("_ret", ret_kind, tenv, rs_lines, "        ")
            rs_lines.append('        wr(",\\"mut\\":{");')
            for midx, (pidx, pk, arr_name) in enumerate(mut_locals):
                if midx > 0:
                    rs_lines.append('        wr(",");')
                rs_lines.append(f'        wr("\\"{pidx}\\":[");')
                rs_lines.append(f"        for (k, x) in {arr_name}.iter().enumerate() {{")
                rs_lines.append('            if k > 0 { wr(","); }')
                if pk == "mut_bytes":
                    rs_lines.append('            print!("{}", x);')
                else:
                    rs_lines.append('            print!("\\"{}\\"", x);')
                rs_lines.append("        }")
                rs_lines.append('        wr("]");')
            rs_lines.append('        wr("}}");')
            rs_lines.append("    }")
        rs_lines.append('    wr("]");')
        rs_lines.append("}")

    rs_lines.append("fn main() {")
    rs_lines.append('    wr("{");')
    for fidx, (fn_name, _, _, _) in enumerate(fn_specs):
        if fidx > 0:
            rs_lines.append('    wr(",");')
        rs_lines.append(f'    wr("\\"{fn_name}\\":");')
        rs_lines.append(f"    run_fn_{fidx}();")
    rs_lines.append('    wr("}");')
    rs_lines.append("}")

    driver_rs = work_dir / "fuzz_rust_driver.rs"
    driver_bin = work_dir / "fuzz_rust_driver"
    driver_rs.write_text("\n".join(rs_lines), encoding="utf-8")
    subprocess.run(
        ["rustc", "--edition", "2021", "-O", "--extern", f"ail_mod={rust_rlib}", str(driver_rs), "-o", str(driver_bin)],
        check=True,
        capture_output=True,
        text=True,
    )
    out = subprocess.check_output([str(driver_bin)], text=True)
    return json.loads(out)


def _load_c_bindings(native_bindings: Path, c_lib: Path, work_dir: Path) -> Any:
    src = native_bindings.read_text(encoding="utf-8")
    lib_name = f"lib{native_bindings.name.removesuffix('_bindings.py')}"
    # Replace `_LIB = ctypes.CDLL(str(Path(__file__).with_name("lib...")))` reliably
    import re

    patched = re.sub(
        r'_LIB\s*=\s*ctypes\.CDLL\([^\n]+\)',
        f'_LIB = ctypes.CDLL({json.dumps(str(c_lib.resolve()))})',
        src,
        count=1,
    )
    c_bind_path = work_dir / f"{native_bindings.stem}_c_fuzz.py"
    c_bind_path.write_text(patched, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("ail_fuzz_c", c_bind_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_native_bindings(native_bindings: Path) -> Any:
    spec = importlib.util.spec_from_file_location("ail_fuzz_native", native_bindings)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_differential_fuzz(
    path_or_source: Path | str,
    out_dir: Path,
    *,
    cases: int = 40,
    seed: int = 42,
    is_source: bool = False,
    stem: str | None = None,
) -> DiffFuzzReport:
    t0 = time.perf_counter()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if is_source:
        src_text = str(path_or_source)
        forms = load_ail_module_with_imports(src_text)
        mod_stem = stem or "fuzz_kernel"
    else:
        p = Path(path_or_source)
        forms = load_ail_module_with_imports(p)
        mod_stem = stem or p.stem

    tenv = check_module_ownership_v2(forms)
    mv = ModuleVerifier(tenv)
    mv.verify_module(forms)

    build_report = build_multi_target(forms, tenv, out_dir, stem=mod_stem, target="all")

    rng = random.Random(seed)
    summaries: list[FnFuzzSummary] = []
    fuzz_targets: list[tuple[str, list[tuple[str, str, SNode]], str, list[list[Any]]]] = []

    for form in forms:
        if not isinstance(form.val, list) or not form.val or str(form.val[0].val) != "fn":
            continue
        fn_name = str(form.val[1].val)
        sig = tenv.sigs[fn_name]
        if any(pk in LINEAR_CAPS or pk == "atomic_u64" for pk in sig.param_kinds) or sig.ret_kind in LINEAR_CAPS:
            summaries.append(FnFuzzSummary(fn_name=fn_name, cases_executed=0, mismatches=0, skipped_reason="linear_or_atomic_capability"))
            continue

        params_node = form.val[2]
        params_meta = [
            (str(pn.val[0].val), pk, pn.val[1])
            for pn, pk in zip(params_node.val, sig.param_kinds)
        ]
        # Pre-scan parameters used as lengths for bytes/mut_bytes/slice/mut_slice
        len_param_names: set[str] = set()
        for _, pk, pspec in params_meta:
            if pk in ("bytes", "mut_bytes", "slice", "mut_slice") and isinstance(pspec.val, list) and len(pspec.val) >= 2:
                len_param_names.add(str(pspec.val[1].val))

        cases_inputs: list[list[Any]] = []
        for cidx in range(cases):
            env: dict[str, Any] = {}
            args: list[Any] = []
            for pname, pk, pspec in params_meta:
                val = _gen_value(rng, cidx, pk, pspec, tenv, env, cap_len=(pname in len_param_names))
                args.append(val)
                env[pname] = val
            cases_inputs.append(args)

        fuzz_targets.append((fn_name, params_meta, sig.ret_kind, cases_inputs))

    if not fuzz_targets:
        return DiffFuzzReport(
            stem=mod_stem,
            seed=seed,
            cases_per_fn=cases,
            total_executions=0,
            mismatches=0,
            functions=summaries,
            first_mismatch=None,
            elapsed_ms=(time.perf_counter() - t0) * 1000.0,
        )

    assert build_report.native is not None
    assert build_report.wasm is not None
    assert build_report.c is not None
    assert build_report.rust is not None
    native_bindings_path = Path(build_report.native.python_bindings_path)
    native_mod = _load_native_bindings(native_bindings_path)
    with tempfile.TemporaryDirectory(prefix="ail_diff_fuzz_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        c_mod = _load_c_bindings(native_bindings_path, Path(build_report.c.shared_lib_path), tmp_path)
        wasm_results = _run_wasm_batch_typed(Path(build_report.wasm.js_wrapper_path), fuzz_targets, tenv)
        rust_results = _run_rust_batch(Path(build_report.rust.rlib_path), tmp_path, fuzz_targets, tenv)

    total_exec = 0
    total_mismatches = 0
    first_mismatch: dict[str, Any] | None = None

    for fn_name, params_meta, ret_kind, cases_inputs in fuzz_targets:
        nat_rows = _run_ctype_batch(native_mod, fn_name, params_meta, ret_kind, cases_inputs, tenv)
        c_rows = _run_ctype_batch(c_mod, fn_name, params_meta, ret_kind, cases_inputs, tenv)
        wasm_rows = wasm_results[fn_name]
        rust_rows = rust_results[fn_name]

        fn_mismatches = 0
        for idx, (n_row, w_row, c_row, r_row) in enumerate(zip(nat_rows, wasm_rows, c_rows, rust_rows)):
            total_exec += 4
            if not (n_row == w_row == c_row == r_row):
                fn_mismatches += 1
                total_mismatches += 1
                if first_mismatch is None:
                    first_mismatch = {
                        "fn_name": fn_name,
                        "case_index": idx,
                        "inputs": [_attach_kinds_for_wasm(v, pk, tenv) for v, (_, pk, _) in zip(cases_inputs[idx], params_meta)],
                        "native": n_row,
                        "wasm": w_row,
                        "c": c_row,
                        "rust": r_row,
                    }
        summaries.append(FnFuzzSummary(fn_name=fn_name, cases_executed=len(cases_inputs), mismatches=fn_mismatches))

    return DiffFuzzReport(
        stem=mod_stem,
        seed=seed,
        cases_per_fn=cases,
        total_executions=total_exec,
        mismatches=total_mismatches,
        functions=summaries,
        first_mismatch=first_mismatch,
        elapsed_ms=(time.perf_counter() - t0) * 1000.0,
    )
