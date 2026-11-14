"""Pure-Python W3C WebAssembly 1.0 Binary Encoder, WAT Emitter, ESM `.mjs` Wrapper, and `.d.ts` Generator."""

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ailang.diagnostics import I64_MAX, I64_MIN, U64_MAX
from ailang.ownership import EnumDef, LINEAR_CAPS, FnSig, ModuleTypeEnv, StructDef, check_module_ownership_v2
from ailang.parser import SNode

WASM_MAGIC_VERSION = b"\x00asm\x01\x00\x00\x00"

VAL_I32 = 0x7F
VAL_I64 = 0x7E
BLOCK_VOID = 0x40
BLOCK_I32 = 0x7F
BLOCK_I64 = 0x7E

TYPE_NAMES = {
    VAL_I32: "i32",
    VAL_I64: "i64",
    BLOCK_VOID: "void",
}

HOST_IMPORT_SPECS: dict[str, tuple[str, tuple[int, ...], tuple[int, ...]]] = {
    "io_print_u64": ("io_print_u64", (VAL_I64,), ()),
    "io_print_i64": ("io_print_i64", (VAL_I64,), ()),
    "fs_write_u64": ("fs_write_u64", (VAL_I64,), ()),
    "fs_write_i64": ("fs_write_i64", (VAL_I64,), ()),
    "net_loopback_u64": ("net_loopback_u64", (VAL_I64, VAL_I64), ()),
}

CAP_INTRINSIC_TO_IMPORT = {
    "io.print_u64": "io_print_u64",
    "io.print_i64": "io_print_i64",
    "fs.write_u64": "fs_write_u64",
    "fs.write_i64": "fs_write_i64",
    "net.loopback_send_u64": "net_loopback_u64",
}

SIMPLE_OPCODES: dict[str, int] = {
    "unreachable": 0x00,
    "nop": 0x01,
    "else": 0x05,
    "end": 0x0B,
    "return": 0x0F,
    "drop": 0x1A,
    "select": 0x1B,
    "i32.eqz": 0x45,
    "i32.eq": 0x46,
    "i32.ne": 0x47,
    "i32.lt_s": 0x48,
    "i32.lt_u": 0x49,
    "i32.gt_s": 0x4A,
    "i32.gt_u": 0x4B,
    "i32.le_s": 0x4C,
    "i32.le_u": 0x4D,
    "i32.ge_s": 0x4E,
    "i32.ge_u": 0x4F,
    "i64.eqz": 0x50,
    "i64.eq": 0x51,
    "i64.ne": 0x52,
    "i64.lt_s": 0x53,
    "i64.lt_u": 0x54,
    "i64.gt_s": 0x55,
    "i64.gt_u": 0x56,
    "i64.le_s": 0x57,
    "i64.le_u": 0x58,
    "i64.ge_s": 0x59,
    "i64.ge_u": 0x5A,
    "i32.add": 0x6A,
    "i32.sub": 0x6B,
    "i32.mul": 0x6C,
    "i32.and": 0x71,
    "i32.or": 0x72,
    "i32.xor": 0x73,
    "i32.shl": 0x74,
    "i32.shr_u": 0x76,
    "i64.add": 0x7C,
    "i64.sub": 0x7D,
    "i64.mul": 0x7E,
    "i64.div_s": 0x7F,
    "i64.div_u": 0x80,
    "i64.rem_s": 0x81,
    "i64.rem_u": 0x82,
    "i64.and": 0x83,
    "i64.or": 0x84,
    "i64.xor": 0x85,
    "i64.shl": 0x86,
    "i64.shr_s": 0x87,
    "i64.shr_u": 0x88,
    "i32.wrap_i64": 0xA7,
    "i64.extend_i32_s": 0xAC,
    "i64.extend_i32_u": 0xAD,
}

MEM_LOAD_STORE_OPCODES: dict[str, tuple[int, int]] = {
    "i32.load": (0x28, 2),
    "i64.load": (0x29, 3),
    "i32.load8_u": (0x2D, 0),
    "i32.load16_u": (0x2F, 1),
    "i64.load8_u": (0x31, 0),
    "i64.load16_u": (0x33, 1),
    "i64.load32_u": (0x35, 2),
    "i32.store": (0x36, 2),
    "i64.store": (0x37, 3),
}


@dataclass(frozen=True)
class WasmArtifacts:
    wasm_path: str
    wat_path: str
    js_wrapper_path: str
    ts_dts_path: str
    wasm_size_bytes: int


@dataclass
class WasmParamInfo:
    name: str
    ail_kind: str
    wasm_ty: int
    len_source: str | int | None = None
    elem_is_i64: bool = False
    struct_or_enum_name: str | None = None


@dataclass
class WasmExportInfo:
    ail_name: str
    wasm_export_names: list[str]
    params: list[WasmParamInfo]
    ret_kind: str  # "u64" | "i64" | "void" | "struct:..." | "enum:..."
    ret_wasm_ty: int | None
    is_main: bool = False


@dataclass
class WasmFuncDef:
    name: str
    params: list[tuple[str, int]]
    results: tuple[int, ...]
    locals_decls: list[tuple[str, int]] = field(default_factory=list)
    instrs: list[tuple[Any, ...]] = field(default_factory=list)
    export_names: list[str] = field(default_factory=list)


def _uleb128(value: int) -> bytes:
    if value < 0:
        raise ValueError(f"Negative uleb128 value: {value}")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        out.append(byte)
        if value == 0:
            break
    return bytes(out)


def _sleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        done = (value == 0 and (byte & 0x40) == 0) or (value == -1 and (byte & 0x40) != 0)
        if not done:
            byte |= 0x80
        out.append(byte)
        if done:
            break
    return bytes(out)


def _to_signed32(value: int) -> int:
    v = value & 0xFFFFFFFF
    return v - (1 << 32) if v >= (1 << 31) else v


def _to_signed64(value: int) -> int:
    v = value & 0xFFFFFFFFFFFFFFFF
    return v - (1 << 64) if v >= (1 << 63) else v


def _encode_str(s: str) -> bytes:
    raw = s.encode("utf-8")
    return _uleb128(len(raw)) + raw


def _encode_section(sec_id: int, payload: bytes) -> bytes:
    return bytes([sec_id]) + _uleb128(len(payload)) + payload


def _slice_elem_is_i64(pspec: SNode) -> bool:
    if not isinstance(pspec.val, list) or len(pspec.val) < 3:
        return False
    elem_raw = pspec.val[2].raw()
    return elem_raw == "i64" or (isinstance(elem_raw, list) and bool(elem_raw) and elem_raw[0] == "i64_range")


def _len_source_from_spec(pspec: SNode) -> str | int | None:
    if not isinstance(pspec.val, list) or len(pspec.val) < 2:
        return None
    len_raw = pspec.val[1].raw()
    if isinstance(len_raw, int):
        return len_raw
    if isinstance(len_raw, str):
        return len_raw
    return None


def _wasm_valtype_for_kind(kind: str) -> int | None:
    if kind in LINEAR_CAPS or kind == "void":
        return None
    if kind == "bool" or kind in ("slice", "mut_slice", "bytes", "atomic_u64") or kind.startswith(("struct:", "enum:")):
        return VAL_I32
    return VAL_I64


def _blocktype_for_valtype(vty: int | None) -> int:
    if vty is None:
        return BLOCK_VOID
    return vty


def _collect_used_host_imports(forms: list[SNode]) -> list[str]:
    found: set[str] = set()

    def walk(node: SNode) -> None:
        if not isinstance(node.val, list) or not node.val:
            return
        head = node.val[0].val
        if isinstance(head, str) and head in CAP_INTRINSIC_TO_IMPORT:
            found.add(CAP_INTRINSIC_TO_IMPORT[head])
        for ch in node.val:
            walk(ch)

    for form in forms:
        if isinstance(form.val, list) and form.val:
            head = str(form.val[0].val)
            if head in ("fn", "main", "map_inplace"):
                walk(form)

    order = ["io_print_u64", "io_print_i64", "fs_write_u64", "fs_write_i64", "net_loopback_u64"]
    return [name for name in order if name in found]


class _WasmFuncBuilder:
    """Lowers an AIL expression tree into WebAssembly 1.0 instructions and locals."""

    def __init__(
        self,
        tenv: ModuleTypeEnv,
        fn_indices: dict[str, int],
        alloc_fn_idx: int,
        param_names: list[str],
        param_types: list[int],
    ) -> None:
        self.tenv = tenv
        self.fn_indices = fn_indices
        self.alloc_fn_idx = alloc_fn_idx
        self.param_count = len(param_names)
        self.locals_decls: list[tuple[str, int]] = []
        self.instrs: list[tuple[Any, ...]] = []
        self._tmp_id = 0

    def alloc_local(self, wty: int, hint: str) -> int:
        idx = self.param_count + len(self.locals_decls)
        self._tmp_id += 1
        self.locals_decls.append((f"{hint}_{self._tmp_id}", wty))
        return idx

    def emit_op(self, op: str, *args: Any) -> None:
        self.instrs.append((op, *args))

    def _raw_kind(self, node: SNode, env: dict[str, tuple[int, int | None, str]]) -> str:
        if id(node) in self.tenv.expr_types:
            return self.tenv.expr_types[id(node)]
        if isinstance(node.val, int):
            return "i64" if node.val < 0 else "lit_pos"
        if isinstance(node.val, str):
            if node.val in ("MIN_I64", "MAX_I64"):
                return "i64"
            if node.val == "MAX":
                return "u64"
            if node.val in env:
                return env[node.val][2]
            return "u64"
        items = node.val
        if not items or not isinstance(items[0].val, str):
            return "u64"
        op = items[0].val
        if op == "to_i64":
            return "i64"
        if op == "to_u64":
            return "u64"
        if op == "make":
            return f"struct:{items[1].val}"
        if op == "variant":
            return f"enum:{items[1].val}"
        if op in ("is_variant", "==", "!=", "<", "<=", ">", ">=", "and", "or", "not"):
            return "bool"
        if op == "field":
            sname = self._node_kind(items[1], env).split(":", 1)[1]
            found = self.tenv.structs[sname].get_field(str(items[2].val))
            return found[1].kind if found else "u64"
        if op in ("byte_at", "read_u16_be", "read_u32_be", "read_u64_be", "bytes_eq4", "get"):
            return "u64"
        if op == "call":
            return self.tenv.sigs[str(items[1].val)].ret_kind
        if op == "fold":
            return self._raw_kind(items[2].val[1], env)
        if op == "match":
            return self._raw_kind(items[2].val[1], env)
        if op == "let":
            nenv = dict(env)
            for b in items[1].val:
                bname = str(b.val[0].val)
                bk = self._node_kind(b.val[1], nenv)
                nenv[bname] = (-1, _wasm_valtype_for_kind(bk), bk)
            return self._raw_kind(items[2], nenv)
        if op == "if":
            k1 = self._raw_kind(items[2], env)
            k2 = self._raw_kind(items[3], env)
            return "i64" if ("i64" in (k1, k2)) else ("u64" if k1 == "lit_pos" else k1)
        if op in ("+", "-", "*", "/", "%", "min", "max", "&", "|", "^"):
            k1 = self._raw_kind(items[1], env)
            k2 = self._raw_kind(items[2], env)
            return "i64" if ("i64" in (k1, k2)) else "u64"
        if op in (">>", "<<", "~"):
            k1 = self._raw_kind(items[1], env)
            return "i64" if k1 == "i64" else "u64"
        return "u64"

    def _node_kind(self, node: SNode, env: dict[str, tuple[int, int | None, str]]) -> str:
        rk = self._raw_kind(node, env)
        return "u64" if rk == "lit_pos" else rk

    def emit_expr(self, node: SNode, env: dict[str, tuple[int, int | None, str]]) -> int | None:
        if isinstance(node.val, int):
            self.emit_op("i64.const", _to_signed64(node.val))
            return VAL_I64

        if isinstance(node.val, str):
            sym = node.val
            if sym == "MAX":
                self.emit_op("i64.const", -1)
                return VAL_I64
            if sym == "MIN_I64":
                self.emit_op("i64.const", I64_MIN)
                return VAL_I64
            if sym == "MAX_I64":
                self.emit_op("i64.const", I64_MAX)
                return VAL_I64
            loc_idx, wty, _ = env[sym]
            if wty is None:
                return None
            self.emit_op("local.get", loc_idx, sym)
            return wty

        items = node.val
        op = str(items[0].val)
        nk = self._node_kind(node, env)

        if op == "let":
            nenv = dict(env)
            for b in items[1].val:
                bname = str(b.val[0].val)
                bk = self._node_kind(b.val[1], nenv)
                rhs_wty = self.emit_expr(b.val[1], nenv)
                if rhs_wty is None:
                    nenv[bname] = (-1, None, bk)
                else:
                    loc_idx = self.alloc_local(rhs_wty, bname)
                    self.emit_op("local.set", loc_idx, bname)
                    nenv[bname] = (loc_idx, rhs_wty, bk)
            return self.emit_expr(items[2], nenv)

        if op == "if":
            res_wty = _wasm_valtype_for_kind(nk)
            cond_wty = self.emit_expr(items[1], env)
            if cond_wty == VAL_I64:
                self.emit_op("i64.const", 0)
                self.emit_op("i64.ne")
            self.emit_op("if", _blocktype_for_valtype(res_wty))
            self.emit_expr(items[2], env)
            self.emit_op("else")
            self.emit_expr(items[3], env)
            self.emit_op("end")
            return res_wty

        if op in ("to_i64", "to_u64"):
            return self.emit_expr(items[1], env)

        if op == "make":
            sname = str(items[1].val)
            sdef = self.tenv.structs[sname]
            size = max(8, 8 * len(sdef.fields))
            ptr_loc = self.alloc_local(VAL_I32, f"{sname}_ptr")
            self.emit_op("i32.const", size)
            self.emit_op("call", self.alloc_fn_idx, "__ail_alloc")
            self.emit_op("local.set", ptr_loc, f"{sname}_ptr")
            for fidx, arg_n in enumerate(items[2:]):
                self.emit_op("local.get", ptr_loc, f"{sname}_ptr")
                self.emit_expr(arg_n, env)
                self.emit_op("i64.store", 3, fidx * 8)
            self.emit_op("local.get", ptr_loc, f"{sname}_ptr")
            return VAL_I32

        if op == "field":
            sv_node = items[1]
            sname = self._node_kind(sv_node, env).split(":", 1)[1]
            fname = str(items[2].val)
            found = self.tenv.structs[sname].get_field(fname)
            assert found is not None
            fidx = found[0]
            self.emit_expr(sv_node, env)
            self.emit_op("i64.load", 3, fidx * 8)
            return VAL_I64

        if op == "variant":
            ename = str(items[1].val)
            vname = str(items[2].val)
            edef = self.tenv.enums[ename]
            vdef = edef.get_variant(vname)
            assert vdef is not None
            size = 8 * (1 + edef.max_fields)
            ptr_loc = self.alloc_local(VAL_I32, f"{ename}_ptr")
            self.emit_op("i32.const", size)
            self.emit_op("call", self.alloc_fn_idx, "__ail_alloc")
            self.emit_op("local.set", ptr_loc, f"{ename}_ptr")
            self.emit_op("local.get", ptr_loc, f"{ename}_ptr")
            self.emit_op("i64.const", vdef.tag)
            self.emit_op("i64.store", 3, 0)
            for fidx, arg_n in enumerate(items[3:]):
                self.emit_op("local.get", ptr_loc, f"{ename}_ptr")
                self.emit_expr(arg_n, env)
                self.emit_op("i64.store", 3, (1 + fidx) * 8)
            for fidx in range(len(items[3:]), edef.max_fields):
                self.emit_op("local.get", ptr_loc, f"{ename}_ptr")
                self.emit_op("i64.const", 0)
                self.emit_op("i64.store", 3, (1 + fidx) * 8)
            self.emit_op("local.get", ptr_loc, f"{ename}_ptr")
            return VAL_I32

        if op == "is_variant":
            sv_node = items[1]
            ename = self._node_kind(sv_node, env).split(":", 1)[1]
            vdef = self.tenv.enums[ename].get_variant(str(items[2].val))
            assert vdef is not None
            self.emit_expr(sv_node, env)
            self.emit_op("i64.load", 3, 0)
            self.emit_op("i64.const", vdef.tag)
            self.emit_op("i64.eq")
            return VAL_I32

        if op == "match":
            return self._emit_match(node, items, nk, env)

        if op in CAP_INTRINSIC_TO_IMPORT:
            imp_name = CAP_INTRINSIC_TO_IMPORT[op]
            self.emit_expr(items[1], env)  # linear capability erased
            for val_arg in items[2:]:
                self.emit_expr(val_arg, env)
            self.emit_op("call", self.fn_indices[imp_name], imp_name)
            return None

        if op == "io.done":
            self.emit_expr(items[1], env)
            return self.emit_expr(items[2], env)

        if op in ("fs.close", "net.close"):
            self.emit_expr(items[1], env)
            self.emit_op("i64.const", 0)
            return VAL_I64

        if op == "get":
            self.emit_expr(items[1], env)
            self.emit_expr(items[2], env)
            self.emit_op("i32.wrap_i64")
            self.emit_op("i32.const", 3)
            self.emit_op("i32.shl")
            self.emit_op("i32.add")
            self.emit_op("i64.load", 3, 0)
            return VAL_I64

        if op in ("byte_at", "read_u16_be", "read_u32_be", "read_u64_be", "bytes_eq4"):
            return self._emit_bytes_op(op, items, env)

        if op == "fold":
            return self._emit_fold(items, nk, env)

        if op == "call":
            callee = str(items[1].val)
            sig = self.tenv.sigs[callee]
            for arg_n, pk in zip(items[2:], sig.param_kinds):
                self.emit_expr(arg_n, env)
            self.emit_op("call", self.fn_indices[callee], callee)
            if sig.kind == "map_inplace" or sig.ret_kind in LINEAR_CAPS:
                return None
            return _wasm_valtype_for_kind(sig.ret_kind)

        if op == "~":
            self.emit_expr(items[1], env)
            self.emit_op("i64.const", -1)
            self.emit_op("i64.xor")
            return VAL_I64

        if op == "not":
            wty = self.emit_expr(items[1], env)
            self.emit_op("i64.eqz" if wty == VAL_I64 else "i32.eqz")
            return VAL_I32

        if op in ("and", "or"):
            for idx, arg_n in enumerate(items[1:]):
                wty = self.emit_expr(arg_n, env)
                if wty == VAL_I64:
                    self.emit_op("i64.const", 0)
                    self.emit_op("i64.ne")
                if idx > 0:
                    self.emit_op("i32.and" if op == "and" else "i32.or")
            return VAL_I32

        if op in ("==", "!=", "<", "<=", ">", ">="):
            cmp_signed = (self._raw_kind(items[1], env) == "i64") or (self._raw_kind(items[2], env) == "i64")
            self.emit_expr(items[1], env)
            self.emit_expr(items[2], env)
            if op == "==":
                self.emit_op("i64.eq")
            elif op == "!=":
                self.emit_op("i64.ne")
            else:
                suffix = "_s" if cmp_signed else "_u"
                cmp_map = {"<": "i64.lt", "<=": "i64.le", ">": "i64.gt", ">=": "i64.ge"}
                self.emit_op(f"{cmp_map[op]}{suffix}")
            return VAL_I32

        is_signed = nk == "i64"
        if op in ("min", "max"):
            a_loc = self.alloc_local(VAL_I64, "mm_a")
            b_loc = self.alloc_local(VAL_I64, "mm_b")
            self.emit_expr(items[1], env)
            self.emit_op("local.set", a_loc, "mm_a")
            self.emit_expr(items[2], env)
            self.emit_op("local.set", b_loc, "mm_b")
            self.emit_op("local.get", a_loc, "mm_a")
            self.emit_op("local.get", b_loc, "mm_b")
            self.emit_op("local.get", a_loc, "mm_a")
            self.emit_op("local.get", b_loc, "mm_b")
            if op == "min":
                self.emit_op("i64.lt_s" if is_signed else "i64.lt_u")
            else:
                self.emit_op("i64.gt_s" if is_signed else "i64.gt_u")
            self.emit_op("select")
            return VAL_I64

        self.emit_expr(items[1], env)
        self.emit_expr(items[2], env)
        bin_map = {
            "+": "i64.add",
            "-": "i64.sub",
            "*": "i64.mul",
            "/": "i64.div_s" if is_signed else "i64.div_u",
            "%": "i64.rem_s" if is_signed else "i64.rem_u",
            "&": "i64.and",
            "|": "i64.or",
            "^": "i64.xor",
            "<<": "i64.shl",
            ">>": "i64.shr_s" if is_signed else "i64.shr_u",
        }
        if op not in bin_map:
            raise ValueError(f"Unsupported AIL operator in WASM codegen: `{op}`")
        self.emit_op(bin_map[op])
        return VAL_I64

    def _emit_match(
        self,
        node: SNode,
        items: list[SNode],
        nk: str,
        env: dict[str, tuple[int, int | None, str]],
    ) -> int | None:
        scrut_n = items[1]
        ename = self._node_kind(scrut_n, env).split(":", 1)[1]
        edef = self.tenv.enums[ename]
        res_wty = _wasm_valtype_for_kind(nk)

        sptr_loc = self.alloc_local(VAL_I32, "match_scrut")
        self.emit_expr(scrut_n, env)
        self.emit_op("local.set", sptr_loc, "match_scrut")

        arms = items[2:]
        if len(arms) == 1:
            pat, arm_body = arms[0].val[0], arms[0].val[1]
            arm_env = self._bind_match_pat(pat, edef, sptr_loc, env)
            return self.emit_expr(arm_body, arm_env)

        tag_to_arm: dict[int, int] = {}
        wildcard_arm: int | None = None
        for aidx, arm in enumerate(arms):
            pat = arm.val[0]
            if isinstance(pat.val, str) and pat.val == "_":
                wildcard_arm = aidx
            else:
                vdef = edef.get_variant(str(pat.val[0].val))
                assert vdef is not None
                tag_to_arm[vdef.tag] = aidx
        default_arm = wildcard_arm if wildcard_arm is not None else 0
        targets = [tag_to_arm.get(t, default_arm) for t in range(len(edef.variants))]

        tag_loc = self.alloc_local(VAL_I32, "match_tag")
        self.emit_op("local.get", sptr_loc, "match_scrut")
        self.emit_op("i64.load", 3, 0)
        self.emit_op("i32.wrap_i64")
        self.emit_op("local.set", tag_loc, "match_tag")

        self.emit_op("block", _blocktype_for_valtype(res_wty))
        for _ in range(len(arms)):
            self.emit_op("block", BLOCK_VOID)
        self.emit_op("local.get", tag_loc, "match_tag")
        self.emit_op("br_table", targets, default_arm)

        for aidx, arm in enumerate(arms):
            self.emit_op("end")
            pat, arm_body = arm.val[0], arm.val[1]
            arm_env = self._bind_match_pat(pat, edef, sptr_loc, env)
            self.emit_expr(arm_body, arm_env)
            if aidx < len(arms) - 1:
                self.emit_op("br", len(arms) - 1 - aidx)
        self.emit_op("end")
        return res_wty

    def _bind_match_pat(
        self,
        pat: SNode,
        edef: EnumDef,
        sptr_loc: int,
        env: dict[str, tuple[int, int | None, str]],
    ) -> dict[str, tuple[int, int | None, str]]:
        arm_env = dict(env)
        if isinstance(pat.val, str) and pat.val == "_":
            return arm_env
        vdef = edef.get_variant(str(pat.val[0].val))
        assert vdef is not None
        for fidx, (bnode, fd) in enumerate(zip(pat.val[1:], vdef.fields)):
            bname = str(bnode.val)
            floc = self.alloc_local(VAL_I64, bname)
            self.emit_op("local.get", sptr_loc, "match_scrut")
            self.emit_op("i64.load", 3, (1 + fidx) * 8)
            self.emit_op("local.set", floc, bname)
            arm_env[bname] = (floc, VAL_I64, fd.kind)
        return arm_env

    def _emit_bytes_op(
        self,
        op: str,
        items: list[SNode],
        env: dict[str, tuple[int, int | None, str]],
    ) -> int:
        # Address = buf_ptr (i32) + i32.wrap_i64(idx)
        self.emit_expr(items[1], env)
        self.emit_expr(items[2], env)
        self.emit_op("i32.wrap_i64")
        self.emit_op("i32.add")

        if op == "byte_at":
            self.emit_op("i64.load8_u", 0, 0)
            return VAL_I64

        if op == "bytes_eq4":
            b0 = int(items[3].val) & 0xFF
            b1 = int(items[4].val) & 0xFF
            b2 = int(items[5].val) & 0xFF
            b3 = int(items[6].val) & 0xFF
            expected_le = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
            self.emit_op("i32.load", 0, 0)
            self.emit_op("i32.const", _to_signed32(expected_le))
            self.emit_op("i32.eq")
            self.emit_op("i64.extend_i32_u")
            return VAL_I64

        nbytes = {"read_u16_be": 2, "read_u32_be": 4, "read_u64_be": 8}[op]
        addr_loc = self.alloc_local(VAL_I32, f"{op}_addr")
        self.emit_op("local.set", addr_loc, f"{op}_addr")
        for byte_i in range(nbytes):
            self.emit_op("local.get", addr_loc, f"{op}_addr")
            self.emit_op("i64.load8_u", 0, byte_i)
            shift = (nbytes - 1 - byte_i) * 8
            if shift > 0:
                self.emit_op("i64.const", shift)
                self.emit_op("i64.shl")
            if byte_i > 0:
                self.emit_op("i64.or")
        return VAL_I64

    def _emit_fold(
        self,
        items: list[SNode],
        nk: str,
        env: dict[str, tuple[int, int | None, str]],
    ) -> int | None:
        ivar = str(items[1].val[0].val)
        n_node = items[1].val[1]
        avar = str(items[2].val[0].val)
        init_node = items[2].val[1]
        step_node = items[3]
        acc_wty = _wasm_valtype_for_kind(nk)
        assert acc_wty is not None

        n_loc = self.alloc_local(VAL_I64, f"fold_n_{ivar}")
        self.emit_expr(n_node, env)
        self.emit_op("local.set", n_loc, f"fold_n_{ivar}")

        i_loc = self.alloc_local(VAL_I64, ivar)
        self.emit_op("i64.const", 0)
        self.emit_op("local.set", i_loc, ivar)

        acc_loc = self.alloc_local(acc_wty, avar)
        self.emit_expr(init_node, env)
        self.emit_op("local.set", acc_loc, avar)

        body_env = dict(env)
        body_env[ivar] = (i_loc, VAL_I64, "u64")
        body_env[avar] = (acc_loc, acc_wty, nk)

        self.emit_op("block", BLOCK_VOID)
        self.emit_op("loop", BLOCK_VOID)
        self.emit_op("local.get", i_loc, ivar)
        self.emit_op("local.get", n_loc, f"fold_n_{ivar}")
        self.emit_op("i64.ge_u")
        self.emit_op("br_if", 1)
        self.emit_expr(step_node, body_env)
        self.emit_op("local.set", acc_loc, avar)
        self.emit_op("local.get", i_loc, ivar)
        self.emit_op("i64.const", 1)
        self.emit_op("i64.add")
        self.emit_op("local.set", i_loc, ivar)
        self.emit_op("br", 0)
        self.emit_op("end")
        self.emit_op("end")
        self.emit_op("local.get", acc_loc, avar)
        return acc_wty


def _build_allocator_functions(start_fn_idx: int) -> list[WasmFuncDef]:
    # $__ail_alloc(size: i32) -> i32
    alloc_fn = WasmFuncDef(
        name="__ail_alloc",
        params=[("size", VAL_I32)],
        results=(VAL_I32,),
        locals_decls=[
            ("aligned", VAL_I64),
            ("ptr", VAL_I32),
            ("needed_end", VAL_I64),
            ("mem_bytes", VAL_I64),
            ("needed_pages", VAL_I32),
        ],
        export_names=["__ail_alloc"],
    )
    # aligned = (u64(size) + 7) & ~7
    # ptr = global.get 0 ($heap_ptr)
    # needed_end = u64(ptr) + aligned
    # mem_bytes = u64(memory.size) << 16
    # if needed_end > mem_bytes: grow(((needed_end - mem_bytes) + 65535) >> 16)
    # global.set 0 (i32.wrap_i64(needed_end))
    # return ptr
    alloc_fn.instrs = [
        ("local.get", 0, "size"),
        ("i64.extend_i32_u",),
        ("i64.const", 7),
        ("i64.add",),
        ("i64.const", -8),
        ("i64.and",),
        ("local.set", 1, "aligned"),
        ("global.get", 0, "$heap_ptr"),
        ("local.tee", 2, "ptr"),
        ("i64.extend_i32_u",),
        ("local.get", 1, "aligned"),
        ("i64.add",),
        ("local.set", 3, "needed_end"),
        ("memory.size",),
        ("i64.extend_i32_u",),
        ("i64.const", 16),
        ("i64.shl",),
        ("local.set", 4, "mem_bytes"),
        ("local.get", 3, "needed_end"),
        ("local.get", 4, "mem_bytes"),
        ("i64.gt_u",),
        ("if", BLOCK_VOID),
        ("local.get", 3, "needed_end"),
        ("local.get", 4, "mem_bytes"),
        ("i64.sub",),
        ("i64.const", 65535),
        ("i64.add",),
        ("i64.const", 16),
        ("i64.shr_u",),
        ("i32.wrap_i64",),
        ("local.set", 5, "needed_pages"),
        ("local.get", 5, "needed_pages"),
        ("memory.grow",),
        ("i32.const", -1),
        ("i32.eq",),
        ("if", BLOCK_VOID),
        ("unreachable",),
        ("end",),
        ("end",),
        ("local.get", 3, "needed_end"),
        ("i32.wrap_i64",),
        ("global.set", 0, "$heap_ptr"),
        ("local.get", 2, "ptr"),
    ]

    mark_fn = WasmFuncDef(
        name="__ail_heap_mark",
        params=[],
        results=(VAL_I32,),
        instrs=[("global.get", 0, "$heap_ptr")],
        export_names=["__ail_heap_mark"],
    )

    reset_fn = WasmFuncDef(
        name="__ail_heap_reset",
        params=[("mark", VAL_I32)],
        results=(),
        instrs=[("local.get", 0, "mark"), ("global.set", 0, "$heap_ptr")],
        export_names=["__ail_heap_reset"],
    )

    return [alloc_fn, mark_fn, reset_fn]


def _encode_instrs(instrs: list[tuple[Any, ...]]) -> bytes:
    out = bytearray()
    for ins in instrs:
        op = ins[0]
        if op in SIMPLE_OPCODES:
            out.append(SIMPLE_OPCODES[op])
        elif op in ("block", "loop", "if"):
            opcode = {"block": 0x02, "loop": 0x03, "if": 0x04}[op]
            out.append(opcode)
            out.append(ins[1])
        elif op == "br":
            out.append(0x0C)
            out.extend(_uleb128(ins[1]))
        elif op == "br_if":
            out.append(0x0D)
            out.extend(_uleb128(ins[1]))
        elif op == "br_table":
            targets: list[int] = ins[1]
            default_t: int = ins[2]
            out.append(0x0E)
            out.extend(_uleb128(len(targets)))
            for t in targets:
                out.extend(_uleb128(t))
            out.extend(_uleb128(default_t))
        elif op == "call":
            out.append(0x10)
            out.extend(_uleb128(ins[1]))
        elif op == "local.get":
            out.append(0x20)
            out.extend(_uleb128(ins[1]))
        elif op == "local.set":
            out.append(0x21)
            out.extend(_uleb128(ins[1]))
        elif op == "local.tee":
            out.append(0x22)
            out.extend(_uleb128(ins[1]))
        elif op == "global.get":
            out.append(0x23)
            out.extend(_uleb128(ins[1]))
        elif op == "global.set":
            out.append(0x24)
            out.extend(_uleb128(ins[1]))
        elif op in MEM_LOAD_STORE_OPCODES:
            opcode, _ = MEM_LOAD_STORE_OPCODES[op]
            align_log2, offset = ins[1], ins[2]
            out.append(opcode)
            out.extend(_uleb128(align_log2))
            out.extend(_uleb128(offset))
        elif op == "memory.size":
            out.extend(b"\x3f\x00")
        elif op == "memory.grow":
            out.extend(b"\x40\x00")
        elif op == "i32.const":
            out.append(0x41)
            out.extend(_sleb128(ins[1]))
        elif op == "i64.const":
            out.append(0x42)
            out.extend(_sleb128(ins[1]))
        else:
            raise ValueError(f"Unknown WASM instruction `{op}`")
    return bytes(out)


def _encode_wasm_binary(
    imports: list[tuple[str, str, tuple[int, ...], tuple[int, ...]]],
    funcs: list[WasmFuncDef],
) -> bytes:
    # 1. Type section
    type_sigs: list[tuple[tuple[int, ...], tuple[int, ...]]] = []
    type_map: dict[tuple[tuple[int, ...], tuple[int, ...]], int] = {}

    def intern_type(params: tuple[int, ...], results: tuple[int, ...]) -> int:
        key = (params, results)
        if key not in type_map:
            type_map[key] = len(type_sigs)
            type_sigs.append(key)
        return type_map[key]

    import_type_idxs = [intern_type(p, r) for _, _, p, r in imports]
    func_type_idxs = [intern_type(tuple(ty for _, ty in fn.params), fn.results) for fn in funcs]

    type_buf = bytearray(_uleb128(len(type_sigs)))
    for params, results in type_sigs:
        type_buf.append(0x60)
        type_buf.extend(_uleb128(len(params)))
        type_buf.extend(params)
        type_buf.extend(_uleb128(len(results)))
        type_buf.extend(results)

    sections: list[bytes] = [WASM_MAGIC_VERSION, _encode_section(1, bytes(type_buf))]

    # 2. Import section (if any)
    if imports:
        imp_buf = bytearray(_uleb128(len(imports)))
        for (mod_name, field_name, _, _), tidx in zip(imports, import_type_idxs):
            imp_buf.extend(_encode_str(mod_name))
            imp_buf.extend(_encode_str(field_name))
            imp_buf.append(0x00)  # func import
            imp_buf.extend(_uleb128(tidx))
        sections.append(_encode_section(2, bytes(imp_buf)))

    # 3. Function section
    fn_sec_buf = bytearray(_uleb128(len(funcs)))
    for tidx in func_type_idxs:
        fn_sec_buf.extend(_uleb128(tidx))
    sections.append(_encode_section(3, bytes(fn_sec_buf)))

    # 5. Memory section (1 initial page = 64 KiB, unbounded grow)
    mem_sec_buf = b"\x01\x00\x01"
    sections.append(_encode_section(5, mem_sec_buf))

    # 6. Global section ($heap_ptr: mut i32 = 1024)
    glob_sec_buf = bytearray(b"\x01")
    glob_sec_buf.append(VAL_I32)
    glob_sec_buf.append(0x01)  # mutable
    glob_sec_buf.append(0x41)  # i32.const
    glob_sec_buf.extend(_sleb128(1024))
    glob_sec_buf.append(0x0B)  # end
    sections.append(_encode_section(6, bytes(glob_sec_buf)))

    # 7. Export section ("memory" + function exports)
    export_entries: list[tuple[str, int, int]] = [("memory", 0x02, 0)]
    base_fn_idx = len(imports)
    for idx, fn in enumerate(funcs):
        for exp_name in fn.export_names:
            export_entries.append((exp_name, 0x00, base_fn_idx + idx))
    exp_buf = bytearray(_uleb128(len(export_entries)))
    for ename, ekind, eidx in export_entries:
        exp_buf.extend(_encode_str(ename))
        exp_buf.append(ekind)
        exp_buf.extend(_uleb128(eidx))
    sections.append(_encode_section(7, bytes(exp_buf)))

    # 10. Code section
    code_buf = bytearray(_uleb128(len(funcs)))
    for fn in funcs:
        # Run-length compress local declarations
        runs: list[tuple[int, int]] = []
        for _, lty in fn.locals_decls:
            if runs and runs[-1][1] == lty:
                runs[-1] = (runs[-1][0] + 1, lty)
            else:
                runs.append((1, lty))
        body_buf = bytearray(_uleb128(len(runs)))
        for cnt, lty in runs:
            body_buf.extend(_uleb128(cnt))
            body_buf.append(lty)
        body_buf.extend(_encode_instrs(fn.instrs))
        body_buf.append(0x0B)  # end of function
        code_buf.extend(_uleb128(len(body_buf)))
        code_buf.extend(body_buf)
    sections.append(_encode_section(10, bytes(code_buf)))

    return b"".join(sections)


def _format_wat(
    imports: list[tuple[str, str, tuple[int, ...], tuple[int, ...]]],
    funcs: list[WasmFuncDef],
) -> str:
    lines: list[str] = ["(module"]
    for mod_name, field_name, params, results in imports:
        p_s = " ".join(f"(param {TYPE_NAMES[p]})" for p in params)
        r_s = " ".join(f"(result {TYPE_NAMES[r]})" for r in results)
        sig = " ".join(x for x in (p_s, r_s) if x)
        lines.append(f'  (import "{mod_name}" "{field_name}" (func ${field_name} {sig}))')

    lines.append('  (memory (export "memory") 1)')
    lines.append("  (global $heap_ptr (mut i32) (i32.const 1024))")

    for fn in funcs:
        ex_s = " ".join(f'(export "{en}")' for en in fn.export_names)
        p_s = " ".join(f"(param ${pname} {TYPE_NAMES[pty]})" for pname, pty in fn.params)
        r_s = " ".join(f"(result {TYPE_NAMES[rty]})" for rty in fn.results)
        header_parts = [f"(func ${fn.name}", ex_s, p_s, r_s]
        lines.append("  " + " ".join(p for p in header_parts if p))
        if fn.locals_decls:
            loc_s = " ".join(f"(local ${lname} {TYPE_NAMES[lty]})" for lname, lty in fn.locals_decls)
            lines.append(f"    {loc_s}")

        indent = 4
        for ins in fn.instrs:
            op = ins[0]
            if op == "else":
                indent = max(4, indent - 2)
                lines.append(" " * indent + "else")
                indent += 2
                continue
            if op == "end":
                indent = max(4, indent - 2)
                lines.append(" " * indent + "end")
                continue

            if op in ("block", "loop", "if"):
                bty = ins[1]
                r_part = "" if bty == BLOCK_VOID else f" (result {TYPE_NAMES[bty]})"
                lines.append(" " * indent + f"{op}{r_part}")
                indent += 2
            elif op == "br_table":
                targets_s = " ".join(str(t) for t in ins[1])
                lines.append(" " * indent + f"br_table {targets_s} {ins[2]}")
            elif op == "call":
                lines.append(" " * indent + f"call ${ins[2]}")
            elif op in ("local.get", "local.set", "local.tee"):
                lines.append(" " * indent + f"{op} {ins[1]}")
            elif op in ("global.get", "global.set"):
                lines.append(" " * indent + f"{op} {ins[1]}")
            elif op in MEM_LOAD_STORE_OPCODES:
                align_bytes = 1 << ins[1]
                offset = ins[2]
                memargs: list[str] = []
                if offset != 0:
                    memargs.append(f"offset={offset}")
                memargs.append(f"align={align_bytes}")
                lines.append(" " * indent + f"{op} {' '.join(memargs)}")
            elif len(ins) == 1:
                lines.append(" " * indent + op)
            else:
                args_s = " ".join(str(a) for a in ins[1:])
                lines.append(" " * indent + f"{op} {args_s}")
        lines.append("  )")

    lines.append(")")
    return "\n".join(lines) + "\n"


def _emit_mjs_wrapper(
    module_name: str,
    tenv: ModuleTypeEnv,
    exports: list[WasmExportInfo],
    used_imports: list[str],
) -> str:
    lines: list[str] = [
        f"// Auto-generated by ailang — Pure WebAssembly 1.0 ESM Wrapper for `{module_name}`",
        "",
        f'const _WASM_URL = new URL("./{module_name}.wasm", import.meta.url);',
        "",
        "async function _loadWasmBytes() {",
        '  if (typeof process !== "undefined" && process.versions && process.versions.node) {',
        '    const { readFile } = await import("node:fs/promises");',
        "    return readFile(_WASM_URL);",
        "  }",
        "  const res = await fetch(_WASM_URL);",
        "  if (!res.ok) {",
        "    throw new Error(`Failed to load WASM module ${_WASM_URL}: ${res.status} ${res.statusText}`);",
        "  }",
        "  return res.arrayBuffer();",
        "}",
        "",
        "const _u64 = (v) => BigInt.asUintN(64, BigInt(v));",
        "const _i64 = (v) => BigInt.asIntN(64, BigInt(v));",
        "",
    ]

    # Struct classes / callable constructors (matches both `Quote(...)` and `new Quote(...)`)
    for sdef in tenv.structs.values():
        ctor_params = ", ".join(f"{fd.name} = 0n" for fd in sdef.fields)
        lines.append(f"export function {sdef.name}({ctor_params}) {{")
        lines.append(f"  if (!(this instanceof {sdef.name})) {{")
        lines.append(f"    return new {sdef.name}({', '.join(fd.name for fd in sdef.fields)});")
        lines.append("  }")
        for fd in sdef.fields:
            conv = "_i64" if fd.kind == "i64" else "_u64"
            lines.append(f"  this.{fd.name} = {conv}({fd.name});")
        lines.append("}")
        lines.append("")

    # Tagged Enum classes (`EnumName.VariantName(...)`, `TAG_VariantName`, `.field(idx, signed)`)
    for edef in tenv.enums.values():
        lines.append(f"export class {edef.name} {{")
        lines.append('  constructor(tag, fields = [], variant = "") {')
        lines.append("    this.tag = Number(tag);")
        lines.append("    this.fields = fields;")
        lines.append("    this.variant = variant;")
        for p_idx in range(edef.max_fields):
            lines.append(f"    this._p{p_idx} = fields[{p_idx}] ?? 0n;")
        lines.append("  }")
        for vdef in edef.variants:
            lines.append(f"  static TAG_{vdef.name} = {vdef.tag};")
        for vdef in edef.variants:
            vparams = ", ".join(fd.name for fd in vdef.fields)
            conv_elems = ", ".join(
                f"{'_i64' if fd.kind == 'i64' else '_u64'}({fd.name})" for fd in vdef.fields
            )
            lines.append(f"  static {vdef.name}({vparams}) {{")
            lines.append(f'    const inst = new {edef.name}({vdef.tag}, [{conv_elems}], "{vdef.name}");')
            for idx, fd in enumerate(vdef.fields):
                if fd.name not in ("tag", "fields", "variant", "field"):
                    lines.append(f"    inst.{fd.name} = inst.fields[{idx}];")
            lines.append("    return inst;")
            lines.append("  }")
        lines.append("  field(idx, signed = false) {")
        lines.append("    const raw = _u64(this.fields[idx] ?? 0n);")
        lines.append("    return signed ? _i64(raw) : raw;")
        lines.append("  }")
        lines.append("}")
        lines.append("")

    # Marshaling helpers for structs and enums
    for sdef in tenv.structs.values():
        size = max(8, 8 * len(sdef.fields))
        lines.append(f"function _write_{sdef.name}(rawExports, memory, val) {{")
        lines.append(f"  const ptr = rawExports.__ail_alloc({size});")
        lines.append("  const dv = new DataView(memory.buffer);")
        for idx, fd in enumerate(sdef.fields):
            setter = "setBigInt64" if fd.kind == "i64" else "setBigUint64"
            conv = "_i64" if fd.kind == "i64" else "_u64"
            lines.append(f"  dv.{setter}(ptr + {idx * 8}, {conv}(val.{fd.name}), true);")
        lines.append("  return ptr;")
        lines.append("}")
        lines.append(f"function _read_{sdef.name}(memory, ptr) {{")
        lines.append("  const dv = new DataView(memory.buffer);")
        reads = []
        for idx, fd in enumerate(sdef.fields):
            getter = "getBigInt64" if fd.kind == "i64" else "getBigUint64"
            reads.append(f"dv.{getter}(ptr + {idx * 8}, true)")
        lines.append(f"  return new {sdef.name}({', '.join(reads)});")
        lines.append("}")
        lines.append("")

    for edef in tenv.enums.values():
        size = 8 * (1 + edef.max_fields)
        lines.append(f"function _write_{edef.name}(rawExports, memory, val) {{")
        lines.append(f"  const ptr = rawExports.__ail_alloc({size});")
        lines.append("  const dv = new DataView(memory.buffer);")
        lines.append("  dv.setBigUint64(ptr, _u64(val.tag), true);")
        lines.append("  const fields = val.fields ?? [];")
        for p_idx in range(edef.max_fields):
            lines.append(f"  dv.setBigUint64(ptr + {(1 + p_idx) * 8}, _u64(fields[{p_idx}] ?? 0n), true);")
        lines.append("  return ptr;")
        lines.append("}")
        lines.append(f"function _read_{edef.name}(memory, ptr) {{")
        lines.append("  const dv = new DataView(memory.buffer);")
        lines.append("  const tag = Number(dv.getBigUint64(ptr, true));")
        for vdef in edef.variants:
            vreads = []
            for fidx, fd in enumerate(vdef.fields):
                getter = "getBigInt64" if fd.kind == "i64" else "getBigUint64"
                vreads.append(f"dv.{getter}(ptr + {(1 + fidx) * 8}, true)")
            lines.append(f"  if (tag === {vdef.tag}) return {edef.name}.{vdef.name}({', '.join(vreads)});")
        lines.append(f"  return new {edef.name}(tag, []);")
        lines.append("}")
        lines.append("")

    # Instantiate factory
    lines.extend(
        [
            "function _createDefaultEnv(overrides = {}) {",
            "  const src = overrides.env ? overrides.env : overrides;",
            "  return {",
            "    io_print_u64: (v) => {",
            "      const val = _u64(v);",
            "      if (src.io_print_u64) return src.io_print_u64(val);",
            "      console.log(val.toString());",
            "    },",
            "    io_print_i64: (v) => {",
            "      const val = _i64(v);",
            "      if (src.io_print_i64) return src.io_print_i64(val);",
            "      console.log(val.toString());",
            "    },",
            "    fs_write_u64: (v) => {",
            "      const val = _u64(v);",
            "      if (src.fs_write_u64) return src.fs_write_u64(val);",
            "      console.log(`[fs] ${val.toString()}`);",
            "    },",
            "    fs_write_i64: (v) => {",
            "      const val = _i64(v);",
            "      if (src.fs_write_i64) return src.fs_write_i64(val);",
            "      console.log(`[fs] ${val.toString()}`);",
            "    },",
            "    net_loopback_u64: (port, payload) => {",
            "      const p = _u64(port);",
            "      const d = _u64(payload);",
            "      if (src.net_loopback_u64) return src.net_loopback_u64(p, d);",
            "      console.log(`[net 127.0.0.1:${p.toString()}] ${d.toString()}`);",
            "    },",
            "  };",
            "}",
            "",
            "export async function instantiate(hostEnv = {}, wasmBytes = null) {",
            "  const bytes = wasmBytes ?? (await _loadWasmBytes());",
            "  const envFns = _createDefaultEnv(hostEnv);",
            "  const imports = {};",
        ]
    )
    if used_imports:
        imp_props = ", ".join(f"{name}: envFns.{name}" for name in used_imports)
        lines.append(f"  imports.env = {{ {imp_props} }};")
    else:
        lines.append("  // No capability host imports required by this module")

    lines.extend(
        [
            "  const { instance } = await WebAssembly.instantiate(bytes, imports);",
            "  const rawExports = instance.exports;",
            "  const memory = rawExports.memory;",
            "",
        ]
    )

    wrapper_fn_names: list[str] = []
    for ex in exports:
        js_params = [f"_arg{i}" for i in range(len(ex.params))]
        primary_wasm_name = ex.wasm_export_names[0]
        fn_js_name = ex.ail_name
        wrapper_fn_names.extend(ex.wasm_export_names)
        lines.append(f"  function {fn_js_name}({', '.join(js_params)}) {{")
        lines.append("    const _mark = rawExports.__ail_heap_mark();")
        lines.append("    try {")

        param_name_to_js = {p.name: f"_arg{i}" for i, p in enumerate(ex.params)}
        call_arg_exprs: list[str] = []
        mut_writebacks: list[tuple[str, str, str, bool]] = []
        atomic_writebacks: list[tuple[str, str]] = []

        for idx, p in enumerate(ex.params):
            aname = f"_arg{idx}"
            if p.ail_kind == "u64":
                lines.append(f"      const _v{idx} = _u64({aname});")
                call_arg_exprs.append(f"_v{idx}")
            elif p.ail_kind == "i64":
                lines.append(f"      const _v{idx} = _i64({aname});")
                call_arg_exprs.append(f"_v{idx}")
            elif p.ail_kind.startswith("struct:") or p.ail_kind.startswith("enum:"):
                lines.append(f"      const _v{idx} = _write_{p.struct_or_enum_name}(rawExports, memory, {aname});")
                call_arg_exprs.append(f"_v{idx}")
            elif p.ail_kind == "bytes":
                len_expr = _js_len_expr(p.len_source, param_name_to_js, aname)
                lines.append(f"      const _u8_{idx} = {aname} instanceof Uint8Array ? {aname} : ({aname} instanceof ArrayBuffer ? new Uint8Array({aname}) : Uint8Array.from({aname}));")
                lines.append(f"      const _len_{idx} = {len_expr};")
                lines.append(f"      if (_u8_{idx}.length < _len_{idx}) throw new RangeError(`bytes buffer shorter than declared length (${{_len_{idx}}})`);")
                lines.append(f"      const _v{idx} = _len_{idx} === 0 ? 0 : rawExports.__ail_alloc(_len_{idx});")
                lines.append(f"      if (_len_{idx} > 0) new Uint8Array(memory.buffer, _v{idx}, _len_{idx}).set(_u8_{idx}.subarray(0, _len_{idx}));")
                call_arg_exprs.append(f"_v{idx}")
            elif p.ail_kind in ("slice", "mut_slice"):
                len_expr = _js_len_expr(p.len_source, param_name_to_js, aname)
                setter = "setBigInt64" if p.elem_is_i64 else "setBigUint64"
                conv = "_i64" if p.elem_is_i64 else "_u64"
                lines.append(f"      const _len_{idx} = {len_expr};")
                lines.append(f"      if (({aname}?.length ?? 0) < _len_{idx}) throw new RangeError(`slice shorter than declared length (${{_len_{idx}}})`);")
                lines.append(f"      const _v{idx} = _len_{idx} === 0 ? 0 : rawExports.__ail_alloc(_len_{idx} * 8);")
                lines.append(f"      if (_len_{idx} > 0) {{")
                lines.append("        const _dv = new DataView(memory.buffer);")
                lines.append(f"        for (let _i = 0; _i < _len_{idx}; _i++) _dv.{setter}(_v{idx} + _i * 8, {conv}({aname}[_i]), true);")
                lines.append("      }")
                call_arg_exprs.append(f"_v{idx}")
                if p.ail_kind == "mut_slice":
                    mut_writebacks.append((aname, f"_v{idx}", f"_len_{idx}", p.elem_is_i64))
            elif p.ail_kind == "atomic_u64":
                lines.append(f"      const _v{idx} = rawExports.__ail_alloc(8);")
                lines.append(f"      new DataView(memory.buffer).setBigUint64(_v{idx}, _u64({aname}[0]), true);")
                call_arg_exprs.append(f"_v{idx}")
                atomic_writebacks.append((aname, f"_v{idx}"))

        call_s = f"rawExports.{primary_wasm_name}({', '.join(call_arg_exprs)})"
        if ex.ret_wasm_ty is None:
            lines.append(f"      {call_s};")
        else:
            lines.append(f"      const _res = {call_s};")

        for target_arr, ptr_var, len_var, is_i64 in mut_writebacks:
            getter = "getBigInt64" if is_i64 else "getBigUint64"
            lines.append(f"      if ({len_var} > 0) {{")
            lines.append("        const _dvOut = new DataView(memory.buffer);")
            lines.append(f"        for (let _i = 0; _i < {len_var}; _i++) {target_arr}[_i] = _dvOut.{getter}({ptr_var} + _i * 8, true);")
            lines.append("      }")
        for target_cell, ptr_var in atomic_writebacks:
            lines.append(f"      {target_cell}[0] = new DataView(memory.buffer).getBigUint64({ptr_var}, true);")

        if ex.ret_kind == "u64":
            lines.append("      return _u64(_res);")
        elif ex.ret_kind == "i64":
            lines.append("      return _i64(_res);")
        elif ex.ret_kind.startswith("struct:") or ex.ret_kind.startswith("enum:"):
            rname = ex.ret_kind.split(":", 1)[1]
            lines.append(f"      return _read_{rname}(memory, _res);")

        lines.append("    } finally {")
        lines.append("      rawExports.__ail_heap_reset(_mark);")
        lines.append("    }")
        lines.append("  }")
        lines.append("")

    ret_fields: list[str] = ["instance", "rawExports", "memory"]
    for sdef in tenv.structs.values():
        ret_fields.append(sdef.name)
    for edef in tenv.enums.values():
        ret_fields.append(edef.name)
    for ex in exports:
        for ename in ex.wasm_export_names:
            if ename == ex.ail_name:
                ret_fields.append(ename)
            else:
                ret_fields.append(f"{ename}: {ex.ail_name}")

    lines.append(f"  return {{ {', '.join(ret_fields)} }};")
    lines.append("}")
    lines.append("")
    lines.append("const _default = await instantiate();")
    lines.append("export const { memory, rawExports, instance } = _default;")
    exported_fn_bindings: list[str] = []
    for ex in exports:
        for ename in ex.wasm_export_names:
            exported_fn_bindings.append(ename)
    if exported_fn_bindings:
        lines.append(f"export const {{ {', '.join(exported_fn_bindings)} }} = _default;")
    lines.append("export default _default;")
    lines.append("")
    return "\n".join(lines)


def _js_len_expr(len_source: str | int | None, param_name_to_js: dict[str, str], fallback_arg: str) -> str:
    if isinstance(len_source, int):
        return str(len_source)
    if isinstance(len_source, str) and len_source in param_name_to_js:
        return f"Number(_u64({param_name_to_js[len_source]}))"
    return f"Number({fallback_arg}?.length ?? 0)"


def _emit_dts_types(
    module_name: str,
    tenv: ModuleTypeEnv,
    exports: list[WasmExportInfo],
) -> str:
    lines: list[str] = [
        f"// Auto-generated by ailang — TypeScript Declarations for `{module_name}`",
        "",
        "export interface HostEnv {",
        "  io_print_u64?: (val: bigint) => void;",
        "  io_print_i64?: (val: bigint) => void;",
        "  fs_write_u64?: (val: bigint) => void;",
        "  fs_write_i64?: (val: bigint) => void;",
        "  net_loopback_u64?: (port: bigint, payload: bigint) => void;",
        "}",
        "",
    ]

    for sdef in tenv.structs.values():
        lines.append(f"export interface {sdef.name} {{")
        for fd in sdef.fields:
            lines.append(f"  {fd.name}: bigint;")
        lines.append("}")
        ctor_args = ", ".join(f"{fd.name}?: bigint | number" for fd in sdef.fields)
        lines.append(f"export const {sdef.name}: {{")
        lines.append(f"  new ({ctor_args}): {sdef.name};")
        lines.append(f"  ({ctor_args}): {sdef.name};")
        lines.append("};")
        lines.append("")

    for edef in tenv.enums.values():
        lines.append(f"export class {edef.name} {{")
        lines.append("  readonly tag: number;")
        lines.append("  readonly variant: string;")
        lines.append("  readonly fields: bigint[];")
        for vdef in edef.variants:
            lines.append(f"  static readonly TAG_{vdef.name}: {vdef.tag};")
        for vdef in edef.variants:
            vargs = ", ".join(f"{fd.name}: bigint | number" for fd in vdef.fields)
            lines.append(f"  static {vdef.name}({vargs}): {edef.name};")
        lines.append("  field(idx: number, signed?: boolean): bigint;")
        lines.append("}")
        lines.append("")

    _TS_RESERVED = {"break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else", "enum", "export", "extends", "false", "finally", "for", "function", "if", "import", "in", "instanceof", "new", "null", "return", "super", "switch", "this", "throw", "true", "try", "typeof", "var", "void", "while", "with", "as", "implements", "interface", "let", "package", "private", "protected", "public", "static", "yield"}

    def ts_pname(name: str) -> str:
        return f"_{name}" if name in _TS_RESERVED else name

    def ts_param(p: WasmParamInfo) -> str:
        if p.ail_kind in ("u64", "i64"):
            return "bigint | number"
        if p.ail_kind == "bytes":
            return "Uint8Array | ArrayBuffer | readonly number[]"
        if p.ail_kind == "slice":
            return "BigUint64Array | BigInt64Array | readonly (bigint | number)[]"
        if p.ail_kind == "mut_slice":
            return "BigUint64Array | BigInt64Array | (bigint | number)[]"
        if p.ail_kind == "atomic_u64":
            return "BigUint64Array | bigint[]"
        if p.struct_or_enum_name:
            return p.struct_or_enum_name
        return "bigint"

    def ts_ret(ret_kind: str) -> str:
        if ret_kind in ("void", *LINEAR_CAPS):
            return "void"
        if ret_kind.startswith(("struct:", "enum:")):
            return ret_kind.split(":", 1)[1]
        return "bigint"

    lines.append("export interface AilModuleInstance {")
    lines.append("  readonly instance: WebAssembly.Instance;")
    lines.append("  readonly rawExports: WebAssembly.Exports;")
    lines.append("  readonly memory: WebAssembly.Memory;")
    for sdef in tenv.structs.values():
        lines.append(f"  readonly {sdef.name}: typeof {sdef.name};")
    for edef in tenv.enums.values():
        lines.append(f"  readonly {edef.name}: typeof {edef.name};")
    for ex in exports:
        p_str = ", ".join(f"{ts_pname(p.name)}: {ts_param(p)}" for p in ex.params)
        r_str = ts_ret(ex.ret_kind)
        for ename in ex.wasm_export_names:
            lines.append(f"  {ename}({p_str}): {r_str};")
    lines.append("}")
    lines.append("")
    lines.append("export const memory: WebAssembly.Memory;")
    lines.append("export const rawExports: WebAssembly.Exports;")
    lines.append("export const instance: WebAssembly.Instance;")
    for ex in exports:
        p_str = ", ".join(f"{ts_pname(p.name)}: {ts_param(p)}" for p in ex.params)
        r_str = ts_ret(ex.ret_kind)
        for ename in ex.wasm_export_names:
            lines.append(f"export const {ename}: ({p_str}) => {r_str};")
    lines.append("")
    lines.append(
        "export function instantiate(hostEnv?: HostEnv | { env?: HostEnv }, wasmBytes?: BufferSource | null): Promise<AilModuleInstance>;"
    )
    lines.append("const _default: AilModuleInstance;")
    lines.append("export default _default;")
    lines.append("")
    return "\n".join(lines)


def _collect_proto_steps(forms: list[SNode]) -> dict[tuple[str, str], tuple[str, SNode]]:
    proto_steps: dict[tuple[str, str], tuple[str, SNode]] = {}
    for form in forms:
        if str(form.val[0].val) == "atomic_protocol":
            pname = str(form.val[1].val)
            f0 = str(form.val[2].val[0].val[0].val)
            for sn in form.val[4:]:
                sname = str(sn.val[1].val)
                next_f0 = sn.val[3].val[0]
                proto_steps[(pname, sname)] = (f0, next_f0)
    return proto_steps


def compile_to_wasm(
    forms: list[SNode],
    tenv: ModuleTypeEnv,
    out_dir: Path,
    module_name: str = "ail_mod",
) -> WasmArtifacts:
    """Compile verified AIL forms into WebAssembly 1.0 (`.wasm`), `.wat`, `.mjs`, and `.d.ts`."""
    out_dir.mkdir(parents=True, exist_ok=True)
    if not tenv.sigs and any(str(f.val[0].val) in ("fn", "map_inplace", "atomic_cas", "main") for f in forms):
        tenv = check_module_ownership_v2(forms)

    used_imports = _collect_used_host_imports(forms)
    imports: list[tuple[str, str, tuple[int, ...], tuple[int, ...]]] = [
        ("env", HOST_IMPORT_SPECS[name][0], HOST_IMPORT_SPECS[name][1], HOST_IMPORT_SPECS[name][2])
        for name in used_imports
    ]

    fn_indices: dict[str, int] = {name: i for i, name in enumerate(used_imports)}
    alloc_fn_idx = len(imports)
    next_idx = len(imports) + 3  # +3 for __ail_alloc, __ail_heap_mark, __ail_heap_reset

    runtime_forms: list[SNode] = []
    existing_names: set[str] = set()
    for form in forms:
        head = str(form.val[0].val)
        if head in ("fn", "map_inplace", "atomic_cas", "main"):
            name = "main" if head == "main" else str(form.val[1].val)
            existing_names.add(name)
            fn_indices[name] = next_idx
            next_idx += 1
            runtime_forms.append(form)

    proto_steps = _collect_proto_steps(forms)
    compiled_funcs: list[WasmFuncDef] = _build_allocator_functions(alloc_fn_idx)
    exports: list[WasmExportInfo] = []

    for form in runtime_forms:
        head = str(form.val[0].val)

        if head in ("fn", "main"):
            is_main = head == "main"
            name = "main" if is_main else str(form.val[1].val)
            params_n = form.val[1] if is_main else form.val[2]
            body_n = form.val[3] if is_main else form.val[4]
            sig = tenv.sigs[name]

            wasm_params: list[tuple[str, int]] = []
            export_params: list[WasmParamInfo] = []
            env: dict[str, tuple[int, int | None, str]] = {}

            for p, pk in zip(params_n.val, sig.param_kinds):
                pname = str(p.val[0].val)
                if pk in LINEAR_CAPS:
                    env[pname] = (-1, None, pk)
                    continue
                wty = _wasm_valtype_for_kind(pk)
                assert wty is not None
                p_idx = len(wasm_params)
                wasm_params.append((pname, wty))
                env[pname] = (p_idx, wty, pk)
                export_params.append(
                    WasmParamInfo(
                        name=pname,
                        ail_kind=pk,
                        wasm_ty=wty,
                        len_source=_len_source_from_spec(p.val[1]) if pk in ("slice", "mut_slice", "bytes") else None,
                        elem_is_i64=_slice_elem_is_i64(p.val[1]) if pk in ("slice", "mut_slice") else False,
                        struct_or_enum_name=pk.split(":", 1)[1] if pk.startswith(("struct:", "enum:")) else None,
                    )
                )

            ret_wty = _wasm_valtype_for_kind(sig.ret_kind)
            results: tuple[int, ...] = () if ret_wty is None else (ret_wty,)
            builder = _WasmFuncBuilder(tenv, fn_indices, alloc_fn_idx, [pn for pn, _ in wasm_params], [pt for _, pt in wasm_params])
            builder.emit_expr(body_n, env)

            if is_main:
                exp_names = ["ail_main", "main"] if "ail_main" not in existing_names else ["main"]
            else:
                exp_names = [name]

            compiled_funcs.append(
                WasmFuncDef(
                    name=name,
                    params=wasm_params,
                    results=results,
                    locals_decls=builder.locals_decls,
                    instrs=builder.instrs,
                    export_names=exp_names,
                )
            )
            exports.append(
                WasmExportInfo(
                    ail_name="ail_main" if is_main else name,
                    wasm_export_names=exp_names,
                    params=export_params,
                    ret_kind="void" if ret_wty is None else sig.ret_kind,
                    ret_wasm_ty=ret_wty,
                    is_main=is_main,
                )
            )

        elif head == "map_inplace":
            name = str(form.val[1].val)
            params_n, _, elem_vars, body_n = form.val[2], form.val[3], form.val[4], form.val[5]
            elem_var = str(elem_vars.val[0].val)
            sig = tenv.sigs[name]

            wasm_params = []
            export_params = []
            env = {}
            buf_loc = 0
            len_source: str | int | None = None
            elem_kind = "u64"

            for p, pk in zip(params_n.val, sig.param_kinds):
                pname = str(p.val[0].val)
                wty = _wasm_valtype_for_kind(pk)
                assert wty is not None
                p_idx = len(wasm_params)
                wasm_params.append((pname, wty))
                env[pname] = (p_idx, wty, pk)
                is_i64_el = _slice_elem_is_i64(p.val[1]) if pk in ("slice", "mut_slice") else False
                lsrc = _len_source_from_spec(p.val[1]) if pk in ("slice", "mut_slice", "bytes") else None
                if pk == "mut_slice":
                    buf_loc = p_idx
                    len_source = lsrc
                    elem_kind = "i64" if is_i64_el else "u64"
                export_params.append(
                    WasmParamInfo(
                        name=pname,
                        ail_kind=pk,
                        wasm_ty=wty,
                        len_source=lsrc,
                        elem_is_i64=is_i64_el,
                    )
                )

            builder = _WasmFuncBuilder(tenv, fn_indices, alloc_fn_idx, [pn for pn, _ in wasm_params], [pt for _, pt in wasm_params])
            idx_loc = builder.alloc_local(VAL_I64, "map_idx")
            elem_ptr_loc = builder.alloc_local(VAL_I32, "map_ptr")
            elem_loc = builder.alloc_local(VAL_I64, elem_var)
            env[elem_var] = (elem_loc, VAL_I64, elem_kind)

            builder.emit_op("i64.const", 0)
            builder.emit_op("local.set", idx_loc, "map_idx")
            builder.emit_op("block", BLOCK_VOID)
            builder.emit_op("loop", BLOCK_VOID)
            builder.emit_op("local.get", idx_loc, "map_idx")
            if isinstance(len_source, int):
                builder.emit_op("i64.const", _to_signed64(len_source))
            elif isinstance(len_source, str) and len_source in env:
                builder.emit_op("local.get", env[len_source][0], len_source)
            else:
                builder.emit_op("i64.const", 0)
            builder.emit_op("i64.ge_u")
            builder.emit_op("br_if", 1)

            builder.emit_op("local.get", buf_loc, "mut_buf")
            builder.emit_op("local.get", idx_loc, "map_idx")
            builder.emit_op("i32.wrap_i64")
            builder.emit_op("i32.const", 3)
            builder.emit_op("i32.shl")
            builder.emit_op("i32.add")
            builder.emit_op("local.tee", elem_ptr_loc, "map_ptr")
            builder.emit_op("i64.load", 3, 0)
            builder.emit_op("local.set", elem_loc, elem_var)

            builder.emit_op("local.get", elem_ptr_loc, "map_ptr")
            builder.emit_expr(body_n, env)
            builder.emit_op("i64.store", 3, 0)

            builder.emit_op("local.get", idx_loc, "map_idx")
            builder.emit_op("i64.const", 1)
            builder.emit_op("i64.add")
            builder.emit_op("local.set", idx_loc, "map_idx")
            builder.emit_op("br", 0)
            builder.emit_op("end")
            builder.emit_op("end")

            compiled_funcs.append(
                WasmFuncDef(
                    name=name,
                    params=wasm_params,
                    results=(),
                    locals_decls=builder.locals_decls,
                    instrs=builder.instrs,
                    export_names=[name],
                )
            )
            exports.append(
                WasmExportInfo(
                    ail_name=name,
                    wasm_export_names=[name],
                    params=export_params,
                    ret_kind="void",
                    ret_wasm_ty=None,
                )
            )

        elif head == "atomic_cas":
            name = str(form.val[1].val)
            pname = str(form.val[2].val)
            sname = str(form.val[3].val)
            params_n = form.val[4]
            ptr_name = str(params_n.val[0].val[0].val)
            req_name = str(params_n.val[1].val[0].val)
            f0_name, next_f0_node = proto_steps[(pname, sname)]

            wasm_params = [(ptr_name, VAL_I32), (req_name, VAL_I64)]
            export_params = [
                WasmParamInfo(name=ptr_name, ail_kind="atomic_u64", wasm_ty=VAL_I32),
                WasmParamInfo(name=req_name, ail_kind="u64", wasm_ty=VAL_I64),
            ]
            builder = _WasmFuncBuilder(tenv, fn_indices, alloc_fn_idx, [ptr_name, req_name], [VAL_I32, VAL_I64])
            obs_loc = builder.alloc_local(VAL_I64, "obs")
            cas_env = {
                f0_name: (obs_loc, VAL_I64, "u64"),
                req_name: (1, VAL_I64, "u64"),
            }

            builder.emit_op("local.get", 0, ptr_name)
            builder.emit_op("i64.load", 3, 0)
            builder.emit_op("local.set", obs_loc, "obs")
            builder.emit_op("local.get", obs_loc, "obs")
            builder.emit_op("local.get", 1, req_name)
            builder.emit_op("i64.ge_u")
            builder.emit_op("if", BLOCK_I64)
            builder.emit_op("local.get", 0, ptr_name)
            builder.emit_expr(next_f0_node, cas_env)
            builder.emit_op("i64.store", 3, 0)
            builder.emit_op("i64.const", 1)
            builder.emit_op("else")
            builder.emit_op("i64.const", 0)
            builder.emit_op("end")

            compiled_funcs.append(
                WasmFuncDef(
                    name=name,
                    params=wasm_params,
                    results=(VAL_I64,),
                    locals_decls=builder.locals_decls,
                    instrs=builder.instrs,
                    export_names=[name],
                )
            )
            exports.append(
                WasmExportInfo(
                    ail_name=name,
                    wasm_export_names=[name],
                    params=export_params,
                    ret_kind="u64",
                    ret_wasm_ty=VAL_I64,
                )
            )

    wasm_bytes = _encode_wasm_binary(imports, compiled_funcs)
    wat_text = _format_wat(imports, compiled_funcs)
    mjs_text = _emit_mjs_wrapper(module_name, tenv, exports, used_imports)
    dts_text = _emit_dts_types(module_name, tenv, exports)

    wasm_file = out_dir / f"{module_name}.wasm"
    wat_file = out_dir / f"{module_name}.wat"
    mjs_file = out_dir / f"{module_name}.mjs"
    dts_file = out_dir / f"{module_name}.d.ts"

    wasm_file.write_bytes(wasm_bytes)
    wat_file.write_text(wat_text)
    mjs_file.write_text(mjs_text)
    dts_file.write_text(dts_text)

    return WasmArtifacts(
        wasm_path=str(wasm_file),
        wat_path=str(wat_file),
        js_wrapper_path=str(mjs_file),
        ts_dts_path=str(dts_file),
        wasm_size_bytes=len(wasm_bytes),
    )
