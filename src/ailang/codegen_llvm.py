"""Layer 4 Native Silicon Backend v0.2: `nuw`/`nsw`/`noalias` LLVM IR, Dependent `struct` ABI, `cap.io`/`fs`/`net`."""

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import platform
import subprocess

from ailang import ail_agent_pb2 as pb
from ailang.diagnostics import I64_MAX, I64_MIN, U64_MAX
from ailang.ownership import LINEAR_CAPS, FnSig, ModuleTypeEnv, StructDef, check_module_ownership_v2
from ailang.parser import SNode


def detect_host_triple() -> str:
    if platform.system() == "Darwin":
        arch = "arm64" if platform.machine() == "arm64" else "x86_64"
        try:
            ver = subprocess.check_output(["sw_vers", "-productVersion"], text=True).strip()
            major = ver.split(".")[0]
            return f"{arch}-apple-macosx{major}.0.0"
        except Exception:
            return f"{arch}-apple-macosx"
    try:
        out = subprocess.check_output(["clang", "-dumpmachine"], text=True).strip()
        if out:
            return out
    except Exception:
        pass
    return "x86_64-unknown-linux-gnu"


@dataclass
class ExportedSymbol:
    name: str
    ret_c: str
    ret_py: str
    params_c: list[tuple[str, str]]
    params_py: list[str]
    param_names: list[str] = field(default_factory=list)
    param_struct_types: list[str | None] = field(default_factory=list)
    ret_struct_type: str | None = None


def _ir_type_for_kind(kind: str) -> str:
    if kind.startswith("struct:"):
        return f"%struct.{kind.split(':', 1)[1]}"
    if kind == "bool":
        return "i1"
    return "i64"


class FunctionIREmitter:
    def __init__(self, tenv: ModuleTypeEnv, var_kinds: dict[str, str]) -> None:
        self.tenv = tenv
        self.sigs = tenv.sigs
        self.var_kinds = dict(var_kinds)
        self.counter = 0
        self.cur_block = "entry"
        self.lines: list[str] = ["entry:"]
        self.uses_printf = False
        self.uses_fmt_i64 = False
        self.uses_fs = False
        self.uses_net = False

    def tmp(self) -> str:
        self.counter += 1
        return f"%t{self.counter}"

    def label(self, prefix: str) -> str:
        self.counter += 1
        return f"{prefix}_{self.counter}"

    def _raw_kind(self, node: SNode) -> str:
        if id(node) in self.tenv.expr_types:
            return self.tenv.expr_types[id(node)]
        if isinstance(node.val, int):
            return "i64" if node.val < 0 else "lit_pos"
        if isinstance(node.val, str) and node.val in self.var_kinds:
            return self.var_kinds[node.val]
        return "u64"

    def _node_kind(self, node: SNode) -> str:
        rk = self._raw_kind(node)
        return "u64" if rk == "lit_pos" else rk

    def emit_expr(self, node: SNode, env: dict[str, str]) -> str:
        if isinstance(node.val, int):
            return str(node.val)
        if isinstance(node.val, str):
            if node.val == "MAX":
                return str(U64_MAX)
            if node.val == "MIN_I64":
                return str(I64_MIN)
            if node.val == "MAX_I64":
                return str(I64_MAX)
            return env.get(node.val, "0")

        items = node.val
        op = str(items[0].val)
        nk = self._node_kind(node)

        if op == "let":
            nenv = dict(env)
            for b in items[1].val:
                bname = str(b.val[0].val)
                self.var_kinds[bname] = self._node_kind(b.val[1])
                nenv[bname] = self.emit_expr(b.val[1], nenv)
            return self.emit_expr(items[2], nenv)

        if op == "if":
            c = self.emit_expr(items[1], env)
            then_lbl = self.label("then")
            else_lbl = self.label("else")
            merge_lbl = self.label("merge")
            self.lines.append(f"  br i1 {c}, label %{then_lbl}, label %{else_lbl}")

            self.lines.append(f"{then_lbl}:")
            self.cur_block = then_lbl
            tv = self.emit_expr(items[2], env)
            then_end = self.cur_block
            self.lines.append(f"  br label %{merge_lbl}")

            self.lines.append(f"{else_lbl}:")
            self.cur_block = else_lbl
            fv = self.emit_expr(items[3], env)
            else_end = self.cur_block
            self.lines.append(f"  br label %{merge_lbl}")

            self.lines.append(f"{merge_lbl}:")
            self.cur_block = merge_lbl
            if nk in LINEAR_CAPS:
                return "0"
            phi_ty = _ir_type_for_kind(nk)
            r = self.tmp()
            self.lines.append(f"  {r} = phi {phi_ty} [ {tv}, %{then_end} ], [ {fv}, %{else_end} ]")
            return r

        if op in ("to_i64", "to_u64"):
            return self.emit_expr(items[1], env)

        if op == "make":
            sname = str(items[1].val)
            ir_sty = f"%struct.{sname}"
            cur_agg = "poison"
            for idx, arg_n in enumerate(items[2:]):
                fval = self.emit_expr(arg_n, env)
                nxt = self.tmp()
                self.lines.append(f"  {nxt} = insertvalue {ir_sty} {cur_agg}, i64 {fval}, {idx}")
                cur_agg = nxt
            return cur_agg

        if op == "field":
            sv_node = items[1]
            sk = self._node_kind(sv_node)
            sname = sk.split(":", 1)[1]
            fname = str(items[2].val)
            found = self.tenv.structs[sname].get_field(fname)
            assert found is not None
            fidx = found[0]
            sreg = self.emit_expr(sv_node, env)
            r = self.tmp()
            self.lines.append(f"  {r} = extractvalue %struct.{sname} {sreg}, {fidx}")
            return r

        if op == "io.print_u64":
            self.uses_printf = True
            val = self.emit_expr(items[2], env)
            self.lines.append(f"  call i32 (ptr, ...) @printf(ptr nonnull @.ail_fmt_u64, i64 {val})")
            return "0"

        if op == "io.print_i64":
            self.uses_printf = True
            self.uses_fmt_i64 = True
            val = self.emit_expr(items[2], env)
            self.lines.append(f"  call i32 (ptr, ...) @printf(ptr nonnull @.ail_fmt_i64, i64 {val})")
            return "0"

        if op == "io.done":
            return self.emit_expr(items[2], env)

        if op == "fs.write_u64":
            self.uses_fs = True
            val = self.emit_expr(items[2], env)
            self.lines.append(f"  call void @__ail_fs_write(ptr nonnull @.ail_fmt_u64, i64 {val})")
            return "0"

        if op == "fs.write_i64":
            self.uses_fs = True
            self.uses_fmt_i64 = True
            val = self.emit_expr(items[2], env)
            self.lines.append(f"  call void @__ail_fs_write(ptr nonnull @.ail_fmt_i64, i64 {val})")
            return "0"

        if op in ("fs.close", "net.close"):
            return "0"

        if op == "net.loopback_send_u64":
            self.uses_net = True
            port_v = self.emit_expr(items[2], env)
            payload_v = self.emit_expr(items[3], env)
            self.lines.append(f"  call void @__ail_net_loopback_u64(i64 {port_v}, i64 {payload_v})")
            return "0"

        if op == "get":
            buf_name = str(items[1].val)
            idx = self.emit_expr(items[2], env)
            ptr = self.tmp()
            val = self.tmp()
            self.lines.append(f"  {ptr} = getelementptr inbounds nuw i64, ptr {env[buf_name]}, i64 {idx}")
            self.lines.append(f"  {val} = load i64, ptr {ptr}, align 8")
            return val

        if op == "fold":
            ivar = str(items[1].val[0].val)
            n_val = self.emit_expr(items[1].val[1], env)
            avar = str(items[2].val[0].val)
            init_val = self.emit_expr(items[2].val[1], env)
            acc_ty = _ir_type_for_kind(nk)

            pre_block = self.cur_block
            cond_lbl = self.label("fold_cond")
            body_lbl = self.label("fold_body")
            exit_lbl = self.label("fold_exit")

            self.lines.append(f"  br label %{cond_lbl}")
            self.lines.append(f"{cond_lbl}:")
            self.cur_block = cond_lbl
            i_phi = self.tmp()
            acc_phi = self.tmp()
            i_next = self.tmp()
            phi_idx = len(self.lines)
            self.lines.append("")
            self.lines.append("")
            cmp_r = self.tmp()
            self.lines.append(f"  {cmp_r} = icmp ult i64 {i_phi}, {n_val}")
            self.lines.append(f"  br i1 {cmp_r}, label %{body_lbl}, label %{exit_lbl}")

            self.lines.append(f"{body_lbl}:")
            self.cur_block = body_lbl
            self.var_kinds[ivar] = "u64"
            self.var_kinds[avar] = nk
            step_val = self.emit_expr(items[3], dict(env, **{ivar: i_phi, avar: acc_phi}))
            body_end = self.cur_block
            self.lines.append(f"  {i_next} = add nuw i64 {i_phi}, 1")
            self.lines.append(f"  br label %{cond_lbl}")

            self.lines[phi_idx] = f"  {i_phi} = phi i64 [ 0, %{pre_block} ], [ {i_next}, %{body_end} ]"
            self.lines[phi_idx + 1] = f"  {acc_phi} = phi {acc_ty} [ {init_val}, %{pre_block} ], [ {step_val}, %{body_end} ]"

            self.lines.append(f"{exit_lbl}:")
            self.cur_block = exit_lbl
            return acc_phi

        if op == "call":
            callee = str(items[1].val)
            sig = self.sigs[callee]
            uses_ssa_helper = sig.ret_kind.startswith("struct:") or any(pk.startswith("struct:") for pk in sig.param_kinds)
            ir_callee = f"__ail_ssa_{callee}" if uses_ssa_helper else callee
            cc = "fastcc " if uses_ssa_helper else ""

            ir_args: list[str] = []
            for arg_node, pk in zip(items[2:], sig.param_kinds):
                if pk in LINEAR_CAPS:
                    continue  # Zero-cost linear capability erasure!
                if pk in ("slice", "mut_slice", "atomic_u64"):
                    ir_args.append(f"ptr {env[str(arg_node.val)]}")
                elif pk.startswith("struct:"):
                    ir_args.append(f"{_ir_type_for_kind(pk)} {self.emit_expr(arg_node, env)}")
                else:
                    ir_args.append(f"i64 {self.emit_expr(arg_node, env)}")
            arg_s = ", ".join(ir_args)
            if sig.kind == "map_inplace" or sig.ret_kind in LINEAR_CAPS:
                self.lines.append(f"  call {cc}void @{ir_callee}({arg_s})")
                return "0"
            ret_ir_ty = _ir_type_for_kind(sig.ret_kind)
            r = self.tmp()
            self.lines.append(f"  {r} = call {cc}{ret_ir_ty} @{ir_callee}({arg_s})")
            return r

        if op == "~":
            a = self.emit_expr(items[1], env)
            r = self.tmp()
            self.lines.append(f"  {r} = xor i64 {a}, -1")
            return r

        args = [self.emit_expr(a, env) for a in items[1:]]
        r = self.tmp()
        if op in ("==", "!=", "<", "<=", ">", ">="):
            cmp_signed = (self._raw_kind(items[1]) == "i64") or (self._raw_kind(items[2]) == "i64")
            if cmp_signed:
                pred = {"==": "eq", "!=": "ne", "<": "slt", "<=": "sle", ">": "sgt", ">=": "sge"}[op]
            else:
                pred = {"==": "eq", "!=": "ne", "<": "ult", "<=": "ule", ">": "ugt", ">=": "uge"}[op]
            self.lines.append(f"  {r} = icmp {pred} i64 {args[0]}, {args[1]}")
            return r

        if op in ("and", "or"):
            lop = "and" if op == "and" else "or"
            self.lines.append(f"  {r} = {lop} i1 {args[0]}, {args[1]}")
            return r

        if op == "not":
            self.lines.append(f"  {r} = xor i1 {args[0]}, true")
            return r

        is_signed = nk == "i64"
        if is_signed:
            ir_map = {
                "+": f"add nsw i64 {args[0]}, {args[1]}",
                "-": f"sub nsw i64 {args[0]}, {args[1]}",
                "*": f"mul nsw i64 {args[0]}, {args[1]}",
                "/": f"sdiv i64 {args[0]}, {args[1]}",
                "%": f"srem i64 {args[0]}, {args[1]}",
                "&": f"and i64 {args[0]}, {args[1]}",
                "|": f"or i64 {args[0]}, {args[1]}",
                "^": f"xor i64 {args[0]}, {args[1]}",
                ">>": f"ashr i64 {args[0]}, {args[1]}",
                "<<": f"shl i64 {args[0]}, {args[1]}",
                "min": f"call i64 @llvm.smin.i64(i64 {args[0]}, i64 {args[1]})",
                "max": f"call i64 @llvm.smax.i64(i64 {args[0]}, i64 {args[1]})",
            }
        else:
            ir_map = {
                "+": f"add nuw i64 {args[0]}, {args[1]}",
                "-": f"sub nuw i64 {args[0]}, {args[1]}",
                "*": f"mul nuw i64 {args[0]}, {args[1]}",
                "/": f"udiv i64 {args[0]}, {args[1]}",
                "%": f"urem i64 {args[0]}, {args[1]}",
                "&": f"and i64 {args[0]}, {args[1]}",
                "|": f"or i64 {args[0]}, {args[1]}",
                "^": f"xor i64 {args[0]}, {args[1]}",
                ">>": f"lshr i64 {args[0]}, {args[1]}",
                "<<": f"shl i64 {args[0]}, {args[1]}",
                "min": f"call i64 @llvm.umin.i64(i64 {args[0]}, i64 {args[1]})",
                "max": f"call i64 @llvm.umax.i64(i64 {args[0]}, i64 {args[1]})",
            }
        self.lines.append(f"  {r} = {ir_map[op]}")
        return r


def _emit_fs_runtime_ir() -> list[str]:
    return [
        '@.ail_fs_env = private unnamed_addr constant [11 x i8] c"AIL_FS_OUT\\00", align 1',
        '@.ail_fs_def = private unnamed_addr constant [15 x i8] c"ail_fs_out.log\\00", align 1',
        '@.ail_fs_mode = private unnamed_addr constant [2 x i8] c"a\\00", align 1',
        "declare ptr @getenv(ptr nocapture noundef readonly) local_unnamed_addr nounwind",
        "declare noalias ptr @fopen(ptr nocapture noundef readonly, ptr nocapture noundef readonly) local_unnamed_addr nounwind",
        "declare noundef i32 @fprintf(ptr nocapture noundef, ptr nocapture noundef readonly, ...) local_unnamed_addr nounwind",
        "declare noundef i32 @fclose(ptr nocapture noundef) local_unnamed_addr nounwind",
        "define internal void @__ail_fs_write(ptr nocapture noundef readonly %fmt, i64 noundef %val) unnamed_addr nounwind {",
        "entry:",
        "  %env_p = call ptr @getenv(ptr nonnull @.ail_fs_env)",
        "  %has_env = icmp ne ptr %env_p, null",
        "  %path = select i1 %has_env, ptr %env_p, ptr @.ail_fs_def",
        "  %fp = call ptr @fopen(ptr nonnull %path, ptr nonnull @.ail_fs_mode)",
        "  %ok = icmp ne ptr %fp, null",
        "  br i1 %ok, label %do_write, label %done",
        "do_write:",
        "  call i32 (ptr, ptr, ...) @fprintf(ptr nonnull %fp, ptr nonnull %fmt, i64 %val)",
        "  call i32 @fclose(ptr nonnull %fp)",
        "  br label %done",
        "done:",
        "  ret void",
        "}\n",
    ]


def _emit_net_loopback_runtime_ir(is_darwin: bool) -> list[str]:
    # Hardcoded 127.0.0.1 (`0x0100007f` = 16777343 in little-endian IPv4 network order)
    lines = [
        "declare i16 @llvm.bswap.i16(i16)",
        "declare i32 @socket(i32 noundef, i32 noundef, i32 noundef) local_unnamed_addr nounwind",
        "declare i64 @sendto(i32 noundef, ptr nocapture noundef readonly, i64 noundef, i32 noundef, ptr nocapture noundef readonly, i32 noundef) local_unnamed_addr nounwind",
        "declare i32 @close(i32 noundef) local_unnamed_addr nounwind",
        "define internal void @__ail_net_loopback_u64(i64 noundef %port, i64 noundef %payload) unnamed_addr nounwind {",
        "entry:",
        "  %fd = call i32 @socket(i32 2, i32 2, i32 0)",
        "  %ok = icmp sge i32 %fd, 0",
        "  br i1 %ok, label %do_send, label %done",
        "do_send:",
        "  %buf = alloca i64, align 8",
        "  store i64 %payload, ptr %buf, align 8",
        "  %p16 = trunc i64 %port to i16",
        "  %pnet = call i16 @llvm.bswap.i16(i16 %p16)",
    ]
    if is_darwin:
        lines.extend(
            [
                "  %addr = alloca { i8, i8, i16, i32, i64 }, align 4",
                "  %f0 = getelementptr inbounds { i8, i8, i16, i32, i64 }, ptr %addr, i64 0, i32 0",
                "  store i8 16, ptr %f0, align 4",
                "  %f1 = getelementptr inbounds { i8, i8, i16, i32, i64 }, ptr %addr, i64 0, i32 1",
                "  store i8 2, ptr %f1, align 1",
                "  %f2 = getelementptr inbounds { i8, i8, i16, i32, i64 }, ptr %addr, i64 0, i32 2",
                "  store i16 %pnet, ptr %f2, align 2",
                "  %f3 = getelementptr inbounds { i8, i8, i16, i32, i64 }, ptr %addr, i64 0, i32 3",
                "  store i32 16777343, ptr %f3, align 4",
                "  %f4 = getelementptr inbounds { i8, i8, i16, i32, i64 }, ptr %addr, i64 0, i32 4",
                "  store i64 0, ptr %f4, align 4",
            ]
        )
    else:
        lines.extend(
            [
                "  %addr = alloca { i16, i16, i32, i64 }, align 4",
                "  %f0 = getelementptr inbounds { i16, i16, i32, i64 }, ptr %addr, i64 0, i32 0",
                "  store i16 2, ptr %f0, align 4",
                "  %f1 = getelementptr inbounds { i16, i16, i32, i64 }, ptr %addr, i64 0, i32 1",
                "  store i16 %pnet, ptr %f1, align 2",
                "  %f2 = getelementptr inbounds { i16, i16, i32, i64 }, ptr %addr, i64 0, i32 2",
                "  store i32 16777343, ptr %f2, align 4",
                "  %f3 = getelementptr inbounds { i16, i16, i32, i64 }, ptr %addr, i64 0, i32 3",
                "  store i64 0, ptr %f3, align 4",
            ]
        )
    lines.extend(
        [
            "  call i64 @sendto(i32 %fd, ptr nonnull %buf, i64 8, i32 0, ptr nonnull %addr, i32 16)",
            "  call i32 @close(i32 %fd)",
            "  br label %done",
            "done:",
            "  ret void",
            "}\n",
        ]
    )
    return lines


def _slice_elem_is_i64(pspec: SNode) -> bool:
    elem_raw = pspec.val[2].raw()
    return elem_raw == "i64" or (isinstance(elem_raw, list) and bool(elem_raw) and elem_raw[0] == "i64_range")


def emit_llvm_module(
    forms: list[SNode],
    tenv: ModuleTypeEnv,
    target_triple: str | None = None,
) -> tuple[str, list[ExportedSymbol], bool]:
    triple = target_triple or detect_host_triple()
    is_darwin = "apple" in triple
    sigs = tenv.sigs

    header = [
        "; Generated by ailang v0.2 — Z3 + Bitwuzla Verified LLVM IR (`nuw`/`nsw`, `noalias`, zero-cost `cap.*`)",
        f'target triple = "{triple}"',
        "declare i64 @llvm.umin.i64(i64, i64)",
        "declare i64 @llvm.umax.i64(i64, i64)",
        "declare i64 @llvm.smin.i64(i64, i64)",
        "declare i64 @llvm.smax.i64(i64, i64)",
    ]

    for sdef in tenv.structs.values():
        fields_ir = ", ".join("i64" for _ in sdef.fields)
        header.append(f"%struct.{sdef.name} = type {{ {fields_ir} }}")

    body_blocks: list[str] = []
    exports: list[ExportedSymbol] = []
    any_printf = False
    any_fmt_i64 = False
    any_fs = False
    any_net = False
    has_main = False

    proto_steps: dict[tuple[str, str], tuple[str, SNode]] = {}
    for form in forms:
        if str(form.val[0].val) == "atomic_protocol":
            pname = str(form.val[1].val)
            f0 = str(form.val[2].val[0].val[0].val)
            for sn in form.val[4:]:
                sname = str(sn.val[1].val)
                next_f0 = sn.val[3].val[0]
                proto_steps[(pname, sname)] = (f0, next_f0)

    for form in forms:
        head = str(form.val[0].val)
        if head in ("spec", "struct", "atomic_protocol"):
            continue

        if head == "fn":
            name = str(form.val[1].val)
            params_n, _, body_n = form.val[2], form.val[3], form.val[4]
            sig = sigs[name]
            var_kinds: dict[str, str] = {}
            ssa_env: dict[str, str] = {}
            ssa_ir_params: list[str] = []
            c_ir_params: list[str] = []
            c_params: list[tuple[str, str]] = []
            py_params: list[str] = []
            param_names: list[str] = []
            param_struct_types: list[str | None] = []
            pure_mem = True
            has_struct_boundary = sig.ret_kind.startswith("struct:") or any(pk.startswith("struct:") for pk in sig.param_kinds)

            for p, pk in zip(params_n.val, sig.param_kinds):
                pname = str(p.val[0].val)
                var_kinds[pname] = pk
                if pk in LINEAR_CAPS:
                    pure_mem = False
                    continue
                ssa_env[pname] = f"%{pname}"
                param_names.append(pname)
                if pk == "slice":
                    pure_mem = False
                    is_i64_el = _slice_elem_is_i64(p.val[1])
                    ssa_ir_params.append(f"ptr noalias nocapture readonly noundef %{pname}")
                    c_ir_params.append(f"ptr noalias nocapture readonly noundef %{pname}")
                    c_params.append(("const int64_t*" if is_i64_el else "const uint64_t*", pname))
                    py_params.append("ctypes.POINTER(ctypes.c_int64)" if is_i64_el else "ctypes.POINTER(ctypes.c_uint64)")
                    param_struct_types.append(None)
                elif pk == "mut_slice":
                    pure_mem = False
                    is_i64_el = _slice_elem_is_i64(p.val[1])
                    ssa_ir_params.append(f"ptr noalias nocapture noundef %{pname}")
                    c_ir_params.append(f"ptr noalias nocapture noundef %{pname}")
                    c_params.append(("int64_t*" if is_i64_el else "uint64_t*", pname))
                    py_params.append("ctypes.POINTER(ctypes.c_int64)" if is_i64_el else "ctypes.POINTER(ctypes.c_uint64)")
                    param_struct_types.append(None)
                elif pk == "atomic_u64":
                    pure_mem = False
                    ssa_ir_params.append(f"ptr nocapture noundef %{pname}")
                    c_ir_params.append(f"ptr nocapture noundef %{pname}")
                    c_params.append(("uint64_t*", pname))
                    py_params.append("ctypes.POINTER(ctypes.c_uint64)")
                    param_struct_types.append(None)
                elif pk.startswith("struct:"):
                    sname = pk.split(":", 1)[1]
                    ssa_ir_params.append(f"%struct.{sname} noundef %{pname}")
                    c_ir_params.append(f"ptr nocapture readonly noundef %{pname}_ptr")
                    c_params.append((f"const {sname}*", pname))
                    py_params.append(f"ctypes.POINTER({sname})")
                    param_struct_types.append(sname)
                elif pk == "i64":
                    ssa_ir_params.append(f"i64 noundef %{pname}")
                    c_ir_params.append(f"i64 noundef %{pname}")
                    c_params.append(("int64_t", pname))
                    py_params.append("ctypes.c_int64")
                    param_struct_types.append(None)
                else:
                    ssa_ir_params.append(f"i64 noundef %{pname}")
                    c_ir_params.append(f"i64 noundef %{pname}")
                    c_params.append(("uint64_t", pname))
                    py_params.append("ctypes.c_uint64")
                    param_struct_types.append(None)

            em = FunctionIREmitter(tenv, var_kinds)
            ret_reg = em.emit_expr(body_n, ssa_env)
            if em.uses_printf:
                any_printf = True
                pure_mem = False
            if em.uses_fmt_i64:
                any_fmt_i64 = True
            if em.uses_fs:
                any_fs = True
                pure_mem = False
            if em.uses_net:
                any_net = True
                pure_mem = False

            mem_attr = " memory(none)" if pure_mem else ""

            if not has_struct_boundary:
                if sig.ret_kind in LINEAR_CAPS:
                    body_blocks.append(f"define void @{name}({', '.join(ssa_ir_params)}) local_unnamed_addr nounwind{mem_attr} {{")
                    body_blocks.extend(em.lines)
                    body_blocks.append("  ret void\n}\n")
                    exports.append(ExportedSymbol(name, "void", "None", c_params, py_params, param_names, param_struct_types))
                else:
                    ret_c = "int64_t" if sig.ret_kind == "i64" else "uint64_t"
                    ret_py = "ctypes.c_int64" if sig.ret_kind == "i64" else "ctypes.c_uint64"
                    body_blocks.append(f"define i64 @{name}({', '.join(ssa_ir_params)}) local_unnamed_addr nounwind{mem_attr} {{")
                    body_blocks.extend(em.lines)
                    body_blocks.append(f"  ret i64 {ret_reg}\n}}\n")
                    exports.append(ExportedSymbol(name, ret_c, ret_py, c_params, py_params, param_names, param_struct_types))
            else:
                # 1. Pure SSA internal helper (`fastcc`, zero memory indirection for intra-AIL calls!)
                ssa_ret_ir = "void" if sig.ret_kind in LINEAR_CAPS else _ir_type_for_kind(sig.ret_kind)
                body_blocks.append(
                    f"define internal fastcc {ssa_ret_ir} @__ail_ssa_{name}({', '.join(ssa_ir_params)}) unnamed_addr alwaysinline nounwind{mem_attr} {{"
                )
                body_blocks.extend(em.lines)
                if ssa_ret_ir == "void":
                    body_blocks.append("  ret void\n}\n")
                else:
                    body_blocks.append(f"  ret {ssa_ret_ir} {ret_reg}\n}}\n")

                # 2. Portable C-ABI wrapper (pointer-based struct ABI safe across AAPCS64 & SysV x86_64)
                wrap_lines: list[str] = ["entry:"]
                call_args: list[str] = []
                for p, pk in zip(params_n.val, sig.param_kinds):
                    if pk in LINEAR_CAPS:
                        continue
                    pname = str(p.val[0].val)
                    if pk.startswith("struct:"):
                        sname = pk.split(":", 1)[1]
                        wrap_lines.append(f"  %{pname}_val = load %struct.{sname}, ptr %{pname}_ptr, align 8")
                        call_args.append(f"%struct.{sname} %{pname}_val")
                    elif pk in ("slice", "mut_slice", "atomic_u64"):
                        call_args.append(f"ptr %{pname}")
                    else:
                        call_args.append(f"i64 %{pname}")

                if sig.ret_kind.startswith("struct:"):
                    ret_sname = sig.ret_kind.split(":", 1)[1]
                    c_ir_params_full = [*c_ir_params, "ptr noalias nocapture writeonly noundef %_ail_out"]
                    c_params_full = [*c_params, (f"{ret_sname}*", "_out")]
                    py_params_full = [*py_params, f"ctypes.POINTER({ret_sname})"]
                    body_blocks.append(f"define void @{name}({', '.join(c_ir_params_full)}) local_unnamed_addr nounwind {{")
                    body_blocks.extend(wrap_lines)
                    body_blocks.append(f"  %_res = call fastcc %struct.{ret_sname} @__ail_ssa_{name}({', '.join(call_args)})")
                    body_blocks.append(f"  store %struct.{ret_sname} %_res, ptr %_ail_out, align 8")
                    body_blocks.append("  ret void\n}\n")
                    exports.append(
                        ExportedSymbol(
                            name,
                            "void",
                            "None",
                            c_params_full,
                            py_params_full,
                            param_names,
                            param_struct_types,
                            ret_struct_type=ret_sname,
                        )
                    )
                elif sig.ret_kind in LINEAR_CAPS:
                    body_blocks.append(f"define void @{name}({', '.join(c_ir_params)}) local_unnamed_addr nounwind {{")
                    body_blocks.extend(wrap_lines)
                    body_blocks.append(f"  call fastcc void @__ail_ssa_{name}({', '.join(call_args)})")
                    body_blocks.append("  ret void\n}\n")
                    exports.append(ExportedSymbol(name, "void", "None", c_params, py_params, param_names, param_struct_types))
                else:
                    ret_c = "int64_t" if sig.ret_kind == "i64" else "uint64_t"
                    ret_py = "ctypes.c_int64" if sig.ret_kind == "i64" else "ctypes.c_uint64"
                    body_blocks.append(f"define i64 @{name}({', '.join(c_ir_params)}) local_unnamed_addr nounwind {{")
                    body_blocks.extend(wrap_lines)
                    body_blocks.append(f"  %_res = call fastcc i64 @__ail_ssa_{name}({', '.join(call_args)})")
                    body_blocks.append("  ret i64 %_res\n}\n")
                    exports.append(ExportedSymbol(name, ret_c, ret_py, c_params, py_params, param_names, param_struct_types))

        elif head == "map_inplace":
            name = str(form.val[1].val)
            params_n, _, elem_vars, body_n = form.val[2], form.val[3], form.val[4], form.val[5]
            elem_var = str(elem_vars.val[0].val)
            sig = sigs[name]
            ir_params = []
            c_params = []
            py_params = []
            env = {}
            var_kinds = {}
            buf_ir = ""
            len_ir = ""
            elem_k = "u64"

            for p, pk in zip(params_n.val, sig.param_kinds):
                pname = str(p.val[0].val)
                var_kinds[pname] = pk
                env[pname] = f"%{pname}"
                if pk == "mut_slice":
                    buf_ir = f"%{pname}"
                    len_ir = f"%{p.val[1].val[1].val}"
                    is_i64_el = _slice_elem_is_i64(p.val[1])
                    elem_k = "i64" if is_i64_el else "u64"
                    ir_params.append(f"ptr noalias nocapture noundef %{pname}")
                    c_params.append(("int64_t*" if is_i64_el else "uint64_t*", pname))
                    py_params.append("ctypes.POINTER(ctypes.c_int64)" if is_i64_el else "ctypes.POINTER(ctypes.c_uint64)")
                elif pk == "i64":
                    ir_params.append(f"i64 noundef %{pname}")
                    c_params.append(("int64_t", pname))
                    py_params.append("ctypes.c_int64")
                else:
                    ir_params.append(f"i64 noundef %{pname}")
                    c_params.append(("uint64_t", pname))
                    py_params.append("ctypes.c_uint64")

            var_kinds[elem_var] = elem_k
            em = FunctionIREmitter(tenv, var_kinds)
            em.lines = []
            em.cur_block = "loop"
            env[elem_var] = f"%{elem_var}"
            res_reg = em.emit_expr(body_n, env)
            loop_end = em.cur_block

            block = [
                f"define void @{name}({', '.join(ir_params)}) local_unnamed_addr nounwind {{",
                "entry:",
                f"  %empty = icmp eq i64 {len_ir}, 0",
                "  br i1 %empty, label %exit, label %loop",
                "loop:",
                f"  %idx = phi i64 [ 0, %entry ], [ %idx_next, %{loop_end} ]",
                f"  %ptr = getelementptr inbounds nuw i64, ptr {buf_ir}, i64 %idx",
                f"  %{elem_var} = load i64, ptr %ptr, align 8",
                *em.lines,
                f"  store i64 {res_reg}, ptr %ptr, align 8",
                "  %idx_next = add nuw i64 %idx, 1",
                f"  %done = icmp eq i64 %idx_next, {len_ir}",
                "  br i1 %done, label %exit, label %loop",
                "exit:",
                "  ret void\n}\n",
            ]
            body_blocks.extend(block)
            exports.append(ExportedSymbol(name, "void", "None", c_params, py_params))

        elif head == "atomic_cas":
            name = str(form.val[1].val)
            pname = str(form.val[2].val)
            sname = str(form.val[3].val)
            params_n = form.val[4]
            ptr_name = str(params_n.val[0].val[0].val)
            req_name = str(params_n.val[1].val[0].val)

            f0_name, next_f0_node = proto_steps[(pname, sname)]
            em = FunctionIREmitter(tenv, {f0_name: "u64", req_name: "u64"})
            em.lines = []
            desired_reg = em.emit_expr(next_f0_node, {f0_name: "%obs", req_name: f"%{req_name}"})

            block = [
                f"define i64 @{name}(ptr nocapture noundef %{ptr_name}, i64 noundef %{req_name}) local_unnamed_addr nounwind {{",
                "entry:",
                f"  %init = load atomic i64, ptr %{ptr_name} monotonic, align 8",
                "  br label %cas_loop",
                "cas_loop:",
                "  %obs = phi i64 [ %init, %entry ], [ %loaded, %cas_retry ]",
                f"  %guard = icmp uge i64 %obs, %{req_name}",
                "  br i1 %guard, label %cas_attempt, label %cas_fail",
                "cas_attempt:",
                *em.lines,
                f"  %pair = cmpxchg ptr %{ptr_name}, i64 %obs, i64 {desired_reg} acq_rel monotonic",
                "  %ok = extractvalue { i64, i1 } %pair, 1",
                "  %loaded = extractvalue { i64, i1 } %pair, 0",
                "  br i1 %ok, label %cas_ok, label %cas_retry",
                "cas_retry:",
                "  br label %cas_loop",
                "cas_ok:",
                "  ret i64 1",
                "cas_fail:",
                "  ret i64 0\n}\n",
            ]
            body_blocks.extend(block)
            exports.append(
                ExportedSymbol(
                    name,
                    "uint64_t",
                    "ctypes.c_uint64",
                    [("uint64_t*", ptr_name), ("uint64_t", req_name)],
                    ["ctypes.POINTER(ctypes.c_uint64)", "ctypes.c_uint64"],
                )
            )

        elif head == "main":
            has_main = True
            body_n = form.val[3]
            em = FunctionIREmitter(tenv, {})
            ret_reg = em.emit_expr(body_n, {})
            if em.uses_printf:
                any_printf = True
            if em.uses_fmt_i64:
                any_fmt_i64 = True
            if em.uses_fs:
                any_fs = True
            if em.uses_net:
                any_net = True
            body_blocks.append("define i32 @main() local_unnamed_addr nounwind {")
            body_blocks.extend(em.lines)
            code32 = em.tmp()
            body_blocks.append(f"  {code32} = trunc i64 {ret_reg} to i32")
            body_blocks.append(f"  ret i32 {code32}\n}}\n")

    if any_printf or any_fs:
        header.append('@.ail_fmt_u64 = private unnamed_addr constant [6 x i8] c"%llu\\0A\\00", align 1')
    if any_fmt_i64:
        header.append('@.ail_fmt_i64 = private unnamed_addr constant [6 x i8] c"%lld\\0A\\00", align 1')
    if any_printf:
        header.append("declare noundef i32 @printf(ptr nocapture noundef readonly, ...) local_unnamed_addr nounwind")
    if any_fs:
        header.extend(_emit_fs_runtime_ir())
    if any_net:
        header.extend(_emit_net_loopback_runtime_ir(is_darwin))

    header.append("")
    return "\n".join(header + body_blocks), exports, has_main


def generate_c_header(exports: list[ExportedSymbol], structs: dict[str, StructDef] | None = None) -> str:
    lines = [
        "/* Auto-generated by ailang v0.2 — Formally Verified C ABI Header */",
        "#pragma once",
        "#include <stdint.h>",
        "#ifdef __cplusplus",
        'extern "C" {',
        "#endif",
        "",
    ]
    for sdef in (structs or {}).values():
        lines.append("typedef struct {")
        for fd in sdef.fields:
            ct = "int64_t" if fd.kind == "i64" else "uint64_t"
            lines.append(f"    {ct} {fd.name};")
        lines.append(f"}} {sdef.name};\n")
    for ex in exports:
        p_str = ", ".join(f"{t} {n}" for t, n in ex.params_c) or "void"
        lines.append(f"{ex.ret_c} {ex.name}({p_str});")
    lines.extend(["", "#ifdef __cplusplus", "}", "#endif", ""])
    return "\n".join(lines)


def generate_python_bindings(
    exports: list[ExportedSymbol],
    lib_filename: str,
    structs: dict[str, StructDef] | None = None,
) -> str:
    lines = [
        '"""Auto-generated by ailang v0.2 — Formally Verified Python ctypes Bindings."""',
        "import ctypes",
        "from pathlib import Path",
        "",
        f'_LIB = ctypes.CDLL(str(Path(__file__).with_name("{lib_filename}")))',
        "",
    ]
    for sdef in (structs or {}).values():
        lines.append(f"class {sdef.name}(ctypes.Structure):")
        lines.append("    _fields_ = [")
        for fd in sdef.fields:
            pyt = "ctypes.c_int64" if fd.kind == "i64" else "ctypes.c_uint64"
            lines.append(f'        ("{fd.name}", {pyt}),')
        lines.append("    ]\n")

    for ex in exports:
        lines.append(f"_LIB.{ex.name}.argtypes = [{', '.join(ex.params_py)}]")
        lines.append(f"_LIB.{ex.name}.restype = {ex.ret_py}")
        has_struct = (ex.ret_struct_type is not None) or any(s is not None for s in ex.param_struct_types)
        if not has_struct:
            lines.append(f"{ex.name} = _LIB.{ex.name}\n")
        else:
            sig_args = ", ".join(ex.param_names)
            call_exprs: list[str] = []
            for pn, st in zip(ex.param_names, ex.param_struct_types):
                if st is not None:
                    call_exprs.append(f"ctypes.byref({pn}) if isinstance({pn}, {st}) else {pn}")
                else:
                    call_exprs.append(pn)
            lines.append(f"def {ex.name}({sig_args}):")
            if ex.ret_struct_type is not None:
                call_exprs.append("ctypes.byref(_out)")
                lines.append(f"    _out = {ex.ret_struct_type}()")
                lines.append(f"    _LIB.{ex.name}({', '.join(call_exprs)})")
                lines.append("    return _out\n")
            else:
                lines.append(f"    return _LIB.{ex.name}({', '.join(call_exprs)})\n")
    return "\n".join(lines)


def count_asm_telemetry(asm_text: str) -> tuple[int, int]:
    simd_tokens = (".2d", ".4s", ".16b", "ldp\tq", "stp\tq", "usra", "bsl.", "bif.", "bit.")
    atomic_tokens = ("casal", "casa", "casl", "ldadd", "swpal", "ldaxr", "stlxr", "lock")
    simd_cnt = 0
    atomic_cnt = 0
    for ln in asm_text.splitlines():
        s = ln.strip()
        if any(t in s for t in simd_tokens):
            simd_cnt += 1
        if any(s.startswith(t) or f"\t{t}" in ln for t in atomic_tokens):
            atomic_cnt += 1
    return simd_cnt, atomic_cnt


def compile_llvm_to_native(
    forms: list[SNode],
    tenv_or_sigs: ModuleTypeEnv | dict[str, FnSig],
    out_dir: Path,
    stem: str,
    build_shared_lib: bool | None = None,
) -> pb.BuildArtifacts:
    out_dir.mkdir(parents=True, exist_ok=True)
    tenv = tenv_or_sigs if isinstance(tenv_or_sigs, ModuleTypeEnv) else check_module_ownership_v2(forms)
    ir_text, exports, has_main = emit_llvm_module(forms, tenv)
    is_lib = (not has_main) if build_shared_lib is None else build_shared_lib

    ll_path = out_dir / f"{stem}.ll"
    s_path = out_dir / f"{stem}.s"
    ll_path.write_text(ir_text)

    subprocess.run(["clang", "-O3", "-S", "-x", "ir", str(ll_path), "-o", str(s_path)], check=True)
    simd_cnt, atomic_cnt = count_asm_telemetry(s_path.read_text())

    if is_lib:
        ext = ".dylib" if platform.system() == "Darwin" else ".so"
        bin_path = out_dir / f"lib{stem}{ext}"
        subprocess.run(["clang", "-O3", "-shared", "-x", "ir", str(ll_path), "-o", str(bin_path)], check=True)
        h_path = out_dir / f"{stem}.h"
        py_path = out_dir / f"{stem}_bindings.py"
        h_path.write_text(generate_c_header(exports, tenv.structs))
        py_path.write_text(generate_python_bindings(exports, bin_path.name, tenv.structs))
        return pb.BuildArtifacts(
            llvm_ir_path=str(ll_path),
            asm_path=str(s_path),
            binary_or_lib_path=str(bin_path),
            c_header_path=str(h_path),
            python_bindings_path=str(py_path),
            neon_simd_instructions=simd_cnt,
            hardware_atomic_instructions=atomic_cnt,
        )
    else:
        bin_path = out_dir / stem
        subprocess.run(["clang", "-O3", "-x", "ir", str(ll_path), "-o", str(bin_path)], check=True)
        return pb.BuildArtifacts(
            llvm_ir_path=str(ll_path),
            asm_path=str(s_path),
            binary_or_lib_path=str(bin_path),
            neon_simd_instructions=simd_cnt,
            hardware_atomic_instructions=atomic_cnt,
        )
