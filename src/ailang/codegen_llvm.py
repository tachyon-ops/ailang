"""Layer 4 Native Silicon Backend v0.2: `nuw`/`nsw`/`noalias` LLVM IR, Dependent `struct` ABI, `cap.io`/`fs`/`net`."""

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import platform
import subprocess

from ailang import ail_agent_pb2 as pb
from ailang.diagnostics import I64_MAX, I64_MIN, U64_MAX
from ailang.ownership import (
    EnumDef,
    LINEAR_CAPS,
    FnSig,
    ModuleTypeEnv,
    StructDef,
    check_module_ownership_v2,
    kind_u64_slots,
)
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
    if kind.startswith("enum:"):
        return f"%enum.{kind.split(':', 1)[1]}"
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

    def _flatten_to_i64_regs(self, reg: str, kind: str) -> list[str]:
        if kind in ("u64", "i64"):
            return [reg]
        if kind.startswith("struct:"):
            sname = kind.split(":", 1)[1]
            sdef = self.tenv.structs[sname]
            out: list[str] = []
            for fidx, fd in enumerate(sdef.fields):
                freg = self.tmp()
                self.lines.append(f"  {freg} = extractvalue %struct.{sname} {reg}, {fidx}")
                out.extend(self._flatten_to_i64_regs(freg, fd.kind))
            return out or ["0"]
        if kind.startswith("enum:"):
            ename = kind.split(":", 1)[1]
            edef = self.tenv.enums[ename]
            nslots = 1 + edef.max_payload_slots(self.tenv.structs, self.tenv.enums)
            out = []
            for sidx in range(nslots):
                sreg = self.tmp()
                self.lines.append(f"  {sreg} = extractvalue %enum.{ename} {reg}, {sidx}")
                out.append(sreg)
            return out
        return [reg]

    def _unflatten_from_i64_regs(self, regs: list[str], kind: str, offset: int = 0) -> tuple[str, int]:
        if kind in ("u64", "i64"):
            return regs[offset], offset + 1
        if kind.startswith("struct:"):
            sname = kind.split(":", 1)[1]
            sdef = self.tenv.structs[sname]
            ir_sty = f"%struct.{sname}"
            cur_agg = "poison"
            cur_off = offset
            for fidx, fd in enumerate(sdef.fields):
                freg, cur_off = self._unflatten_from_i64_regs(regs, fd.kind, cur_off)
                nxt = self.tmp()
                self.lines.append(f"  {nxt} = insertvalue {ir_sty} {cur_agg}, {_ir_type_for_kind(fd.kind)} {freg}, {fidx}")
                cur_agg = nxt
            return cur_agg, cur_off
        if kind.startswith("enum:"):
            ename = kind.split(":", 1)[1]
            edef = self.tenv.enums[ename]
            ir_ety = f"%enum.{ename}"
            nslots = 1 + edef.max_payload_slots(self.tenv.structs, self.tenv.enums)
            cur_agg = "poison"
            for sidx in range(nslots):
                nxt = self.tmp()
                self.lines.append(f"  {nxt} = insertvalue {ir_ety} {cur_agg}, i64 {regs[offset + sidx]}, {sidx}")
                cur_agg = nxt
            return cur_agg, offset + nslots
        return regs[offset], offset + 1

    def _emit_aggregate_eq(self, a_reg: str, b_reg: str, kind: str) -> str:
        if kind in ("u64", "i64"):
            r = self.tmp()
            self.lines.append(f"  {r} = icmp eq i64 {a_reg}, {b_reg}")
            return r
        if kind.startswith("struct:"):
            sname = kind.split(":", 1)[1]
            sdef = self.tenv.structs[sname]
            ir_sty = f"%struct.{sname}"
            acc = "true"
            for fidx, fd in enumerate(sdef.fields):
                fa = self.tmp()
                fb = self.tmp()
                self.lines.append(f"  {fa} = extractvalue {ir_sty} {a_reg}, {fidx}")
                self.lines.append(f"  {fb} = extractvalue {ir_sty} {b_reg}, {fidx}")
                feq = self._emit_aggregate_eq(fa, fb, fd.kind)
                if acc == "true":
                    acc = feq
                else:
                    nxt = self.tmp()
                    self.lines.append(f"  {nxt} = and i1 {acc}, {feq}")
                    acc = nxt
            return acc
        if kind.startswith("enum:"):
            ename = kind.split(":", 1)[1]
            edef = self.tenv.enums[ename]
            ir_ety = f"%enum.{ename}"
            nslots = 1 + edef.max_payload_slots(self.tenv.structs, self.tenv.enums)
            slots_a = []
            slots_b = []
            for sidx in range(nslots):
                sa = self.tmp()
                sb = self.tmp()
                self.lines.append(f"  {sa} = extractvalue {ir_ety} {a_reg}, {sidx}")
                self.lines.append(f"  {sb} = extractvalue {ir_ety} {b_reg}, {sidx}")
                slots_a.append(sa)
                slots_b.append(sb)
            acc = self.tmp()
            self.lines.append(f"  {acc} = icmp eq i64 {slots_a[0]}, {slots_b[0]}")
            for vdef in edef.variants:
                if not vdef.fields:
                    continue
                tag_ne = self.tmp()
                self.lines.append(f"  {tag_ne} = icmp ne i64 {slots_a[0]}, {vdef.tag}")
                cur_off = 1
                veq = "true"
                for fd in vdef.fields:
                    needed = kind_u64_slots(fd.kind, self.tenv.structs, self.tenv.enums)
                    fa, _ = self._unflatten_from_i64_regs(slots_a[cur_off : cur_off + needed], fd.kind, 0)
                    fb, _ = self._unflatten_from_i64_regs(slots_b[cur_off : cur_off + needed], fd.kind, 0)
                    cur_off += needed
                    feq = self._emit_aggregate_eq(fa, fb, fd.kind)
                    if veq == "true":
                        veq = feq
                    else:
                        nv = self.tmp()
                        self.lines.append(f"  {nv} = and i1 {veq}, {feq}")
                        veq = nv
                v_ok = self.tmp()
                self.lines.append(f"  {v_ok} = or i1 {tag_ne}, {veq}")
                nxt = self.tmp()
                self.lines.append(f"  {nxt} = and i1 {acc}, {v_ok}")
                acc = nxt
            return acc
        r = self.tmp()
        self.lines.append(f"  {r} = icmp eq i64 {a_reg}, {b_reg}")
        return r

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
            sdef = self.tenv.structs[sname]
            ir_sty = f"%struct.{sname}"
            cur_agg = "poison"
            for idx, (fd, arg_n) in enumerate(zip(sdef.fields, items[2:])):
                fval = self.emit_expr(arg_n, env)
                fty = _ir_type_for_kind(fd.kind)
                nxt = self.tmp()
                self.lines.append(f"  {nxt} = insertvalue {ir_sty} {cur_agg}, {fty} {fval}, {idx}")
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

        if op == "variant":
            ename = str(items[1].val)
            vname = str(items[2].val)
            vdef = self.tenv.enums[ename].get_variant(vname)
            assert vdef is not None
            ir_ety = f"%enum.{ename}"
            cur_agg = self.tmp()
            self.lines.append(f"  {cur_agg} = insertvalue {ir_ety} zeroinitializer, i64 {vdef.tag}, 0")
            slot_idx = 1
            for fd, arg_n in zip(vdef.fields, items[3:]):
                fval = self.emit_expr(arg_n, env)
                for reg in self._flatten_to_i64_regs(fval, fd.kind):
                    nxt = self.tmp()
                    self.lines.append(f"  {nxt} = insertvalue {ir_ety} {cur_agg}, i64 {reg}, {slot_idx}")
                    cur_agg = nxt
                    slot_idx += 1
            return cur_agg

        if op == "is_variant":
            sv_node = items[1]
            ename = self._node_kind(sv_node).split(":", 1)[1]
            vdef = self.tenv.enums[ename].get_variant(str(items[2].val))
            assert vdef is not None
            sreg = self.emit_expr(sv_node, env)
            tag_r = self.tmp()
            cmp_r = self.tmp()
            self.lines.append(f"  {tag_r} = extractvalue %enum.{ename} {sreg}, 0")
            self.lines.append(f"  {cmp_r} = icmp eq i64 {tag_r}, {vdef.tag}")
            return cmp_r

        if op == "match":
            scrut_n = items[1]
            ename = self._node_kind(scrut_n).split(":", 1)[1]
            edef = self.tenv.enums[ename]
            ir_ety = f"%enum.{ename}"
            sreg = self.emit_expr(scrut_n, env)
            tag_r = self.tmp()
            self.lines.append(f"  {tag_r} = extractvalue {ir_ety} {sreg}, 0")

            arms = items[2:]
            arm_lbls = [self.label(f"marm{i}") for i in range(len(arms))]
            merge_lbl = self.label("mmerge")

            switch_cases: list[str] = []
            for arm, lbl in zip(arms[:-1], arm_lbls[:-1]):
                pat = arm.val[0]
                vdef = edef.get_variant(str(pat.val[0].val))
                assert vdef is not None
                switch_cases.append(f"i64 {vdef.tag}, label %{lbl}")
            self.lines.append(f"  switch i64 {tag_r}, label %{arm_lbls[-1]} [ {' '.join(switch_cases)} ]")

            arm_results: list[tuple[str, str]] = []
            for arm, lbl in zip(arms, arm_lbls):
                pat, arm_body = arm.val[0], arm.val[1]
                self.lines.append(f"{lbl}:")
                self.cur_block = lbl
                arm_env = dict(env)
                if not (isinstance(pat.val, str) and pat.val == "_"):
                    vdef = edef.get_variant(str(pat.val[0].val))
                    assert vdef is not None
                    slot_offset = 1
                    for bnode, fd in zip(pat.val[1:], vdef.fields):
                        bname = str(bnode.val)
                        self.var_kinds[bname] = fd.kind
                        needed = kind_u64_slots(fd.kind, self.tenv.structs, self.tenv.enums)
                        slot_regs: list[str] = []
                        for sidx in range(slot_offset, slot_offset + needed):
                            freg = self.tmp()
                            self.lines.append(f"  {freg} = extractvalue {ir_ety} {sreg}, {sidx}")
                            slot_regs.append(freg)
                        slot_offset += needed
                        val_reg, _ = self._unflatten_from_i64_regs(slot_regs, fd.kind, 0)
                        arm_env[bname] = val_reg
                av = self.emit_expr(arm_body, arm_env)
                aend = self.cur_block
                arm_results.append((av, aend))
                self.lines.append(f"  br label %{merge_lbl}")

            self.lines.append(f"{merge_lbl}:")
            self.cur_block = merge_lbl
            if nk in LINEAR_CAPS:
                return "0"
            phi_ty = _ir_type_for_kind(nk)
            phi_in = ", ".join(f"[ {av}, %{aend} ]" for av, aend in arm_results)
            r = self.tmp()
            self.lines.append(f"  {r} = phi {phi_ty} {phi_in}")
            return r

        if op == "io.print_u64":
            self.uses_printf = True
            _ = self.emit_expr(items[1], env)
            val = self.emit_expr(items[2], env)
            self.lines.append(f"  call i32 (ptr, ...) @printf(ptr nonnull @.ail_fmt_u64, i64 {val})")
            return "0"

        if op == "io.print_i64":
            self.uses_printf = True
            self.uses_fmt_i64 = True
            _ = self.emit_expr(items[1], env)
            val = self.emit_expr(items[2], env)
            self.lines.append(f"  call i32 (ptr, ...) @printf(ptr nonnull @.ail_fmt_i64, i64 {val})")
            return "0"

        if op == "io.done":
            self.uses_printf = True
            _ = self.emit_expr(items[1], env)
            ret_v = self.emit_expr(items[2], env)
            self.lines.append("  call i32 @fflush(ptr null)")
            return ret_v

        if op == "fs.write_u64":
            self.uses_fs = True
            _ = self.emit_expr(items[1], env)
            val = self.emit_expr(items[2], env)
            self.lines.append(f"  call void @__ail_fs_write(ptr nonnull @.ail_fmt_u64, i64 {val})")
            return "0"

        if op == "fs.write_i64":
            self.uses_fs = True
            self.uses_fmt_i64 = True
            _ = self.emit_expr(items[1], env)
            val = self.emit_expr(items[2], env)
            self.lines.append(f"  call void @__ail_fs_write(ptr nonnull @.ail_fmt_i64, i64 {val})")
            return "0"

        if op in ("fs.close", "net.close"):
            _ = self.emit_expr(items[1], env)
            return "0"

        if op == "net.loopback_send_u64":
            self.uses_net = True
            _ = self.emit_expr(items[1], env)
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

        if op == "byte_at":
            buf_name = str(items[1].val)
            idx = self.emit_expr(items[2], env)
            ptr = self.tmp()
            b8 = self.tmp()
            val = self.tmp()
            self.lines.append(f"  {ptr} = getelementptr inbounds nuw i8, ptr {env[buf_name]}, i64 {idx}")
            self.lines.append(f"  {b8} = load i8, ptr {ptr}, align 1")
            self.lines.append(f"  {val} = zext i8 {b8} to i64")
            return val

        if op in ("read_u16_be", "read_u32_be", "read_u64_be"):
            buf_name = str(items[1].val)
            idx = self.emit_expr(items[2], env)
            width_bits = {"read_u16_be": 16, "read_u32_be": 32, "read_u64_be": 64}[op]
            ty = f"i{width_bits}"
            ptr = self.tmp()
            raw = self.tmp()
            swapped = self.tmp()
            self.lines.append(f"  {ptr} = getelementptr inbounds nuw i8, ptr {env[buf_name]}, i64 {idx}")
            self.lines.append(f"  {raw} = load {ty}, ptr {ptr}, align 1")
            self.lines.append(f"  {swapped} = call {ty} @llvm.bswap.{ty}({ty} {raw})")
            if width_bits < 64:
                val = self.tmp()
                self.lines.append(f"  {val} = zext {ty} {swapped} to i64")
                return val
            return swapped

        if op in ("read_u16_le", "read_u32_le", "read_u64_le"):
            buf_name = str(items[1].val)
            idx = self.emit_expr(items[2], env)
            width_bits = {"read_u16_le": 16, "read_u32_le": 32, "read_u64_le": 64}[op]
            ty = f"i{width_bits}"
            ptr = self.tmp()
            raw = self.tmp()
            self.lines.append(f"  {ptr} = getelementptr inbounds nuw i8, ptr {env[buf_name]}, i64 {idx}")
            self.lines.append(f"  {raw} = load {ty}, ptr {ptr}, align 1")
            if width_bits < 64:
                val = self.tmp()
                self.lines.append(f"  {val} = zext {ty} {raw} to i64")
                return val
            return raw

        if op == "write_byte":
            buf_name = str(items[1].val)
            idx = self.emit_expr(items[2], env)
            v = self.emit_expr(items[3], env)
            ptr = self.tmp()
            b8 = self.tmp()
            self.lines.append(f"  {ptr} = getelementptr inbounds nuw i8, ptr {env[buf_name]}, i64 {idx}")
            self.lines.append(f"  {b8} = trunc i64 {v} to i8")
            self.lines.append(f"  store i8 {b8}, ptr {ptr}, align 1")
            return "1"

        if op in ("write_u16_be", "write_u32_be", "write_u64_be", "write_u16_le", "write_u32_le", "write_u64_le"):
            buf_name = str(items[1].val)
            idx = self.emit_expr(items[2], env)
            v = self.emit_expr(items[3], env)
            width_bytes = 2 if "u16" in op else (4 if "u32" in op else 8)
            width_bits = width_bytes * 8
            ty = f"i{width_bits}"
            ptr = self.tmp()
            self.lines.append(f"  {ptr} = getelementptr inbounds nuw i8, ptr {env[buf_name]}, i64 {idx}")
            if width_bits < 64:
                narrow = self.tmp()
                self.lines.append(f"  {narrow} = trunc i64 {v} to {ty}")
            else:
                narrow = v
            if op.endswith("_be"):
                out_v = self.tmp()
                self.lines.append(f"  {out_v} = call {ty} @llvm.bswap.{ty}({ty} {narrow})")
            else:
                out_v = narrow
            self.lines.append(f"  store {ty} {out_v}, ptr {ptr}, align 1")
            return str(width_bytes)

        if op in ("mul_div_u64", "mul_div_ceil_u64"):
            a = self.emit_expr(items[1], env)
            b = self.emit_expr(items[2], env)
            d = self.emit_expr(items[3], env)
            a128 = self.tmp()
            b128 = self.tmp()
            d128 = self.tmp()
            prod = self.tmp()
            self.lines.append(f"  {a128} = zext i64 {a} to i128")
            self.lines.append(f"  {b128} = zext i64 {b} to i128")
            self.lines.append(f"  {d128} = zext i64 {d} to i128")
            self.lines.append(f"  {prod} = mul nuw i128 {a128}, {b128}")
            num = prod
            if op == "mul_div_ceil_u64":
                dm1 = self.tmp()
                num = self.tmp()
                self.lines.append(f"  {dm1} = sub nuw i128 {d128}, 1")
                self.lines.append(f"  {num} = add nuw i128 {prod}, {dm1}")
            quot = self.tmp()
            res = self.tmp()
            self.lines.append(f"  {quot} = udiv i128 {num}, {d128}")
            self.lines.append(f"  {res} = trunc i128 {quot} to i64")
            return res

        if op == "bytes_eq4":
            buf_name = str(items[1].val)
            idx = self.emit_expr(items[2], env)
            b0, b1, b2, b3 = (int(a.val) for a in items[3:7])
            expected = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
            expected_i32 = expected - (1 << 32) if expected >= (1 << 31) else expected
            ptr = self.tmp()
            raw = self.tmp()
            be_val = self.tmp()
            cmp_r = self.tmp()
            val = self.tmp()
            self.lines.append(f"  {ptr} = getelementptr inbounds nuw i8, ptr {env[buf_name]}, i64 {idx}")
            self.lines.append(f"  {raw} = load i32, ptr {ptr}, align 1")
            self.lines.append(f"  {be_val} = call i32 @llvm.bswap.i32(i32 {raw})")
            self.lines.append(f"  {cmp_r} = icmp eq i32 {be_val}, {expected_i32}")
            self.lines.append(f"  {val} = zext i1 {cmp_r} to i64")
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
            uses_ssa_helper = sig.ret_kind.startswith(("struct:", "enum:")) or any(
                pk.startswith(("struct:", "enum:")) for pk in sig.param_kinds
            )
            ir_callee = f"__ail_ssa_{callee}" if uses_ssa_helper else callee
            cc = "fastcc " if uses_ssa_helper else ""

            ir_args: list[str] = []
            for arg_node, pk in zip(items[2:], sig.param_kinds):
                if pk in LINEAR_CAPS:
                    continue  # Zero-cost linear capability erasure!
                if pk in ("slice", "mut_slice", "atomic_u64", "bytes", "mut_bytes"):
                    ir_args.append(f"ptr {env[str(arg_node.val)]}")
                elif pk.startswith(("struct:", "enum:")):
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
        if op in ("==", "!=", "<", "<=", ">", ">="):
            rk1 = self._raw_kind(items[1])
            rk2 = self._raw_kind(items[2])
            if rk1.startswith(("struct:", "enum:")) and op in ("==", "!="):
                eq_r = self._emit_aggregate_eq(args[0], args[1], rk1)
                if op == "==":
                    return eq_r
                ne_r = self.tmp()
                self.lines.append(f"  {ne_r} = xor i1 {eq_r}, true")
                return ne_r
            r = self.tmp()
            cmp_signed = (rk1 == "i64") or (rk2 == "i64")
            if cmp_signed:
                pred = {"==": "eq", "!=": "ne", "<": "slt", "<=": "sle", ">": "sgt", ">=": "sge"}[op]
            else:
                pred = {"==": "eq", "!=": "ne", "<": "ult", "<=": "ule", ">": "ugt", ">=": "uge"}[op]
            self.lines.append(f"  {r} = icmp {pred} i64 {args[0]}, {args[1]}")
            return r
        r = self.tmp()

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
        "; Generated by ailang v0.3 — Z3 + Bitwuzla Verified LLVM IR (`nuw`/`nsw`, `noalias`, zero-cost `cap.*`)",
        f'target triple = "{triple}"',
        "declare i64 @llvm.umin.i64(i64, i64)",
        "declare i64 @llvm.umax.i64(i64, i64)",
        "declare i64 @llvm.smin.i64(i64, i64)",
        "declare i64 @llvm.smax.i64(i64, i64)",
        "declare i16 @llvm.bswap.i16(i16)",
        "declare i32 @llvm.bswap.i32(i32)",
        "declare i64 @llvm.bswap.i64(i64)",
    ]

    type_order = tenv.type_order or (
        [("struct", s) for s in tenv.structs] + [("enum", e) for e in tenv.enums]
    )
    for tkind, tname in type_order:
        if tkind == "struct" and tname in tenv.structs:
            sdef = tenv.structs[tname]
            fields_ir = ", ".join(_ir_type_for_kind(fd.kind) for fd in sdef.fields) or "i64"
            header.append(f"%struct.{sdef.name} = type {{ {fields_ir} }}")
        elif tkind == "enum" and tname in tenv.enums:
            edef = tenv.enums[tname]
            slots = ", ".join("i64" for _ in range(1 + edef.max_payload_slots(tenv.structs, tenv.enums)))
            header.append(f"%enum.{edef.name} = type {{ {slots} }}")

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
        if head in ("spec", "struct", "enum", "atomic_protocol"):
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
            has_agg_boundary = sig.ret_kind.startswith(("struct:", "enum:")) or any(
                pk.startswith(("struct:", "enum:")) for pk in sig.param_kinds
            )

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
                elif pk == "bytes":
                    pure_mem = False
                    ssa_ir_params.append(f"ptr noalias nocapture readonly noundef %{pname}")
                    c_ir_params.append(f"ptr noalias nocapture readonly noundef %{pname}")
                    c_params.append(("const uint8_t*", pname))
                    py_params.append("ctypes.POINTER(ctypes.c_uint8)")
                    param_struct_types.append(None)
                elif pk == "mut_bytes":
                    pure_mem = False
                    ssa_ir_params.append(f"ptr noalias nocapture noundef %{pname}")
                    c_ir_params.append(f"ptr noalias nocapture noundef %{pname}")
                    c_params.append(("uint8_t*", pname))
                    py_params.append("ctypes.POINTER(ctypes.c_uint8)")
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
                elif pk.startswith("enum:"):
                    ename = pk.split(":", 1)[1]
                    ssa_ir_params.append(f"%enum.{ename} noundef %{pname}")
                    c_ir_params.append(f"ptr nocapture readonly noundef %{pname}_ptr")
                    c_params.append((f"const {ename}*", pname))
                    py_params.append(f"ctypes.POINTER({ename})")
                    param_struct_types.append(ename)
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

            if not has_agg_boundary:
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

                # 2. Portable C-ABI wrapper (pointer-based struct/enum ABI safe across AAPCS64 & SysV x86_64)
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
                    elif pk.startswith("enum:"):
                        ename = pk.split(":", 1)[1]
                        wrap_lines.append(f"  %{pname}_val = load %enum.{ename}, ptr %{pname}_ptr, align 8")
                        call_args.append(f"%enum.{ename} %{pname}_val")
                    elif pk in ("slice", "mut_slice", "atomic_u64", "bytes", "mut_bytes"):
                        call_args.append(f"ptr %{pname}")
                    else:
                        call_args.append(f"i64 %{pname}")

                if sig.ret_kind.startswith(("struct:", "enum:")):
                    ret_sname = sig.ret_kind.split(":", 1)[1]
                    ret_agg_ty = _ir_type_for_kind(sig.ret_kind)
                    c_ir_params_full = [*c_ir_params, "ptr noalias nocapture writeonly noundef %_ail_out"]
                    c_params_full = [*c_params, (f"{ret_sname}*", "_out")]
                    py_params_full = [*py_params, f"ctypes.POINTER({ret_sname})"]
                    body_blocks.append(f"define void @{name}({', '.join(c_ir_params_full)}) local_unnamed_addr nounwind {{")
                    body_blocks.extend(wrap_lines)
                    body_blocks.append(f"  %_res = call fastcc {ret_agg_ty} @__ail_ssa_{name}({', '.join(call_args)})")
                    body_blocks.append(f"  store {ret_agg_ty} %_res, ptr %_ail_out, align 8")
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
                elif pk in ("bytes", "mut_bytes"):
                    ro = " readonly" if pk == "bytes" else ""
                    c_ty = "const uint8_t*" if pk == "bytes" else "uint8_t*"
                    ir_params.append(f"ptr noalias nocapture{ro} noundef %{pname}")
                    c_params.append((c_ty, pname))
                    py_params.append("ctypes.POINTER(ctypes.c_uint8)")
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
        header.append("declare noundef i32 @fflush(ptr nocapture noundef) local_unnamed_addr nounwind")
    if any_fs:
        header.extend(_emit_fs_runtime_ir())
    if any_net:
        header.extend(_emit_net_loopback_runtime_ir(is_darwin))

    header.append("")
    return "\n".join(header + body_blocks), exports, has_main


def generate_c_header(
    exports: list[ExportedSymbol],
    structs: dict[str, StructDef] | None = None,
    enums: dict[str, EnumDef] | None = None,
    type_order: list[tuple[str, str]] | None = None,
) -> str:
    lines = [
        "/* Auto-generated by ailang v1.1 — Formally Verified C ABI Header */",
        "#pragma once",
        "#include <stdint.h>",
        "#ifdef __cplusplus",
        'extern "C" {',
        "#endif",
        "",
    ]
    s_map = structs or {}
    e_map = enums or {}
    order = type_order or ([("struct", s) for s in s_map] + [("enum", e) for e in e_map])
    for tkind, tname in order:
        if tkind == "struct" and tname in s_map:
            sdef = s_map[tname]
            lines.append("typedef struct {")
            for fd in sdef.fields:
                if fd.kind == "i64":
                    ct = "int64_t"
                elif fd.kind == "u64":
                    ct = "uint64_t"
                else:
                    ct = fd.kind.split(":", 1)[1]
                lines.append(f"    {ct} {fd.name};")
            lines.append(f"}} {sdef.name};\n")
        elif tkind == "enum" and tname in e_map:
            edef = e_map[tname]
            lines.append("typedef enum {")
            for vdef in edef.variants:
                lines.append(f"    {edef.name}_{vdef.name} = {vdef.tag},")
            lines.append(f"}} {edef.name}_Tag;\n")
            lines.append("typedef struct {")
            lines.append("    uint64_t tag;")
            for p_idx in range(edef.max_payload_slots(s_map, e_map)):
                lines.append(f"    uint64_t _p{p_idx};")
            lines.append(f"}} {edef.name};\n")
    for ex in exports:
        p_str = ", ".join(f"{t} {n}" for t, n in ex.params_c) or "void"
        lines.append(f"{ex.ret_c} {ex.name}({p_str});")
    lines.extend(["", "#ifdef __cplusplus", "}", "#endif", ""])
    return "\n".join(lines)


def generate_python_bindings(
    exports: list[ExportedSymbol],
    lib_filename: str,
    structs: dict[str, StructDef] | None = None,
    enums: dict[str, EnumDef] | None = None,
    type_order: list[tuple[str, str]] | None = None,
) -> str:
    import keyword

    def _py_ident(nm: str) -> str:
        return f"{nm}_" if (keyword.iskeyword(nm) or nm in ("cls", "ctypes", "_LIB", "_out", "_slots", "_kw")) else nm

    s_map = structs or {}
    e_map = enums or {}
    lines = [
        '"""Auto-generated by ailang v1.1 — Formally Verified Python ctypes Bindings."""',
        "import ctypes",
        "from pathlib import Path",
        "",
        f'_LIB = ctypes.CDLL(str(Path(__file__).with_name("{lib_filename}")))',
        "",
    ]
    if e_map:
        lines.extend(
            [
                "def _ail_flatten_slots(v):",
                "    if isinstance(v, ctypes.Structure):",
                "        out = []",
                "        for fnm, _ in v._fields_:",
                "            out.extend(_ail_flatten_slots(getattr(v, fnm)))",
                "        return out",
                "    return [int(v) & 0xFFFFFFFFFFFFFFFF]",
                "",
            ]
        )
    order = type_order or ([("struct", s) for s in s_map] + [("enum", e) for e in e_map])
    for tkind, tname in order:
        if tkind == "struct" and tname in s_map:
            sdef = s_map[tname]
            lines.append(f"class {sdef.name}(ctypes.Structure):")
            lines.append("    _fields_ = [")
            for fd in sdef.fields:
                if fd.kind == "i64":
                    pyt = "ctypes.c_int64"
                elif fd.kind == "u64":
                    pyt = "ctypes.c_uint64"
                else:
                    pyt = fd.kind.split(":", 1)[1]
                lines.append(f'        ("{fd.name}", {pyt}),')
            lines.append("    ]\n")
        elif tkind == "enum" and tname in e_map:
            edef = e_map[tname]
            lines.append(f"class {edef.name}(ctypes.Structure):")
            lines.append("    _fields_ = [")
            lines.append('        ("tag", ctypes.c_uint64),')
            for p_idx in range(edef.max_payload_slots(s_map, e_map)):
                lines.append(f'        ("_p{p_idx}", ctypes.c_uint64),')
            lines.append("    ]")
            for vdef in edef.variants:
                lines.append(f"    TAG_{vdef.name} = {vdef.tag}")
            for vdef in edef.variants:
                safe_fnames = [_py_ident(fd.name) for fd in vdef.fields]
                params_s = ", ".join(["cls", *safe_fnames])
                lines.append("    @classmethod")
                lines.append(f"    def {vdef.name}({params_s}):")
                if not vdef.fields:
                    lines.append(f"        return cls(tag={vdef.tag})")
                elif all(fd.kind in ("u64", "i64") for fd in vdef.fields):
                    assigns = [f"tag={vdef.tag}"] + [f"_p{i}=({snm} & 0xFFFFFFFFFFFFFFFF)" for i, snm in enumerate(safe_fnames)]
                    lines.append(f"        return cls({', '.join(assigns)})")
                else:
                    slot_expr = " + ".join(f"_ail_flatten_slots({snm})" for snm in safe_fnames)
                    lines.append(f"        _slots = {slot_expr}")
                    lines.append(f"        _kw = {{'tag': {vdef.tag}}}")
                    lines.append("        for _i, _sv in enumerate(_slots):")
                    lines.append("            _kw[f'_p{_i}'] = _sv")
                    lines.append("        return cls(**_kw)")
            lines.append("    def field(self, idx: int, signed: bool = False) -> int:")
            lines.append('        raw = getattr(self, f"_p{idx}")')
            lines.append("        return raw - (1 << 64) if signed and raw >= (1 << 63) else raw\n")

    for ex in exports:
        lines.append(f"_LIB.{ex.name}.argtypes = [{', '.join(ex.params_py)}]")
        lines.append(f"_LIB.{ex.name}.restype = {ex.ret_py}")
        has_struct = (ex.ret_struct_type is not None) or any(s is not None for s in ex.param_struct_types)
        has_bytes = any(pt == "ctypes.POINTER(ctypes.c_uint8)" for pt in ex.params_py)
        if not has_struct and not has_bytes:
            lines.append(f"{ex.name} = _LIB.{ex.name}\n")
        else:
            safe_pnames = [_py_ident(pn) for pn in ex.param_names]
            sig_args = ", ".join(safe_pnames)
            call_exprs: list[str] = []
            for pn, st, pt, pc in zip(safe_pnames, ex.param_struct_types, ex.params_py, ex.params_c):
                if st is not None:
                    call_exprs.append(f"ctypes.byref({pn}) if isinstance({pn}, {st}) else {pn}")
                elif pt == "ctypes.POINTER(ctypes.c_uint8)":
                    if pc[0] == "uint8_t*":
                        call_exprs.append(f"((ctypes.c_uint8 * len({pn})).from_buffer({pn}) if isinstance({pn}, (bytearray, memoryview)) else {pn})")
                    else:
                        call_exprs.append(f"((ctypes.c_uint8 * len({pn})).from_buffer_copy({pn}) if isinstance({pn}, (bytes, bytearray, memoryview)) else {pn})")
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
        h_path.write_text(generate_c_header(exports, tenv.structs, tenv.enums, tenv.type_order))
        py_path.write_text(generate_python_bindings(exports, bin_path.name, tenv.structs, tenv.enums, tenv.type_order))
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
