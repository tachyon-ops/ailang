"""Tests for ailang v1.0: zero-copy `bytes` slices, big-endian readers, `(import ...)`/`(const ...)` modules, stdlib, and examples."""

from __future__ import annotations

import ctypes
import importlib.util
import sys
from pathlib import Path

import pytest

from ailang import ail_agent_pb2 as pb
from ailang.codegen_llvm import compile_llvm_to_native
from ailang.diagnostics import AILCompilerError, U64_MAX
from ailang.modules import list_stdlib_modules, load_ail_module_with_imports
from ailang.ownership import check_module_ownership_v2
from ailang.spec_firewall import audit_module_specifications
from ailang.verifier import ModuleVerifier


ROOT = Path(__file__).resolve().parent.parent


def _load_py_module(py_path: Path, mod_name: str):
    spec = importlib.util.spec_from_file_location(mod_name, str(py_path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_bytes_bounds_and_ownership_rejections() -> None:
    oob_programs = [
        # byte_at at idx == len
        """
        (fn bad_at_len ((n u64[0..MAX]) (buf (bytes n)))
          u64[0..255]
          (byte_at buf n))
        """,
        # byte_at on potentially empty buffer
        """
        (fn bad_empty ((n u64[0..MAX]) (buf (bytes n)))
          u64[0..255]
          (byte_at buf 0))
        """,
        # read_u16_be off-by-one: len - 1 leaves only 1 byte
        """
        (fn bad_u16 ((n u64[1..MAX]) (buf (bytes n)))
          u64[0..65535]
          (read_u16_be buf (- n 1)))
        """,
        # read_u32_be off-by-one: len - 3 leaves only 3 bytes
        """
        (fn bad_u32 ((n u64[3..MAX]) (buf (bytes n)))
          u64[0..4294967295]
          (read_u32_be buf (- n 3)))
        """,
        # read_u64_be off-by-one: len - 7 leaves only 7 bytes
        """
        (fn bad_u64 ((n u64[7..MAX]) (buf (bytes n)))
          u64[0..MAX]
          (read_u64_be buf (- n 7)))
        """,
        # bytes_eq4 off-by-one: len - 3 leaves only 3 bytes
        """
        (fn bad_eq4 ((n u64[3..MAX]) (buf (bytes n)))
          u64[0..1]
          (bytes_eq4 buf (- n 3) 65 73 76 49))
        """,
        # Caller spoofing longer length to helper expecting (bytes n)
        """
        (fn helper ((m u64[4..MAX]) (b (bytes m)))
          u64[0..4294967295]
          (read_u32_be b 0))
        (fn bad_caller_len ((n u64[3..100]) (buf (bytes n)))
          u64[0..4294967295]
          (call helper (+ n 1) buf))
        """,
    ]

    for idx, src in enumerate(oob_programs):
        forms = load_ail_module_with_imports(src)
        tenv = check_module_ownership_v2(forms)
        with pytest.raises(AILCompilerError) as ei:
            ModuleVerifier(tenv).verify_module(forms)
        assert ei.value.diag.code == pb.E_OUT_OF_BOUNDS, f"Case {idx} gave {pb.ErrorCode.Name(ei.value.diag.code)}: {ei.value}"

    # Ownership validation checks on (bytes len_var) and bytes_eq4 literals
    bad_len_order = """
    (fn bad ((buf (bytes n)) (n u64)) u64 (byte_at buf 0))
    """
    with pytest.raises(AILCompilerError):
        check_module_ownership_v2(load_ail_module_with_imports(bad_len_order))

    bad_signed_len = """
    (fn bad ((n i64) (buf (bytes n))) u64 (byte_at buf 0))
    """
    with pytest.raises(AILCompilerError):
        check_module_ownership_v2(load_ail_module_with_imports(bad_signed_len))

    bad_eq4_lit = """
    (fn bad ((n u64[4..MAX]) (buf (bytes n))) u64[0..1] (bytes_eq4 buf 0 256 0 0 0))
    """
    with pytest.raises(AILCompilerError) as ei_lit:
        check_module_ownership_v2(load_ail_module_with_imports(bad_eq4_lit))
    assert ei_lit.value.diag.code == pb.E_TYPE_MISMATCH


def test_bytes_native_llvm_readers_and_wire_frame_parser(tmp_path: Path) -> None:
    reader_src = """
    (fn peek_byte ((n u64[1..MAX]) (buf (bytes n)) (i u64[0..MAX]))
      u64[0..255]
      (if (< i n) (byte_at buf i) 0))

    (fn get_u16_at1 ((n u64[3..MAX]) (buf (bytes n)))
      (out u64[0..65535] (== out (read_u16_be buf 1)))
      (read_u16_be buf 1))

    (fn get_u32_at1 ((n u64[5..MAX]) (buf (bytes n)))
      (out u64[0..4294967295] (== out (read_u32_be buf 1)))
      (read_u32_be buf 1))

    (fn get_u64_at1 ((n u64[9..MAX]) (buf (bytes n)))
      (out u64[0..MAX] (== out (read_u64_be buf 1)))
      (read_u64_be buf 1))

    (fn check_high_magic ((n u64[5..MAX]) (buf (bytes n)))
      (out u64[0..1] (== out (bytes_eq4 buf 1 255 128 0 1)))
      (bytes_eq4 buf 1 255 128 0 1))
    """
    forms = load_ail_module_with_imports(reader_src)
    tenv = check_module_ownership_v2(forms)
    stats = ModuleVerifier(tenv).verify_module(forms)
    assert len(stats) == 5 and all(s.verified for s in stats)

    # Spec firewall must cleanly skip functions containing `bytes` parameters
    audits, diags = audit_module_specifications(forms, tenv)
    assert audits == [] and diags == []

    artifacts = compile_llvm_to_native(forms, tenv, tmp_path, "bytes_readers")
    ir_text = Path(artifacts.llvm_ir_path).read_text()
    h_text = Path(artifacts.c_header_path).read_text()
    py_text = Path(artifacts.python_bindings_path).read_text()
    assert "ptr noalias nocapture readonly noundef %buf" in ir_text
    assert "@llvm.bswap.i16" in ir_text and "@llvm.bswap.i32" in ir_text and "@llvm.bswap.i64" in ir_text
    assert "const uint8_t* buf" in h_text
    assert "ctypes.POINTER(ctypes.c_uint8)" in py_text

    mod = _load_py_module(Path(artifacts.python_bindings_path), "test_bytes_readers_mod")
    payload = bytes([0x99, 0xFF, 0x80, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF])
    assert mod.peek_byte(len(payload), payload, 0) == 0x99
    assert mod.peek_byte(len(payload), payload, 8) == 0xEF
    assert mod.peek_byte(len(payload), payload, 9) == 0
    assert mod.get_u16_at1(len(payload), payload) == 0xFF80
    assert mod.get_u32_at1(len(payload), payload) == 0xFF800001
    assert mod.get_u64_at1(len(payload), payload) == 0xFF800001DEADBEEF
    assert mod.check_high_magic(len(payload), payload) == 1
    assert mod.check_high_magic(len(payload), b"\x99\x00\x80\x00\x01\x00\x00\x00\x00") == 0

    # Full E2E on `examples/wire_frame_parser.ail`
    wf_forms = load_ail_module_with_imports(ROOT / "examples" / "wire_frame_parser.ail")
    wf_tenv = check_module_ownership_v2(wf_forms)
    wf_stats = ModuleVerifier(wf_tenv).verify_module(wf_forms)
    assert all(s.verified for s in wf_stats)
    wf_audits, wf_diags = audit_module_specifications(wf_forms, wf_tenv)
    assert len(wf_audits) == 1 and wf_audits[0].fn_name == "frame_result_seq"
    assert wf_audits[0].uniquely_tight and wf_diags == []

    wf_art = compile_llvm_to_native(wf_forms, wf_tenv, tmp_path, "wire_frame_parser")
    wf = _load_py_module(Path(wf_art.python_bindings_path), "test_wire_frame_mod")
    FR = wf.FrameResult

    # Valid AIL1 v1 frame: flags=0x2A, payload_len=12, seq=0x12345678 + 8 payload bytes
    frame = b"AIL1\x01\x2a\x00\x0c\x12\x34\x56\x78\xaa\xbb\xcc\xdd\xee\xff\x00\x11"
    res = wf.parse_frame(len(frame), frame)
    assert res.tag == FR.TAG_Valid
    assert res.field(0) == 1
    assert res.field(1) == 0x2A
    assert res.field(2) == 12
    assert res.field(3) == 0x12345678
    assert wf.frame_result_seq(res) == 0x12345678
    assert wf.read_frame_u64_payload(len(frame), frame) == 0x12345678AABBCCDD

    short = b"AIL1"
    res_short = wf.parse_frame(len(short), short)
    assert res_short.tag == FR.TAG_Truncated
    assert res_short.field(0) == 4 and res_short.field(1) == 8

    bad_magic = b"NOPE\x01\x00\x00\x04\x00\x00\x00\x01"
    assert wf.parse_frame(len(bad_magic), bad_magic).tag == FR.TAG_BadMagic

    bad_ver = b"AIL1\x02\x00\x00\x04\x00\x00\x00\x01"
    res_ver = wf.parse_frame(len(bad_ver), bad_ver)
    assert res_ver.tag == FR.TAG_UnsupportedVersion and res_ver.field(0) == 2

    trunc_payload = b"AIL1\x01\x00\x00\x20\x00\x00\x00\x01"
    res_tp = wf.parse_frame(len(trunc_payload), trunc_payload)
    assert res_tp.tag == FR.TAG_Truncated
    assert res_tp.field(0) == 12 and res_tp.field(1) == 40
    assert wf.frame_result_seq(res_tp) == 0


def test_module_imports_constants_diamond_dedup_and_cycles(tmp_path: Path) -> None:
    # 1. Diamond import deduplication + shared const propagation + lexical shadowing safety
    (tmp_path / "shared.ail").write_text(
        """
        (const SCALE u64 100)
        (const NEG_OFFSET i64 -7)
        (fn scale_up ((x u64[0..1000]))
          (out u64[0..100000] (== out (* x SCALE)))
          (* x SCALE))
        """
    )
    (tmp_path / "left.ail").write_text(
        """
        (import "shared.ail")
        (fn left_fn ((x u64[0..10]))
          u64[0..1000]
          (call scale_up x))
        """
    )
    (tmp_path / "right.ail").write_text(
        """
        (import "shared")
        ; Param `SCALE` must lexically shadow shared const `SCALE`
        (fn right_fn ((SCALE u64[0..5]) (k i64[-10..10]))
          i64[-17..15]
          (+ (to_i64 SCALE) (+ k NEG_OFFSET)))
        """
    )
    main_file = tmp_path / "app.ail"
    main_file.write_text(
        """
        (import "left")
        (import "right")
        (import "stdlib/math")
        (fn app_entry ((x u64[0..10]))
          u64[0..2000]
          (let ((a (call left_fn x))
                (NEG_OFFSET 3))
            (+ a (call clamp_u64 NEG_OFFSET 0 SCALE))))
        """
    )

    forms = load_ail_module_with_imports(main_file)
    fn_names = [str(f.val[1].val) for f in forms if str(f.val[0].val) == "fn"]
    # Diamond shared.ail must appear strictly once
    assert fn_names.count("scale_up") == 1
    assert all(str(f.val[0].val) not in ("import", "const") for f in forms)

    tenv = check_module_ownership_v2(forms)
    stats = ModuleVerifier(tenv).verify_module(forms)
    assert all(s.verified for s in stats)

    art = compile_llvm_to_native(forms, tenv, tmp_path, "diamond_app")
    mod = _load_py_module(Path(art.python_bindings_path), "test_diamond_app_mod")
    assert mod.left_fn(4) == 400
    assert mod.right_fn(3, 2) == 3 + 2 - 7
    assert mod.app_entry(5) == 500 + 3

    # 2. Import cycle detection -> pb.E_IMPORT_CYCLE (26)
    cyc_a = tmp_path / "cyc_a.ail"
    cyc_b = tmp_path / "cyc_b.ail"
    cyc_a.write_text('(import "cyc_b")\n(fn fa ((x u64)) u64 x)\n')
    cyc_b.write_text('(import "cyc_a")\n(fn fb ((x u64)) u64 x)\n')
    with pytest.raises(AILCompilerError) as ei_cyc:
        load_ail_module_with_imports(cyc_a)
    assert ei_cyc.value.diag.code == pb.E_IMPORT_CYCLE

    # Self-cycle
    self_cyc = tmp_path / "self_cyc.ail"
    self_cyc.write_text('(import "self_cyc.ail")\n(fn f ((x u64)) u64 x)\n')
    with pytest.raises(AILCompilerError) as ei_self:
        load_ail_module_with_imports(self_cyc)
    assert ei_self.value.diag.code == pb.E_IMPORT_CYCLE


def test_stdlib_modules_and_defi_waterfall_v1_e2e(tmp_path: Path) -> None:
    mods = {p.stem: p for p in list_stdlib_modules()}
    assert {"math", "finance", "bits", "parse"}.issubset(set(mods.keys()))

    loaded: dict[str, object] = {}
    for name in ("math", "finance", "bits", "parse"):
        forms = load_ail_module_with_imports(mods[name])
        tenv = check_module_ownership_v2(forms)
        stats = ModuleVerifier(tenv).verify_module(forms)
        assert stats and all(s.verified for s in stats), f"{name} failed verification"

        if name in ("math", "finance"):
            audits, diags = audit_module_specifications(forms, tenv)
            assert not diags, f"{name} audit diags: {diags}"
            assert all(a.non_vacuous and a.uniquely_tight for a in audits)

        art = compile_llvm_to_native(forms, tenv, tmp_path, f"stdlib_{name}")
        loaded[name] = _load_py_module(Path(art.python_bindings_path), f"test_stdlib_{name}")

    m = loaded["math"]
    assert m.midpoint_u64(U64_MAX - 1, U64_MAX) == U64_MAX - 1
    assert m.sat_add_u64(U64_MAX - 5, 100) == U64_MAX
    assert m.sat_sub_u64(10, 25) == 0
    assert m.clamp_u64(50, 10, 40) == 40
    assert m.clamp_i64(-20, -10, 5) == -10
    assert m.abs_diff_u64(12, 30) == 18
    assert m.div_ceil_u64(0, 7) == 0
    assert m.div_ceil_u64(U64_MAX, U64_MAX) == 1
    assert m.div_ceil_u64(10, 3) == 4

    f = loaded["finance"]
    assert f.mul_bps_floor(1_000_000, 250) == 25_000
    assert f.net_after_bps_fee(1_000_000, 250) == 975_000
    assert f.maker_rebate_capped(1_000_000, 50, 3_000) == 3_000
    q = f.Quote2Way(bid=10_000, ask=10_125)
    assert f.quote_spread_bps(q) == 125

    b = loaded["bits"]
    assert b.low_byte(0x1234ABCD) == 0xCD
    packed = b.pack_u32_pair(0xCAFEBABE, 0xDEADBEEF)
    assert packed == 0xCAFEBABEDEADBEEF
    assert b.unpack_hi32(packed) == 0xCAFEBABE
    assert b.unpack_lo32(packed) == 0xDEADBEEF
    assert b.mask_bits_u64(0xFFFF, 5) == 0x1F

    p = loaded["parse"]
    hdr = b"AIL1\x03\x00\x01\x00"
    assert p.has_ail_magic(len(hdr), hdr) == 1
    assert p.has_ail_magic(len(hdr), b"BAD!\x03\x00\x01\x00") == 0
    assert p.frame_version_byte(len(hdr), hdr) == 3
    assert p.frame_payload_len_u16(len(hdr), hdr) == 256

    # Full E2E on `examples/defi_waterfall_v1.ail`
    wf_forms = load_ail_module_with_imports(ROOT / "examples" / "defi_waterfall_v1.ail")
    wf_tenv = check_module_ownership_v2(wf_forms)
    wf_stats = ModuleVerifier(wf_tenv).verify_module(wf_forms)
    assert all(s.verified for s in wf_stats)
    wf_audits, wf_diags = audit_module_specifications(wf_forms, wf_tenv)
    assert wf_diags == [] and all(a.non_vacuous and a.uniquely_tight for a in wf_audits)

    wf_art = compile_llvm_to_native(wf_forms, wf_tenv, tmp_path, "defi_waterfall_v1")
    df = _load_py_module(Path(wf_art.python_bindings_path), "test_defi_waterfall_mod")
    # gross=1_000_000, fee=300bps (30_000), reserve=2000bps of 30_000 (6_000) -> distributable=994_000
    assert df.waterfall_junior_payout(1_000_000, 700_000, 300, 2000) == 294_000
    assert df.share_price_ceil_per_unit(101, 10) == 11
    q2 = df.Quote2Way(bid=20_000, ask=20_400)
    # spread = 200bps, rebate = min(1_000_000 * 10 / 10000 = 1000, 500) = 500 -> 700
    assert df.pool_quote_health_check(q2, 1_000_000, 10, 500) == 700
