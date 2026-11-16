"""AIL v1.1.0 Expressiveness Tests: 128-bit widening math, mut_bytes + LE/BE codecs, type aliases, nested ADTs & SpecMut."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess

import pytest

from ailang import ail_agent_pb2 as pb
from ailang.diff_fuzz import run_differential_fuzz
from ailang.diagnostics import AILCompilerError
from ailang.modules import load_ail_module_with_imports
from ailang.multi_target import build_multi_target
from ailang.ownership import check_module_ownership_v2
from ailang.spec_firewall import audit_module_specifications
from ailang.verifier import ModuleVerifier


def _verify_and_build(source: str, out_dir: Path, stem: str):
    src_path = out_dir / f"{stem}.ail"
    out_dir.mkdir(parents=True, exist_ok=True)
    src_path.write_text(source, encoding="utf-8")
    forms = load_ail_module_with_imports(src_path)
    tenv = check_module_ownership_v2(forms)
    ModuleVerifier(tenv).verify_module(forms)
    audits, _ = audit_module_specifications(forms, tenv)
    rep = build_multi_target(forms, tenv, out_dir, stem=stem, target="all")
    return forms, tenv, audits, rep


def _load_mod(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_1a_widening_mul_div_u64_and_ceil_4_targets(tmp_path: Path) -> None:
    src = """
(fn wide_floor ((a u64[0..MAX]) (b u64[0..MAX]) (d u64[(max b 1)..MAX]))
  (out u64[0..a] (== out (mul_div_u64 a b d)))
  (mul_div_u64 a b d))

(fn wide_ceil ((a u64[0..MAX]) (b u64[0..MAX]) (d u64[(max b 1)..MAX]))
  (out u64[0..a] (== out (mul_div_ceil_u64 a b d)))
  (mul_div_ceil_u64 a b d))
"""
    _, _, audits, rep = _verify_and_build(src, tmp_path / "wide", "wide_test")
    assert all(a.non_vacuous and a.uniquely_tight for a in audits)

    assert rep.native is not None and rep.c is not None
    nat_mod = _load_mod(Path(rep.native.python_bindings_path), "nat_wide")
    # Values whose intermediate product a * b far exceeds U64_MAX (2^64 - 1)
    a = (1 << 63) + 17
    b = 1_000_000_000_003
    d = 1_000_000_000_009
    assert nat_mod.wide_floor(a, b, d) == (a * b) // d
    assert nat_mod.wide_ceil(a, b, d) == (a * b + d - 1) // d

    fuzz_rep = run_differential_fuzz(tmp_path / "wide" / "wide_test.ail", tmp_path / "wide_fuzz", cases=20, seed=11)
    assert fuzz_rep.mismatches == 0

    zig = shutil.which("zig")
    if zig and rep.c is not None:
        res = subprocess.run(
            [
                zig,
                "cc",
                "-target",
                "wasm32-freestanding",
                "-nostdlib",
                "-Wl,--no-entry",
                "-rdynamic",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                rep.c.c_source_path,
                "-o",
                str(tmp_path / "wide" / "c_freestanding.wasm"),
            ],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, res.stderr


def test_1a_widening_rejections(tmp_path: Path) -> None:
    div0 = """
(fn bad_div0 ((a u64[0..100]) (b u64[0..100]) (d u64[0..10]))
  u64[0..MAX]
  (mul_div_u64 a b d))
"""
    p1 = tmp_path / "bad_div0.ail"
    p1.write_text(div0, encoding="utf-8")
    forms = load_ail_module_with_imports(p1)
    tenv = check_module_ownership_v2(forms)
    with pytest.raises(AILCompilerError) as err1:
        ModuleVerifier(tenv).verify_module(forms)
    assert err1.value.diag.code == pb.E_DIV_BY_ZERO

    ovf = """
(fn bad_ovf ((a u64[0..MAX]) (b u64[1..4]))
  u64[0..MAX]
  (mul_div_u64 a b 1))
"""
    p2 = tmp_path / "bad_ovf.ail"
    p2.write_text(ovf, encoding="utf-8")
    forms2 = load_ail_module_with_imports(p2)
    tenv2 = check_module_ownership_v2(forms2)
    with pytest.raises(AILCompilerError) as err2:
        ModuleVerifier(tenv2).verify_module(forms2)
    assert err2.value.diag.code == pb.E_U64_OVERFLOW


def test_1b_mut_bytes_le_writers_coercion_and_rejections(tmp_path: Path) -> None:
    src = """
(fn read_back_u32 ((n u64[8..MAX]) (buf (bytes n)))
  u64[0..4294967295]
  (read_u32_le buf 4))

(fn write_and_borrow ((n u64[16..MAX]) (buf (mut_bytes n)) (v32 u64[0..4294967295]) (v64 u64[0..MAX]))
  u64[0..MAX]
  (let ((w1 (write_u16_le buf 0 4660))
        (w2 (write_byte buf 2 171))
        (w3 (write_byte buf 3 205))
        (w4 (write_u32_le buf 4 v32))
        (w5 (write_u64_be buf 8 v64))
        (chk (call read_back_u32 n buf)))
    (+ w1 (+ w2 (+ w3 (+ w4 (+ w5 chk)))))))
"""
    _, _, _, rep = _verify_and_build(src, tmp_path / "mutb", "mutb_test")
    assert rep.native is not None
    mod = _load_mod(Path(rep.native.python_bindings_path), "nat_mutb")

    buf = bytearray(16)
    res = mod.write_and_borrow(16, buf, 0x78563412, 0x0102030405060708)
    assert res == (2 + 1 + 1 + 4 + 8 + 0x78563412)
    assert buf[0:2] == bytes([0x34, 0x12])
    assert buf[2:4] == bytes([171, 205])
    assert buf[4:8] == bytes([0x12, 0x34, 0x56, 0x78])
    assert buf[8:16] == bytes([1, 2, 3, 4, 5, 6, 7, 8])

    fuzz_rep = run_differential_fuzz(tmp_path / "mutb" / "mutb_test.ail", tmp_path / "mutb_fuzz", cases=20, seed=9)
    assert fuzz_rep.mismatches == 0

    # 1. Aliasing violation when passing same mut_bytes twice
    alias_src = """
(fn helper ((n u64[4..MAX]) (a (mut_bytes n)) (b (bytes n))) u64[0..255] (byte_at b 0))
(fn bad_alias ((n u64[4..MAX]) (buf (mut_bytes n)))
  u64[0..255]
  (call helper n buf buf))
"""
    p_alias = tmp_path / "alias.ail"
    p_alias.write_text(alias_src, encoding="utf-8")
    with pytest.raises(AILCompilerError) as err_alias:
        check_module_ownership_v2(load_ail_module_with_imports(p_alias))
    assert err_alias.value.diag.code == pb.E_ALIASING_VIOLATION

    # 2. Out-of-bounds writer
    oob_src = """
(fn bad_oob ((n u64[4..MAX]) (buf (mut_bytes n))) u64[4..4] (write_u32_le buf 2 9))
"""
    p_oob = tmp_path / "oob.ail"
    p_oob.write_text(oob_src, encoding="utf-8")
    f_oob = load_ail_module_with_imports(p_oob)
    with pytest.raises(AILCompilerError) as err_oob:
        ModuleVerifier(check_module_ownership_v2(f_oob)).verify_module(f_oob)
    assert err_oob.value.diag.code == pb.E_OUT_OF_BOUNDS

    # 3. Value > 255 for write_byte
    val_src = """
(fn bad_val ((n u64[4..MAX]) (buf (mut_bytes n)) (x u64[0..300])) u64[1..1] (write_byte buf 0 x))
"""
    p_val = tmp_path / "val.ail"
    p_val.write_text(val_src, encoding="utf-8")
    f_val = load_ail_module_with_imports(p_val)
    with pytest.raises(AILCompilerError) as err_val:
        ModuleVerifier(check_module_ownership_v2(f_val)).verify_module(f_val)
    assert err_val.value.diag.code == pb.E_PRECONDITION_FAILED


def test_1c_type_aliases_nested_adts_and_equality(tmp_path: Path) -> None:
    src = """
(type Price u64[1..1000000])
(type SignedDelta i64[-1000..1000])

(struct Inner
  ((p Price)
   (d SignedDelta)))

(enum Choice
  (One (in Inner))
  (Two (code u64[1..10]) (flag u64[0..1])))

(struct Outer
  ((ch Choice)
   (tag_val u64[0..100])))

(fn roundtrip_eq ((a Outer) (b Outer))
  (out u64[0..2]
    (== out (+ (if (== a b) 1 0) (if (!= a b) 0 1))))
  (+ (if (== a b) 1 0) (if (!= a b) 0 1)))

(fn inspect_outer ((o Outer))
  (out i64[-999..1001000]
    (== out (match (field o ch)
              ((One i) (+ (to_i64 (field i p)) (field i d)))
              ((Two code flag) (to_i64 (+ code flag))))))
  (match (field o ch)
    ((One i) (+ (to_i64 (field i p)) (field i d)))
    ((Two code flag) (to_i64 (+ code flag)))))
"""
    _, _, audits, _ = _verify_and_build(src, tmp_path / "nested", "nested_test")
    assert len(audits) == 2
    assert all(a.non_vacuous and a.uniquely_tight for a in audits)

    fuzz_rep = run_differential_fuzz(tmp_path / "nested" / "nested_test.ail", tmp_path / "nested_fuzz", cases=24, seed=17)
    assert fuzz_rep.mismatches == 0
    assert fuzz_rep.total_executions == 2 * 24 * 4
