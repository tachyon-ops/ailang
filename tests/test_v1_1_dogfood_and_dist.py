"""Tests for AIL v1.1.0 Track 3 (static export, packaging, self-hosted workflows) and Track 4 (dogfood-gateway)."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile


ROOT_DIR = Path(__file__).resolve().parent.parent


def test_cli_export_static_site(tmp_path: Path) -> None:
    site_dir = tmp_path / "site"
    res = subprocess.run(
        [
            sys.executable,
            "-m",
            "ailang.cli",
            "studio",
            "--export-static",
            str(site_dir),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "[EXPORTED-SITE]" in res.stdout
    for fname in (".nojekyll", "index.html", "styles.css", "app.js", "demos.json"):
        assert (site_dir / fname).is_file(), f"Missing exported file: {fname}"

    demos = json.loads((site_dir / "demos.json").read_text(encoding="utf-8"))
    assert demos["version"] == "1.1.0"
    assert len(demos["presets"]) == 7
    assert any(p["id"] == "wire_codec_v1_1" for p in demos["presets"])
    html_txt = (site_dir / "index.html").read_text(encoding="utf-8")
    assert "AIL v1.1 Web Studio" in html_txt
    assert 'data-preset="wire_codec_v1_1"' in html_txt
    js_txt = (site_dir / "app.js").read_text(encoding="utf-8")
    assert "mut_bytes" in js_txt


def test_self_hosted_github_workflows() -> None:
    for wf_name in ("verify.yml", "pages-and-dist.yml"):
        wf_path = ROOT_DIR / ".github" / "workflows" / wf_name
        assert wf_path.is_file()
        txt = wf_path.read_text(encoding="utf-8")
        assert "runs-on: self-hosted" in txt
        assert "workflow_dispatch:" in txt
        assert "ubuntu-latest" not in txt
        assert "macos-latest" not in txt
        assert "rm -rf /" not in txt


def test_uv_build_wheel_contains_v1_1_modules(tmp_path: Path) -> None:
    if not shutil.which("uv"):
        pytest.skip("uv not available")
    dist_dir = tmp_path / "dist"
    subprocess.run(
        ["uv", "build", "--out-dir", str(dist_dir)],
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        check=True,
    )
    wheels = list(dist_dir.glob("ailang-1.1.0-*.whl"))
    sdists = list(dist_dir.glob("ailang-1.1.0.tar.gz"))
    assert len(wheels) == 1
    assert len(sdists) == 1
    with zipfile.ZipFile(wheels[0]) as zf:
        names = set(zf.namelist())
        assert "ailang/stdlib/wire.ail" in names
        assert "ailang/diff_fuzz.py" in names


def test_dogfood_gateway_cargo_tests_and_wasm_parity() -> None:
    gw_dir = ROOT_DIR / "integrations" / "dogfood-gateway"
    assert (gw_dir / "kernels" / "gateway_kernel.ail").is_file()
    res = subprocess.run(
        ["cargo", "test", "--manifest-path", str(gw_dir / "Cargo.toml")],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "3 passed; 0 failed" in res.stdout

    wasm_mjs = (gw_dir / "wasm" / "gateway_kernel.mjs").resolve()
    assert wasm_mjs.is_file()
    if shutil.which("node"):
        node_code = f"""
import * as gw from {json.dumps(str(wasm_mjs))};
const buf = new Uint8Array(32);
const notional = 1000000000000000000n;
const fee = gw.mul_bps_ceil_u64(notional, 25n);
const w = gw.encode_mrnt_rpc_frame(32n, buf, 131n, 42n, notional, fee);
const dec = gw.decode_mrnt_rpc_frame(32n, buf);
if (w !== 32n || fee !== 2500000000000000n || dec.tag !== 0 || dec.fields[2] !== notional || dec.fields[3] !== fee) {{
  throw new Error("WASM dogfood parity mismatch");
}}
console.log("OK", dec.fields[3].toString());
"""
        node_res = subprocess.run(
            ["node", "--input-type=module", "-e", node_code],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "OK 2500000000000000" in node_res.stdout
