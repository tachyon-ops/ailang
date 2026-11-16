"""Tests for the Agensi / multi-marketplace verified skill bundles and deterministic zip releases."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile


ROOT_DIR = Path(__file__).resolve().parent.parent
SKILLS_ROOT = ROOT_DIR / "integrations" / "agensi-skills"
RELEASES_DIR = SKILLS_ROOT / "releases"

EXPECTED_SLUGS = [
    "ailang-verified-kernels",
    "defi-verified-math-pack",
    "zero-cve-wire-parsers",
    "z3-spec-mutation-auditor",
    "lockfree-atomic-protocol-verifier",
    "safe-db-migration-auditor",
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_agensi_skill_bundles_verify_and_build_deterministically() -> None:
    script = SKILLS_ROOT / "build_and_verify.py"
    assert script.is_file()

    res1 = subprocess.run(
        [sys.executable, str(script)],
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(res1.stdout)
    assert payload["status"] == "ALL_BUNDLES_VERIFIED_AND_PACKAGED"
    slugs = [b["slug"] for b in payload["bundles"]]
    assert slugs == EXPECTED_SLUGS

    hashes_before = {}
    for slug in EXPECTED_SLUGS:
        zpath = RELEASES_DIR / f"{slug}.zip"
        assert zpath.is_file()
        hashes_before[slug] = _sha256(zpath)
        with zipfile.ZipFile(zpath) as zf:
            names = zf.namelist()
            assert f"{slug}/SKILL.md" in names

    # Second run must produce byte-identical .zip hashes (clean git tree in CI)
    subprocess.run(
        [sys.executable, str(script)],
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        check=True,
    )
    for slug in EXPECTED_SLUGS:
        assert _sha256(RELEASES_DIR / f"{slug}.zip") == hashes_before[slug]
