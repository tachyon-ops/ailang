#!/usr/bin/env python3
"""End-to-end Validator, AIL/Z3 Prover, Security Pre-Flight Scanner & Zip Packager
for the 6 Agensi / Multi-Marketplace Skill Bundles.
"""

from __future__ import annotations
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent.parent
RELEASES_DIR = ROOT / "releases"
DETERMINISTIC_ZIP_TIME = (2026, 11, 16, 0, 0, 0)

BANNED_SECURITY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("dangerous_shell_rm", re.compile(r"\brm\s+-rf\b")),
    ("pipe_to_shell", re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash|zsh)\b")),
    ("python_eval_exec", re.compile(r"\b(?:eval|exec)\s*\(")),
    ("subprocess_shell_true", re.compile(r"shell\s*=\s*True")),
    ("prompt_injection_phrase", re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE)),
    ("secret_key_literal", re.compile(r"\b(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,})\b")),
]


def parse_frontmatter(skill_md: Path) -> dict[str, str]:
    text = skill_md.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError(f"{skill_md}: Missing YAML frontmatter opening ---")
    end = text.find("\n---\n", 4)
    if end == -1:
        raise ValueError(f"{skill_md}: Missing YAML frontmatter closing ---")
    header = text[4:end]
    name_m = re.search(r"^name:\s*(.+)$", header, re.MULTILINE)
    desc_m = re.search(r"^description:\s*(.+)$", header, re.MULTILINE)
    if not name_m or not desc_m:
        raise ValueError(f"{skill_md}: Frontmatter must contain `name` and `description`")
    return {"name": name_m.group(1).strip(), "size_bytes": str(len(text.encode("utf-8")))}


def run_cmd(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return proc.stdout


def write_deterministic_zip(zip_path: Path, slug: str, sdir: Path, files: list[Path]) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            rel = f.relative_to(sdir)
            arcname = (Path(slug) / rel).as_posix()
            zinfo = zipfile.ZipInfo(filename=arcname, date_time=DETERMINISTIC_ZIP_TIME)
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if f.suffix == ".py" else 0o644
            zinfo.external_attr = (mode & 0xFFFF) << 16
            zf.writestr(zinfo, f.read_bytes())


def main() -> int:
    RELEASES_DIR.mkdir(parents=True, exist_ok=True)
    skill_dirs = sorted(p for p in ROOT.iterdir() if p.is_dir() and p.name[0].isdigit())
    summary: list[dict] = []

    for sdir in skill_dirs:
        skill_md = sdir / "SKILL.md"
        meta = parse_frontmatter(skill_md)

        # 1. Security pre-flight scan across all bundle files
        files = sorted(f for f in sdir.rglob("*") if f.is_file() and "__pycache__" not in f.parts)
        for f in files:
            content = f.read_text(encoding="utf-8")
            for rule_name, pat in BANNED_SECURITY_PATTERNS:
                if pat.search(content):
                    raise RuntimeError(f"Security pre-flight hit `{rule_name}` in {f}")

        # 2. Formally verify any .ail reference kernels with `ail check` + `audit-spec`
        ail_checked: list[str] = []
        for ail_file in sorted(sdir.rglob("*.ail")):
            run_cmd([sys.executable, "-m", "ailang.cli", "check", str(ail_file)])
            run_cmd([sys.executable, "-m", "ailang.cli", "audit-spec", str(ail_file)])
            ail_checked.append(ail_file.name)

        # 3. Execute any standalone Python scripts in `--demo` / `--suite all` mode & verify JSON output
        scripts_tested: list[str] = []
        for py_file in sorted((sdir / "scripts").glob("*.py")) if (sdir / "scripts").exists() else []:
            flag = "--suite" if "verify_defi" in py_file.name else "--demo"
            cmd = [sys.executable, str(py_file)] + ([flag, "all"] if flag == "--suite" else [flag])
            out = run_cmd(cmd)
            parsed = json.loads(out)
            assert parsed, f"Empty JSON from {py_file}"
            scripts_tested.append(py_file.name)

        # 4. Build deterministic portable .zip archive rooted at `<skill-slug>/`
        slug = meta["name"]
        zip_path = RELEASES_DIR / f"{slug}.zip"
        write_deterministic_zip(zip_path, slug, sdir, files)

        summary.append({
            "folder": sdir.name,
            "slug": slug,
            "files_count": len(files),
            "ail_kernels_proven": ail_checked,
            "scripts_verified": scripts_tested,
            "zip_bundle": str(zip_path.relative_to(REPO_ROOT)),
            "zip_bytes": zip_path.stat().st_size,
        })

    print(json.dumps({"status": "ALL_BUNDLES_VERIFIED_AND_PACKAGED", "bundles": summary}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
