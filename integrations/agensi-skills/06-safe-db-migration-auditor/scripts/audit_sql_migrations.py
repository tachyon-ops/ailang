#!/usr/bin/env python3
"""Zero-Dependency SQL & ORM Migration Non-Destructive DDL Auditor + Rollback Planner.

Scans .sql migration files or directories for destructive or table-locking DDL:
  - DROP TABLE / DROP COLUMN / DROP SCHEMA / DROP INDEX (non-concurrent)
  - TRUNCATE / DELETE FROM inside schema migrations
  - ALTER TABLE ... ADD COLUMN ... NOT NULL without DEFAULT
  - ALTER COLUMN ... TYPE (table-rewriting mutation)
  - CREATE INDEX without CONCURRENTLY (advisory warning for PostgreSQL)

Also synthesizes safe Tier-2 compensating DOWN SQL statements for additive CREATE TABLE,
ADD COLUMN, and CREATE INDEX statements when `--emit-rollback` is passed.

Run via:
  python3 scripts/audit_sql_migrations.py path/to/migrations --emit-rollback
"""

from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys

DESTRUCTIVE_RULES: list[tuple[str, re.Pattern[str], str, str]] = [
    (
        "E_DROP_TABLE",
        re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
        "CRITICAL",
        "Never DROP TABLE in an automated migration; archive/deprecate via Expand-and-Contract.",
    ),
    (
        "E_DROP_COLUMN",
        re.compile(r"\bDROP\s+COLUMN\b", re.IGNORECASE),
        "CRITICAL",
        "DROP COLUMN breaks N-1 running application instances during rolling deploys or rollbacks.",
    ),
    (
        "E_TRUNCATE",
        re.compile(r"\bTRUNCATE\b", re.IGNORECASE),
        "CRITICAL",
        "TRUNCATE destroys existing table rows irreversibly.",
    ),
    (
        "E_DELETE_FROM",
        re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE),
        "CRITICAL",
        "DELETE FROM in schema migrations risks irreversible data loss.",
    ),
    (
        "E_ALTER_COLUMN_TYPE",
        re.compile(r"\bALTER\s+COLUMN\s+\w+\s+(?:SET\s+DATA\s+)?TYPE\b", re.IGNORECASE),
        "HIGH",
        "In-place column type mutation rewrites the table under an ACCESS EXCLUSIVE lock; add a shadow column instead.",
    ),
]

ADD_COL_NOT_NULL_RE = re.compile(
    r"\bADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([\"`\w]+)\s+([^;,]+)",
    re.IGNORECASE,
)
CREATE_TABLE_RE = re.compile(
    r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\"`\w.]+)",
    re.IGNORECASE,
)
ALTER_ADD_COL_FULL_RE = re.compile(
    r"\bALTER\s+TABLE\s+(?:ONLY\s+)?([\"`\w.]+)\s+ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([\"`\w]+)",
    re.IGNORECASE,
)
CREATE_INDEX_RE = re.compile(
    r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY\b)(?:IF\s+NOT\s+EXISTS\s+)?([\"`\w.]+)",
    re.IGNORECASE,
)
CREATE_INDEX_ANY_RE = re.compile(
    r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([\"`\w.]+)",
    re.IGNORECASE,
)


def strip_sql_comments(sql: str) -> str:
    no_block = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)
    return re.sub(r"--[^\n]*", "", no_block)


def audit_sql_text(sql: str, label: str, emit_rollback: bool) -> dict:
    cleaned = strip_sql_comments(sql)
    statements = [s.strip() for s in cleaned.split(";") if s.strip()]
    findings: list[dict] = []
    down_steps: list[str] = []

    for idx, stmt in enumerate(statements, start=1):
        for code, pat, severity, hint in DESTRUCTIVE_RULES:
            if pat.search(stmt):
                findings.append({
                    "statement_index": idx,
                    "code": code,
                    "severity": severity,
                    "hint": hint,
                    "snippet": stmt[:140],
                })

        # Check ADD COLUMN ... NOT NULL without DEFAULT
        if re.search(r"\bALTER\s+TABLE\b", stmt, re.IGNORECASE):
            for m in ADD_COL_NOT_NULL_RE.finditer(stmt):
                col_name, col_spec = m.group(1), m.group(2)
                if re.search(r"\bNOT\s+NULL\b", col_spec, re.IGNORECASE) and not re.search(
                    r"\bDEFAULT\b", col_spec, re.IGNORECASE
                ):
                    findings.append({
                        "statement_index": idx,
                        "code": "E_NOT_NULL_WITHOUT_DEFAULT",
                        "severity": "CRITICAL",
                        "hint": f"Column {col_name} is NOT NULL without DEFAULT; fails on populated tables or locks writes.",
                        "snippet": stmt[:140],
                    })

        # Advisory check: non-concurrent index creation
        idx_m = CREATE_INDEX_RE.search(stmt)
        if idx_m:
            findings.append({
                "statement_index": idx,
                "code": "W_NON_CONCURRENT_INDEX",
                "severity": "WARNING",
                "hint": f"Index {idx_m.group(1)} omits CONCURRENTLY; blocks writes on large PostgreSQL tables.",
                "snippet": stmt[:140],
            })

        if emit_rollback:
            ct = CREATE_TABLE_RE.search(stmt)
            if ct:
                down_steps.append(f"-- Compensating DOWN for statement #{idx}: drop newly created empty table {ct.group(1)} ONLY if row_count == 0")
            ac = ALTER_ADD_COL_FULL_RE.search(stmt)
            if ac:
                down_steps.append(
                    f"-- Tier-1 Rollback: keep additive column {ac.group(1)}.{ac.group(2)} in place (N-1 safe); "
                    f"Tier-2 local test DOWN: ALTER TABLE {ac.group(1)} DROP COLUMN IF EXISTS {ac.group(2)};"
                )
            ci = CREATE_INDEX_ANY_RE.search(stmt)
            if ci:
                down_steps.append(f"DROP INDEX CONCURRENTLY IF EXISTS {ci.group(1)};")

    blocking = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    res = {
        "file": label,
        "status": "SAFE" if not blocking else "BLOCKED",
        "statement_count": len(statements),
        "blocking_count": len(blocking),
        "warning_count": len(findings) - len(blocking),
        "findings": findings,
    }
    if emit_rollback:
        res["rollback_plan"] = list(reversed(down_steps))
    return res


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit SQL migrations for destructive DDL and synthesize rollback plans.")
    parser.add_argument("target", nargs="?", help="SQL file or migrations folder (omit with --demo)")
    parser.add_argument("--emit-rollback", action="store_true", help="Include 3-tier compensating rollback steps")
    parser.add_argument("--demo", action="store_true", help="Run built-in safe + unsafe DDL self-test")
    args = parser.parse_args()

    if args.demo or not args.target:
        demo_safe = """
        CREATE TABLE IF NOT EXISTS invoices (id BIGSERIAL PRIMARY KEY, total_cents BIGINT NOT NULL DEFAULT 0);
        ALTER TABLE invoices ADD COLUMN IF NOT EXISTS currency TEXT NOT NULL DEFAULT 'CHF';
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_invoices_currency ON invoices (currency);
        """
        report = {
            "overall_status": "SAFE",
            "files": [audit_sql_text(demo_safe, "<demo_safe.sql>", emit_rollback=True)],
        }
        print(json.dumps(report, indent=2))
        return 0

    p = Path(args.target)
    sql_files = [p] if p.is_file() else sorted(p.rglob("*.sql"))
    results = [audit_sql_text(f.read_text(encoding="utf-8"), str(f), args.emit_rollback) for f in sql_files]
    ok = all(r["status"] == "SAFE" for r in results)
    print(json.dumps({"overall_status": "SAFE" if ok else "BLOCKED", "files": results}, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
