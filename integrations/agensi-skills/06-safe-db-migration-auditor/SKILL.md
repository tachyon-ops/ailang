---
name: safe-db-migration-auditor
description: >-
  Enforce 100% non-destructive, zero-downtime SQL, Prisma, Drizzle, and Alembic
  database migrations using a 5-Gate Expand-and-Contract Firewall and 3-Tier
  Rollback Synthesizer. Blocks DROP TABLE/COLUMN, TRUNCATE, un-defaulted NOT NULL,
  and table-locking DDL before migrations touch staging or production.
---

# 5-Gate Non-Destructive DB Migration & Rollback Verifier

AI coding agents routinely generate migrations containing silent production
time-bombs: `DROP COLUMN` while old app containers are still reading that column,
`ALTER TABLE ... ADD COLUMN ... NOT NULL` without a `DEFAULT` (failing on non-empty
tables), `CREATE INDEX` without `CONCURRENTLY` (locking writes), or destructive ORM
commands like `prisma migrate reset` / `db push --accept-data-loss`.

Use this skill whenever creating, reviewing, or modifying database schemas, SQL
migrations, or seeders.

## Included Deterministic Scanner & Rollback Planner

- `scripts/audit_sql_migrations.py` — Zero-dependency Python 3.11+ static DDL
  auditor and compensating `DOWN` SQL synthesizer:
  ```bash
  python3 scripts/audit_sql_migrations.py path/to/migrations/ --emit-rollback
  ```
- `references/expand_and_contract_playbook.md` — Multi-release zero-downtime
  recipes for renaming columns, changing column types, adding constraints (`NOT VALID`
  + `VALIDATE CONSTRAINT`), and safe additive seeding.

## The 5 Non-Negotiable Safety Gates

1. **Gate 1 — Zero Destructive DDL (`Static DDL Audit`)**
   Never emit `DROP TABLE`, `DROP COLUMN`, `TRUNCATE`, `DELETE FROM` inside schema
   migrations, or `ADD COLUMN ... NOT NULL` without a `DEFAULT`. Run
   `scripts/audit_sql_migrations.py` on every new migration file and require exit
   code `0`.

2. **Gate 2 — Expand-and-Contract Rollout Compatibility (`Tier-1 Code Rollback`)**
   Every migration `M_k` MUST be 100% backward-compatible with the *currently
   running* application release `App_{k-1}` so that rolling back application
   containers requires **zero** emergency database rollback during an incident:
   - **Expand (Release 1):** Add nullable column (or column with `DEFAULT`), dual-write
     in code, backfill in small batches.
   - **Switch (Release 2):** Read from new column, validate `CHECK` constraint using
     `NOT VALID` followed by `VALIDATE CONSTRAINT`.
   - **Contract (Release 3+, explicit human sign-off only):** Stop writing legacy
     column; archive before any eventual cleanup.

3. **Gate 3 — Additive-Only Seeding**
   Runtime seeders MUST use `INSERT ... ON CONFLICT DO NOTHING` / `upsert` create-only
   semantics — never `TRUNCATE` or overwrite live user/tenant rows.

4. **Gate 4 — Compensating `DOWN` SQL & `UP -> DOWN -> RE-UP` Verification**
   Synthesize explicit compensating `DOWN` SQL for every additive migration
   (`--emit-rollback`) and test the full `UP -> DOWN -> RE-UP` cycle against a
   local ephemeral database (`127.0.0.1` / `localhost`) before opening a PR.

5. **Gate 5 — Pre-Migration Logical Backup Hook**
   Ensure CI/CD captures a compressed logical dump (`pg_dump -Fc`) immediately
   prior to applying production migrations.
