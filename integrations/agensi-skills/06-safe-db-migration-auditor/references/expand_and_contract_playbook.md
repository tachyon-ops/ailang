# Zero-Downtime Expand-and-Contract SQL Playbook

## 1. Renaming a Column Safely (3 Releases, Zero Downtime)

Never run `ALTER TABLE users RENAME COLUMN full_name TO display_name;` while live
containers still query `full_name`.

1. **Release 1 (Expand):**
   ```sql
   ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT;
   ```
   Update application write paths to write **both** `full_name` and `display_name`,
   and read `COALESCE(display_name, full_name)`.
2. **Backfill (Batched Idempotent Job):**
   Update `display_name = full_name WHERE display_name IS NULL` in chunks of 5,000 rows.
3. **Release 2 (Switch):**
   Switch application reads and writes exclusively to `display_name`.

## 2. Adding a `NOT NULL` or `CHECK` Constraint Without Locking Writes (PostgreSQL)

Instead of scanning the whole table under an `ACCESS EXCLUSIVE` lock:

```sql
ALTER TABLE orders
  ADD CONSTRAINT chk_orders_positive_amount CHECK (amount_cents >= 0) NOT VALID;

-- Acquires only SHARE UPDATE EXCLUSIVE (allows concurrent reads & writes!)
ALTER TABLE orders VALIDATE CONSTRAINT chk_orders_positive_amount;
```
