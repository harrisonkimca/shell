# Alembic migration

Alembic migrates Shell's database only, never the providers'
([arch §6](../architecture.md#6-data-ownership-and-database-layout)); CI
applies it as a job, expand then contract
([arch §13](../architecture.md#13-operations-baseline)).

1. Change the model in the owning context's `infrastructure/`.
2. `uv run alembic revision --autogenerate -m "<context>: <change>"`.
3. Read and fix the file: autogenerate misses renames, server defaults and
   grants.
4. Write `downgrade()`.
5. Upgrade an empty database to head, then run the tests.

Running code must always read the schema it meets, so a breaking change
takes two pull requests:

1. Expand: add the new column or table, nullable or defaulted; backfill;
   write both, read the new.
2. Contract, once no running code uses the old: drop it.

- A context migrates only its own tables.
- Key users by Shell's UUID; store no address and no personal field outside
  AUTH-PRIVACY-008's list.
- Deactivation retains account rows; forks define lawful deletion and
  retention before launch wherever applicable (spec §15).
- Only features managed PostgreSQL supports: no superuser, no unmanaged
  extensions.
- Grant `shell_app` only what it needs; `audit_log` stays insert and read
  (AUTH-AUDIT-004).
