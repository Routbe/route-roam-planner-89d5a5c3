-- 0275_rls_non_interference_hardening.sql — Stap 9 (CONTRACT, held in db-pending/ until the owner's GO).
--
-- Found by scripts/formal-rls-verifier.ts on the 0274 schema (db/schema.snapshot.json):
--   F4  public.public_profiles and public.profile_handles are views that run with their owner's
--       rights, and rout_app holds INSERT/UPDATE/DELETE on them. A write through such a view is
--       checked against public.profiles as the owner, so RLS on profiles does not apply: any
--       rout_app session could rewrite or delete another member's profile row.
--   F5  auth.users reads public.users with its owner's rights, so every member's e-mail address
--       and metadata are readable through it although public.users only shows the caller's row.
--
-- Neither view is written by app code or by any function, and no function or app code reads
-- auth.users (checked against the 0274 snapshot and src/). Public reads of public_profiles and
-- profile_handles stay as they are. The view definitions and policies are not changed. Rollback:
-- db-pending/0275_rls_non_interference_hardening_rollback.sql.

revoke insert, update, delete, truncate, references, trigger on public.public_profiles from rout_app, public;
revoke insert, update, delete, truncate, references, trigger on public.profile_handles from rout_app, public;

-- With security_invoker, public.users' own policy (id = rout_current_user_id()) applies to readers of the view.
alter view auth.users set (security_invoker = true);
