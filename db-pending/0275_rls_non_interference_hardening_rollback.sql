-- Rollback of 0275_rls_non_interference_hardening.sql: restores the 0274 rights exactly.
-- Idempotent. It reopens findings F4 and F5 of the Stap 9 verifier, so use it only to undo a failed rollout.

grant insert, update, delete on public.public_profiles to rout_app;
grant insert, update, delete on public.profile_handles to rout_app;
alter view auth.users reset (security_invoker);
