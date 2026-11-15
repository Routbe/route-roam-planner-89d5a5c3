/**
 * Reviewed inputs to the formal RLS verifier (Stap 9). Every entry carries a
 * reason, and the verifier fails on an entry nothing uses, so this file can
 * only shrink by fixing the schema, never by quietly growing.
 */

/** A column names a principal (a user) when it matches this name or carries a FK to a user table. */
export const IDENTITY_COLUMN = /^((.+_)?user_id|owner_id|creator_id|recipient_id|sender_id|author_id|member_id|profile_id|created_by|consumed_by|granted_by|invited_by)$/;
export const USER_TABLES = new Set(["users", "profiles", "user"]);
export const WORKSPACE_TABLES = new Set(["workspaces"]);

/**
 * Settings the application sets from the verified session (src/lib/db-context.ts)
 * or that only name the caller. The model reads every one as "the caller"
 * (worst case: the app set it to the authenticated member).
 */
export const IDENTITY_SETTINGS = new Set(["rout.current_user_id", "rout.user_id", "rout.auth_user_id", "app.current_user_id"]);
export const IDENTITY_FUNCTIONS = new Set(["rout_current_user_id", "current_app_user_id", "caller_user_id"]);

/**
 * Public by design. The proof shows these reads are satisfiable for a stranger's
 * row; that is the declassification. Read-only and listed one by one.
 */
export const DECLASSIFIED: ReadonlyArray<{ table: string; cmd: "SELECT"; reason: string }> = [];

/**
 * Tables outside the per-member RLS model. Their rows are reached by the
 * auth adapter before any member identity exists.
 */
export const SERVICE_BOUNDARY: ReadonlyArray<{ schema: string; table: string; reason: string }> = [];

/**
 * Open findings that are known and tracked (HANDOVER appendix Stap 9). The
 * test fails when this list and the verifier's findings differ either way.
 */
export const KNOWN_OPEN: ReadonlyArray<{ id: string; reason: string }> = [];

/**
 * Set-returning SECURITY DEFINER helpers that policies call inside IN (...).
 * Each is modelled by its own SQL body, which is pinned: if the snapshot body
 * changes, the lemma no longer applies and the policy counts as unproven.
 */
export const SRF_LEMMAS: Record<string, { body: string; sql: string; bypassRls: true }> = {
  rout_accessible_tracked_qr_ids: {
    body: `  select t.id from public.tracked_qrs t
   where public.rout_current_user_id() is not null
     and (t.user_id = public.rout_current_user_id()
          or (t.workspace_id is not null and public.rout_is_workspace_member(t.workspace_id)))`,
    sql: "SELECT t.id FROM tracked_qrs t WHERE ((rout_current_user_id() IS NOT NULL) AND ((t.user_id = rout_current_user_id()) OR ((t.workspace_id IS NOT NULL) AND rout_is_workspace_member(t.workspace_id))))",
    bypassRls: true,
  },
};

/**
 * Views created WITH (security_invoker = true). The snapshot has no view
 * options, so the replay test compares this list with pg_class.reloptions.
 */
export const INVOKER_VIEWS: ReadonlySet<string> = new Set(["public.grid_items", "public.ingest_tokens"]);
