import type { Pool } from "pg";

export type IdentityOperationalSnapshot = Readonly<{
  observedAt: string;
  migrationCount: number;
  users: number;
  activeSessions: number;
  passkeys: number;
  activeTotpFactors: number;
  pendingNotifications: number;
  deadLetterNotifications: number;
  staleNotificationLocks: number;
  expiredWebAuthnChallenges: number;
  deniedSecurityEvents: number;
}>;

export class IdentityObservabilityRepository {
  constructor(private readonly pool: Pool) {}

  async snapshot(windowMinutes: number, staleLockSeconds: number): Promise<IdentityOperationalSnapshot> {
    const result = await this.pool.query<Record<string, unknown>>(`
      select
        now() as observed_at,
        (select count(*)::int from phoenix_schema_migrations) as migration_count,
        (select count(*)::int from identity_users) as users,
        (select count(*)::int from identity_sessions where revoked_at is null and idle_expires_at > now() and expires_at > now()) as active_sessions,
        (select count(*)::int from identity_passkeys) as passkeys,
        (select count(*)::int from identity_totp_factors where disabled_at is null) as active_totp_factors,
        (select count(*)::int from identity_notification_outbox where sent_at is null and dead_lettered_at is null) as pending_notifications,
        (select count(*)::int from identity_notification_outbox where dead_lettered_at is not null) as dead_letter_notifications,
        (select count(*)::int from identity_notification_outbox where sent_at is null and dead_lettered_at is null and locked_at is not null and locked_at < now() - ($2::int * interval '1 second')) as stale_notification_locks,
        (select count(*)::int from identity_webauthn_challenges where consumed_at is null and expires_at <= now()) as expired_webauthn_challenges,
        (select count(*)::int from identity_security_events where outcome='denied' and created_at >= now() - ($1::int * interval '1 minute')) as denied_security_events
    `, [windowMinutes, staleLockSeconds]);
    const row = result.rows[0];
    if (!row) throw new Error("identity_observability_query_returned_no_row");
    return {
      observedAt: new Date(String(row.observed_at)).toISOString(),
      migrationCount: Number(row.migration_count),
      users: Number(row.users),
      activeSessions: Number(row.active_sessions),
      passkeys: Number(row.passkeys),
      activeTotpFactors: Number(row.active_totp_factors),
      pendingNotifications: Number(row.pending_notifications),
      deadLetterNotifications: Number(row.dead_letter_notifications),
      staleNotificationLocks: Number(row.stale_notification_locks),
      expiredWebAuthnChallenges: Number(row.expired_webauthn_challenges),
      deniedSecurityEvents: Number(row.denied_security_events),
    };
  }
}

export function snapshotStatus(
  snapshot: IdentityOperationalSnapshot,
  thresholds: Readonly<{ maxDeadLetters: number; maxStaleLocks: number; maxDeniedEvents: number }>,
): "healthy" | "degraded" {
  return snapshot.deadLetterNotifications > thresholds.maxDeadLetters
    || snapshot.staleNotificationLocks > thresholds.maxStaleLocks
    || snapshot.deniedSecurityEvents > thresholds.maxDeniedEvents
    ? "degraded"
    : "healthy";
}

export function prometheusMetrics(snapshot: IdentityOperationalSnapshot, status: "healthy" | "degraded", version: string): string {
  const lines = [
    "# HELP phoenix_identity_operational_health Whether identity operations are healthy (1) or degraded (0).",
    "# TYPE phoenix_identity_operational_health gauge",
    `phoenix_identity_operational_health ${status === "healthy" ? 1 : 0}`,
    "# HELP phoenix_identity_users_total Number of identity users.",
    "# TYPE phoenix_identity_users_total gauge",
    `phoenix_identity_users_total ${snapshot.users}`,
    "# HELP phoenix_identity_active_sessions Number of active sessions.",
    "# TYPE phoenix_identity_active_sessions gauge",
    `phoenix_identity_active_sessions ${snapshot.activeSessions}`,
    "# HELP phoenix_identity_passkeys_total Number of registered passkeys.",
    "# TYPE phoenix_identity_passkeys_total gauge",
    `phoenix_identity_passkeys_total ${snapshot.passkeys}`,
    "# HELP phoenix_identity_active_totp_factors Number of active TOTP factors.",
    "# TYPE phoenix_identity_active_totp_factors gauge",
    `phoenix_identity_active_totp_factors ${snapshot.activeTotpFactors}`,
    "# HELP phoenix_identity_notification_pending Number of pending notification messages.",
    "# TYPE phoenix_identity_notification_pending gauge",
    `phoenix_identity_notification_pending ${snapshot.pendingNotifications}`,
    "# HELP phoenix_identity_notification_dead_letters Number of dead-letter notification messages.",
    "# TYPE phoenix_identity_notification_dead_letters gauge",
    `phoenix_identity_notification_dead_letters ${snapshot.deadLetterNotifications}`,
    "# HELP phoenix_identity_notification_stale_locks Number of stale notification locks.",
    "# TYPE phoenix_identity_notification_stale_locks gauge",
    `phoenix_identity_notification_stale_locks ${snapshot.staleNotificationLocks}`,
    "# HELP phoenix_identity_expired_webauthn_challenges Number of expired unconsumed WebAuthn challenges.",
    "# TYPE phoenix_identity_expired_webauthn_challenges gauge",
    `phoenix_identity_expired_webauthn_challenges ${snapshot.expiredWebAuthnChallenges}`,
    "# HELP phoenix_identity_denied_events_window Number of denied identity events in the configured observation window.",
    "# TYPE phoenix_identity_denied_events_window gauge",
    `phoenix_identity_denied_events_window ${snapshot.deniedSecurityEvents}`,
    "# HELP phoenix_schema_migrations_total Number of applied schema migrations.",
    "# TYPE phoenix_schema_migrations_total gauge",
    `phoenix_schema_migrations_total ${snapshot.migrationCount}`,
    "# HELP phoenix_build_info Build metadata.",
    "# TYPE phoenix_build_info gauge",
    `phoenix_build_info{version=${JSON.stringify(version)}} 1`,
  ];
  return `${lines.join("\n")}\n`;
}
