import test from "node:test";
import assert from "node:assert/strict";
import { verifyOperationsBearer } from "../src/operations/auth.js";
import { prometheusMetrics, snapshotStatus, type IdentityOperationalSnapshot } from "../src/operations/identity-observability.js";

const snapshot: IdentityOperationalSnapshot = { observedAt: new Date(0).toISOString(), migrationCount: 4, users: 2, activeSessions: 3, passkeys: 1, activeTotpFactors: 1, pendingNotifications: 0, deadLetterNotifications: 0, staleNotificationLocks: 0, expiredWebAuthnChallenges: 0, deniedSecurityEvents: 2 };

test("operations bearer comparison and metrics are deterministic", () => {
  const token = Buffer.alloc(32, 7).toString("base64url");
  assert.equal(verifyOperationsBearer(`Bearer ${token}`, token), true);
  assert.equal(verifyOperationsBearer("Bearer wrong", token), false);
  assert.equal(verifyOperationsBearer(undefined, token), false);
  assert.equal(snapshotStatus(snapshot, { maxDeadLetters: 0, maxStaleLocks: 0, maxDeniedEvents: 10 }), "healthy");
  assert.equal(snapshotStatus({ ...snapshot, deadLetterNotifications: 1 }, { maxDeadLetters: 0, maxStaleLocks: 0, maxDeniedEvents: 10 }), "degraded");
  const metrics = prometheusMetrics(snapshot, "healthy", "3.7.1");
  assert.match(metrics, /phoenix_identity_operational_health 1/u);
  assert.match(metrics, /phoenix_build_info\{version="3\.7\.1"\} 1/u);
  assert.doesNotMatch(metrics, /email|token|subject_hash/iu);
});
