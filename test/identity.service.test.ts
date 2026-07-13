import test from "node:test";
import assert from "node:assert/strict";
import { IdentityService, IdentityError } from "../src/identity/service.js";
import { IdentityRepositoryConflictError, type IdentityRepository } from "../src/identity/repository.js";
import type { SessionRecord, UserRecord } from "../src/identity/types.js";

class MemoryRepository implements IdentityRepository {
  users: UserRecord[] = [];
  sessions: SessionRecord[] = [];
  conflictOnCreate = false;

  async createUser(input: { id: string; email: string; displayName: string; passwordHash: string }): Promise<UserRecord> {
    if (this.conflictOnCreate) throw new IdentityRepositoryConflictError("email");
    const now = new Date().toISOString();
    const user: UserRecord = { ...input, status: "active", createdAt: now, updatedAt: now };
    this.users.push(user);
    return user;
  }
  async findUserByEmail(email: string) { return this.users.find((item) => item.email === email) ?? null; }
  async findUserById(id: string) { return this.users.find((item) => item.id === id) ?? null; }
  async createSession(input: { id: string; userId: string; tokenHash: string; expiresAt: string }) {
    const session: SessionRecord = { ...input, createdAt: new Date().toISOString(), revokedAt: null };
    this.sessions.push(session);
    return session;
  }
  async findActiveSessionByTokenHash(tokenHash: string) {
    return this.sessions.find((item) => item.tokenHash === tokenHash && !item.revokedAt && new Date(item.expiresAt) > new Date()) ?? null;
  }
  async revokeSession(tokenHash: string) {
    const index = this.sessions.findIndex((item) => item.tokenHash === tokenHash);
    if (index >= 0) this.sessions[index] = { ...this.sessions[index]!, revokedAt: new Date().toISOString() };
  }
}

test("register, authenticate, and logout", async () => {
  const repository = new MemoryRepository();
  const service = new IdentityService(repository, { sessionTtlSeconds: 60 });
  const created = await service.register({
    email: "User@Example.com",
    displayName: "Phoenix User",
    password: "strong-password-123"
  });
  assert.equal(created.user.email, "user@example.com");
  assert.equal((await service.authenticate(created.sessionToken)).id, created.user.id);
  const expiry = new Date(repository.sessions[0]!.expiresAt).getTime();
  assert.ok(expiry > Date.now() + 50_000 && expiry <= Date.now() + 61_000);
  await service.logout(created.sessionToken);
  await assert.rejects(
    () => service.authenticate(created.sessionToken),
    (error: unknown) => error instanceof IdentityError && error.code === "session_invalid"
  );
});

test("login rejects wrong password with a generic error", async () => {
  const repository = new MemoryRepository();
  const service = new IdentityService(repository);
  await service.register({ email: "u@example.com", displayName: "User", password: "strong-password-123" });
  await assert.rejects(
    () => service.login({ email: "u@example.com", password: "wrong" }),
    (error: unknown) => error instanceof IdentityError && error.code === "credentials_invalid"
  );
});

test("registration maps a database uniqueness race to a controlled conflict", async () => {
  const repository = new MemoryRepository();
  repository.conflictOnCreate = true;
  const service = new IdentityService(repository);
  await assert.rejects(
    () => service.register({ email: "race@example.com", displayName: "Race", password: "strong-password-123" }),
    (error: unknown) => error instanceof IdentityError && error.code === "registration_unavailable" && error.statusCode === 409
  );
});

test("registration rejects malformed email", async () => {
  const service = new IdentityService(new MemoryRepository());
  await assert.rejects(
    () => service.register({ email: "invalid", displayName: "User", password: "strong-password-123" }),
    (error: unknown) => error instanceof IdentityError && error.code === "email_invalid"
  );
});
