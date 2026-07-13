import test from "node:test";
import assert from "node:assert/strict";
import { IdentityService, IdentityError } from "../src/identity/service.js";
import type { IdentityRepository } from "../src/identity/repository.js";
import type { SessionRecord, UserRecord } from "../src/identity/types.js";

class MemoryRepository implements IdentityRepository {
  users: UserRecord[] = [];
  sessions: SessionRecord[] = [];
  async createUser(input: { id: string; email: string; displayName: string; passwordHash: string }): Promise<UserRecord> {
    const now = new Date().toISOString();
    const user: UserRecord = { ...input, status: "active", createdAt: now, updatedAt: now };
    this.users.push(user);
    return user;
  }
  async findUserByEmail(email: string) { return this.users.find(x => x.email === email) ?? null; }
  async findUserById(id: string) { return this.users.find(x => x.id === id) ?? null; }
  async createSession(input: { id: string; userId: string; tokenHash: string; expiresAt: string }) {
    const session: SessionRecord = { ...input, createdAt: new Date().toISOString(), revokedAt: null };
    this.sessions.push(session);
    return session;
  }
  async findActiveSessionByTokenHash(tokenHash: string) {
    return this.sessions.find(x => x.tokenHash === tokenHash && !x.revokedAt && new Date(x.expiresAt) > new Date()) ?? null;
  }
  async revokeSession(tokenHash: string) {
    const index = this.sessions.findIndex(x => x.tokenHash === tokenHash);
    if (index >= 0) this.sessions[index] = { ...this.sessions[index]!, revokedAt: new Date().toISOString() };
  }
}

test("register, authenticate, logout", async () => {
  const repo = new MemoryRepository();
  const service = new IdentityService(repo);
  const created = await service.register({ email: "User@Example.com", displayName: "Phoenix User", password: "strong-password-123" });
  assert.equal(created.user.email, "user@example.com");
  assert.equal((await service.authenticate(created.sessionToken)).id, created.user.id);
  await service.logout(created.sessionToken);
  await assert.rejects(() => service.authenticate(created.sessionToken), (error: unknown) => error instanceof IdentityError && error.code === "session_invalid");
});

test("login rejects wrong password", async () => {
  const repo = new MemoryRepository();
  const service = new IdentityService(repo);
  await service.register({ email: "u@example.com", displayName: "User", password: "strong-password-123" });
  await assert.rejects(() => service.login({ email: "u@example.com", password: "wrong" }), /credentials_invalid/);
});
