export type OrganizationStatus = "active" | "suspended";
export type OrganizationRole = "owner" | "admin" | "member";
export type MembershipStatus = "active" | "suspended";

export type AuthenticatedActor = Readonly<{
  userId: string;
  sessionId: string;
  requestId: string;
}>;

export type OrganizationRecord = Readonly<{
  id: string;
  slug: string;
  name: string;
  status: OrganizationStatus;
  createdByUserId: string;
  createdAt: string;
  updatedAt: string;
}>;

export type OrganizationMembershipRecord = Readonly<{
  organizationId: string;
  userId: string;
  role: OrganizationRole;
  status: MembershipStatus;
  createdByUserId: string;
  createdAt: string;
  updatedAt: string;
}>;

export type TenantContext = Readonly<{
  organization: OrganizationRecord;
  membership: OrganizationMembershipRecord;
  actor: AuthenticatedActor;
}>;

export type IdempotentOrganizationResult = Readonly<{
  organization: OrganizationRecord;
  replayed: boolean;
}>;
