# Phoenix Platform Foundation 4.0.0

## Scope

Release 1 Slice A introduces the first multi-tenant platform boundary:

- organizations;
- organization memberships;
- authenticated actor and tenant context;
- repository-enforced tenant filtering;
- idempotent organization creation;
- platform audit events;
- first governed organization and membership API routes.

## Security invariants

- Tenant access is derived from the authenticated session user, never from a body-supplied actor identifier.
- Organization reads join through an active membership.
- Unauthorized and nonexistent organizations return the same `platform_resource_not_found` result.
- Membership creation is authorized inside the repository transaction.
- Only owners and administrators may add members.
- The owner role cannot be assigned through the membership API.
- Organization creation requires a bounded idempotency key.
- Reusing an idempotency key with a different normalized request fails closed.
- Audit metadata excludes email addresses, bearer tokens, and other direct credentials.

## Release boundary

This slice does not yet provide role customization, invitations, ownership transfer, member removal, organization suspension, row-level security, or background expiration cleanup. Those remain explicit future gates.
