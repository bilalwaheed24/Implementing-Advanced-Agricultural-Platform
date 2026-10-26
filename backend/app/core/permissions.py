"""Role → permission matrix. Deny by default (Security.md §7).

A permission constant is `domain:action`. Every mutating route MUST declare one;
`tests/security/test_authorization_coverage.py` enforces that mechanically.
"""
from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    FARM_OPERATOR = "FARM_OPERATOR"
    AGRONOMIST = "AGRONOMIST"
    BIOTECH_RESEARCHER = "BIOTECH_RESEARCHER"
    BIOSAFETY_OFFICER = "BIOSAFETY_OFFICER"
    SUPPLY_CHAIN_OPERATOR = "SUPPLY_CHAIN_OPERATOR"
    CERTIFIER = "CERTIFIER"
    REGULATOR = "REGULATOR"


class P(StrEnum):
    """Permission constants."""
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    ORG_READ = "org:read"
    ORG_WRITE = "org:write"

    FARM_READ = "farm:read"
    FARM_WRITE = "farm:write"

    DEVICE_READ = "device:read"
    DEVICE_WRITE = "device:write"
    DEVICE_CONTAIN = "device:contain"          # quarantine / suspend / revoke

    TELEMETRY_READ = "telemetry:read"
    TELEMETRY_WRITE = "telemetry:write"        # satellite scene ingestion by an operator

    AI_READ = "ai:read"
    AI_RUN = "ai:run"

    ALERT_READ = "alert:read"
    ALERT_WRITE = "alert:write"
    INCIDENT_READ = "incident:read"
    INCIDENT_WRITE = "incident:write"

    BIOSECURITY_READ = "biosecurity:read"
    BIOSECURITY_SUBMIT = "biosecurity:submit"
    BIOSECURITY_REVIEW = "biosecurity:review"
    HAZARD_WRITE = "hazard:write"

    GMO_READ = "gmo:read"
    GMO_WRITE = "gmo:write"
    GMO_APPROVE = "gmo:approve"

    SUPPLY_READ = "supply:read"
    SUPPLY_WRITE = "supply:write"
    # Running an integrity check persists a FraudAssessment and updates the batch's
    # integrity_status, so it is a write even though it reads to decide. Kept separate from
    # SUPPLY_WRITE so a role may verify without being able to create batches.
    SUPPLY_VERIFY = "supply:verify"

    CERT_READ = "cert:read"
    CERT_ISSUE = "cert:issue"
    CERT_REVOKE = "cert:revoke"

    COMPLIANCE_READ = "compliance:read"
    COMPLIANCE_RUN = "compliance:run"

    BLOCKCHAIN_READ = "blockchain:read"
    # Raw ledger inspection: blocks, transaction args, write sets and world state. The ledger
    # stores real business payloads (batch quantities, GMO traits, certification subjects), so
    # this is platform-wide business data, not neutral technical metadata, and is separate from
    # BLOCKCHAIN_READ, which every role holds for scoped proof verification.
    BLOCKCHAIN_EXPLORE = "blockchain:explore"
    AUDIT_READ = "audit:read"
    # Anchoring the audit head submits a ledger transaction. Reading the trail must not
    # confer the ability to write to the chain.
    AUDIT_ANCHOR = "audit:anchor"

    ADMIN_ALL = "admin:all"


_READ_EVERYTHING = {
    P.USER_READ, P.ORG_READ, P.FARM_READ, P.DEVICE_READ, P.TELEMETRY_READ, P.AI_READ,
    P.ALERT_READ, P.INCIDENT_READ, P.BIOSECURITY_READ, P.GMO_READ, P.SUPPLY_READ,
    P.CERT_READ, P.COMPLIANCE_READ, P.BLOCKCHAIN_READ, P.BLOCKCHAIN_EXPLORE, P.AUDIT_READ,
}

# Regulated acts that belong to a named specialist role rather than to platform
# administration. Kept as one named set so the exclusion is explicit and testable.
REGULATED_SPECIALIST_PERMISSIONS: frozenset[P] = frozenset({
    P.GMO_APPROVE,            # a regulator's market-access decision
    P.CERT_ISSUE,             # a certifier's attestation about another organisation
    P.BIOSECURITY_REVIEW,     # a biosafety officer's four-eyes release of a blocked record
    P.HAZARD_WRITE,           # curation of the hazard database the screener trusts
})

ROLE_PERMISSIONS: dict[Role, frozenset[P]] = {
    # Platform administration, not regulated authority. ADMIN previously held every
    # permission, which meant one compromised or careless administrator could clear a
    # biosecurity screening, grant a GMO market approval, issue a certification and edit the
    # hazard database — defeating the separation of duties the rest of this table exists to
    # express (audit P2). Those four are the regulated acts of a specialist role, and an
    # administrator who needs one must be granted that role instead. Everything an
    # administrator actually does — identity, membership, approvals of accounts, containment,
    # audit — is unchanged, and ADMIN remains a cross-tenant reader.
    Role.ADMIN: frozenset(set(P) - REGULATED_SPECIALIST_PERMISSIONS),

    Role.SECURITY_ANALYST: frozenset(_READ_EVERYTHING | {
        P.ALERT_WRITE, P.INCIDENT_WRITE, P.DEVICE_CONTAIN, P.AI_RUN,
        P.SUPPLY_VERIFY, P.AUDIT_ANCHOR,
    }),

    # INCIDENT_READ: a farm operator is notified of, and contains, incidents about its own
    # devices; it could already read the alerts behind them. Not cross-tenant, so
    # repositories.visible() scopes every incident read to the operator's organisation.
    Role.FARM_OPERATOR: frozenset({
        P.FARM_READ, P.FARM_WRITE, P.DEVICE_READ, P.DEVICE_WRITE, P.DEVICE_CONTAIN,
        P.TELEMETRY_READ, P.TELEMETRY_WRITE, P.AI_READ, P.AI_RUN, P.ALERT_READ, P.ALERT_WRITE,
        P.INCIDENT_READ,
        P.GMO_READ, P.SUPPLY_READ, P.SUPPLY_WRITE, P.SUPPLY_VERIFY, P.CERT_READ,
        P.BLOCKCHAIN_READ, P.ORG_READ,
    }),

    Role.AGRONOMIST: frozenset({
        P.FARM_READ, P.DEVICE_READ, P.TELEMETRY_READ, P.AI_READ, P.AI_RUN,
        P.ALERT_READ, P.GMO_READ, P.SUPPLY_READ, P.BLOCKCHAIN_READ, P.ORG_READ,
    }),

    Role.BIOTECH_RESEARCHER: frozenset({
        P.BIOSECURITY_READ, P.BIOSECURITY_SUBMIT, P.GMO_READ, P.GMO_WRITE, P.AI_READ, P.AI_RUN,
        P.SUPPLY_READ, P.BLOCKCHAIN_READ, P.ALERT_READ, P.ORG_READ,
    }),

    # A biosafety officer approves *biosecurity* work (screenings, gene edits). Market
    # access in a jurisdiction is a separate, regulatory act and belongs to REGULATOR:
    # only a regulator organisation can submit gmo_registry.RecordApproval on the ledger.
    Role.BIOSAFETY_OFFICER: frozenset({
        P.BIOSECURITY_READ, P.BIOSECURITY_SUBMIT, P.BIOSECURITY_REVIEW, P.HAZARD_WRITE,
        P.GMO_READ, P.AI_READ, P.AI_RUN, P.ALERT_READ, P.ALERT_WRITE,
        P.INCIDENT_READ, P.BLOCKCHAIN_READ, P.BLOCKCHAIN_EXPLORE, P.AUDIT_READ, P.ORG_READ,
    }),

    # ALERT_WRITE and INCIDENT_READ: COMPLIANCE and FRAUD alerts are routed to this role and
    # filed against batches it holds as custodian (alerts.custodian_org_id), so it must be able
    # to acknowledge and resolve them and follow the incident a HIGH one opens. Both stay
    # tenant-scoped through repositories.visible(). ALERT_WRITE does not reach the alerts in
    # OVERSIGHT_ALERT_CATEGORIES (a DATA_THEFT alert about the user's own account, say), and
    # resolving an alert closes its incident only for a holder of INCIDENT_WRITE (round 4).
    Role.SUPPLY_CHAIN_OPERATOR: frozenset({
        P.SUPPLY_READ, P.SUPPLY_WRITE, P.SUPPLY_VERIFY, P.CERT_READ, P.GMO_READ, P.TELEMETRY_READ,
        P.COMPLIANCE_READ, P.COMPLIANCE_RUN, P.BLOCKCHAIN_READ, P.ALERT_READ, P.ALERT_WRITE,
        P.INCIDENT_READ, P.AI_READ, P.DEVICE_READ, P.ORG_READ,
    }),

    Role.CERTIFIER: frozenset({
        P.CERT_READ, P.CERT_ISSUE, P.CERT_REVOKE, P.SUPPLY_READ, P.SUPPLY_VERIFY, P.GMO_READ,
        P.COMPLIANCE_READ, P.COMPLIANCE_RUN, P.BLOCKCHAIN_READ, P.ALERT_READ, P.AI_READ,
        P.ORG_READ,
    }),

    # Cannot mutate operational data. COMPLIANCE_RUN computes and stores a report and touches
    # no operational entity; GMO_APPROVE is the regulator's one regulated write. Deliberately
    # excludes SUPPLY_VERIFY and AUDIT_ANCHOR, both of which persist state (audit P1).
    Role.REGULATOR: frozenset(_READ_EVERYTHING | {P.COMPLIANCE_RUN, P.GMO_APPROVE}),
}

# Platform-wide oversight roles: permitted to read across organisation boundaries.
# Single source of truth — repositories, request dependencies and notification fan-out
# all import this rather than restating the set (a duplicated definition is how the
# security analyst silently lost visibility of other tenants' alerts).
# Every cross-tenant read through repositories.unscoped() is audit-logged by its caller.
CROSS_TENANT_ROLES = frozenset({
    Role.ADMIN,               # platform administration
    Role.REGULATOR,           # read-only regulatory oversight
    Role.SECURITY_ANALYST,    # security operations across all tenants (PRD.md §11)
    Role.BIOSAFETY_OFFICER,   # biosafety oversight across all tenants (PRD.md §11)
})

# Security operations: the roles that work insider and platform-integrity alerts and run the
# data-theft detector. Narrower than CROSS_TENANT_ROLES (a regulator or biosafety officer reads
# across tenants but does not investigate users' access patterns).
SECURITY_OVERSIGHT_ROLES = frozenset({Role.ADMIN, Role.SECURITY_ANALYST})

# Alert categories only SECURITY_OVERSIGHT_ROLES may acknowledge or resolve, whatever
# alert:write a tenant role holds. A DATA_THEFT alert is filed under the suspect user's own
# organisation, so a colleague, or the suspect, could otherwise see it and clear it (round 4:
# a supply-chain operator resolved "Possible data exfiltration by ..." and the incident closed
# with it). LEDGER alerts are platform integrity, likewise not a tenant's to dismiss.
OVERSIGHT_ALERT_CATEGORIES = frozenset({"DATA_THEFT", "LEDGER"})

# Roles that may READ OVERSIGHT_ALERT_CATEGORIES and their incidents without being able to
# work them. Oversight of the platform is the point of these two roles: a regulator audits how
# the operator handles insider findings and ledger integrity, and a biosafety officer who is
# shown a BIOSECURITY incident but not the DATA_THEFT alert about the same account is being
# asked to judge a containment she cannot see the whole of. Read only, deliberately: the
# acknowledge/resolve gate stays SECURITY_OVERSIGHT_ROLES, so neither role can clear a finding
# or close its incident, and neither is added to the notification fan-out (see
# services/notifications.fan_out) — these alerts are read when they are looked for, not pushed.
OVERSIGHT_ALERT_READER_ROLES = frozenset({Role.REGULATOR, Role.BIOSAFETY_OFFICER})


# Cross-tenant roles whose reach across organisations is limited to certain alert and incident
# categories (round 6). A biosafety officer oversees biosecurity on every tenant, so she reads
# and works BIOSECURITY and DURC alerts (and their incidents) wherever they were raised, but a
# farm's device-health alert or another company's expired certificate is none of her business:
# outside these categories she sees only her own organisation's alerts and incidents. Her audit
# trail is limited the same way: biosecurity entries (AUDIT_CROSS_TENANT_ACTION_PREFIXES) from
# every organisation, everything else from her own organisation only.
#
# DATA_THEFT and LEDGER were added to her reach afterwards, and this deliberately widens what
# round 6 narrowed. Round 6 was about noise and tenancy — a farm's offline sensor and another
# company's expired certificate were never hers to read. These two are the opposite case: the
# owner ruled that platform-integrity and insider findings must be auditable by the oversight
# roles in every organisation, because a biosafety officer who holds a BIOSECURITY incident
# open while a DATA_THEFT alert names the same account is judging a containment with a piece
# missing. It is a read widening only — OVERSIGHT_ALERT_READER_ROLES says why, and the
# acknowledge/resolve gate is untouched, so the round 4 finding (a tenant clearing an alert
# about itself) stays fixed.
CATEGORY_LIMITED_CROSS_TENANT: dict[Role, frozenset[str]] = {
    Role.BIOSAFETY_OFFICER: frozenset({"BIOSECURITY", "DURC", "DATA_THEFT", "LEDGER"}),
}
AUDIT_CROSS_TENANT_ACTION_PREFIXES: dict[Role, tuple[str, ...]] = {
    Role.BIOSAFETY_OFFICER: ("biosecurity.",),
}


def cross_tenant_categories(role: str) -> frozenset[str] | None:
    """The alert categories a category-limited cross-tenant role reads across tenants, or
    None when the role is not limited that way."""
    try:
        return CATEGORY_LIMITED_CROSS_TENANT.get(Role(role))
    except ValueError:
        return None


def is_security_oversight(role: str) -> bool:
    return role in {r.value for r in SECURITY_OVERSIGHT_ROLES}


def may_read_oversight_alerts(role: str) -> bool:
    """Whether `role` may READ OVERSIGHT_ALERT_CATEGORIES. Never a licence to work them:
    acknowledge, resolve and incident assignment all ask is_security_oversight instead."""
    return role in {r.value for r in SECURITY_OVERSIGHT_ROLES | OVERSIGHT_ALERT_READER_ROLES}


# Roles that must be approved by an administrator before their first login.
APPROVAL_REQUIRED_ROLES = frozenset({
    Role.ADMIN, Role.SECURITY_ANALYST, Role.BIOSAFETY_OFFICER, Role.CERTIFIER, Role.REGULATOR,
})

# Public self-registration never grants an effective role. An anonymous request may ask to
# join an organisation, but the account is created PENDING with the least-privileged role and
# stays inert until an administrator approves it and assigns the real role — otherwise anyone
# who can read an organisation id could mint an active member of that tenant.
SELF_REGISTRATION_ROLE = Role.AGRONOMIST

_WRITE_MARKERS = ("write", "issue", "revoke", "approve", "contain", "review", "run", "all",
                  "submit", "anchor", "verify")


def is_write_permission(permission: P) -> bool:
    return any(marker in permission.value.split(":")[1] for marker in _WRITE_MARKERS)


def has_permission(role: str, permission: P) -> bool:
    try:
        return permission in ROLE_PERMISSIONS[Role(role)]
    except (ValueError, KeyError):
        return False


def permissions_for(role: str) -> list[str]:
    try:
        return sorted(p.value for p in ROLE_PERMISSIONS[Role(role)])
    except (ValueError, KeyError):
        return []
