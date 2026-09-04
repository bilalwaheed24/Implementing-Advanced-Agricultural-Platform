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

    CERT_READ = "cert:read"
    CERT_ISSUE = "cert:issue"
    CERT_REVOKE = "cert:revoke"

    COMPLIANCE_READ = "compliance:read"
    COMPLIANCE_RUN = "compliance:run"

    BLOCKCHAIN_READ = "blockchain:read"
    AUDIT_READ = "audit:read"

    ADMIN_ALL = "admin:all"


_READ_EVERYTHING = {
    P.USER_READ, P.ORG_READ, P.FARM_READ, P.DEVICE_READ, P.TELEMETRY_READ, P.AI_READ,
    P.ALERT_READ, P.INCIDENT_READ, P.BIOSECURITY_READ, P.GMO_READ, P.SUPPLY_READ,
    P.CERT_READ, P.COMPLIANCE_READ, P.BLOCKCHAIN_READ, P.AUDIT_READ,
}

ROLE_PERMISSIONS: dict[Role, frozenset[P]] = {
    Role.ADMIN: frozenset(set(P)),

    Role.SECURITY_ANALYST: frozenset(_READ_EVERYTHING | {
        P.ALERT_WRITE, P.INCIDENT_WRITE, P.DEVICE_CONTAIN, P.AI_RUN,
    }),

    Role.FARM_OPERATOR: frozenset({
        P.FARM_READ, P.FARM_WRITE, P.DEVICE_READ, P.DEVICE_WRITE, P.DEVICE_CONTAIN,
        P.TELEMETRY_READ, P.TELEMETRY_WRITE, P.AI_READ, P.AI_RUN, P.ALERT_READ, P.ALERT_WRITE,
        P.GMO_READ, P.SUPPLY_READ, P.SUPPLY_WRITE, P.CERT_READ, P.BLOCKCHAIN_READ, P.ORG_READ,
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
        P.INCIDENT_READ, P.BLOCKCHAIN_READ, P.AUDIT_READ, P.ORG_READ,
    }),

    Role.SUPPLY_CHAIN_OPERATOR: frozenset({
        P.SUPPLY_READ, P.SUPPLY_WRITE, P.CERT_READ, P.GMO_READ, P.TELEMETRY_READ,
        P.COMPLIANCE_READ, P.COMPLIANCE_RUN, P.BLOCKCHAIN_READ, P.ALERT_READ, P.AI_READ,
        P.DEVICE_READ, P.ORG_READ,
    }),

    Role.CERTIFIER: frozenset({
        P.CERT_READ, P.CERT_ISSUE, P.CERT_REVOKE, P.SUPPLY_READ, P.GMO_READ,
        P.COMPLIANCE_READ, P.COMPLIANCE_RUN, P.BLOCKCHAIN_READ, P.ALERT_READ, P.AI_READ,
        P.ORG_READ,
    }),

    # Cannot mutate operational data. The only non-read permission is COMPLIANCE_RUN,
    # which computes and stores a report and touches no operational entity.
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

# Roles that must be approved by an administrator before their first login.
APPROVAL_REQUIRED_ROLES = frozenset({
    Role.ADMIN, Role.SECURITY_ANALYST, Role.BIOSAFETY_OFFICER, Role.CERTIFIER, Role.REGULATOR,
})

_WRITE_MARKERS = ("write", "issue", "revoke", "approve", "contain", "review", "run", "all", "submit")


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
