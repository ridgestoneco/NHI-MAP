"""Azure NHI Crawler — discovers service principals, app registrations,
managed identities, federated credentials, and role assignments."""

import json
import subprocess
import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session

from models import Identity, Credential, CrawlRun

logger = logging.getLogger(__name__)


def _run_az(args: list[str]) -> dict | list:
    """Execute an Azure CLI command and return parsed JSON."""
    cmd = ["az"] + args + ["--output", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
    return json.loads(result.stdout)


def _parse_datetime(value: str) -> Optional[datetime]:
    if not value or value == "N/A":
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def crawl_service_principals(db: Session, account_id: UUID, crawl_run_id: UUID):
    """Crawl all service principals (Application and ManagedIdentity types)."""
    logger.info("Crawling Azure service principals...")
    data = _run_az(["ad", "sp", "list", "--all"])
    count = 0

    for sp in data:
        sp_type = sp.get("servicePrincipalType", "Unknown")

        # Skip human-oriented SPs
        if sp_type in ("SocialIdp",):
            continue

        identity = Identity(
            account_id=account_id,
            crawl_run_id=crawl_run_id,
            provider="azure",
            identity_type="service_principal",
            name=sp.get("displayName", sp.get("appId", "Unknown")),
            unique_id=sp["id"],
            sub_type=sp_type,
            is_active=sp.get("accountEnabled", True),
            cloud_created_at=_parse_datetime(sp.get("createdDateTime", "")),
            extra_data={
                "app_id": sp.get("appId"),
                "app_display_name": sp.get("appDisplayName"),
                "app_owner_org_id": sp.get("appOwnerOrganizationId"),
                "service_principal_names": sp.get("servicePrincipalNames", []),
                "alternative_names": sp.get("alternativeNames", []),
                "tags": sp.get("tags", []),
                "app_role_assignment_required": sp.get("appRoleAssignmentRequired"),
            },
        )
        db.add(identity)
        db.flush()

        # Crawl password credentials
        for pc in sp.get("passwordCredentials", []):
            cred = Credential(
                identity_id=identity.id,
                credential_type="password_credential",
                key_id=pc.get("keyId"),
                display_name=pc.get("displayName"),
                created_at=_parse_datetime(pc.get("startDateTime", "")),
                expires_at=_parse_datetime(pc.get("endDateTime", "")),
                extra_data={"hint": pc.get("hint")},
            )
            db.add(cred)

        # Crawl certificate credentials
        for kc in sp.get("keyCredentials", []):
            cred = Credential(
                identity_id=identity.id,
                credential_type="certificate",
                key_id=kc.get("keyId"),
                display_name=kc.get("displayName"),
                created_at=_parse_datetime(kc.get("startDateTime", "")),
                expires_at=_parse_datetime(kc.get("endDateTime", "")),
                extra_data={
                    "type": kc.get("type"),
                    "usage": kc.get("usage"),
                },
            )
            db.add(cred)

        count += 1

    db.flush()
    logger.info(f"Discovered {count} service principals")
    return count


def crawl_app_registrations(db: Session, account_id: UUID, crawl_run_id: UUID):
    """Crawl app registrations and their credentials + federated creds."""
    logger.info("Crawling Azure app registrations...")
    data = _run_az(["ad", "app", "list", "--all"])
    count = 0

    for app in data:
        app_object_id = app["id"]

        identity = Identity(
            account_id=account_id,
            crawl_run_id=crawl_run_id,
            provider="azure",
            identity_type="app_registration",
            name=app.get("displayName", app.get("appId", "Unknown")),
            unique_id=app_object_id,
            sub_type=app.get("signInAudience", "Unknown"),
            is_active=True,
            cloud_created_at=_parse_datetime(app.get("createdDateTime", "")),
            extra_data={
                "app_id": app.get("appId"),
                "sign_in_audience": app.get("signInAudience"),
                "identifier_uris": app.get("identifierUris", []),
                "publisher_domain": app.get("publisherDomain"),
                "required_resource_access": app.get("requiredResourceAccess", []),
                "redirect_uris": app.get("web", {}).get("redirectUris", []),
            },
        )
        db.add(identity)
        db.flush()

        # Password credentials on app registration
        for pc in app.get("passwordCredentials", []):
            cred = Credential(
                identity_id=identity.id,
                credential_type="password_credential",
                key_id=pc.get("keyId"),
                display_name=pc.get("displayName"),
                created_at=_parse_datetime(pc.get("startDateTime", "")),
                expires_at=_parse_datetime(pc.get("endDateTime", "")),
                extra_data={"hint": pc.get("hint")},
            )
            db.add(cred)

        # Certificate credentials on app registration
        for kc in app.get("keyCredentials", []):
            cred = Credential(
                identity_id=identity.id,
                credential_type="certificate",
                key_id=kc.get("keyId"),
                display_name=kc.get("displayName"),
                created_at=_parse_datetime(kc.get("startDateTime", "")),
                expires_at=_parse_datetime(kc.get("endDateTime", "")),
                extra_data={
                    "type": kc.get("type"),
                    "usage": kc.get("usage"),
                },
            )
            db.add(cred)

        # Federated identity credentials
        try:
            fed_creds = _run_az(["ad", "app", "federated-credential", "list", "--id", app_object_id])
            for fc in fed_creds:
                cred = Credential(
                    identity_id=identity.id,
                    credential_type="federated",
                    key_id=fc.get("id"),
                    display_name=fc.get("name"),
                    extra_data={
                        "issuer": fc.get("issuer"),
                        "subject": fc.get("subject"),
                        "audiences": fc.get("audiences", []),
                        "description": fc.get("description"),
                    },
                )
                db.add(cred)
        except subprocess.CalledProcessError:
            logger.warning(f"Could not fetch federated credentials for app {app_object_id}")

        count += 1

    db.flush()
    logger.info(f"Discovered {count} app registrations")
    return count


def crawl_managed_identities(db: Session, account_id: UUID, crawl_run_id: UUID):
    """Crawl user-assigned managed identities."""
    logger.info("Crawling Azure user-assigned managed identities...")
    data = _run_az(["identity", "list"])
    count = 0

    for mi in data:
        identity = Identity(
            account_id=account_id,
            crawl_run_id=crawl_run_id,
            provider="azure",
            identity_type="managed_identity",
            name=mi.get("name", "Unknown"),
            unique_id=mi.get("id", ""),
            sub_type="user_assigned",
            is_active=True,
            extra_data={
                "client_id": mi.get("clientId"),
                "principal_id": mi.get("principalId"),
                "tenant_id": mi.get("tenantId"),
                "resource_group": mi.get("resourceGroup"),
                "location": mi.get("location"),
                "tags": mi.get("tags", {}),
            },
        )
        db.add(identity)
        db.flush()

        # Check for federated credentials on user-assigned MI
        rg = mi.get("resourceGroup")
        mi_name = mi.get("name")
        if rg and mi_name:
            try:
                fed_creds = _run_az([
                    "identity", "federated-credential", "list",
                    "--identity-name", mi_name,
                    "--resource-group", rg,
                ])
                for fc in fed_creds:
                    cred = Credential(
                        identity_id=identity.id,
                        credential_type="federated",
                        key_id=fc.get("id"),
                        display_name=fc.get("name"),
                        extra_data={
                            "issuer": fc.get("issuer"),
                            "subject": fc.get("subject"),
                            "audiences": fc.get("audiences", []),
                        },
                    )
                    db.add(cred)
            except subprocess.CalledProcessError:
                pass

        count += 1

    db.flush()
    logger.info(f"Discovered {count} user-assigned managed identities")
    return count


def crawl_system_assigned_identities(db: Session, account_id: UUID, crawl_run_id: UUID):
    """Discover system-assigned managed identities across all resources."""
    logger.info("Crawling Azure system-assigned managed identities...")
    data = _run_az([
        "resource", "list",
        "--query", "[?identity.principalId!=null].{name:name, principalId:identity.principalId, type:type, identityType:identity.type}",
    ])
    count = 0

    for res in data:
        identity = Identity(
            account_id=account_id,
            crawl_run_id=crawl_run_id,
            provider="azure",
            identity_type="managed_identity",
            name=res.get("name", "Unknown"),
            unique_id=res.get("principalId", ""),
            sub_type="system_assigned",
            is_active=True,
            extra_data={
                "resource_type": res.get("type"),
                "identity_type": res.get("identityType"),
            },
        )
        db.add(identity)
        count += 1

    db.flush()
    logger.info(f"Discovered {count} system-assigned managed identities")
    return count


def crawl_role_assignments(db: Session, account_id: UUID, crawl_run_id: UUID):
    """Crawl role assignments for service principals — stored as extra_data updates on existing identities."""
    logger.info("Crawling Azure NHI role assignments...")
    data = _run_az([
        "role", "assignment", "list", "--all",
        "--query", "[?principalType=='ServicePrincipal']",
    ])

    # Build a map of principalId -> list of assignments
    assignments_by_principal: dict[str, list] = {}
    for ra in data:
        pid = ra.get("principalId", "")
        if pid not in assignments_by_principal:
            assignments_by_principal[pid] = []
        assignments_by_principal[pid].append({
            "role": ra.get("roleDefinitionName"),
            "scope": ra.get("scope"),
            "created_on": ra.get("createdOn"),
        })

    # Update identities that match
    updated = 0
    for pid, assignments in assignments_by_principal.items():
        existing = db.query(Identity).filter(
            Identity.crawl_run_id == crawl_run_id,
            Identity.unique_id == pid,
        ).first()
        if existing and existing.extra_data:
            meta = dict(existing.extra_data)
            meta["role_assignments"] = assignments
            existing.extra_data = meta
            updated += 1

    db.flush()
    logger.info(f"Enriched {updated} identities with role assignments")
    return 0  # These aren't new identities


def run_full_crawl(db: Session, account_id: UUID, crawl_run: CrawlRun):
    """Run all Azure crawlers for an account."""
    total = 0
    total += crawl_service_principals(db, account_id, crawl_run.id)
    total += crawl_app_registrations(db, account_id, crawl_run.id)
    total += crawl_managed_identities(db, account_id, crawl_run.id)
    total += crawl_system_assigned_identities(db, account_id, crawl_run.id)
    crawl_role_assignments(db, account_id, crawl_run.id)
    return total
