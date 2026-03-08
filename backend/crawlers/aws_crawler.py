"""AWS NHI Crawler — discovers IAM roles, service-account users, access keys,
instance profiles, OIDC providers, and SAML providers."""

import json
import subprocess
import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session

from models import Identity, Credential, CrawlRun

logger = logging.getLogger(__name__)


def _run_aws(args: list[str], profile: Optional[str] = None) -> dict | list | str:
    """Execute an AWS CLI command and return parsed JSON."""
    cmd = ["aws"] + args + ["--output", "json"]
    if profile:
        cmd += ["--profile", profile]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        # Some commands legitimately fail (e.g. get-login-profile for service accounts)
        raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
    return json.loads(result.stdout)


def _parse_datetime(value: str) -> Optional[datetime]:
    """Parse AWS datetime strings."""
    if not value or value == "N/A":
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def crawl_roles(db: Session, account_id: UUID, crawl_run_id: UUID, profile: Optional[str] = None):
    """Crawl all IAM roles and their details."""
    logger.info("Crawling IAM roles...")
    data = _run_aws(["iam", "list-roles"], profile)
    roles = data.get("Roles", [])
    count = 0

    for role in roles:
        role_name = role["RoleName"]

        # Determine sub_type
        path = role.get("Path", "/")
        sub_type = "service_linked_role" if "/aws-service-role/" in path else "iam_role"

        # Get detailed info (tags, last used)
        try:
            detail = _run_aws(["iam", "get-role", "--role-name", role_name], profile)
            role_detail = detail.get("Role", {})
        except subprocess.CalledProcessError:
            role_detail = role

        last_used = role_detail.get("RoleLastUsed", {})
        assume_policy = role.get("AssumeRolePolicyDocument", {})

        # Detect IRSA / OIDC / SAML from trust policy
        trust_type = _classify_trust_policy(assume_policy)

        identity = Identity(
            account_id=account_id,
            crawl_run_id=crawl_run_id,
            provider="aws",
            identity_type="iam_role",
            name=role_name,
            unique_id=role["Arn"],
            sub_type=sub_type,
            is_active=True,
            cloud_created_at=_parse_datetime(role.get("CreateDate", "")),
            last_used_at=_parse_datetime(last_used.get("LastUsedDate", "")),
            extra_data={
                "role_id": role.get("RoleId"),
                "path": path,
                "description": role_detail.get("Description"),
                "max_session_duration": role.get("MaxSessionDuration"),
                "trust_policy": assume_policy,
                "trust_type": trust_type,
                "tags": role_detail.get("Tags", []),
                "last_used_region": last_used.get("Region"),
                "permission_boundary": role_detail.get("PermissionsBoundary"),
            },
        )
        db.add(identity)
        count += 1

    db.flush()
    logger.info(f"Discovered {count} IAM roles")
    return count


def _classify_trust_policy(policy: dict) -> str:
    """Classify what type of trust a role has."""
    policy_str = json.dumps(policy)
    if "oidc.eks" in policy_str:
        return "irsa"
    if "sts:AssumeRoleWithWebIdentity" in policy_str:
        return "oidc_federation"
    if "sts:AssumeRoleWithSAML" in policy_str:
        return "saml_federation"
    return "standard"


def crawl_users(db: Session, account_id: UUID, crawl_run_id: UUID, profile: Optional[str] = None):
    """Crawl IAM users, detect NHI users (no console, no MFA, has access keys)."""
    logger.info("Crawling IAM users...")
    data = _run_aws(["iam", "list-users"], profile)
    users = data.get("Users", [])
    count = 0

    for user in users:
        username = user["UserName"]

        # Check for NHI signals
        has_console = True
        try:
            _run_aws(["iam", "get-login-profile", "--user-name", username], profile)
        except subprocess.CalledProcessError:
            has_console = False

        mfa_data = _run_aws(["iam", "list-mfa-devices", "--user-name", username], profile)
        has_mfa = len(mfa_data.get("MFADevices", [])) > 0

        keys_data = _run_aws(["iam", "list-access-keys", "--user-name", username], profile)
        access_keys = keys_data.get("AccessKeyMetadata", [])
        has_active_keys = any(k["Status"] == "Active" for k in access_keys)

        is_nhi = not has_console and not has_mfa and has_active_keys
        if not is_nhi:
            continue  # Skip human users

        identity = Identity(
            account_id=account_id,
            crawl_run_id=crawl_run_id,
            provider="aws",
            identity_type="iam_user_service_account",
            name=username,
            unique_id=user["Arn"],
            sub_type="service_account",
            is_active=True,
            cloud_created_at=_parse_datetime(user.get("CreateDate", "")),
            last_used_at=_parse_datetime(user.get("PasswordLastUsed", "")),
            extra_data={
                "user_id": user.get("UserId"),
                "path": user.get("Path"),
                "has_console": has_console,
                "has_mfa": has_mfa,
            },
        )
        db.add(identity)
        db.flush()

        # Store access keys as credentials
        for key in access_keys:
            try:
                usage = _run_aws(
                    ["iam", "get-access-key-last-used", "--access-key-id", key["AccessKeyId"]],
                    profile,
                )
                last_used_info = usage.get("AccessKeyLastUsed", {})
            except subprocess.CalledProcessError:
                last_used_info = {}

            cred = Credential(
                identity_id=identity.id,
                credential_type="access_key",
                key_id=key["AccessKeyId"],
                status=key["Status"],
                created_at=_parse_datetime(key.get("CreateDate", "")),
                last_used_at=_parse_datetime(last_used_info.get("LastUsedDate", "")),
                extra_data={
                    "service_name": last_used_info.get("ServiceName"),
                    "region": last_used_info.get("Region"),
                },
            )
            db.add(cred)

        count += 1

    db.flush()
    logger.info(f"Discovered {count} NHI IAM users")
    return count


def crawl_instance_profiles(db: Session, account_id: UUID, crawl_run_id: UUID, profile: Optional[str] = None):
    """Crawl instance profiles."""
    logger.info("Crawling instance profiles...")
    data = _run_aws(["iam", "list-instance-profiles"], profile)
    profiles = data.get("InstanceProfiles", [])
    count = 0

    for ip in profiles:
        attached_roles = [r["Arn"] for r in ip.get("Roles", [])]
        identity = Identity(
            account_id=account_id,
            crawl_run_id=crawl_run_id,
            provider="aws",
            identity_type="instance_profile",
            name=ip["InstanceProfileName"],
            unique_id=ip["Arn"],
            sub_type="instance_profile",
            is_active=len(attached_roles) > 0,
            cloud_created_at=_parse_datetime(ip.get("CreateDate", "")),
            extra_data={
                "instance_profile_id": ip.get("InstanceProfileId"),
                "path": ip.get("Path"),
                "attached_roles": attached_roles,
            },
        )
        db.add(identity)
        count += 1

    db.flush()
    logger.info(f"Discovered {count} instance profiles")
    return count


def crawl_oidc_providers(db: Session, account_id: UUID, crawl_run_id: UUID, profile: Optional[str] = None):
    """Crawl OIDC identity providers."""
    logger.info("Crawling OIDC providers...")
    data = _run_aws(["iam", "list-open-id-connect-providers"], profile)
    providers = data.get("OpenIDConnectProviderList", [])
    count = 0

    for p in providers:
        arn = p["Arn"]
        try:
            detail = _run_aws([
                "iam", "get-open-id-connect-provider",
                "--open-id-connect-provider-arn", arn
            ], profile)
        except subprocess.CalledProcessError:
            detail = {}

        identity = Identity(
            account_id=account_id,
            crawl_run_id=crawl_run_id,
            provider="aws",
            identity_type="oidc_provider",
            name=detail.get("Url", arn.split("/")[-1]),
            unique_id=arn,
            sub_type="oidc_provider",
            is_active=True,
            cloud_created_at=_parse_datetime(detail.get("CreateDate", "")),
            extra_data={
                "url": detail.get("Url"),
                "client_id_list": detail.get("ClientIDList", []),
                "thumbprint_list": detail.get("ThumbprintList", []),
                "tags": detail.get("Tags", []),
            },
        )
        db.add(identity)
        count += 1

    db.flush()
    logger.info(f"Discovered {count} OIDC providers")
    return count


def crawl_saml_providers(db: Session, account_id: UUID, crawl_run_id: UUID, profile: Optional[str] = None):
    """Crawl SAML identity providers."""
    logger.info("Crawling SAML providers...")
    data = _run_aws(["iam", "list-saml-providers"], profile)
    providers = data.get("SAMLProviderList", [])
    count = 0

    for p in providers:
        arn = p["Arn"]
        try:
            detail = _run_aws([
                "iam", "get-saml-provider", "--saml-provider-arn", arn
            ], profile)
        except subprocess.CalledProcessError:
            detail = {}

        name = arn.split("/")[-1]

        identity = Identity(
            account_id=account_id,
            crawl_run_id=crawl_run_id,
            provider="aws",
            identity_type="saml_provider",
            name=name,
            unique_id=arn,
            sub_type="saml_provider",
            is_active=True,
            cloud_created_at=_parse_datetime(p.get("CreateDate", "")),
            extra_data={
                "valid_until": p.get("ValidUntil"),
                "saml_provider_uuid": detail.get("SAMLProviderUUID"),
                "tags": detail.get("Tags", []),
            },
        )
        db.add(identity)

        # Track the SAML cert expiration as a credential
        if p.get("ValidUntil"):
            cred = Credential(
                identity_id=identity.id,
                credential_type="certificate",
                display_name=f"SAML cert - {name}",
                expires_at=_parse_datetime(p["ValidUntil"]),
                created_at=_parse_datetime(p.get("CreateDate", "")),
            )
            db.add(cred)

        count += 1

    db.flush()
    logger.info(f"Discovered {count} SAML providers")
    return count


def run_full_crawl(db: Session, account_id: UUID, crawl_run: CrawlRun, aws_profile: Optional[str] = None):
    """Run all AWS crawlers for an account."""
    total = 0
    total += crawl_roles(db, account_id, crawl_run.id, aws_profile)
    total += crawl_users(db, account_id, crawl_run.id, aws_profile)
    total += crawl_instance_profiles(db, account_id, crawl_run.id, aws_profile)
    total += crawl_oidc_providers(db, account_id, crawl_run.id, aws_profile)
    total += crawl_saml_providers(db, account_id, crawl_run.id, aws_profile)
    return total
