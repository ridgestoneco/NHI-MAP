# CLI commands for discovering non-human identities on AWS and Azure

**Every machine identity in your cloud — IAM roles, service principals, managed identities, OIDC providers, and more — can be enumerated through specific CLI commands.** This reference covers the exact syntax, realistic JSON output, and critical fields for SIEM ingestion across both AWS and Azure. The commands below form the foundation of a non-human identity (NHI) inventory pipeline: they let you discover, classify, and monitor every application and service credential in your environment. Both platforms require combining multiple commands to build a complete picture, since no single command exposes all NHI types.

---

## AWS: IAM roles and service-linked roles

All IAM roles are inherently non-human identities — they are assumed by services, applications, or federated principals. The `AssumeRolePolicyDocument` reveals *what* can assume each role.

### List all roles

```bash
aws iam list-roles --output json
```

**Important:** `list-roles` does **not** return `Tags`, `RoleLastUsed`, or `PermissionsBoundary`. You must call `get-role` per role for those fields.

```json
{
    "Roles": [
        {
            "Path": "/",
            "RoleName": "EC2-S3-ReadOnly",
            "RoleId": "AROAJ52OTH4H7LEXAMPLE",
            "Arn": "arn:aws:iam::123456789012:role/EC2-S3-ReadOnly",
            "CreateDate": "2023-09-12T19:23:36+00:00",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": { "Service": "ec2.amazonaws.com" },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "MaxSessionDuration": 3600
        },
        {
            "Path": "/aws-service-role/elasticloadbalancing.amazonaws.com/",
            "RoleName": "AWSServiceRoleForElasticLoadBalancing",
            "RoleId": "AROAI4QRP7UFT7EXAMPLE",
            "Arn": "arn:aws:iam::123456789012:role/aws-service-role/elasticloadbalancing.amazonaws.com/AWSServiceRoleForElasticLoadBalancing",
            "CreateDate": "2022-01-15T08:10:22+00:00",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": { "Service": "elasticloadbalancing.amazonaws.com" },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "MaxSessionDuration": 3600
        }
    ]
}
```

### Get full role detail (includes Tags and RoleLastUsed)

```bash
aws iam get-role --role-name EC2-S3-ReadOnly --output json
```

```json
{
    "Role": {
        "Path": "/",
        "RoleName": "EC2-S3-ReadOnly",
        "RoleId": "AROA1234567890EXAMPLE",
        "Arn": "arn:aws:iam::123456789012:role/EC2-S3-ReadOnly",
        "CreateDate": "2023-11-13T16:45:56Z",
        "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22...%7D",
        "Description": "Allows EC2 instances to read S3 buckets",
        "MaxSessionDuration": 3600,
        "PermissionsBoundary": {
            "PermissionsBoundaryType": "Policy",
            "PermissionsBoundaryArn": "arn:aws:iam::123456789012:policy/BoundaryPolicy"
        },
        "Tags": [
            { "Key": "Environment", "Value": "Production" },
            { "Key": "ManagedBy", "Value": "Terraform" }
        ],
        "RoleLastUsed": {
            "LastUsedDate": "2025-12-01T17:14:00Z",
            "Region": "us-east-1"
        }
    }
}
```

Note: the `AssumeRolePolicyDocument` in `get-role` is **URL-encoded** (RFC 3986). In `list-roles`, it is returned as parsed JSON. The `RoleLastUsed` field tracks activity for the trailing **400 days**.

### Service-linked roles

Service-linked roles live under the path `/aws-service-role/` and are auto-created by AWS services. Their permissions cannot be modified. Filter them with:

```bash
aws iam list-roles --path-prefix /aws-service-role/ --output json
```

Common examples include `AWSServiceRoleForElasticLoadBalancing`, `AWSServiceRoleForECS`, `AWSServiceRoleForAutoScaling`, `AWSServiceRoleForRDS`, and `AWSServiceRoleForAccessAnalyzer`. The `Path` encodes the owning service (e.g., `/aws-service-role/ecs.amazonaws.com/`). Service-linked roles are **not** subject to SCPs.

**Critical fields for SIEM ingestion:** `RoleId` (immutable, prefix `AROA`), `Arn`, `RoleName`, `CreateDate`, `AssumeRolePolicyDocument.Statement[].Principal` (identifies which service can assume the role), `RoleLastUsed.LastUsedDate` (via `get-role` only), `Tags` (via `get-role` only), `Path` (identifies service-linked roles).

---

## AWS: IAM users acting as service accounts

AWS has no formal "service account" type. Non-human IAM users are identified by the absence of console access and MFA combined with the presence of active access keys.

### List users

```bash
aws iam list-users --output json
```

```json
{
    "Users": [
        {
            "Path": "/",
            "UserName": "Admin",
            "UserId": "AIDA1111111111EXAMPLE",
            "Arn": "arn:aws:iam::123456789012:user/Admin",
            "CreateDate": "2022-10-16T16:03:09+00:00",
            "PasswordLastUsed": "2025-06-03T18:37:29+00:00"
        },
        {
            "Path": "/service-accounts/",
            "UserName": "cicd-deployer",
            "UserId": "AIDA2222222222EXAMPLE",
            "Arn": "arn:aws:iam::123456789012:user/service-accounts/cicd-deployer",
            "CreateDate": "2023-09-17T19:30:40+00:00"
        }
    ]
}
```

Note that `PasswordLastUsed` is absent/null for users who have never logged in or have no password set — a strong NHI signal.

### Confirm no console access exists

```bash
aws iam get-login-profile --user-name cicd-deployer
```

For a service account, this returns an error: `An error occurred (NoSuchEntity) when calling the GetLoginProfile operation: Login Profile for User cicd-deployer cannot be found.`

### Confirm no MFA is configured

```bash
aws iam list-mfa-devices --user-name cicd-deployer --output json
```

```json
{ "MFADevices": [] }
```

### NHI detection heuristic for IAM users

A user is a non-human identity when **all** of the following are true: has active access keys (`list-access-keys`), has no login profile (`get-login-profile` returns `NoSuchEntity`), has no MFA devices (empty `MFADevices` array), and `PasswordLastUsed` is absent/null.

**Critical fields for SIEM:** `UserId` (prefix `AIDA`), `Arn`, `UserName`, `CreateDate`, `PasswordLastUsed`, `Path`.

---

## AWS: Access keys and usage tracking

### List access keys for a user

```bash
aws iam list-access-keys --user-name cicd-deployer --output json
```

```json
{
    "AccessKeyMetadata": [
        {
            "UserName": "cicd-deployer",
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "Status": "Active",
            "CreateDate": "2023-09-17T19:31:00Z"
        },
        {
            "UserName": "cicd-deployer",
            "AccessKeyId": "AKIAI44QH8DHBEXAMPLE",
            "Status": "Inactive",
            "CreateDate": "2023-06-06T20:42:26Z"
        }
    ]
}
```

Secret access keys are **never returned** — only available at creation time.

### Track last usage of a key

```bash
aws iam get-access-key-last-used --access-key-id AKIAIOSFODNN7EXAMPLE --output json
```

```json
{
    "UserName": "cicd-deployer",
    "AccessKeyLastUsed": {
        "LastUsedDate": "2025-11-16T22:45:00Z",
        "ServiceName": "s3",
        "Region": "us-east-1"
    }
}
```

`ServiceName` and `Region` are `N/A` if the key has never been used. The `AccessKeyId` prefix `AKIA` denotes long-term keys; prefix `ASIA` denotes temporary/STS credentials.

**Critical fields:** `AccessKeyId`, `UserName`, `Status`, `CreateDate` (key age = rotation compliance), `LastUsedDate`, `ServiceName`, `Region`.

---

## AWS: Credential report for bulk NHI discovery

The credential report is the **single most efficient tool** for bulk-identifying non-human IAM users. It produces a CSV covering every IAM user in the account with password, MFA, and access key status in one snapshot.

### Generate and retrieve

```bash
aws iam generate-credential-report
# Wait for State: "COMPLETE"
aws iam get-credential-report --query 'Content' --output text | base64 --decode > credential_report.csv
```

The raw API returns base64-encoded CSV inside a JSON wrapper:

```json
{
    "Content": "dXNlcixhcm4sdXNlcl9jcmVhdGlvbl90aW1lLC...",
    "ReportFormat": "text/csv",
    "GeneratedTime": "2025-12-14T09:16:00+00:00"
}
```

### CSV columns (all 22)

`user`, `arn`, `user_creation_time`, `password_enabled`, `password_last_used`, `password_last_changed`, `password_next_rotation`, `mfa_active`, `access_key_1_active`, `access_key_1_last_rotated`, `access_key_1_last_used_date`, `access_key_1_last_used_region`, `access_key_1_last_used_service`, `access_key_2_active`, `access_key_2_last_rotated`, `access_key_2_last_used_date`, `access_key_2_last_used_region`, `access_key_2_last_used_service`, `cert_1_active`, `cert_1_last_rotated`, `cert_2_active`, `cert_2_last_rotated`.

### Example decoded rows

```csv
cicd-deployer,arn:aws:iam::123456789012:user/service-accounts/cicd-deployer,2023-09-17T19:30:40+00:00,false,N/A,N/A,N/A,false,true,2024-09-17T12:00:00+00:00,2025-12-14T08:00:00+00:00,us-east-1,s3,true,2024-03-01T10:00:00+00:00,2025-12-13T21:00:00+00:00,us-east-1,iam,false,N/A,false,N/A
```

### One-liner to extract NHI users

```bash
aws iam get-credential-report --query 'Content' --output text | \
  base64 --decode | \
  awk -F',' 'NR>1 && $4=="false" && $8=="false" && ($9=="true" || $14=="true") {print $1","$2","$3","$9","$14}'
```

This filters for: `password_enabled=false` AND `mfa_active=false` AND (access_key_1 or access_key_2 active). Reports regenerate at most once every **4 hours**.

---

## AWS: Instance profiles

Instance profiles bridge IAM roles to EC2 instances. Every instance profile is inherently a non-human identity.

```bash
aws iam list-instance-profiles --output json
```

```json
{
    "InstanceProfiles": [
        {
            "Path": "/",
            "InstanceProfileName": "EC2-S3-ReadOnly-Profile",
            "InstanceProfileId": "AIPA1111111111EXAMPLE",
            "Arn": "arn:aws:iam::123456789012:instance-profile/EC2-S3-ReadOnly-Profile",
            "CreateDate": "2023-06-07T21:05:24Z",
            "Roles": [
                {
                    "Path": "/",
                    "RoleName": "EC2-S3-ReadOnly",
                    "RoleId": "AROA2222222222EXAMPLE",
                    "Arn": "arn:aws:iam::123456789012:role/EC2-S3-ReadOnly",
                    "CreateDate": "2023-06-07T20:42:15Z",
                    "AssumeRolePolicyDocument": "<URL-encoded-JSON>"
                }
            ]
        }
    ]
}
```

An instance profile holds at most **one** role; an empty `Roles` array means it is unassociated. Use `get-instance-profile` for Tags. The `InstanceProfileId` prefix is `AIPA`.

**Critical fields:** `InstanceProfileId`, `Arn`, `InstanceProfileName`, `CreateDate`, `Roles[].Arn`, `Roles[].RoleName`.

---

## AWS: OIDC and SAML federation providers

### OIDC providers

```bash
aws iam list-open-id-connect-providers --output json
```

```json
{
    "OpenIDConnectProviderList": [
        { "Arn": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E" },
        { "Arn": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }
    ]
}
```

The list only returns ARNs. Get full detail per provider:

```bash
aws iam get-open-id-connect-provider \
    --open-id-connect-provider-arn arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E
```

```json
{
    "Url": "oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E",
    "ClientIDList": ["sts.amazonaws.com"],
    "ThumbprintList": ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"],
    "CreateDate": "2024-01-21T04:29:09+00:00",
    "Tags": [
        { "Key": "Environment", "Value": "production" }
    ]
}
```

For EKS IRSA, `ClientIDList` is always `["sts.amazonaws.com"]`. The `Url` field omits the `https://` prefix.

### SAML providers

```bash
aws iam list-saml-providers --output json
```

```json
{
    "SAMLProviderList": [
        {
            "Arn": "arn:aws:iam::123456789012:saml-provider/SAMLADFS",
            "ValidUntil": "2026-06-05T22:45:14+00:00",
            "CreateDate": "2024-06-05T22:45:14+00:00"
        }
    ]
}
```

```bash
aws iam get-saml-provider --saml-provider-arn arn:aws:iam::123456789012:saml-provider/SAMLADFS
```

```json
{
    "SAMLProviderUUID": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "SAMLMetadataDocument": "<EntityDescriptor>...XML...</EntityDescriptor>",
    "CreateDate": "2024-06-05T22:45:14+00:00",
    "ValidUntil": "2026-06-05T22:45:14+00:00",
    "Tags": [{ "Key": "IdP", "Value": "ADFS" }]
}
```

**Monitor `ValidUntil`** — expired SAML certificates break federation silently. The `SAMLMetadataDocument` is typically too large for SIEM but should be archived for audit.

**Critical OIDC fields:** `Arn`, `Url`, `ClientIDList`, `ThumbprintList`, `CreateDate`. **Critical SAML fields:** `Arn`, `SAMLProviderUUID`, `ValidUntil`, `CreateDate`.

---

## AWS: STS and assumed role sessions

### Identify the current caller

```bash
aws sts get-caller-identity --output json
```

For an IAM user:

```json
{ "UserId": "AIDACKCEVSQ6C2EXAMPLE", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/DevAdmin" }
```

For an assumed role:

```json
{ "UserId": "AROACKCEVSQ6C2EXAMPLE:session-name", "Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/xaccounts3access/session-name" }
```

This command requires **no IAM permissions** and always works. The ARN pattern distinguishes identity types: `iam::...user/` vs `sts::...assumed-role/`.

### Assume a role

```bash
aws sts assume-role \
    --role-arn arn:aws:iam::123456789012:role/xaccounts3access \
    --role-session-name s3-access-example \
    --duration-seconds 3600
```

```json
{
    "Credentials": {
        "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "SessionToken": "FwoGZXIvYXdzEBYaDHqa0AP6gZaLCMtDtSLIAdsj...",
        "Expiration": "2026-03-08T15:00:00+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROA3XFRBF23GREXAMPLE:s3-access-example",
        "Arn": "arn:aws:sts::123456789012:assumed-role/xaccounts3access/s3-access-example"
    },
    "PackedPolicySize": 6,
    "SourceIdentity": "DevAdmin"
}
```

The `ASIA` prefix on `AccessKeyId` signals temporary credentials. The `AssumedRoleId` format is `ROLE_UNIQUE_ID:SESSION_NAME`. `SourceIdentity` (optional) traces the original caller through role-chaining.

**Critical fields:** `Credentials.AccessKeyId`, `AssumedRoleUser.Arn`, `AssumedRoleUser.AssumedRoleId`, `Credentials.Expiration`, `SourceIdentity`.

---

## AWS: EKS service accounts and IRSA

IAM Roles for Service Accounts (IRSA) lets Kubernetes pods assume IAM roles without long-lived credentials. The chain is: **EKS OIDC provider → IAM role trust policy → Kubernetes ServiceAccount annotation**.

### Discover the cluster OIDC issuer

```bash
aws eks describe-cluster --name production-app-cluster \
    --query "cluster.identity.oidc.issuer" --output text
```

Returns: `https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E`

### Find IRSA-enabled IAM roles

Filter roles whose trust policy references `oidc.eks`:

```bash
aws iam list-roles --output json | \
    jq '.Roles[] | select(.AssumeRolePolicyDocument.Statement[].Principal.Federated // "" | contains("oidc.eks"))'
```

### Example IRSA trust policy

```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {
            "Federated": "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E"
        },
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {
            "StringEquals": {
                "oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E:sub": "system:serviceaccount:kube-system:aws-load-balancer-controller",
                "oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E:aud": "sts.amazonaws.com"
            }
        }
    }]
}
```

The `:sub` condition locks the role to a specific `system:serviceaccount:NAMESPACE:SA_NAME`. The `:aud` condition must be `sts.amazonaws.com`.

### Kubernetes-side annotation

```bash
kubectl get serviceaccounts -A -o json
```

```json
{
    "apiVersion": "v1",
    "kind": "ServiceAccount",
    "metadata": {
        "name": "aws-load-balancer-controller",
        "namespace": "kube-system",
        "annotations": {
            "eks.amazonaws.com/role-arn": "arn:aws:iam::111122223333:role/AmazonEKSLoadBalancerControllerRole"
        }
    }
}
```

**Critical fields:** `cluster.identity.oidc.issuer`, trust policy `Principal.Federated`, `Condition` `:sub` and `:aud` values, K8s annotation `eks.amazonaws.com/role-arn`.

### Key detection patterns across all AWS NHI types

- `AROA` prefix → IAM Role ID
- `AIDA` prefix → IAM User ID
- `AIPA` prefix → Instance Profile ID
- `AKIA` prefix → Long-term access key
- `ASIA` prefix → Temporary/STS credentials
- Path `/aws-service-role/` → Service-linked role
- Trust policy containing `oidc.eks` → IRSA role
- Trust policy action `sts:AssumeRoleWithWebIdentity` → OIDC-federated role
- Trust policy action `sts:AssumeRoleWithSAML` → SAML-federated role

---

## Azure: Service principals

Service principals are the core non-human identity in Azure/Entra ID. Every application, managed identity, and external integration is represented as a service principal.

### List all service principals

```bash
az ad sp list --all --output json
```

The `--all` flag is required — without it, only the first 100 results return. Filter by type to isolate NHI categories:

```bash
# Application-type SPs (app registrations)
az ad sp list --filter "servicePrincipalType eq 'Application'" --output json

# Managed identity SPs
az ad sp list --filter "servicePrincipalType eq 'ManagedIdentity'" --output json
```

```json
[
  {
    "accountEnabled": true,
    "appDisplayName": "my-cicd-pipeline",
    "appId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "appOwnerOrganizationId": "72f988bf-86f1-41af-91ab-2d7cd011db47",
    "appRoleAssignmentRequired": false,
    "createdDateTime": "2025-06-15T10:30:00Z",
    "description": "CI/CD pipeline service principal",
    "displayName": "my-cicd-pipeline",
    "id": "f8e7d6c5-b4a3-2109-8765-43210fedcba9",
    "keyCredentials": [],
    "oauth2PermissionScopes": [
      {
        "adminConsentDisplayName": "Access my-cicd-pipeline",
        "id": "b1c2d3e4-f5a6-7890-bcde-f12345678901",
        "isEnabled": true,
        "type": "User",
        "value": "user_impersonation"
      }
    ],
    "passwordCredentials": [],
    "servicePrincipalNames": [
      "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "https://myapp.azurewebsites.net"
    ],
    "servicePrincipalType": "Application",
    "tags": ["WindowsAzureActiveDirectoryIntegratedApp"],
    "verifiedPublisher": {
      "displayName": null,
      "verifiedPublisherId": null
    }
  }
]
```

The **`servicePrincipalType`** field is the primary classifier: `Application` (standard app SPs), `ManagedIdentity` (system-assigned and user-assigned managed identities), `Legacy`, or `SocialIdp`. The `appOwnerOrganizationId` reveals whether a SP is internal or from an **external tenant** — critical for detecting third-party integrations.

### List credentials (secrets and certificates) on a service principal

```bash
# Password/secret credentials
az ad sp credential list --id a1b2c3d4-e5f6-7890-abcd-ef1234567890 --output json

# Certificate credentials
az ad sp credential list --id a1b2c3d4-e5f6-7890-abcd-ef1234567890 --cert --output json
```

```json
[
  {
    "customKeyIdentifier": null,
    "displayName": "my-secret-1",
    "endDateTime": "2027-03-08T00:42:06Z",
    "hint": "1Zx",
    "keyId": "670007de-a1b2-c3d4-e5f6-789012345678",
    "secretText": null,
    "startDateTime": "2025-03-08T00:42:06Z"
  }
]
```

Actual secret values are **never returned** — only metadata. The `endDateTime` is critical for monitoring credential expiration. Certificate credentials include additional fields: `type` (`AsymmetricX509Cert`) and `usage` (`Verify`).

**Critical fields for SIEM:** `id` (objectId — correlates with sign-in logs), `appId` (client ID used in auth flows), `displayName`, `servicePrincipalType`, `accountEnabled`, `appOwnerOrganizationId` (detect external/multi-tenant), `createdDateTime`, `keyCredentials`/`passwordCredentials` (credential expiration monitoring), `servicePrincipalNames`.

---

## Azure: App registrations

App registrations are the *definition* of an application; service principals are the *instance* in a given tenant. One app registration can spawn service principals in multiple tenants. **Credentials are set on the app registration** and inherited by the SP.

```bash
az ad app list --all --output json
```

```json
[
  {
    "appId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "createdDateTime": "2025-06-15T10:30:00Z",
    "displayName": "my-cicd-pipeline",
    "id": "03ef14b0-ca33-4840-8f4f-d6e91916010e",
    "identifierUris": ["api://a1b2c3d4-e5f6-7890-abcd-ef1234567890"],
    "keyCredentials": [
      {
        "customKeyIdentifier": "A1B2C3D4E5F6...",
        "displayName": "CN=my-cert",
        "endDateTime": "2027-06-15T00:00:00Z",
        "keyId": "890abcde-f123-4567-8901-abcdef123456",
        "startDateTime": "2025-06-15T00:00:00Z",
        "type": "AsymmetricX509Cert",
        "usage": "Verify"
      }
    ],
    "passwordCredentials": [
      {
        "displayName": "my-secret-1",
        "endDateTime": "2027-03-08T00:42:06Z",
        "hint": "1Zx",
        "keyId": "670007de-a1b2-c3d4-e5f6-789012345678",
        "startDateTime": "2025-03-08T00:42:06Z"
      }
    ],
    "publisherDomain": "contoso.com",
    "requiredResourceAccess": [
      {
        "resourceAppId": "00000003-0000-0000-c000-000000000000",
        "resourceAccess": [
          { "id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope" }
        ]
      }
    ],
    "signInAudience": "AzureADMyOrg",
    "web": {
      "homePageUrl": "https://myapp.azurewebsites.net",
      "redirectUris": ["https://myapp.azurewebsites.net/.auth/login/aad/callback"]
    }
  }
]
```

The `signInAudience` field reveals exposure scope: `AzureADMyOrg` (single-tenant), `AzureADMultipleOrgs` (multi-tenant), or `AzureADandPersonalMicrosoftAccount` (broadest). The `requiredResourceAccess` array lists API permissions requested — `resourceAppId` value `00000003-0000-0000-c000-000000000000` is Microsoft Graph.

**Critical fields:** `id`, `appId`, `displayName`, `signInAudience`, `keyCredentials`/`passwordCredentials` (credential expiry), `requiredResourceAccess` (permission scope), `web.redirectUris` (detect suspicious redirect targets), `publisherDomain`, `createdDateTime`.

---

## Azure: Federated identity credentials and workload identity

Federated identity credentials eliminate secrets entirely by establishing trust between an external OIDC provider and an Azure app or managed identity. This is the modern approach for GitHub Actions, Terraform Cloud, AKS workload identity, and cross-cloud federation.

### On app registrations

```bash
az ad app federated-credential list --id <app-object-id> --output json
```

```json
[
  {
    "audiences": ["api://AzureADTokenExchange"],
    "description": "GitHub Actions for production deployment",
    "id": "d4e5f6a7-b8c9-0123-4567-89abcdef0123",
    "issuer": "https://token.actions.githubusercontent.com",
    "name": "github-actions-prod",
    "subject": "repo:contoso-org/my-app:environment:Production"
  },
  {
    "audiences": ["api://AzureADTokenExchange"],
    "description": "AKS workload identity for payments service",
    "id": "e5f6a7b8-c9d0-1234-5678-9abcdef01234",
    "issuer": "https://eastus.oic.prod-aks.azure.com/72f988bf-86f1-41af-91ab-2d7cd011db47/a1b2c3d4-e5f6-7890-abcd-ef1234567890/",
    "name": "aks-payments-workload",
    "subject": "system:serviceaccount:payments:payments-sa"
  },
  {
    "audiences": ["api://AzureADTokenExchange"],
    "description": "Terraform Cloud workspace federation",
    "id": "f6a7b8c9-d0e1-2345-6789-abcdef012345",
    "issuer": "https://app.terraform.io",
    "name": "terraform-cloud-prod",
    "subject": "organization:contoso:project:infra:workspace:production:run_phase:apply"
  }
]
```

### On user-assigned managed identities

```bash
az identity federated-credential list \
  --identity-name myManagedIdentity \
  --resource-group myResourceGroup --output json
```

```json
[
  {
    "audiences": ["api://AzureADTokenExchange"],
    "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/myResourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/myManagedIdentity/federatedIdentityCredentials/aks-workload-fed",
    "issuer": "https://eastus.oic.prod-aks.azure.com/72f988bf-86f1-41af-91ab-2d7cd011db47/a1b2c3d4-e5f6-7890-abcd-ef1234567890/",
    "name": "aks-workload-fed",
    "resourceGroup": "myResourceGroup",
    "subject": "system:serviceaccount:default:workload-identity-sa",
    "type": "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials"
  }
]
```

Maximum **20 federated identity credentials** per app registration or per user-assigned managed identity. Common issuers include GitHub Actions (`token.actions.githubusercontent.com`), AKS OIDC (`{region}.oic.prod-aks.azure.com/...`), Terraform Cloud (`app.terraform.io`), GitLab CI (`gitlab.com`), and Google Cloud (`accounts.google.com`).

**Critical fields:** `issuer` (detect unauthorized external IdPs), `subject` (specific external identity — repo, service account, workspace), `audiences`, `name`, `id`.

---

## Azure: Managed identities — user-assigned and system-assigned

### User-assigned managed identities (centrally listed)

```bash
az identity list --output json
```

```json
[
  {
    "clientId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "id": "/subscriptions/11111111-2222-3333-4444-555555555555/resourcegroups/rg-prod-identity/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uai-app-backend",
    "location": "eastus",
    "name": "uai-app-backend",
    "principalId": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
    "resourceGroup": "rg-prod-identity",
    "tags": { "environment": "production", "team": "platform" },
    "tenantId": "aaaabbbb-cccc-dddd-eeee-ffffgggghhh0",
    "type": "Microsoft.ManagedIdentity/userAssignedIdentities"
  }
]
```

### System-assigned identities (discovered per-resource)

System-assigned identities have **no central listing command**. Discover them across all resources with:

```bash
az resource list --query "[?identity.principalId!=null].{Name:name, principalId:identity.principalId, type:type, identityType:identity.type}" --output json
```

Or per-resource type:

```bash
# VMs
az vm identity show --name myVM --resource-group rg-prod-compute --output json

# App Service
az webapp identity show --name webapp-prod-01 --resource-group rg-prod-apps --output json

# Azure Functions
az functionapp identity show --name func-processor-prod --resource-group rg-prod-functions --output json

# Container Instances
az container show --name ci-worker-prod --resource-group rg-prod-containers --query identity --output json
```

All return the same schema:

```json
{
  "principalId": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "tenantId": "aaaabbbb-cccc-dddd-eeee-ffffgggghhh0",
  "type": "SystemAssigned, UserAssigned",
  "userAssignedIdentities": {
    "/subscriptions/.../providers/Microsoft.ManagedIdentity/userAssignedIdentities/uai-app-backend": {
      "clientId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "principalId": "b2c3d4e5-f6a7-8901-bcde-f12345678901"
    }
  }
}
```

### Managed identities as Entra ID service principals

Every managed identity creates a corresponding service principal with `servicePrincipalType = "ManagedIdentity"`. The `alternativeNames` array on the SP contains the **ARM resource ID** — the key for cross-referencing:

```bash
az ad sp list --all --filter "servicePrincipalType eq 'ManagedIdentity'" --output json
```

```json
[
  {
    "accountEnabled": true,
    "alternativeNames": [
      "isExplicit=False",
      "/subscriptions/.../providers/Microsoft.ManagedIdentity/userAssignedIdentities/uai-app-backend"
    ],
    "appId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "displayName": "uai-app-backend",
    "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
    "servicePrincipalType": "ManagedIdentity"
  }
]
```

**Cross-reference mapping:** `clientId` (from `az identity`) = `appId` (from `az ad sp`). `principalId` (from `az identity`) = `id`/objectId (from `az ad sp`). The ARM resource `id` from `az identity` appears in `alternativeNames` on the Entra SP.

**Critical fields for user-assigned MI:** `clientId`, `principalId`, `tenantId`, `id` (ARM resource ID), `name`, `resourceGroup`, `location`, `tags`. **For system-assigned:** `principalId`, `tenantId`, resource `name`, resource `type`.

---

## Azure: AKS cluster identities and workload identity

AKS clusters use multiple non-human identities: a control-plane identity, a kubelet identity, and optionally workload identities for pods.

### Control plane and kubelet identity

```bash
az aks show --name aks-prod-01 --resource-group rg-prod-aks \
    --query "{identity:identity, identityProfile:identityProfile, oidcIssuerProfile:oidcIssuerProfile}" --output json
```

```json
{
  "identity": {
    "principalId": "f6a7b890-1234-5678-9abc-def012345678",
    "tenantId": "aaaabbbb-cccc-dddd-eeee-ffffgggghhh0",
    "type": "SystemAssigned"
  },
  "identityProfile": {
    "kubeletidentity": {
      "clientId": "44445555-6666-7777-8888-999900001111",
      "objectId": "55556666-7777-8888-9999-000011112222",
      "resourceId": "/subscriptions/.../providers/Microsoft.ManagedIdentity/userAssignedIdentities/aks-prod-01-agentpool"
    }
  },
  "oidcIssuerProfile": {
    "enabled": true,
    "issuerUrl": "https://eastus.oic.prod-aks.azure.com/aaaabbbb-cccc-dddd-eeee-ffffgggghhh0/12345678-abcd-ef01-2345-6789abcdef01/"
  }
}
```

### Kubernetes service account with workload identity

```bash
kubectl get serviceaccounts -A -o json
```

```json
{
  "apiVersion": "v1",
  "kind": "ServiceAccount",
  "metadata": {
    "name": "workload-sa",
    "namespace": "default",
    "annotations": {
      "azure.workload.identity/client-id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "azure.workload.identity/tenant-id": "aaaabbbb-cccc-dddd-eeee-ffffgggghhh0"
    },
    "labels": {
      "azure.workload.identity/use": "true"
    }
  }
}
```

The end-to-end AKS Workload Identity chain is: **user-assigned managed identity** → **federated credential** (trusting AKS OIDC issuer + K8s SA subject) → **Kubernetes ServiceAccount** annotated with `azure.workload.identity/client-id` → **Pod label** `azure.workload.identity/use: "true"`.

---

## Azure: Role assignments for non-human identities

```bash
az role assignment list --all --query "[?principalType=='ServicePrincipal']" --output json
```

```json
[
  {
    "principalId": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
    "principalName": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "principalType": "ServicePrincipal",
    "roleDefinitionName": "Storage Blob Data Contributor",
    "scope": "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-prod-data",
    "createdOn": "2025-01-15T14:22:33.000000+00:00"
  }
]
```

Both managed identities and app service principals appear with `principalType = "ServicePrincipal"`. To distinguish them, cross-reference with `az ad sp show --id <principalId>` and check `servicePrincipalType` (`ManagedIdentity` vs `Application`).

**Critical fields:** `principalId`, `principalType`, `roleDefinitionName`, `scope`, `createdOn`, `condition` (for ABAC conditions).

---

## Planning for SIEM and identity inventory ingestion

Building a complete NHI inventory requires combining multiple command outputs. The table below summarizes the recommended command execution order and the fields most critical for security monitoring.

### AWS ingestion priority

| Identity Type | Primary Command | Key Ingest Fields |
|---|---|---|
| IAM Roles | `list-roles` + `get-role` per role | `RoleId`, `Arn`, `AssumeRolePolicyDocument.Principal`, `RoleLastUsed`, `Tags` |
| Service Users | `get-credential-report` (bulk) | `user`, `arn`, `password_enabled`, `mfa_active`, `access_key_*_active`, `access_key_*_last_used_date` |
| Instance Profiles | `list-instance-profiles` | `InstanceProfileId`, `Arn`, `Roles[].Arn` |
| Access Keys | `list-access-keys` + `get-access-key-last-used` | `AccessKeyId`, `Status`, `CreateDate`, `LastUsedDate`, `ServiceName` |
| OIDC Providers | `list-open-id-connect-providers` + `get-*` | `Arn`, `Url`, `ClientIDList`, `CreateDate` |
| SAML Providers | `list-saml-providers` + `get-*` | `Arn`, `ValidUntil`, `CreateDate` |
| EKS/IRSA | `describe-cluster` + trust policy analysis | `identity.oidc.issuer`, trust `Federated` principal, `:sub` condition |

### Azure ingestion priority

| Identity Type | Primary Command | Key Ingest Fields |
|---|---|---|
| Service Principals | `az ad sp list --all` | `id`, `appId`, `servicePrincipalType`, `accountEnabled`, `appOwnerOrganizationId`, `createdDateTime` |
| App Registrations | `az ad app list --all` | `appId`, `signInAudience`, `keyCredentials`, `passwordCredentials`, `requiredResourceAccess` |
| SP Credentials | `az ad sp credential list` | `keyId`, `endDateTime`, `type` |
| User-Assigned MI | `az identity list` | `clientId`, `principalId`, `tenantId`, ARM `id`, `tags` |
| System-Assigned MI | `az resource list --query "[?identity...]"` | `principalId`, resource `name`, resource `type` |
| Federated Credentials | `az ad app federated-credential list` + `az identity federated-credential list` | `issuer`, `subject`, `audiences`, `name` |
| AKS Identity | `az aks show` | `identity`, `identityProfile.kubeletidentity`, `oidcIssuerProfile.issuerUrl` |
| Role Assignments | `az role assignment list --all` (filter `principalType=='ServicePrincipal'`) | `principalId`, `roleDefinitionName`, `scope`, `createdOn` |

### Recommended batch inventory scripts

**AWS — full NHI snapshot:**
```bash
aws iam generate-credential-report && sleep 10
aws iam get-credential-report --query 'Content' --output text | base64 --decode > cred_report.csv
aws iam list-roles --output json > roles.json
aws iam list-roles --path-prefix /aws-service-role/ --output json > slr.json
aws iam list-instance-profiles --output json > instance_profiles.json
aws iam list-open-id-connect-providers --output json > oidc.json
aws iam list-saml-providers --output json > saml.json
```

**Azure — full NHI snapshot:**
```bash
az ad sp list --all --output json > sp_inventory.json
az ad app list --all --output json > app_inventory.json
az identity list --output json > managed_identities.json
az role assignment list --all --query "[?principalType=='ServicePrincipal']" --output json > nhi_role_assignments.json
az resource list --query "[?identity.principalId!=null]" --output json > system_assigned_resources.json
```

## Conclusion

AWS and Azure take fundamentally different approaches to non-human identity. **AWS splits NHI across roles, users-as-service-accounts, and instance profiles** with no native "service account" type — the credential report is the most efficient bulk-discovery tool. **Azure centralizes NHIs under service principals in Entra ID** where the `servicePrincipalType` field (`Application` vs `ManagedIdentity`) is the primary classifier. Both platforms now support OIDC-based workload identity federation (IRSA for EKS, Workload Identity for AKS) that eliminates long-lived secrets. For SIEM ingestion, the most overlooked data points are credential expiration timestamps (`endDateTime` / `CreateDate` of access keys), the `AssumeRolePolicyDocument` principal analysis on AWS, and the `appOwnerOrganizationId` field on Azure that reveals external tenant integrations. A complete identity inventory requires combining 6-8 CLI commands per platform — no single command captures the full NHI landscape.