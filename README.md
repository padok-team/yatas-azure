<p align="center">
<img src="docs/auditory.png" alt="yatas-logo" width="30%">
<p align="center">

# YATAS — Azure plugin

Yet Another Testing &amp; Auditing Solution

`yatas-azure` is a [YATAS](https://github.com/padok-team/yatas) plugin that audits **Azure subscriptions**, the same way [yatas-aws](https://github.com/padok-team/yatas-aws) audits AWS accounts.

**Phase 1 ships the 25 checks tagged `HDS`** (Hébergeur de Données de Santé, the French health-data-hosting certification). Run only those with `yatas --hds`.

## Getting started

1. Build and install the plugin locally:
   ```bash
   make install
   ```
2. Create a `.yatas.yml` (see [`.yatas.example.yml`](.yatas.example.yml)):
   ```yaml
   plugins:
     - name: "azure"
       enabled: true
       source: "github.com/padok-team/yatas-azure"
       version: "local"

   pluginsConfiguration:
     - pluginName: "azure"
       accounts:
         - name: "prod"
           subscription_id: "00000000-0000-0000-0000-000000000000"
           # tenant_id: "..."        # optional
           # resource_group: "..."   # optional: audit one resource group only
   ```
3. Authenticate (see [Authentication](#authentication)) and run `yatas --hds`.

## Authentication

The plugin uses [`DefaultAzureCredential`](https://learn.microsoft.com/azure/developer/go/sdk/authentication/credential-chains#defaultazurecredential-overview): environment variables (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` / `AZURE_CLIENT_CERTIFICATE_PATH`, `AZURE_TENANT_ID`), workload identity, managed identity, or a local `az login`. Nothing is hand-rolled.

If authentication or a permission fails, the affected checks report **`FAIL` with "Unable to evaluate: …"** and the error is logged. A failure is never reported as compliant.

### Azure RBAC (ARM checks)

Assign these built-in roles to the identity, **scoped to each audited subscription**:

| Role | Why |
| --- | --- |
| `Reader` | List networks, storage, disks, SQL/PostgreSQL/MySQL, Cosmos DB, AKS, CDN/Front Door, backup vaults, role assignments |
| `Security Reader` | Read Microsoft Defender for Cloud plans |

### ⚠️ Microsoft Entra ID (Graph) — extra setup

The `entra` checks (`AZURE_ENT_*`) read **Entra ID through Microsoft Graph, not ARM**. An Azure `Reader` role (including via Azure PIM) is not enough, and there is no ARM equivalent. Pick one of two ways to give the identity Entra access:

**A. Signed-in user (`az login`), no app registration.** The user needs an **Entra directory role**, activated in PIM → *Microsoft Entra roles* (separate from Azure RBAC PIM). Guests (B2B) have no directory access by default and get `403` without one.
- Simplest: `Global Reader`.
- Least privilege: `Directory Readers` + `Reports Reader` (the MFA registration report also needs Entra ID P1/P2).

**B. App registration (service principal), for unattended runs.** Grant it these Microsoft Graph **application** permissions and have a tenant administrator grant admin consent:

| Permission | Used for |
| --- | --- |
| `Application.Read.All` | service principals, app registrations (`AZURE_ENT_001`, `AZURE_ENT_004`) |
| `User.Read.All`, `GroupMember.Read.All` | resolve users and expand assigned groups (`AZURE_ENT_002`, `AZURE_ENT_003`) |
| `AuditLog.Read.All` | MFA registration report (`AZURE_ENT_002`, requires Entra ID P1 or P2) |
| `UserAuthenticationMethod.Read.All` | per-user MFA methods, fallback without P1 (`AZURE_ENT_002`) |
| `Policy.Read.All` | Security Defaults and Conditional Access (`AZURE_ENT_002`) |
| `Domain.Read.All` | verified domains (`AZURE_ENT_003`) |
| `Directory.Read.All` | lockout settings (`AZURE_ENT_003`) |

**IAM checks are scoped to the subscription.** `AZURE_ENT_*` only evaluate the identities holding a role assignment that applies to the audited subscription (assigned on it, above it, or on a resource group or resource inside it): users directly assigned, members of assigned groups (expanded), and assigned service principals. They never sweep the whole tenant. Guests with access are evaluated too. Their MFA is usually registered in their home tenant, so a guest failure message asks to check that the home tenant enforces MFA or is trusted through cross-tenant access settings. Guests don't count in the password-policy check: their password policy is their home tenant's.

**MFA** (`AZURE_ENT_002`) is decided from several sources, strongest first. A user passes as soon as one covers them, and the message names which:
1. **Azure Policy**: both built-in definitions *Users must authenticate with multi-factor authentication to create or update resources* (`4e6c27d5-…`) and *…to delete resources* (`db4a9d17-…`) assigned in **Deny** mode with no resource selector or `notScopes` limit. Needs only `Reader` (ARM), no Graph. Audit mode does not enforce and does not count.
2. **Security Defaults** enabled (Graph `Policy.Read.All`).
3. An enabled **Conditional Access** policy requiring MFA (or an authentication strength) for *all users* on *all apps or Azure Management*, with no location, risk, platform or device narrowing, and not excluding the user, their groups or any role (Graph `Policy.Read.All`).
4. The user **registered an MFA method**: registration report (Entra ID P1+, `AuditLog.Read.All`), else each user's authentication methods (`UserAuthenticationMethod.Read.All`, no premium licence). Only read for users sources 1 to 3 don't cover.

If a source can't be read (permission, licence), the failure says so ("MFA could not be confirmed (…)") and never passes. "Nothing enforces it" is reported only when every source was readable. Microsoft's own [mandatory MFA](https://learn.microsoft.com/entra/identity/authentication/concept-mandatory-multifactor-authentication) for Azure management (since October 2025) is not visible through any API, so it can't count as evidence. The `az login` token of the Azure CLI carries neither `Policy.Read.All` (Security Defaults) nor `UserAuthenticationMethod.Read.All`; use an app registration (option B) when you need them.

Without Entra access, `AZURE_ENT_*` fail with `Unable to evaluate … returned 403`; the ARM-only categories are unaffected.

## HDS checks (phase 1)

| ID | Check | Mirrors (yatas-aws) |
| --- | --- | --- |
| `AZURE_NET_001` | One VNet per region in the subscription | VPC can't be in the same account |
| `AZURE_NET_002` | VNets have private and public subnets | VPCs have private and public subnets |
| `AZURE_NET_003` | VNets have at least 2 subnets | VPC have at least 2 subnets |
| `AZURE_NET_004` | VMs of a VNet span ≥ 2 availability zones | VPC's subnets are in different zones |
| `AZURE_NET_005` | VNet / NSG flow logs enabled | VPC Flow Logs are activated |
| `AZURE_STO_001` | Storage accounts: CMK or infrastructure encryption | S3 are encrypted |
| `AZURE_DSK_001` | Managed disks encrypted with a CMK | EC2's volumes are encrypted |
| `AZURE_DSK_002` | Disk snapshots encrypted with a CMK | EC2's snapshots are encrypted |
| `AZURE_BCK_001` | VM backup recovery point < 24h | EC2's snapshots are younger than a day old |
| `AZURE_SQL_001` | SQL / PostgreSQL / MySQL deny public access | RDS aren't publicly accessible |
| `AZURE_SQL_002` | TDE enabled (Azure SQL) | RDS are encrypted |
| `AZURE_SQL_003` | PITR retention ≥ 7 days | RDS are backed up with PITR |
| `AZURE_SQL_004` | No `0.0.0.0–255.255.255.255` / "Allow Azure services" firewall rule | RDS have properly restricted security groups |
| `AZURE_SQL_005` | Minor versions updated automatically | RDS have minor versions automatically updated |
| `AZURE_DEF_001` | Defender for Cloud **threat protection** plans on | GuardDuty is enabled |
| `AZURE_DEF_002` | Azure Policy assignment applies to the subscription | AWS Config is enabled |
| `AZURE_AKS_001` | AKS API server private or restricted to authorized IPs | EKS clusters have private endpoint |
| `AZURE_COS_001` | Cosmos DB encrypted with a CMK | Dynamodbs are encrypted |
| `AZURE_COS_002` | Cosmos DB continuous backup (PITR) | Dynamodb have continuous backup with PITR |
| `AZURE_CDN_001` | CDN endpoints / Front Door routes HTTPS only | Cloudfronts only allow HTTPS |
| `AZURE_RBAC_001` | No identity can write role assignments at subscription scope or above | IAM User can't elevate rights |
| `AZURE_ENT_001` | Service principals with access to the subscription have no interactive sign-in credentials | IAM Non-human users don't have console password |
| `AZURE_ENT_002` | Enabled users (members and guests) with access to the subscription have MFA enforced or registered (see below) | IAM Users have 2FA activated |
| `AZURE_ENT_003` | Password expiry ≤ 365 days on the users' managed domains, and smart lockout ≤ 10 | IAM password policy must be defined and enforced |
| `AZURE_ENT_004` | Active secrets / certificates < 90 days old, for apps with access to the subscription | IAM access key younger than 90 days |

### Design decisions worth knowing

- **GuardDuty → Defender for Cloud.** GuardDuty is *threat detection*. Defender for Cloud's workload-protection plans are the Azure equivalent; its CSPM plan only assesses posture. `AZURE_DEF_001` therefore requires the Resource Manager plan (`Arm`) plus at least one workload plan (Servers, SQL, Storage, Containers, Key Vault, App Service, Cosmos DB, open-source databases) on the *Standard* tier.
- **AWS Config → Azure Policy.** `AZURE_DEF_002` asks for at least one Azure Policy assignment (e.g. the Microsoft cloud security benchmark assigned by Defender for Cloud).
- **Encryption at rest is on by default in Azure**, so a check that only tests "enabled" would never fail. The HDS-grade checks (`STO_001`, `DSK_001/002`, `COS_001`) require a **customer-managed key** (or infrastructure encryption for storage).
- **Subnets aren't zonal in Azure**, so `NET_004` evaluates the zone spread of the VMs hosted in each VNet.
- **PostgreSQL/MySQL flexible servers are always patched**; `SQL_005` asks for a custom maintenance window so updates are scheduled and auditable. Azure SQL is platform-patched and passes.
- Use `resource_group` in the target to scope the audit; resources outside it are skipped.

Restricted to what the Azure APIs expose, a few AWS HDS checks (ALB HTTPS-only, bastion audit logs) were **not** part of the phase-1 mapping.

## Architecture

```
Run (main.go)
└── run                  one goroutine per TARGET    (.yatas.yml accounts = Azure subscriptions)
    └── initTest         one goroutine per CATEGORY  (checks/<category>/)
        └── RunChecks    one goroutine per CHECK
            └── checkIf...  emits OK/FAIL Results
```

- **`internal/`**: `Target` (subscription), `Session` (`azcore.TokenCredential`), `UnmarshalConfig`, a thin Microsoft Graph client, and the `Fetched[T]` helper that carries a getter's error to the check.
- **`checks/<category>/`**: `getter.go` (all SDK calls, returns plain structs), `<category>.go` (`RunChecks`), `checks.go` or `<check>.go` (pure predicates), `*_test.go` (a passing and a failing case per check).

Categories: `network`, `storage`, `disks`, `backup`, `sql`, `defender`, `aks`, `cosmosdb`, `cdn`, `rbac`, `entra`.

### Add a check

1. Add the predicate in the category (a pure function over the structs returned by the getter), with a new, never-reused ID.
2. Tag it with `internal.NewHDSCheck(...)` **only if** it belongs to the HDS scope. The tag is what `yatas --hds` filters on.
3. Register it with one `go commons.CheckTest(...)` line in `RunChecks`, and add it to `hdsChecks` in `main_test.go`.
4. Add a passing and a failing unit test.

## Exclude / include checks, ignore results

Same as every YATAS plugin:

```yaml
plugins:
  - name: "azure"
    enabled: true
    exclude:
      - AZURE_SQL_005
```

## How to test?

```bash
make test      # unit tests
make install   # then run `yatas --hds` with version: "local"
```

Debug logs: `export YATAS_LOG=debug`.

## How to deploy?

`.github/workflows/release.yml` releases the plugin with [GoReleaser](https://goreleaser.com/) on tag push. The binary must be named `yatas-azure`.

## PR labels

`.github/labeler.yml` labels pull requests per category.
