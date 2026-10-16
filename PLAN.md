# yatas-azure — Build Plan

Status: phase 1 (HDS) implemented — 25 checks, unit-tested; not yet validated against a real subscription. Companion repo to [yatas-aws](../yatas-aws) and built from [yatas-template](../yatas-template).

## 0. Goal

A new [YATAS](../yatas) plugin that audits Azure subscriptions the same way `yatas-aws` audits AWS
accounts: one Go plugin binary, RPC-registered with the YATAS core, organized as
`checks/<category>/{getter.go, <category>.go, <check>.go, <check>_test.go}`.

**Priority constraint from the user:** build and land the checks tagged `HDS` first — before
breadth. HDS ("Hébergeur de Données de Santé") is a French health-data-hosting certification.
YATAS core already has first-class support for it (`--hds` CLI flag, `Categories: []string{...,
"HDS"}` tag, `report.FilterHDSChecks`) — `yatas-azure` just needs checks that carry the tag
correctly. See §3 for the prioritized list.

## 1. Reference material already in this workspace

- `../yatas-template` — canonical plugin skeleton. Copy it, don't start from scratch.
- `../yatas-aws` — the sibling plugin to mirror in spirit (not line-by-line — Azure's resource
  model differs from AWS's). Same category/check/getter split, same test conventions, same
  `.goreleaser.yml` / GitHub Actions / labeler setup.
- `../yatas/plugins/commons` — the shared types every plugin imports (`Check`, `CheckConfig`,
  `Result`, `CheckTest`, `CheckMacroTest`, `YatasPlugin` RPC glue). Do not vendor or fork this —
  import it like yatas-aws and yatas-template do.
- `../yatas/internal/report/report.go` (`FilterHDSChecks`) and `../yatas/internal/cli/cli.go`
  (`--hds` flag) — confirms the tag string must be the literal `"HDS"`, checked via
  `check.Categories`.

## 2. Architecture (unchanged from the template — do not redesign)

```
Run (main.go)
└── run                     one goroutine per TARGET   (.yatas.yml pluginsConfiguration accounts)
    └── initTest            one goroutine per CATEGORY (checks/<category>/)
        └── RunChecks       one goroutine per CHECK
            └── checkIf...  emits OK/FAIL Results
```

Azure-specific mapping of the template's placeholders:

| Template concept | yatas-aws equivalent | yatas-azure equivalent |
| --- | --- | --- |
| `internal.Target` | `AWS_Account` (account ID, role ARN, region) | `Subscription` — subscription ID, tenant ID, optional resource group scope filter |
| `internal.Session` | `aws.Config` | `azcore.TokenCredential` + per-service SDK clients, scoped to one subscription |
| `initSession` (main.go) | STS `AssumeRole` / static creds | `azidentity.NewDefaultAzureCredential` (supports env vars, managed identity, az-cli login, workload identity — no bespoke auth code needed) |
| `PluginName` | `"aws"` | `"azure"` |
| Check ID prefix | `AWS_<CATEGORY>_<NNN>` | `AZURE_<CATEGORY>_<NNN>` |

Go module: `github.com/padok-team/yatas-azure`. SDK: `github.com/Azure/azure-sdk-for-go/sdk/...`
(the modern `azcore`/`azidentity` + per-resource-provider modules, e.g.
`sdk/resourcemanager/storage/armstorage`, NOT the legacy `Azure/azure-sdk-for-go/services`
tree — the legacy tree is in maintenance mode).

### Target/Session shape (concrete proposal)

```go
// internal/target.go
type Target struct {
    Name           string `yaml:"name"`
    SubscriptionID string `yaml:"subscription_id"`
    TenantID       string `yaml:"tenant_id,omitempty"`   // optional, DefaultAzureCredential covers most cases
    ResourceGroup  string `yaml:"resource_group,omitempty"` // optional: scope audit to one RG instead of the whole subscription
}

type Session struct {
    Target     Target
    Credential azcore.TokenCredential // built once in initSession, reused by every getter
}
```

Each category's `getter.go` constructs its own typed client from `Session.Credential` +
`Session.Target.SubscriptionID` (e.g. `armstorage.NewAccountsClient(subID, cred, nil)`) —
exactly like yatas-aws's getters build `s3.NewFromConfig(s.Config)` per category.

## 3. HDS-priority checklist (phase 1 — build this first)

Derived from every AWS check currently tagged `HDS` in yatas-aws, re-mapped to its closest Azure
resource. This is the phase-1 scope; everything else in yatas-aws's non-HDS checklist is phase 2+
(§4).

| # | AWS check (HDS-tagged) | Azure equivalent check | Azure category folder |
| --- | --- | --- | --- |
| 1 | S3 are encrypted | Storage Accounts use encryption at rest (enabled by default, but check customer-managed key / `infrastructureEncryption` where relevant) | `storage` |
| 2 | AWS Config is enabled in the account | Azure Policy / Microsoft Defender for Cloud is enabled on the subscription | `policy` (or `defender`) |
| 3 | Cloudfronts only allow HTTPS or redirect to HTTPS | Azure Front Door / CDN endpoints enforce HTTPS-only | `cdn` |
| 4 | Dynamodbs are encrypted | Cosmos DB accounts are encrypted (default; check CMK) | `cosmosdb` |
| 5 | Dynamodb have continuous backup enabled with PITR | Cosmos DB continuous backup / PITR enabled | `cosmosdb` |
| 6 | IAM Non-human users don't have console password | Service principals / managed identities don't have interactive sign-in credentials assigned | `entra` (Entra ID / AAD) |
| 7 | IAM Users have 2FA activated | Entra ID users have MFA enforced (via Conditional Access or per-user MFA) | `entra` |
| 8 | IAM User can't elevate rights | No custom RBAC role / assignment allows privilege escalation (`Microsoft.Authorization/roleAssignments/write` at broad scope) | `rbac` |
| 9 | IAM password policy must be defined and enforced | Entra ID password/lockout policy meets baseline (or: federated/passwordless enforced) | `entra` |
| 10 | IAM access key younger than 90 days | Service principal client secrets / certificates rotated within 90 days | `entra` |
| 11 | EKS clusters have private endpoint or strict public access | AKS clusters have private cluster mode enabled or restricted authorized IP ranges | `aks` |
| 12 | GuardDuty is enabled in the account | Microsoft Defender for Cloud (standard tier) enabled on the subscription | `defender` |
| 13 | Aurora RDS aren't publicly accessible / RDS aren't publicly accessible | Azure SQL / PostgreSQL / MySQL flexible servers deny public network access | `sql` (or split `postgresql`/`mysql`) |
| 14 | Aurora RDS are encrypted / RDS are encrypted (Aurora only tagged HDS; plain RDS wasn't) | Azure SQL / PostgreSQL TDE (Transparent Data Encryption) enabled | `sql` |
| 15 | RDS are backedup automatically with PITR / Aurora RDS are backedup automatically with PITR | Azure SQL / PostgreSQL automated backup + PITR retention configured | `sql` |
| 16 | RDS have properly restricted security groups | Azure SQL / DB servers firewall rules don't allow `0.0.0.0-255.255.255.255` (Allow Azure Services = off unless justified) | `sql` |
| 17 | RDS have minor versions automatically updated | Azure SQL / PostgreSQL flexible server auto-minor-version-upgrade enabled | `sql` |
| 18 | EC2's Snapshots are encrypted | Managed Disk snapshots are encrypted (default; check CMK for HDS-grade) | `disks` |
| 19 | EC2's snapshots are younger than a day old | Managed Disk / VM backup recovery points exist within last 24h (Azure Backup) | `backup` |
| 20 | EC2's volumes are encrypted | Managed Disks have encryption-at-rest (SSE) enabled, and encryption-at-host / ADE where required | `disks` |
| 21 | VPC can't be in the same account | Subscription doesn't mix prod/non-prod workloads in a single VNet (or: no unexpected VNet peering across environments) | `network` |
| 22 | VPCs have private and public subnets | VNets segment public-facing subnets (NSG + public IP) from private/backend subnets | `network` |
| 23 | VPC have at least 2 subnets | VNets have at least 2 subnets (network segmentation baseline) | `network` |
| 24 | VPC's Subnets are in different zones | Resources spanning subnets use Availability Zones (zone-redundant deployment) | `network` |
| 25 | VPC Flow Logs are activated | NSG Flow Logs (or VNet Flow Logs, the newer replacement) are enabled | `network` |

This gives phase 1 roughly **7 categories**: `storage`, `policy`/`defender`, `cdn`, `cosmosdb`,
`entra`, `rbac`, `aks`, `sql`, `disks`, `backup`, `network`. Some can be merged (e.g. `policy` +
`defender` → one `defender` category covering both Defender for Cloud and Azure Policy
assignment; `rbac` folded into `entra`) — finalize the split during scaffolding based on how
naturally the SDK clients group (see §5 step 2).

**Open questions to resolve with the user before / during phase 1** (flag, don't block on):
- Azure has no exact "GuardDuty" or "Config" analogue — Defender for Cloud + Azure Policy overlap
  in role. Confirm which one satisfies the HDS auditor's actual requirement before hard-coding it.
- HDS certification in Azure is typically satisfied via Azure's own HDS-qualified regions
  (France Central docs) — worth a "resources are deployed in an HDS-eligible region" check that
  has no AWS analogue at all. Consider adding it as `AZURE_GENERAL_001` or similar.
- Entra ID (AAD) checks (MFA, password policy, privileged roles) require Microsoft Graph API
  permissions, not ARM permissions — this is a different auth/consent flow (`GraphServiceClient`
  from `github.com/microsoftgraph/msgraph-sdk-go`, needs `Directory.Read.All` /
  `UserAuthenticationMethod.Read.All` application permissions granted by a tenant admin). Flag
  this explicitly in the README's setup section — it's the one category that needs extra
  Azure AD app registration steps beyond a standard reader role assignment.

## 4. Phase 2+ — remaining category backlog (breadth, after HDS phase lands)

Mirror the rest of yatas-aws's non-HDS checks, mapped by AWS service → Azure service:

| AWS category | Azure category | Notes |
| --- | --- | --- |
| `acm` | `keyvault-certs` | Key Vault-managed certificates: in use, not expiring soon, valid |
| `apigateway` | `apim` | API Management: logging, tracing, WAF/ACL |
| `autoscaling` | `vmss` | VM Scale Sets: multi-zone, capacity thresholds |
| `cloudfront` | `cdn` | Remaining non-HDS CDN checks: query logging, TLS version, WAF policy |
| `cloudtrail` | `activitylog` | Azure Activity Log: export enabled, retention, multi-region N/A (Azure AL is tenant-wide) |
| `cognito` | `b2c` | Azure AD B2C: self-registration, unauthenticated access — lower priority, only if in use |
| `dynamodb` | `cosmosdb` | Remaining: TTL configuration |
| `ec2` | `vm` | VMs: no public IP, boot diagnostics/monitoring enabled |
| `ecr` | `acr` | Azure Container Registry: encryption, image immutability (retention/lock), image scanning (Defender for Containers) |
| `eks` | `aks` | Remaining: control-plane logging enabled |
| `elb` | `loadbalancer` | Standard LB / App Gateway access logs enabled |
| `guardduty` | `defender` | Remaining: no HIGH severity active alerts |
| `iam` | `entra`/`rbac` | Remaining: stale password/sign-in checks, role elevation for roles (not just users) |
| `lambda` | `functions` | Azure Functions: VNet integration/private, no hard-coded secrets, error rate, no anonymous HTTP trigger |
| `rds` | `sql` | Remaining non-HDS: delete protection (SQL: "protect against accidental deletion" via resource locks), logging to Log Analytics |
| `s3` | `storage` | Remaining: soft delete (S3 versioning analogue), immutability policy (object lock analogue), lifecycle/deletion policy, geo-replication (GRS) status |
| `sqs` | `servicebus`/`storage-queue` | Message retention ≤ 14 days |
| `ssm` (bastion audit logs) | `bastion` | Azure Bastion diagnostic logs shipped to a log destination |
| `volumes` | `disks` | Remaining: unused disks, disk SKU recommendation (Premium SSD v2 analogue to GP3), disks have recent snapshots |
| `vpc` | `network` | Remaining: CIDR size, single NAT/gateway per VNet |

Sequence phase 2 by what's cheapest to add given phase-1 SDK clients already wired up (e.g.
`storage`, `sql`, `network`, `defender` extensions before net-new categories like `apim` or
`functions`).

## 5. Execution steps

1. **Scaffold the repo.**
   - `cp -r yatas-template yatas-azure`, strip `.git`, re-init.
   - Rename per the template's own checklist: `go.mod` module path, `Makefile` binary name,
     `internal/constants.go` `PluginName = "azure"`, `package.json` name/repository,
     `.goreleaser.yml` binary name (must stay prefixed `yatas-` per YATAS's plugin resolution
     rule), `.github/workflows/*`, `README.md`.
   - Delete `checks/example/` once the first real category exists — don't ship it.
   - `go get` the Azure SDK modules as they're needed per category (`azidentity`, `azcore`, then
     one `armXxx` module per resource provider touched).

2. **Build `internal/` (Target, Session, UnmarshalConfig, initSession).**
   - `Target`/`Session` per §2's proposal.
   - `UnmarshalConfig`: same `pluginConfig["pluginName"] == "azure"` → `accounts` → per-entry
     switch pattern as the template, reading `subscription_id`, `tenant_id`, `resource_group`.
   - `initSession` (main.go): `azidentity.NewDefaultAzureCredential(nil)` — do NOT hand-roll auth;
     this one call covers env vars (`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`/`AZURE_TENANT_ID`),
     managed identity, and local `az login` for dev, matching yatas-aws's use of the default AWS
     credential chain.

3. **Land phase-1 categories one at a time**, each as its own PR, each following the template's
   file convention (`getter.go` / `<category>.go` / `<check>.go` + `_test.go` per check). Suggested
   landing order — cheapest/most foundational first:
   1. `network` (VNet/NSG/Flow Logs — 5 HDS checks, one client, no cross-tenant Graph API needed)
   2. `storage` (encryption — 1 HDS check, simple client, good second PR to validate the pattern)
   3. `disks` + `backup` (encryption, snapshot recency — 3 HDS checks)
   4. `sql` (public access, TDE, PITR, firewall, auto-upgrade — 5 HDS checks, biggest single win)
   5. `defender` (Defender for Cloud enabled — 1 HDS check, subscription-level, simple)
   6. `aks` (private cluster — 1 HDS check)
   7. `cosmosdb` (encryption, PITR — 2 HDS checks)
   8. `cdn` (HTTPS-only — 1 HDS check)
   9. `entra` + `rbac` (MFA, password policy, privilege escalation, secret rotation — 5 HDS
      checks, saved for last because it needs the separate Graph API app-registration/consent
      step called out in §3's open questions — don't let it block the ARM-only categories)

   For each check: write the `getter.go` fetch, the `checkIf...` predicate, a passing and a
   failing unit test (mock the SDK client interface exactly like `rds/getter_test.go` does with
   `mockGetRdsAPI`), then wire the one `go commons.CheckTest(...)` line into `RunChecks`. Tag every
   check's `InitCheck(...)` categories with `"HDS"` if and only if it's in the §3 table — don't
   over-tag; the flag's value depends on the tag being precise.

4. **Wire `initTest` (main.go)** — add one `go commons.CheckMacroTest(&wg, c, <category>.RunChecks)`
   line per category as it lands, exactly like the template shows.

5. **Docs and config**: update `README.md` (architecture section can mostly copy the template's,
   swap AWS analogies for Azure ones), `.yatas.example.yml` with a realistic `subscription_id`
   example, and add the Entra ID/Graph API prerequisite as its own callout since it deviates from
   "just assign a Reader role" (Azure equivalent of yatas-aws's IAM read-only policy — document
   the minimum ARM role, likely built-in `Reader` plus `Security Reader` for Defender/Policy checks,
   scoped per subscription).

6. **CI**: reuse `yatas-template`'s `.github/workflows/release.yml` (GoReleaser) and
   `codecov.yml` as-is; extend `.github/labeler.yml` with one glob rule per category as they land
   (mirrors yatas-aws's per-service PR labels).

7. **Validate against real YATAS**: `make install`, set `version: "local"` in a test `.yatas.yml`
   pointing at a real (non-prod) Azure subscription, run `yatas --hds` and confirm only the
   phase-1 checks appear and produce correct OK/FAIL results.

## 6. Definition of done for phase 1 (HDS)

- All 25 mapped checks in §3 exist, are unit-tested (pass + fail case each), and carry
  `"HDS"` in their `Categories`.
- `yatas --hds` against a real subscription returns only these checks, with accurate results.
- README documents subscription-level Reader/Security-Reader role requirement and the separate
  Graph API consent step for the `entra` category.
- No check silently no-ops on missing permissions — a Graph/ARM auth failure should surface as a
  logged error (matching `logger.Logger.Error(...)` + empty-slice-return pattern used throughout
  yatas-aws's getters), not a false "compliant" result.
