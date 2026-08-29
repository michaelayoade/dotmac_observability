<!-- Companion to docs/inventories/observer-as-built.md, same read-only wave,
     2026-08-29. Facts, not mandates. Redacted under ADR-0004: logical names,
     repository revisions and counts only — no resolved endpoint, address,
     port or credential filename appears here. -->

# Provenance ledger — 56 live alert rules, 16 live scrape jobs

Dotmac observability host, live configuration captured read-only 2026-08-29.
**Analysis only.** No rule was repaired, no repository was written to, nothing
was deployed. Everything below is attribution, not remediation.

**Redaction:** resolved hostnames, IP addresses, ports, complete scrape URLs and
credential-file *paths* are omitted. Logical job names, rule names, metric names,
group names, repository names, revisions and secret-file *basenames* appear as-is.
No live alert expression embeds a hostname or address — this was checked
explicitly, and the check found none, so no expression is withheld on that basis.

## Method and its sensitivity proof

Attribution used three independent passes:

1. `git grep -F` for every one of the 56 alert names against `HEAD` of 14 local
   checkouts (`dotmac_sub`, `dotmac_erp`, `dotmac_starter_mt`, `dotmac_integrator`,
   `dotmac_vendor_control_plane`, `dotmac_academy_app`, `dotmac_workspace`,
   `dotmac_cloud`, `dotmac_crm`, `dotmac_observability`, `dotmac_identity_ops`,
   `claude_knowledge`, `dotmac_governance`, `dotmac_backoffice`).
2. A structural YAML comparison of every candidate rule file against the live
   groups, rule-body by rule-body.
3. A Spotlight (`mdfind`) sweep of the whole indexed filesystem for each of the
   56 names, which reaches untracked files, sibling worktrees and any checkout
   outside `~/Downloads/management`.

**Sensitivity proof for pass 3** (a negative result from an unproven detector is
worth nothing): the same query returns 16 hits for `PrepaidCoverageRepairFailed`
and 1 hit for `ClaudeKnowledgeMetricsSnapshotUnavailable`, i.e. the index does
carry alert names inside `.yml` and `.py` files. The zero-hit results below are
therefore evidence of absence, not of an unindexed corpus.

**`UNATTRIBUTED` is defined narrowly:** no owning repository can be identified
from *repository-local* evidence. A product-shaped name (`ErpSlowRequests`) or a
suggestive `service` label is **not** attribution, and is not counted as one
anywhere in this document. Where a de-facto product owner is obvious but no
repository carries the rule, that is stated separately and labelled as such.

## Repository revisions this ledger is pinned to

| Repository | `main` SHA | `main` date | Local checkout |
|---|---|---|---|
| `dotmac_sub` | `1a3edf0eb567fe02665606d368f8f342536f548c` | 2026-08-25 | yes |
| `dotmac_erp` | `7b62974b366eead1b32bead380e47d9cf10ec4c7` | 2026-08-25 | yes |
| `dotmac_starter_mt` | `eddb761ce0c518a0fd6969e7be7958dab36998ff` | 2026-08-28 | yes |
| `dotmac_integrator` | `78bcaebf4692fbde298ef2107b231d983e04a5c6` | 2026-08-23 | yes |
| `dotmac_vendor_control_plane` | `e56becc81d6d7ae6ce97ca0b8636d105ab902106` | 2026-08-25 | yes |
| `dotmac_academy_app` | `a5e25e4e829350e503e66a03d73739529ba7da7f` | 2026-08-16 | yes |
| `dotmac_workspace` | `4c97dda18f6f6a8000ba2ade64f59210508b1d46` | 2026-08-26 | yes |
| `dotmac_cloud` | `d546f8dae7afee0d6434ab8674ff7a6e207bc917` | 2026-08-24 | yes |
| `dotmac_crm` (retired) | `a922decf1356f296f1816aba06cf2bcf966fc212` | 2026-08-25 | yes |
| `dotmac_observability` | `aef833d6bd71718dcff8989bdad1ca33f253ad22` | 2026-08-29 | yes |
| `dotmac_identity_ops` | `d11cf2a84b9d1ec05e984683f33c55c841193fbd` (HEAD, no `main`) | 2026-08-27 | yes |
| `claude_knowledge` | `2959f291d5b6a836f23f96f8562205471b2886d9` (HEAD, no `main`) | 2026-07-26 | **yes** — the brief assumed none exists |

`claude_knowledge` **does** have a local checkout at
`/Users/michaelayoade/Downloads/management/claude_knowledge`, and it carries the
live rule file. The Knowledge service is therefore fully attributed, not a
no-checkout special case.

## Headline counts

| Measure | Count |
|---|---|
| Live alerting rules | 56 |
| Live recording rules | **0** (verified) |
| Rule groups | 9 |
| Rules attributed to a repository **with a live source file** | 21 |
| Rules attributed to a repository, **deliberately removed from source** | 2 |
| **`UNATTRIBUTED`** | **33** |
| Rules with at least one `PRODUCER-NOT-FOUND` metric | **9** |
| Rules that are permanently silent (no series can ever match) | **2** |
| Rules currently silent because their target is decommissioned | 4 |
| Rules with `runbook_url` | 3 (all three point at an error-tracker issue query, not a procedure) |
| Rules without `runbook_url` | 53 |

## Rule ledger (all 56)

`Source status` is one of:

- **`IN-SOURCE`** — the exact rule body exists in a checked-in file.
- **`RETIRED-FROM-SOURCE`** — the owning repository names this rule in a
  checked-in architecture test that asserts it must **not** exist, and the
  metric it reads is emitted only by that repository. Owner is known; the rule
  itself lives nowhere but the host.
- **`NO-SOURCE`** — the name appears in no repository, no worktree and nowhere
  on the indexed filesystem.

| # | Rule | Group | Sev | Runbook | Owning repo | Source path | Repo `main` SHA | Source status | Producer metric(s) | Producer found |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `HighCPUUsage` | `host_alerts` | warning | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `node_cpu_seconds_total` → node_exporter (upstream) | Y |
| 2 | `HighMemoryUsage` | `host_alerts` | warning | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `node_memory_MemAvailable_bytes` → node_exporter (upstream); `node_memory_MemTotal_bytes` → node_exporter (upstream) | Y |
| 3 | `DiskSpaceLow` | `host_alerts` | critical | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `node_filesystem_avail_bytes` → node_exporter (upstream); `node_filesystem_size_bytes` → node_exporter (upstream) | Y |
| 4 | `ServiceDown` | `host_alerts` | critical | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `up` → Prometheus (synthetic) | Y |
| 5 | `HostSwapCritical` | `host_alerts` | critical | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `node_memory_SwapFree_bytes` → node_exporter (upstream); `node_memory_SwapTotal_bytes` → node_exporter (upstream) | Y |
| 6 | `ClaudeKnowledgeMetricsSnapshotUnavailable` | `claude-knowledge` | warning | N | claude_knowledge | ops/prometheus-rules.yml | `2959f291d5b6` | IN-SOURCE | `claude_knowledge_metrics_snapshot_available` → claude_knowledge | Y |
| 7 | `ClaudeKnowledgeMetricsSnapshotRefreshFailed` | `claude-knowledge` | warning | N | claude_knowledge | ops/prometheus-rules.yml | `2959f291d5b6` | IN-SOURCE | `claude_knowledge_metrics_snapshot_refresh_success` → claude_knowledge | Y |
| 8 | `ClaudeKnowledgeMetricsSnapshotStale` | `claude-knowledge` | warning | N | claude_knowledge | ops/prometheus-rules.yml | `2959f291d5b6` | IN-SOURCE | `claude_knowledge_metrics_snapshot_age_seconds` → claude_knowledge | Y |
| 9 | `SubBillingSnapshotUnavailable` | `dotmac_sub` | warning | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `billing_health_snapshot_available` → dotmac_sub | Y |
| 10 | `SubBillingMetricsSilent` | `dotmac_sub` | critical | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `billing_health_snapshot_available` → dotmac_sub | Y |
| 11 | `SubRadiusProbeFailing` | `dotmac_sub` | critical | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `radius_probe_ok` → dotmac_sub | Y |
| 12 | `SubRadiusAccountingReadFailing` | `dotmac_sub` | critical | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `radius_radacct_read_ok` → dotmac_sub | Y |
| 13 | `SubRadiusMetricsSilent` | `dotmac_sub` | critical | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `radius_probe_ok` → dotmac_sub | Y |
| 14 | `AcademyLabHostUnreachable` | `dotmac_academy` | critical | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `academy_lab_host_up` → dotmac_academy_app | Y |
| 15 | `AcademyLabsNearCapacity` | `dotmac_academy` | warning | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `academy_lab_capacity` → dotmac_academy_app; `academy_lab_instances` → dotmac_academy_app | Y |
| 16 | `AcademyLabsQueuedNotDraining` | `dotmac_academy` | warning | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `academy_lab_instances` → dotmac_academy_app | Y |
| 17 | `AcademyLabProvisioningFailures` | `dotmac_academy` | warning | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `academy_lab_instances` → dotmac_academy_app | Y |
| 18 | `AcademyHighErrorRate` | `dotmac_academy` | critical | Y | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `academy_http_requests_total` → dotmac_academy_app | Y |
| 19 | `AcademyWaitlistBacklog` | `dotmac_academy` | warning | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `academy_applicants` → dotmac_academy_app | Y |
| 20 | `ErpHighErrorRate` | `dotmac_erp` | critical | Y | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `http_requests_total` → dotmac_erp / dotmac_crm | Y |
| 21 | `ErpSlowRequests` | `dotmac_erp` | warning | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `http_request_duration_seconds_bucket` → dotmac_erp / dotmac_crm | Y |
| 22 | `ErpLokiLogsDropping` | `dotmac_erp` | warning | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `loki_logs_dropped_total` → dotmac_erp | Y |
| 23 | `CrmHighErrorRate` | `dotmac_omni` | critical | Y | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `http_requests_total` → dotmac_erp / dotmac_crm | Y |
| 24 | `CrmDbPoolNearExhaustion` | `dotmac_omni` | warning | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `db_pool_checked_out` → dotmac_crm; `db_pool_size` → dotmac_crm | Y |
| 25 | `CrmLongRunningTransaction` | `dotmac_omni` | warning | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `db_oldest_transaction_age_seconds` → dotmac_crm | Y |
| 26 | `CrmSlowRequests` | `dotmac_omni` | warning | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `http_request_duration_seconds_bucket` → dotmac_erp / dotmac_crm | Y |
| 27 | `PrepaidEnforcementRunnerMissing` | `prepaid_enforcement` | critical | N | dotmac_sub | deploy/observability/prepaid_enforcement.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_snapshot_age_seconds` → dotmac_sub | Y |
| 28 | `PrepaidEnforcementRunnerStale` | `prepaid_enforcement` | critical | N | dotmac_sub | deploy/observability/prepaid_enforcement.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_snapshot_age_seconds` → dotmac_sub | Y |
| 29 | `PrepaidCoverageRepairFailed` | `prepaid_enforcement` | critical | N | dotmac_sub | deploy/observability/prepaid_enforcement.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 30 | `PrepaidCoverageRepairableGapsPersist` | `prepaid_enforcement` | critical | N | dotmac_sub | deploy/observability/prepaid_enforcement.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 31 | `PrepaidCoverageQuarantinedEvidence` | `prepaid_enforcement` | warning | N | dotmac_sub | deploy/observability/prepaid_enforcement.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 32 | `PrepaidRenewalTermsUnresolved` | `prepaid_enforcement` | warning | N | dotmac_sub | deploy/observability/prepaid_enforcement.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 33 | `PrepaidFundingQuarantineActive` | `prepaid_enforcement` | warning | N | dotmac_sub | tests/architecture/test_billing_health_alert_contract.py (negative assertion only) | `1a3edf0eb567` | RETIRED-FROM-SOURCE | `observability_state` → dotmac_sub | Y |
| 34 | `PrepaidNoContactRouteAccounts` | `prepaid_enforcement` | warning | N | dotmac_sub | deploy/observability/prepaid_enforcement.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 35 | `PrepaidNoticeDeliveryUnavailable` | `prepaid_enforcement` | warning | N | dotmac_sub | deploy/observability/prepaid_enforcement.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 36 | `PrepaidSweepCycleAgeHigh` | `prepaid_enforcement` | warning | N | dotmac_sub | deploy/observability/prepaid_enforcement.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 37 | `PrepaidSweepCycleAgeCritical` | `prepaid_enforcement` | critical | N | dotmac_sub | deploy/observability/prepaid_enforcement.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 38 | `PrepaidSweepBudgetDeferredPersistent` | `prepaid_enforcement` | warning | N | dotmac_sub | deploy/observability/prepaid_enforcement.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 39 | `PrepaidNoticeShieldPersistent` | `prepaid_enforcement` | warning | N | dotmac_sub | deploy/observability/prepaid_enforcement.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 40 | `SubInvoicesPaidWithoutIssue` | `billing_health` | warning | N | dotmac_sub | deploy/observability/billing_health.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 41 | `SubBillingProfileMismatch` | `billing_health` | warning | N | dotmac_sub | deploy/observability/billing_health.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 42 | `SubBillingProfileMixedModes` | `billing_health` | warning | N | dotmac_sub | deploy/observability/billing_health.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 43 | `SubActiveSubscriptionsWithoutBillingPath` | `billing_health` | warning | N | dotmac_sub | deploy/observability/billing_health.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 44 | `SubAgedDraftInvoiceBacklogGrowing` | `billing_health` | warning | N | dotmac_sub | tests/architecture/test_billing_health_alert_contract.py (negative assertion only) | `1a3edf0eb567` | RETIRED-FROM-SOURCE | `observability_state` → dotmac_sub | Y |
| 45 | `SubAccountCreditInvariantViolationsGrowing` | `billing_health` | warning | N | dotmac_sub | deploy/observability/billing_health.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 46 | `SubNegativePrepaidExposureUnmeasurable` | `billing_health` | warning | N | dotmac_sub | deploy/observability/billing_health.rules.yml | `1a3edf0eb567` | IN-SOURCE | `observability_state` → dotmac_sub | Y |
| 47 | `WorkspaceLoginPageDown` | `dotmac_identity_plane` | critical | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `workspace_login_page_up` → **NOT FOUND** | N |
| 48 | `WorkspaceLoginPageSlow` | `dotmac_identity_plane` | warning | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `workspace_login_page_duration_seconds` → **NOT FOUND** | N |
| 49 | `IdpDiscoveryDown` | `dotmac_identity_plane` | critical | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `idp_discovery_up` → **NOT FOUND** | N |
| 50 | `IdpIssuerChanged` | `dotmac_identity_plane` | critical | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `idp_discovery_up` → **NOT FOUND**; `idp_issuer_matches_bindings` → **NOT FOUND** | N |
| 51 | `IdpHasNoSigningKeys` | `dotmac_identity_plane` | critical | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `idp_discovery_up` → **NOT FOUND**; `idp_jwks_signing_keys` → **NOT FOUND** | N |
| 52 | `IdentityPlaneCertificateExpiringSoon` | `dotmac_identity_plane` | warning | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `idp_tls_expiry_seconds` → **NOT FOUND**; `workspace_tls_expiry_seconds` → **NOT FOUND** | N |
| 53 | `IdentityPlaneCertificateExpiringCritical` | `dotmac_identity_plane` | critical | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `idp_tls_expiry_seconds` → **NOT FOUND**; `workspace_tls_expiry_seconds` → **NOT FOUND** | N |
| 54 | `WorkspaceBackupNotValidated` | `dotmac_identity_plane` | critical | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `workspace_backup_last_validated_age_seconds` → **NOT FOUND** | N |
| 55 | `WorkspaceBackupStateMissing` | `dotmac_identity_plane` | warning | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `workspace_backup_last_validated_age_seconds` → **NOT FOUND** | N |
| 56 | `IdentityProbeDown` | `dotmac_identity_plane` | critical | N | **UNATTRIBUTED** | — | `—` | NO-SOURCE | `up` → Prometheus (synthetic) | Y |

### Attribution summary by owner

| Owner | Rules | Basis |
|---|---|---|
| `dotmac_sub` | 20 | 18 `IN-SOURCE` (`deploy/observability/{prepaid_enforcement,billing_health}.rules.yml`) + 2 `RETIRED-FROM-SOURCE` |
| `claude_knowledge` | 3 | `IN-SOURCE` (`ops/prometheus-rules.yml`) |
| **`UNATTRIBUTED`** | **33** | no repository-local evidence of any kind |

The 33 `UNATTRIBUTED` rules, by group: `dotmac_identity_plane` 10,
`dotmac_academy` 6, `host_alerts` 5, `dotmac_sub` (the group, not the repo) 5,
`dotmac_omni` 4, `dotmac_erp` 3.

Two hits that look like attribution and are **not**:

- `dotmac_observability` `docs/inventories/observer-as-built.md` mentions
  `ServiceDown`, `ErpHighErrorRate`, `ErpSlowRequests` and `ErpLokiLogsDropping`.
  That document is the 2026-08-29 census itself — a characterization of the live
  host. Citing a rule in an inventory is not owning it, and counting it would be
  circular.
- `claude_knowledge` `README.md` mentions `ServiceDown` in prose, explaining that
  the host-level rule already covers process failure. That is a reference to
  someone else's rule, not a declaration of it.

Neither was counted as attribution.

## Producers

`PRODUCER-NOT-FOUND` means no `Counter(`/`Gauge(`/`Histogram(` declaration, no
metric-name string, and no exporter emitting that name was located in any
repository, worktree, or anywhere on the indexed filesystem.

### The 9 `PRODUCER-NOT-FOUND` rules — all in one group

Every one is in `dotmac_identity_plane`. Eight metric names have no producer
anywhere: `workspace_login_page_up`, `workspace_login_page_duration_seconds`,
`workspace_tls_expiry_seconds`, `workspace_backup_last_validated_age_seconds`,
`idp_discovery_up`, `idp_issuer_matches_bindings`, `idp_jwks_signing_keys`,
`idp_tls_expiry_seconds`.

| Rule | Sev | Missing metric(s) |
|---|---|---|
| `WorkspaceLoginPageDown` | critical | `workspace_login_page_up` |
| `WorkspaceLoginPageSlow` | warning | `workspace_login_page_duration_seconds` |
| `IdpDiscoveryDown` | critical | `idp_discovery_up` |
| `IdpIssuerChanged` | critical | `idp_issuer_matches_bindings`, `idp_discovery_up` |
| `IdpHasNoSigningKeys` | critical | `idp_jwks_signing_keys`, `idp_discovery_up` |
| `IdentityPlaneCertificateExpiringSoon` | warning | `workspace_tls_expiry_seconds`, `idp_tls_expiry_seconds` |
| `IdentityPlaneCertificateExpiringCritical` | critical | `workspace_tls_expiry_seconds`, `idp_tls_expiry_seconds` |
| `WorkspaceBackupNotValidated` | critical | `workspace_backup_last_validated_age_seconds` |
| `WorkspaceBackupStateMissing` | warning | `workspace_backup_last_validated_age_seconds` |

The tenth rule in the group, `IdentityProbeDown`, reads `up{job="identity-probe"}`,
which Prometheus synthesises, so it is producer-backed.

**Important distinction: these nine are not silent.** The `identity-probe`
scrape job is one of the 18 healthy targets, so something on that host *is*
emitting these metrics — an exporter whose source code exists in no Dotmac
repository and nowhere on this workstation. `PRODUCER-NOT-FOUND` here means the
producer is **unversioned and unlocatable**, which is a supply-chain gap rather
than a coverage gap: nine rules, seven of them `critical`, depend on a binary or
script that nobody can review, rebuild, or restore.

### Rules that are permanently silent — a rule that reads "all clear" forever

Two rules can never fire, because the label value they select is not one the
producer emits. Both are in `billing_health`, and — this is the part that
matters — **both are wrong in `dotmac_sub`'s own checked-in rules file too**, so
this is not host drift:

| Rule | Selects | `dotmac_sub` actually emits |
|---|---|---|
| `SubBillingProfileMismatch` | `observability_state{domain="billing_health",signal="billing_profile_mismatch"}` | `signal="billing_profile_mismatch_accounts"` |
| `SubBillingProfileMixedModes` | `observability_state{domain="billing_health",signal="billing_profile_mixed_modes"}` | `signal="billing_profile_mixed_accounts"` |

Evidence: `dotmac_sub` `app/services/billing_health.py` lines 374–381 emit the
`_accounts`-suffixed names; the bare names appear only in that file's
*anomaly-string* list (line 294–296), which is a different vocabulary that never
reaches the `observability_state` gauge. The rename landed in
`12a6a67909be0c549c926e911aa079fa7a6885d3` (2026-07-14, "Move billing and database
pressure metrics to bounded snapshots", #1260); the rules file was created later,
in `146394b1b` (#2219), against names that by then no longer existed. **These two
rules were born silent and have never fired.** They report "no billing-profile
mismatches" and always will.

A further four rules are silent for a different reason — see the CRM section.

## Rule dependencies and group boundaries

**Recording rules: zero.** Verified two ways — every `rules:` entry in the live
file carries an `alert:` key and none carries a `record:` key, and no expression
anywhere references the `ALERTS` or `ALERTS_FOR_STATE` meta-series. Nothing in
this rule set consumes another rule's output. The census's claim holds.

**Cross-rule dependencies** are all expressed *inside* expressions, never through
a recording rule or Alertmanager:

- `IdpIssuerChanged` and `IdpHasNoSigningKeys` both `and`-gate on
  `idp_discovery_up == 1` — the exact condition `IdpDiscoveryDown` fires on. A
  self-suppression built into PromQL rather than into an inhibit rule. Splitting
  these three across files would leave the gate intact (same evaluator, same
  series), but splitting them across *evaluators* would not.
- Four "silence detector" pairs, where one rule watches for the metric another
  rule reads going absent: `SubBillingMetricsSilent` ↔ `SubBillingSnapshotUnavailable`;
  `SubRadiusMetricsSilent` ↔ `SubRadiusProbeFailing`; `PrepaidEnforcementRunnerMissing`
  ↔ `PrepaidEnforcementRunnerStale`; `SubNegativePrepaidExposureUnmeasurable`, which
  uses `absent(...) and on() observability_state{...,signal="active_subscriptions"} > 0`
  — a genuine cross-signal join inside one group.
- Three threshold ladders on one metric: `PrepaidSweepCycleAgeHigh`/`Critical`,
  `IdentityPlaneCertificateExpiring` `Soon`/`Critical`, `DiskSpaceLow` alone.

**Group boundaries — a later migration must never split one of these across files.**
Order and line ranges are as they appear in the single live rule file (738 lines):

| Order | Group | Line range | Rules | critical / warning |
|---|---|---|---|---|
| 1 | `host_alerts` | 2–48 | 5 | 3 / 2 |
| 2 | `claude-knowledge` | 49–83 | 3 | 0 / 3 |
| 3 | `dotmac_sub` | 84–145 | 5 | 4 / 1 |
| 4 | `dotmac_academy` | 146–222 | 6 | 2 / 4 |
| 5 | `dotmac_erp` | 223–263 | 3 | 1 / 2 |
| 6 | `dotmac_omni` | 264–314 | 4 | 1 / 3 |
| 7 | `prepaid_enforcement` | 315–522 | 13 | 5 / 8 |
| 8 | `billing_health` | 523–629 | 7 | 0 / 7 |
| 9 | `dotmac_identity_plane` | 630–738 | 10 | 7 / 3 |
| | **Total** | | **56** | **23 / 33** |

No group declares an `interval`; all nine inherit the global
`evaluation_interval: 15s`. No alert name is duplicated across groups, so a
group split cannot collide names — but note that the group name `dotmac_sub`
(5 rules) is **not** the set of rules owned by the `dotmac_sub` repository
(20 rules, in the `prepaid_enforcement` and `billing_health` groups). Any
migration that routes by group name will get this backwards.

## Scrape-job ledger (all 16)

19 active targets across 16 jobs, 0 dropped. Targets, ports and URLs are
redacted; `instance` labels are logical names the configuration already assigns
and are reproduced as such. Seven jobs authenticate, all via
`authorization: {type: Bearer, credentials_file: …}`; no inline credential
appears anywhere in the scrape configuration.

| # | Job | Owning product / service | Owning repo | Still exists? | Auth | Targets | Notes |
|---|---|---|---|---|---|---|---|
| 1 | `prometheus` | the observability stack itself | `dotmac_observability` (control plane; the running config is **not** version-controlled) | yes | no | 1 | self-scrape |
| 2 | `node-exporter` | fleet infrastructure | none — upstream exporter | yes | no | 4 | logical instances `dotmac-observe`, `dotmac-db-primary`, `dotmac-s3`, `seabone` |
| 3 | `cadvisor` | fleet infrastructure | none — upstream exporter | yes | no | 1 | container runs as root with host mounts |
| 4 | `loki` | log store | none — upstream | yes | no | 1 | |
| 5 | `postgres-exporter` | shared Postgres | none — upstream exporter | yes | no | 1 | instance `dotmac-db-primary` |
| 6 | `redis-exporter` | shared Redis | none — upstream exporter | yes | no | 1 | instance `dotmac-db-primary` |
| 7 | `minio-cluster` | object storage | none — upstream (MinIO) | yes | **yes** | 1 | instance `dotmac-s3`, cluster metrics path |
| 8 | `minio-node` | object storage | none — upstream (MinIO) | yes | **yes** | 1 | instance `dotmac-s3`, node metrics path |
| 9 | `openbao` | secret store | none — upstream (OpenBao) | yes | **yes** | 1 | instance `dotmac-observe` |
| 10 | `dotmac-sub-victoriametrics` | DotMac Sub | `dotmac_sub` | yes | no | 1 | instance `dotmac-sub`, `environment: production` |
| 11 | `dotmac-sub-federation` | DotMac Sub | `dotmac_sub` | yes | no | 1 | `/federate`, `match[]={__name__=~".+"}`, `honor_labels: true`, and a `metric_relabel_config` renaming `(up\|scrape_.+)` → `federated_${1}` so federated series cannot clobber local ones. This is the only part of the as-built the control-plane renderer already matches. |
| 12 | `claude-knowledge` | Knowledge service | `claude_knowledge` (local checkout present) | yes | **yes** | 1 | |
| 13 | `dotmac-academy-app` | DotMac Academy | `dotmac_academy_app` | yes | **yes** | 1 | instance `dotmac-academy` |
| 14 | `dotmac-crm-app` | DotMac CRM | `dotmac_crm` | **RETIRED** | **yes** | 1 | **DOWN, HTTP 502.** The only unhealthy target. Firing `ServiceDown`. |
| 15 | `dotmac-erp-app` | DotMac ERP | `dotmac_erp` | yes | **yes** | 1 | instance `dotmac-erp`; comment records that `x-metrics-token` remains a deprecated fallback |
| 16 | `identity-probe` | the identity plane (Workspace + Keycloak) | **none found** | probe runs; source unlocatable | no | 1 | instance `dotmac-identity-plane`, the only job with its own `scrape_interval` (30s). Emits the 8 unproducible metrics above. |

**Products with no scrape job at all:** `dotmac_integrator`,
`dotmac_vendor_control_plane`, `dotmac_cloud`, `dotmac_starter_mt`, and the
`dotmac_workspace` application itself (only the external `identity-probe` covers
it). `dotmac_integrator` is the sharpest case — it carries 22 checked-in alert
rules in `deploy/alerts/ingress.rules.yml` (groups `integrator-worker` 4,
`integrator-queues` 6, `integrator-ingress` 6, `integrator-delivery` 4,
`integrator-retention` 2) at `78bcaebf4692fbde298ef2107b231d983e04a5c6`, none of
which is loaded and none of which could evaluate if it were, because nothing
scrapes the product.

## CRM retirement — proof, and the exact deletion list

### Retirement is a decision, not yet an executed state

| Check | Result |
|---|---|
| `dotmac_crm` last commit on `main` | `a922decf1356f296f1816aba06cf2bcf966fc212`, 2026-08-25, "Merge pull request #301 … version bump" |
| GitHub `isArchived` | **`false`** |
| GitHub visibility | `PUBLIC` |
| GitHub `pushedAt` | 2026-08-26T03:41:43Z |
| Local checkout | present, ~40 top-level entries, 4 days stale |
| Retirement work visible in-repo | yes — recent commits retire the direct ERP sync and the legacy ERPNext importer; `dotmac_sub` carries `docs/designs/CRM_WEB_RETIREMENT.md` and `docs/audits/crm_web_retirement_ledger.json` |

So: the product is being wound down and its integrations are being cut, but the
repository is live, unarchived, public, and was pushed to three days ago. The
observability configuration is not lagging behind a completed retirement; it is
in step with an *incomplete* one. Anyone deleting the observability references
should know the repo itself is still an open surface.

### Every remaining CRM reference in the live observability configuration

An exact list a later PR can delete against. Line numbers are against the
captured live files.

**A. Scrape configuration (`prometheus.yml`, 161 lines) — delete lines 131–142**

| Item | Location | What it is |
|---|---|---|
| A1 | lines 131–132 | two comment lines: the nginx `/metrics` restriction note and the `(dotmac_omni#1)` bearer-gate note |
| A2 | line 133 | `- job_name: 'dotmac-crm-app'` |
| A3 | lines 134–135 | `scheme: https`, `metrics_path: /metrics` |
| A4 | lines 136–138 | `authorization: {type: Bearer, credentials_file: …}` referencing secret basename *(credential basename redacted — ADR-0004)* |
| A5 | lines 139–142 | `static_configs` — one target (redacted) with label `instance: 'dotmac-crm'` |

**B. Alert rules (`alerts.yml`, 738 lines) — delete the whole group, lines 264–314**

| Item | Rule | Severity | Runbook | Metric(s) read |
|---|---|---|---|---|
| B1 | `CrmHighErrorRate` | critical | yes — error-tracker query, project `4` | `http_requests_total{job="dotmac-crm-app"}` |
| B2 | `CrmDbPoolNearExhaustion` | warning | no | `db_pool_checked_out`, `db_pool_size` |
| B3 | `CrmLongRunningTransaction` | warning | no | `db_oldest_transaction_age_seconds` |
| B4 | `CrmSlowRequests` | warning | no | `http_request_duration_seconds_bucket` |
| B5 | the group container `- name: dotmac_omni` itself | — | — | — |

Delete B5 with B1–B4: with the four rules gone the group is empty, and an empty
`groups[]` entry is a config-load error in Prometheus, not a harmless no-op.

**C. Secret material — 1 file**

| Item | Basename | Note |
|---|---|---|
| C1 | *(credential basename redacted — ADR-0004)* | one of the ten secret files in the stack's secrets directory, mounted read-only. Referenced only by A4. Contents were never read. |

**D. Consequential, not a deletion**

| Item | What |
|---|---|
| D1 | the currently-firing `ServiceDown{job="dotmac-crm-app"}` clears as soon as A2 is removed — it is a *symptom* of A2, and deleting it from `host_alerts` would be wrong, since `ServiceDown` covers all 19 targets |
| D2 | error-tracker project `4` (referenced by B1's `runbook_url`) is a separate system's cleanup, outside these config files |

**E. Verified absent — nothing to delete**

Checked and clean of any CRM/`dotmac_omni` reference: `alertmanager.yml` (no
route, no receiver, no inhibition mentions CRM — there is only one receiver and
zero child routes, so nothing was ever CRM-specific), `loki-config.yml`,
`promtail-config.yml`, and the stack's `docker-compose.yml`.

**Deletion list size: 11 items** (A1–A5, B1–B5, C1) across 3 files, plus 2
consequential notes (D1, D2). In line terms: 12 lines of `prometheus.yml`,
51 lines of `alerts.yml`, and 1 secret file.

### The four CRM rules are already silent

`dotmac-crm-app` returns HTTP 502, so no `http_requests_total`, `db_pool_*` or
`db_oldest_transaction_age_seconds` series exist for `job="dotmac-crm-app"`. All
four rules therefore evaluate to no-data — which in Prometheus means *not
firing*, i.e. they read as "all clear" for a product that is off the air. Their
producers do exist in `dotmac_crm` `app/metrics.py` (lines 4, 9, 39, 63 at
`a922decf1356f296f1816aba06cf2bcf966fc212`), so this is a reachability failure,
not a missing-producer one — but the operational effect is identical to the two
permanently-silent billing rules: a green dashboard that means nothing.

## ERP: the three legacy rules, and the Foundation bundle

### 1. Where the three legacy rules come from

`ErpHighErrorRate`, `ErpSlowRequests`, `ErpLokiLogsDropping` are
**`UNATTRIBUTED` — host-only, hand-written.**

- `git grep -F` across all 14 checkouts: no hit in any repository, including
  `dotmac_erp` itself.
- `mdfind` across the whole indexed filesystem: **0 hits each** (against a
  detector proven to return 16 hits for a name that does exist).
- `dotmac_erp` has **no** `deploy/alerts/`, **no** `deploy/rendered/`, and **no**
  `deploy/observability/` — its entire `deploy/` tree at
  `7b62974b366eead1b32bead380e47d9cf10ec4c7` is `deploy/systemd/` (three files).
- The only textual match anywhere is `dotmac_observability`
  `docs/inventories/observer-as-built.md` line 141, which is the census
  describing these very rules. Circular; not counted.

Their metrics, by contrast, are real and correctly labelled:

| Rule | Metric | Producer | Verified |
|---|---|---|---|
| `ErpHighErrorRate` | `http_requests_total{status=~"5.."}` | `dotmac_erp` `app/metrics.py:5` (Counter) | yes — `app/observability.py:158` labels with `str(status_code)`, so a raw `500` matches `5..`. Note `categorize_http_status()` in the same module produces word-shaped statuses (`server_error`) but is used for *job and integration* metrics, not this one, so there is no label-vocabulary mismatch here. |
| `ErpSlowRequests` | `http_request_duration_seconds_bucket` | `dotmac_erp` `app/metrics.py:10` (Histogram `http_request_duration_seconds`) | yes |
| `ErpLokiLogsDropping` | `loki_logs_dropped_total` | `dotmac_erp` `app/metrics.py:98` (Counter) | yes |

So the ERP situation is the inverse of the identity plane's: **ERP's producers
are versioned and its rules are not.**

### 2. ERP's rendered Deployment Foundation bundle — where it actually is

It is **not in `dotmac_erp`**. `dotmac_erp` has never adopted the Deployment
Foundation: no `deploy/product.toml`, no `deploy/rendered/`. Of ten repositories
checked, exactly one carries a `deploy/product.toml` on `main` —
`dotmac_starter_mt`, for itself.

ERP's bundle exists only on **unmerged branches of `dotmac_starter_mt`**, in
local worktrees:

| Worktree | Branch | HEAD | Product group name |
|---|---|---|---|
| `erp_deployment_adapter_worktree` | `feat/deployment-foundation-adapter-cutover` | `2766197837f6` | `dotmac_product_dotmac_erp` |
| `erp_pr387_worktree` | `feat/deployment-foundation-integration` | `1e1cb93f7277` | `dotmac_product_dotmac-erp` |
| `erp_people_employment_type_activation_worktree` | `feat/people-employment-type-activation` | `eccf0c327051` | `dotmac_product_dotmac-erp` |
| `erp_people_employment_type_bootstrap_worktree` | `feat/people-employment-type-bootstrap` | `3ed51a1d0f04` | `dotmac_product_dotmac-erp` |

Its own `deploy/product.toml` says it plainly: *"ERP is the first FULL adopter of
the deployment foundation … This descriptor is an ADAPTER, not a cutover."*

**Naming drift to fix before a supersession map is drawn:** the adapter branch
renders the product group as `dotmac_product_dotmac_erp` (underscore) while the
other three render `dotmac_product_dotmac-erp` (hyphen). A migration keyed on
group name will treat these as two different groups.

### 3. The bundle's contents (27 rules)

`dotmac_foundation` — 22 rules, byte-identical across all four branches and to
`dotmac_starter_mt` `main`'s own render:

`FDN_READINESS_FAILING`, `FDN_LIVENESS_FAILING`, `FDN_CONTAINER_OOM_KILLED`,
`FDN_CONTAINER_CPU_SATURATION`, `FDN_CONTAINER_MEMORY_SATURATION`,
`FDN_HOST_CPU_SATURATION`, `FDN_HOST_MEMORY_SATURATION`, `FDN_HOST_DISK_LOW`,
`FDN_HOST_DISK_CRITICAL`, `FDN_HOST_INODES_LOW`, `FDN_HOST_CLOCK_SKEW`,
`FDN_PG_DOWN`, `FDN_PG_POOL_SATURATION`, `FDN_PG_LONG_TRANSACTION`,
`FDN_PG_REPLICATION_LAG_HIGH`, `FDN_PG_DISK_LOW`, `FDN_REDIS_DOWN`,
`FDN_REDIS_MEMORY_HIGH`, `FDN_REDIS_PERSISTENCE_STALE`,
`FDN_TLS_CERT_EXPIRY_WARNING`, `FDN_TLS_CERT_EXPIRY_CRITICAL`,
`FDN_SYNTHETIC_HEALTH_FAILING`.

`dotmac_product_dotmac_erp` — 5 ERP-owned domain rules:
`GL_UNPOSTED_BATCH_STALLED`, `AP_PAYMENT_POSTING_STALLED`,
`PAYROLL_DRAFT_GENERATION_FAILED`, `IMPORT_BACKLOG_STALLED`,
`GL_POSTING_LATENCY_HIGH`.

(For contrast, `dotmac_starter_mt` `main`'s own render is the same 22 plus
`dotmac_product_dotmac_starter_mt` with **0** rules.)

### 4. The 22 / 42 counts — verified against the repository, not the plan

**Both numbers are correct.** Derived independently from
`dotmac_starter_mt` `eddb761ce0c518a0fd6969e7be7958dab36998ff`,
`packages/dotmac-deployment-foundation/src/dotmac_deployment_foundation/alerts.py`:

| Producer | Alerts |
|---|---|
| `node_exporter` | 7 |
| `blackbox_exporter` | 5 |
| `postgres_exporter` | 4 |
| `cadvisor` | 3 |
| `redis_exporter` | 3 |
| **Backed subtotal** | **22** |
| `unbacked` | **42** |
| **`COMMON_ALERTS` total** | **64** |

Cross-checked three ways: the `COMMON_ALERTS` tuple holds exactly 64 `Alert(...)`
literals; the rendered bundle's own header comment reads *"42 alert(s) omitted:
producer=UNBACKED"*; and `docs/inventories/deployment-foundation-alert-producers.md`
(dated 2026-08-26) states the same split. The 22 rendered rule names match the 22
backed producers one-for-one.

### 5. Supersession map — and why it currently subtracts coverage

| Live legacy rule | Nearest Foundation alert | Its producer class | In the rendered bundle? |
|---|---|---|---|
| `ErpHighErrorRate` (5xx ratio > 0.05) | `FDN_HTTP_5XX_RATE_CRITICAL` (`> {{error_rate_critical_pct}}`, and ERP's own `deploy/alerts/thresholds.json` on the adapter branch sets that to `0.05` — the same number as the live rule) | `unbacked` | **no — omitted** |
| `ErpSlowRequests` (p95 > 3s) | `FDN_HTTP_LATENCY_P99_HIGH` (p99, `{{latency_p99_warning_seconds}}` = `2.0`) | `unbacked` | **no — omitted** |
| `ErpLokiLogsDropping` (`loki_logs_dropped_total` rate > 0) | `FDN_LOG_INGESTION_GAP` (reads `log_lines_received_total`) | `unbacked` | **no — omitted** |

**Adopting ERP's Foundation bundle today would delete all three live ERP
application rules and replace them with nothing.** The three Foundation
counterparts are all in the omitted 42. A cutover that swaps the `dotmac_erp`
group for the rendered bundle is a net *loss* of ERP application coverage — it
trades three working rules for 22 infrastructure rules that overlap `host_alerts`
instead.

Two further mismatches worth carrying into the supersession decision:

- `ErpSlowRequests` is p95 at 3s; `FDN_HTTP_LATENCY_P99_HIGH` is p99 at 2.0s.
  Not a rename — a different percentile against a different threshold.
- `ErpLokiLogsDropping` reads a counter ERP genuinely increments;
  `FDN_LOG_INGESTION_GAP` reads `log_lines_received_total`, which the Foundation's
  own inventory says nothing in the stack emits. These are not the same alert.

### 6. A finding for the Foundation's owner: `unbacked` over-counts against the fleet

`docs/inventories/deployment-foundation-alert-producers.md` leads with *"42 are
`UNBACKED` — no process **anywhere in the Dotmac fleet**, and no off-the-shelf
exporter this facility could plausibly run, emits that metric today."* Its own
methodology paragraph is narrower and accurate (*"Concretely checked and found
absent **in this codebase**"* — i.e. `dotmac_kernel`), but the headline claim is
falsified by the live host:

- `FDN_HTTP_5XX_RATE_HIGH`/`_CRITICAL`/`FDN_HTTP_TRAFFIC_DROP` read
  `http_requests_total` — emitted by `dotmac_erp` `app/metrics.py:5` and
  `dotmac_crm` `app/metrics.py:4`, and live in Prometheus right now (it is what
  `ErpHighErrorRate` reads).
- `FDN_HTTP_LATENCY_P99_HIGH` reads `http_request_duration_seconds_bucket` —
  emitted by `dotmac_erp` `app/metrics.py:10`.
- `FDN_SCRAPE_TARGET_DOWN` reads `up`, which every Prometheus synthesises and
  which `ServiceDown` and `IdentityProbeDown` both read today.

At least 5 of the 42 are backed *at the fleet level*. The 22/42 split is exactly
right as a statement about `dotmac_kernel`; it is wrong as a statement about the
fleet, and a supersession map built on the headline sentence will conclude that
ERP has no HTTP producer when it demonstrably does. This is a documentation-scope
defect, not a code defect — `Alert.producer` and the `UNBACKED_ALERTS` ratchet
are internally consistent. Recorded for the Foundation's owner; not repaired here.

## The 53 missing runbooks, assigned to owners

Two columns, deliberately kept apart. **Repo-attributed** is the rigorous count —
a repository whose checked-in files carry the rule. **De-facto owner** is who a
migration should actually send the work to, inferred from the group, the `owner`
/ `area` / `service` labels the rules already carry, and which product's metrics
they read. The second column is a routing convenience and is **not** attribution;
nothing in the `UNATTRIBUTED` count depends on it.

| De-facto owner | Rules missing `runbook_url` | Repo-attributed? | The concrete list |
|---|---|---|---|
| `dotmac_sub` | **25** | 20 yes / 5 no | all 13 `prepaid_enforcement` + all 7 `billing_health` + all 5 in the `dotmac_sub` group (`SubBillingSnapshotUnavailable`, `SubBillingMetricsSilent`, `SubRadiusProbeFailing`, `SubRadiusAccountingReadFailing`, `SubRadiusMetricsSilent`) |
| identity plane (Workspace + Keycloak) — **no repository found** | **10** | no | the whole `dotmac_identity_plane` group |
| platform / host (the observability stack itself) | **5** | no | `HighCPUUsage`, `HighMemoryUsage`, `DiskSpaceLow`, `ServiceDown`, `HostSwapCritical` |
| `dotmac_academy_app` | **5** | no | `AcademyLabHostUnreachable`, `AcademyLabsNearCapacity`, `AcademyLabsQueuedNotDraining`, `AcademyLabProvisioningFailures`, `AcademyWaitlistBacklog` (`AcademyHighErrorRate` has one) |
| `dotmac_crm` — **RETIRED, delete instead of documenting** | **3** | no | `CrmDbPoolNearExhaustion`, `CrmLongRunningTransaction`, `CrmSlowRequests` (`CrmHighErrorRate` has one) |
| `claude_knowledge` | **3** | **yes** | all 3 `claude-knowledge` rules |
| `dotmac_erp` | **2** | no | `ErpSlowRequests`, `ErpLokiLogsDropping` (`ErpHighErrorRate` has one) |
| | **53** | | |

Strictly by repository attribution, the same 53 split: `dotmac_sub` 20,
`claude_knowledge` 3, `UNATTRIBUTED` 30.

### The three that "have" a runbook do not have one

All three `runbook_url` values are the same shape: an error-tracker
unresolved-issue query, differing only in project id — `AcademyHighErrorRate` →
project `3`, `ErpHighErrorRate` → project `5`, `CrmHighErrorRate` → project `4`.
Alertmanager's Telegram template renders them behind the literal link text
*"Investigate in GlitchTip ↗"*.

A list of unresolved issues is a place to look, not a procedure to follow. On the
definition the Deployment Foundation uses — *"the responder who gets paged at
03:00 starts from zero instead of from a known procedure"* — **all 56 rules lack
a runbook**, and one of the three that nominally has one belongs to a retired
product.

### 14 rules carry a runbook that never reaches the responder

Separately, 14 rules carry a plain `runbook` annotation (not `runbook_url`)
pointing at `docs/adr/0007-end-to-end-billing-target-architecture.md` — a
repo-relative path in `dotmac_sub`: all 13 `prepaid_enforcement` rules plus
`SubInvoicesPaidWithoutIssue`. **Alertmanager's message template renders only
`runbook_url`**, so this annotation is carried on every alert and displayed on
none. It is also useful corroborating evidence of ownership: a repo-relative ADR
path pointing into `dotmac_sub`, on rules whose metrics only `dotmac_sub` emits.

The full annotation/label vocabulary in use across the 56: `severity` (56),
`summary` (56), `description` (54), `owner` (20 — all `dotmac_sub`-owned rules,
values `financial-billing`, `financial-collections`, `support-collections`),
`area` (20), `runbook` (14), `service` (10 — the identity-plane group, values
`workspace`, `keycloak`, `identity`), `runbook_url` (3).

## Findings

Numbered so a later change can cite one. None was acted on.

**PROV-01 — 33 of 56 live rules exist in no repository (blocking).** More than
half the production alerting surface has no version-controlled source, no review
history, and no owner who can be named from evidence. The delivery plan blocks
promotion until this reaches zero. It breaks down as six intact groups, which is
the useful shape: whoever adopts `dotmac_identity_plane` (10), `dotmac_academy`
(6), `host_alerts` (5), the `dotmac_sub` *group* (5), `dotmac_omni` (4, delete
instead) and `dotmac_erp` (3) closes it completely. Five of those six map to a
product with a live repository; only the identity plane has no candidate home.

**PROV-02 — two rules have never fired and never can.**
`SubBillingProfileMismatch` and `SubBillingProfileMixedModes` select
`signal="billing_profile_mismatch"` / `"billing_profile_mixed_modes"`; `dotmac_sub`
emits `billing_profile_mismatch_accounts` / `billing_profile_mixed_accounts`. The
producer rename landed 2026-07-14 (#1260); the rules were written afterwards
(#2219) against names that no longer existed. **The defect is in `dotmac_sub`'s
checked-in `deploy/observability/billing_health.rules.yml`, not in host drift** —
deploying the repo version verbatim reproduces it. Two billing-integrity checks
have reported "clean" since the day they were written. For `dotmac_sub`.

**PROV-03 — the identity plane's exporter exists nowhere.** Nine `critical`/`warning`
rules and eight metric names depend on a probe that runs on the host and whose
source is in no repository, no worktree, and nowhere on the indexed filesystem —
including `dotmac_workspace` and `dotmac_identity_ops`, the two repositories that
would plausibly own it. The job is healthy, so the code exists and runs; it
cannot be reviewed, rebuilt, or restored after a host loss. This is the single
largest unowned surface in the census and the only `UNATTRIBUTED` group with no
obvious home.

**PROV-04 — the Alertmanager inhibition rule is structurally inert.** It
suppresses `severity: warning` with `severity: critical` where
`equal: [alertname, instance]`. Every rule has exactly one fixed severity label
and no alert name is duplicated, so no `critical` alert can ever share an
`alertname` with a `warning` alert. The inhibition can never match. The pairs it
was presumably meant to cover — `PrepaidSweepCycleAgeHigh`/`Critical`,
`IdentityPlaneCertificateExpiringSoon`/`Critical` — use *different* alert names
and so are exactly the case it cannot handle. Combined with zero child routes
(census OBS-04), severity has no delivery consequence anywhere in this stack.

**PROV-05 — the live host runs two rules `dotmac_sub` deliberately retired, and a
third in a shape `dotmac_sub` deliberately narrowed.** `dotmac_sub`
`tests/architecture/test_billing_health_alert_contract.py` asserts
`"SubAgedDraftInvoiceBacklogGrowing" not in source` and
`"PrepaidFundingQuarantineActive" not in prepaid_source`; both are live. They
were replaced by `SubRecentDraftInvoiceCohortStalled` and
`SubPrepaidFundingQuarantineGrowing`, whose test names the reason: aged draft
*stock* must not page as new *leakage*. Separately,
`SubAccountCreditInvariantViolationsGrowing` is live **without** the `scope="all"`
selector the repo version pins — and `account_credit_invariant_violations` is
emitted at `all`, at `opening_balance`, and once per entry in a dynamic
per-invariant breakdown, so the live rule evaluates across scopes it must not.

That last one is the sharpest fact in this ledger: it is a **known defect that
was already found and fixed, and the fix never reached the host**. It was
introduced in `dotmac_sub` PR #2219 (2026-08-09), diagnosed and repaired in
PR #2275 (2026-08-11) by pinning `scope="all"` — because `scope="opening_balance"`
carries the 13,312 rows brought in at the Splynx handoff, which the snapshot
deliberately never raises as an anomaly. The live host has been running the
unfixed #2219 shape for the 18 days since. Nothing was wrong with the diagnosis
or the fix; there is simply no path from a merged `dotmac_sub` rule change to
`/etc/prometheus/alerts.yml`, which is PROV-01 stated as a consequence rather
than as a count.

So `dotmac_sub` currently has a passing architecture test, a merged corrective
PR, and a Knowledge entry generalising the lesson — all three describing a
production rule set that ignores them. For `dotmac_sub`.

**PROV-06 — `dotmac_crm` is not archived.** The repository is public, unarchived,
and was pushed to on 2026-08-26, three days after the "retired" designation was
acted on elsewhere. The 11-item deletion list above is safe to execute against the
observability stack, but "CRM is retired" is not yet true of the repository, and
anyone reasoning from that premise should know it.

**PROV-07 — adopting ERP's Foundation bundle today subtracts coverage.** All three
live ERP application rules map onto Foundation alerts in the omitted `unbacked`
42 (`FDN_HTTP_5XX_RATE_CRITICAL`, `FDN_HTTP_LATENCY_P99_HIGH`,
`FDN_LOG_INGESTION_GAP`). A straight swap trades three working application rules
for 22 infrastructure rules that largely duplicate `host_alerts`. The bundle is
also not on `dotmac_erp` at all — it lives on four unmerged `dotmac_starter_mt`
branches, two of which disagree about the product group's name
(`dotmac_product_dotmac_erp` vs `dotmac_product_dotmac-erp`).

**PROV-08 — the Foundation's `UNBACKED` headline over-counts against the fleet.**
At least 5 of the 42 read metrics that Dotmac products genuinely emit and that are
live in Prometheus now (`http_requests_total`, `http_request_duration_seconds_bucket`,
`up`). The methodology paragraph is scoped correctly to `dotmac_kernel`; the
headline sentence says "anywhere in the Dotmac fleet" and is falsified by the
running system. Documentation scope, not code. For `dotmac_starter_mt`.

**PROV-09 — `dotmac_integrator` has 22 reviewed rules and no way to run them.**
`deploy/alerts/ingress.rules.yml` at `78bcaebf4692fbde298ef2107b231d983e04a5c6`
holds five groups totalling 22 rules. None is loaded, and none could evaluate if
it were, because no scrape job covers the product. This is the mirror image of
PROV-01: rules with an owner and no deployment, versus deployment and no owner.

**PROV-10 — `runbook` and `runbook_url` are two vocabularies, and the stack reads
one.** 14 rules carry `runbook` (a `dotmac_sub`-relative ADR path); 3 carry
`runbook_url` (an error-tracker query). Alertmanager's template renders only
`runbook_url`. So the 14 rules with the more useful pointer show nothing, and the
3 that render show a list of unresolved issues rather than a procedure. Any rule
schema the control plane adopts should pick one field and validate it.

**PROV-11 — the group name `dotmac_sub` does not mean "owned by `dotmac_sub`".**
The `dotmac_sub` group holds 5 rules, none of which is in the `dotmac_sub`
repository. The 20 rules that *are* in that repository live in the
`prepaid_enforcement` and `billing_health` groups. Any migration that routes
ownership by group name inverts this.

**PROV-12 — three of four "product" groups are named after something other than the
product.** `dotmac_omni` holds CRM rules, `claude-knowledge` is the only group with
a hyphen rather than an underscore, and `host_alerts` / `billing_health` /
`prepaid_enforcement` are named by domain instead. A rules-directory layout keyed
on group name (the open question in the census's §11) inherits this inconsistency
unless it is normalised at the cutover.

**PROV-13 — worth noting for whoever owns `host_alerts`.** `DiskSpaceLow` excludes
only `fstype!="tmpfs"`, so container `overlay` and `shm` filesystems are included
in a host-level disk alert; and `WorkspaceBackupStateMissing` detects a missing
backup state via a negative sentinel (`… < 0`), which cannot fire if the metric is
absent entirely rather than negative — the case `WorkspaceBackupNotValidated`
also misses. Recorded for the owner; **not repaired here**, and neither is a
blocker for attribution.
