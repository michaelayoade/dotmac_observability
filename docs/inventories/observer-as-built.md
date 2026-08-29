# Observer as-built census — 2026-08-29

A dated characterization of the observability control plane as it actually
runs. **Facts, not mandates** (see `docs/inventories/README.md`), and
deliberately not a plan: what should change about any of this is argued in an
ADR or a pull request, not here.

Method: read-only inspection over SSH, authorized by Michael and confined to
`docker inspect`, `docker image inspect`, `stat`, `find`, `sha256sum`, the
Prometheus and Alertmanager read APIs, and reading configuration files. No
container environment was printed, no credential value or secret-file content
was read, and **nothing on the host was changed**. The raw capture lives in an
ephemeral private workspace and is not committed.

Redaction follows ADR-0004. Resolved hostnames, addresses, complete scrape
URLs, credential-file bindings and federation endpoints are private promotion
material and appear only in the private inventory handed over separately. What
is below is structure, counts, versions, digests and health.

## 1. Platform and project identity

| Fact | Value |
| --- | --- |
| Docker | 29.4.3 (build 055a478) |
| Compose | v5.1.3 |
| Compose project | `observability`, from `/opt/observability/docker-compose.yml` |
| Services in the project | 9 — prometheus, alertmanager, grafana, loki, promtail, node-exporter, cadvisor, glitchtip, glitchtip-worker |
| Version control on `/opt/observability` | **none** — no `.git`, no remote, no history |

The host also runs eight unrelated Compose projects, including roughly sixty
exited test containers and eleven test PostgreSQL instances. That is outside
this repository's scope but bears on capacity (§7) and on the standing rule
that Observer is not a test host.

## 2. Running images

Every observability image is tagged `:latest`. None is pinned by digest. The
digests below are what was *actually running* at census time and are the only
thing that identifies these deployments; the tag does not.

| Service | Image ref | Running digest | Image built |
| --- | --- | --- | --- |
| prometheus | `prom/prometheus:latest` | `sha256:e4254400b856…6146acc3` | 2026-04-27 |
| alertmanager | `prom/alertmanager:latest` | `sha256:51a825c2a40a…47a4d286` | 2026-04-29 |
| grafana | `grafana/grafana:latest` | `sha256:0f86bada30d6…78a4a73a` | 2026-04-17 |
| loki | `grafana/loki:latest` | `sha256:73e905b51a7f…cc0dc8eb4` | 2026-03-26 |
| promtail | `grafana/promtail:latest` | `sha256:6cfa64ec432b…dd7241381` | 2026-03-25 |
| node-exporter | `prom/node-exporter:latest` | `sha256:e9cff4fc67b1…1b357205` | 2026-04-07 |
| cadvisor | `gcr.io/cadvisor/cadvisor:latest` | `sha256:3de2bd520312…6f44ec57` | 2025-12-25 |

Binary versions reported by the running processes: **Prometheus 3.11.3**,
**Alertmanager 0.32.1**.

> This repository's CI pins `promtool` 3.2.1 and `amtool` 0.28.0 for its
> config-acceptance job. Those are older than what production runs, so CI
> currently proves the rendered configuration is accepted by a *different*
> version than the one that would load it. Aligning the pins is PR 3 work.

Container users: prometheus and alertmanager run as `nobody`, grafana as 472,
loki as 10001. **promtail and cadvisor run as root**, both with host mounts.

## 3. Configuration mounts — the inode constraint, measured

| Path | Mounted at | Mode | Inode | Links | RO? |
| --- | --- | --- | --- | --- | --- |
| `prometheus/prometheus.yml` | `/etc/prometheus/prometheus.yml` | 644 | 524424 | 1 | **no** |
| `prometheus/alerts.yml` | `/etc/prometheus/alerts.yml` | 644 | 524425 | 1 | **no** |
| `alertmanager/alertmanager.yml` | `/etc/alertmanager/alertmanager.yml` | 644 | 524428 | 1 | **no** |
| `secrets/` | `/etc/prometheus/secrets` | dir | — | — | yes |
| `secrets/telegram_bot_token` | `/etc/alertmanager/telegram_bot_token` | 600 | — | — | yes |

Three configuration files are **single-file bind mounts**, each with one link,
and each mounted **read-write** into its container. This is the mechanism
ADR-0001 and ADR-0002 describe, now confirmed on the host: a bind mount binds
an inode, so any editor that writes a replacement file detaches it and the
container keeps reading the old content while the edit appears to succeed. The
only safe gesture is appending in place.

Alertmanager's credential is likewise a single-**file** mount, so the same
hazard applies to rotating it, not merely to editing configuration.

## 4. Prometheus

- `global`: `scrape_interval: 15s`, `evaluation_interval: 15s`.
- `external_labels`: **empty**. This evaluator stamps nothing on its own
  series, so nothing distinguishes them by environment or control plane.
- `rule_files`: **a single file**, `/etc/prometheus/alerts.yml` — not a
  directory glob. There is no per-product rule file and no place to drop one.
- `alerting`: one Alertmanager, one static target.
- 16 scrape jobs; 19 active targets; 0 dropped.
- Flags: `--web.enable-lifecycle` (so `POST /-/reload` works),
  `--web.enable-remote-write-receiver`, retention `30d`.

Credentials on the seven authenticated jobs are all
`authorization: {type, credentials_file}`. **No inline credential appears in
`prometheus.yml`** — checked explicitly.

> This repository's renderer emits `bearer_token_file`, which is the older
> spelling of the same thing. Reproducing the as-built byte-for-byte needs the
> `authorization` block. PR 3.

The federation job's relabelling is, in shape, exactly what this repository's
rule 9 requires and what its renderer already emits:
`source_labels: [__name__]`, `regex: (up|scrape_.+)`, `target_label: __name__`,
`replacement: federated_${1}`, with `honor_labels: true`. This is the one part
of the as-built the design already matches.

### Target health

18 of 19 targets up. One down: **`dotmac-crm-app`, HTTP 502** — a scrape job
for a product that has been retired. It is not merely stale configuration: it
is currently firing `ServiceDown`, so a decommissioned system is generating
live pages.

## 5. Rules

56 alerting rules in 9 groups. **Zero recording rules.** All 56 report
`health: ok`. Five are firing at census time.

| Group | Rules |
| --- | --- |
| `prepaid_enforcement` | 13 |
| `dotmac_identity_plane` | 10 |
| `billing_health` | 7 |
| `dotmac_academy` | 6 |
| `host_alerts` | 5 |
| `dotmac_sub` | 5 |
| `dotmac_omni` | 4 |
| `claude-knowledge` | 3 |
| `dotmac_erp` | 3 |

Severity split: 33 `warning`, 23 `critical`. No duplicate alert names. Every
rule carries a `severity` label and a `summary` annotation.

**53 of 56 carry no `runbook_url`.** This repository's rule 8 requires one on
every rule; the as-built satisfies it three times.

### The ERP gap, stated precisely

The `dotmac_erp` group holds three hand-written application rules —
`ErpHighErrorRate`, `ErpSlowRequests`, `ErpLokiLogsDropping`. **None of them
comes from ERP's rendered Deployment Foundation alert bundle.** So the summary
"central Prometheus scrapes ERP while loading none of its rendered alert
rules" is accurate: ERP is scraped, three unrelated rules about ERP exist, and
the rendered bundle is absent.

The `dotmac_omni` group holds four **CRM** rules, one of them `critical`, for
the same retired product as the dead scrape job.

## 6. Alertmanager

- One receiver, `default`, with a single `telegram_configs` entry using
  `bot_token_file`. No inline token.
- **Zero child routes.** Every alert — all 56 rules, both severities — reaches
  the same receiver. The `critical`/`warning` distinction has no delivery
  consequence today.
- One inhibition, `critical` suppressing `warning`, `equal: [alertname,
  instance]`. It uses the **deprecated `source_match`/`target_match`
  spelling**, not `source_matchers`/`target_matchers`.
- `templates`: none.
- `global`: `resolve_timeout` only. No SMTP, consistent with telegram-only
  delivery.
- **No `--web.enable-lifecycle`.** Alertmanager cannot be reloaded over HTTP;
  a configuration change needs SIGHUP or a container recreate. Prometheus and
  Alertmanager therefore have *different* activation mechanisms, which any
  promotion lane has to handle rather than assume.

## 7. Backups, rollback and drift

`/opt/observability` contains **26 ad-hoc backup files** beside the live
configuration — 20 for `alerts.yml`, 8 for `prometheus.yml`, 2 for
`alertmanager.yml`, 4 for `docker-compose.yml` — in at least four naming
conventions: Unix epoch (`.bak.1784900394`), compact timestamp
(`.bak.20260816142004`), ISO-ish (`.bak-20260801T050357Z`), and semantic
(`.bak-crmerprunbook-20260730`, `.bak-hostrename`, `.bak-pregroupsplit`).

Material for a rollback exists. A rollback *mechanism* does not: there is no
ordering, no manifest, no record of which file corresponds to the currently
running configuration, and at least one file whose embedded date disagrees
with its mtime. Restoring would be a judgement call under pressure.

None of the backup names ends in `.yml`, which is the only reason a future
`rule_files` glob over that directory would not load them as rules. That is
luck, not design, and it is why this repository's releases keep rendered rules
in their own directory.

Host capacity: 8 CPUs, 23 GiB RAM (16 GiB available), root filesystem
**83% full** (320 G of 387 G used, 67 G free). Prometheus data 59.4 GB, Loki
data 34.9 GB — 94 GB of the usage, against a 30-day retention.

## 8. Secrets

Ten secret files under `/opt/observability/secrets`, all mode 600 except one
at 400, owned by the container users that read them. Contents were not read;
only sizes and digests were taken, and neither is recorded here. The exact
filenames are credential-file bindings and therefore private material under
ADR-0004.

There is one operator script, `ops/render-grafana-secret.sh`, mode 700.

## 9. Findings

Numbered so a later change can cite one. Severity is this census's judgement.

| # | Severity | Finding |
| --- | --- | --- |
| OBS-01 | high | No version control on `/opt/observability`. Every change is an unattributable in-place edit. This is the finding the whole repository exists to close. |
| OBS-02 | high | All seven images float on `:latest`. A restart can silently change the running version; nothing records what was deployed. |
| OBS-03 | high | Rules live in one 33 KB file loaded by an exact path. There is no per-product bundle, so no product can own its own rules and no bundle can be swapped atomically. |
| OBS-04 | high | Alertmanager has no child routes. `critical` and `warning` are recorded but not routed differently, so severity is presentational. |
| OBS-05 | medium | 53 of 56 rules have no runbook. |
| OBS-06 | medium | A retired product (CRM) still has a scrape job and four alert rules, and its dead target is firing `ServiceDown` — live noise from a decommissioned system. |
| OBS-07 | **critical** | **Corrected — see §9.1.** The original wording of this finding was wrong. IPv4 containment is in place and persisted; the unremediated exposure is IPv6, by a mechanism that makes the existing IPv6 rules inert. Detail withheld here because it is unremediated. |
| OBS-08 | medium | No rollback mechanism (§7), only 26 unordered backup files. |
| OBS-09 | medium | `external_labels` is empty, so this evaluator's own series carry no environment or control-plane identity. |
| OBS-10 | **medium** | **The single inhibition is structurally inert**, not merely deprecated. It requires `alertname` to be equal across a `critical` source and a `warning` target, and no alert name is duplicated in the rule set — so it can never match anything. The `High`/`Critical` pairs it looks designed for are exactly the case an `alertname` equality cannot express. It also uses the deprecated `source_match` spelling. |
| OBS-11 | low | Root filesystem is 83% full; Prometheus and Loki hold 94 GB. |
| OBS-12 | low | promtail and cadvisor run as root with host mounts. |
| OBS-13 | info | CI pins older promtool/amtool than production runs (§2). |
| OBS-14 | info | The as-built uses `authorization.credentials_file`; the renderer emits `bearer_token_file`. Parity needs the former. |
| OBS-15 | high | **33 of 56 live rules have no attributable owner.** Only 23 trace to a repository. Six intact groups are unattributed, one of which has no candidate home at all. Detail and method in `observer-rule-provenance.md`. |
| OBS-16 | high | **Two live rules can never fire.** They select a label value that was renamed in the producing product before the rules were written, so they have matched nothing since the day they were added. |
| OBS-17 | high | **A rule repaired upstream 18 days ago is still running here in its unfixed form.** The product fixed it, merged it, and wrote up the lesson; the host never received it. This is precisely the drift class this repository exists to make impossible, observed before the control plane exists. |
| OBS-18 | medium | **Nine rules reference metrics no repository emits.** Their probe job is healthy, so the exporter runs — its source is simply not in any checkout. A supply-chain gap rather than a coverage gap. |
| OBS-19 | medium | **ERP has no rendered Foundation alert bundle in its repository.** It exists only on unmerged branches elsewhere, and adopting it as-is would *subtract* coverage: all three working ERP application rules map onto Foundation alerts that are in the omitted set, trading them for infrastructure alerts that duplicate `host_alerts`. PR 9's premise needs revisiting before it is scheduled. |

OBS-07 is the only finding that is not this repository's own business to fix,
and it should not wait for the promotion train.

## 9.1 OBS-07, corrected

This census first recorded OBS-07 as "several services published on all
interfaces with no host firewall restriction". **That was wrong, and the error
was mine.** The check behind it grepped the `DOCKER-USER` chain for
`--ctorigdstport`, which is the matching strategy used by two of the rule
blocks; it is not the only one. Counting only those matches returned zero for
the observability ports and the conclusion followed from the undercount.

A full read of the chain finds **198 IPv4 rules in `DOCKER-USER`** — nine
blocks covering the observability ports and others — dating from a fleet
firewall sweep on 2026-08-14, byte-identical to the persisted
`/etc/iptables/rules.v4`, with packet counters showing roughly fifteen days of
work. `iptables-persistent` is installed and enabled, so the IPv4 restriction
survives a reboot. **IPv4 containment exists, works and persists.**

The correct finding is narrower and worse:

**The exposure is IPv6, and the IPv6 rules that were supposed to cover it
cannot ever fire.** They are installed in the `ip6tables` `DOCKER-USER` chain,
which is only jumped from `FORWARD`. With no IPv6 DNAT in play, `docker-proxy`
terminates an IPv6 connection as an ordinary local process, so the traffic
arrives on `INPUT` and never traverses `FORWARD`. Every IPv6 rule in that
chain shows a zero packet counter, which is the observable signature of a rule
that is not merely unused but unreachable.

This was verified rather than inferred: probes from two other fleet hosts
found the affected ports open over IPv6, with a port known to be closed used
as a discriminating control. A third probe, from a host with no global IPv6,
failed even against the control port and was discarded — without the control
it would have read as a false pass, which is worth recording as the method
that made the result trustworthy.

Consequences that follow from the mechanism rather than from this host:

- A fix must **not** be written into `ip6tables DOCKER-USER`. It belongs on
  `INPUT`, or the IPv6 publish should be removed by naming an interface in the
  Compose port binding. An `INPUT` rule carries SSH, so it needs proven
  out-of-band recovery first (see below).
- **The same inert idiom was applied fleet-wide in the 2026-08-14 sweep.**
  Every host that sweep touched needs re-checking. That is outside this
  repository and is tracked in Knowledge, not here.

Two further facts from the same preflight, recorded because a later change
must not break them:

- **Loki cannot be loopback-bound.** It has six live remote log shippers.
  Every other affected service is reachable only from this host's own
  Prometheus, over the container bridge and by container name, so unpublishing
  those breaks nothing.
- **Source allowlists must be derived from observed addresses, not from DNS.**
  One shipper's hostname resolves to an address that was never seen
  connecting; it actually arrives from a different address in the same
  autonomous system. Narrowing to DNS-derived host addresses would have cut it
  off.

Out-of-band recovery is **present but unproven**: the provider console and a
serial getty exist, but no working root password was confirmed. That is a
blocker for any change touching the `INPUT` chain, and therefore for the IPv6
fix itself.

The port-level detail, the observed shipper addresses and the draft rules stay
in the private preflight material. This section says what class of thing is
wrong and what the fix must respect; it deliberately does not publish a map of
what is currently reachable.

### Why this correction is in the census rather than replacing it

A census that silently rewrites a finding is not evidence. The original
wording is left visible in the table above with a pointer here, so a reader
can see both what was claimed and why it was withdrawn. The undercount is also
a reusable lesson: a firewall chain has more than one matching strategy, and a
grep for one of them is not a count of the chain.

## 9.2 Provenance

A companion document, `observer-rule-provenance.md`, attributes every live
rule and scrape job to an owning repository and revision where one can be
found, and says plainly where one cannot. Its two load-bearing numbers are
**33 unattributed rules** and **9 rules whose producer metric no repository
emits**.

Both are inputs to the migration, not opinions about it: the delivery plan
blocks production promotion until the unattributed count reaches zero, so 33
is the size of the work rather than a note. The attribution method carries its
own sensitivity proof, and two tempting matches were refused as circular
because the document they appear in is this census.

## 10. The private inventory this census produced

Everything redacted above was captured into a proposed private inventory,
handed over separately and destined for an approved OpenBao
deployment-inventory path. Per ADR-0004 public Git records its identity and
nothing else:

| Field | Value |
| --- | --- |
| Document | `observability-private-inventory.v1` (proposed) |
| Environment | production |
| Version | 1 |
| sha256 | `1ecd635ba332c1c22883d6add04dceb52329ab36cfd4194da3edae33f9f5b7c5` |
| Contents | 16 logical targets (7 authenticated), 1 Alertmanager endpoint, 1 receiver binding |

The digest is over the document, so a later census that produces the same
bytes proves nothing drifted, and one that does not identifies drift without
either version being published. Promotion receipts will record this pair, never
its values.

## 11. What this changes about the plan

PR 3 cannot render this control plane byte-for-byte until the contracts gain:
digest-pinned images by measurement rather than by requirement (§2), the
`authorization` credential block (§4), an `external_labels` value that is
currently empty (§4), and a decision about whether the rendered layout adopts
a rules **directory** — which the as-built does not have — as part of the
cutover rather than as a same-shape reproduction (§4, OBS-03).

That last one is the substantive design question this census raises: a
byte-identical reproduction of the as-built would reproduce OBS-03. Parity and
correctness point in different directions here, and the resolution belongs in
PR 3's ADR, not in this file.
