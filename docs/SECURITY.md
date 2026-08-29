# Security posture

What this repository protects, how, and what it explicitly does not protect.
`AGENTS.md` rule 1 is the hard rule; this document is its reasoning and its
boundary. `docs/ARCHITECTURE.md` describes the machinery referred to here.

## The secret-reference model

This repository holds references to secrets. It never holds a secret value, and
it never dereferences one.

A credential is declared as a `secret_file` object with exactly two fields
(`contracts/target.schema.json` `$defs/secret_file`, loaded into
`model.SecretFile`):

- `openbao_path` — where an operator obtains the value, for example
  `secret/dotmac/observability/erp-scrape`.
- `file_name` — the basename the evaluator will read from its secrets
  directory, for example `erp-scrape.token`.

Both strings are safe to commit. Neither can be turned into a credential by
reading this repository. The value is host state, placed by the deployment from
OpenBao, and OpenBao remains its owner.

The renderer converts `file_name` into a path under the fixed secrets constant
for the service that will read it, and emits the file-reference form of
whichever field the receiving system expects:

| Where | Rendered field | Directory |
| --- | --- | --- |
| Prometheus scrape job | `bearer_token_file` | `/etc/prometheus/secrets` |
| Prometheus federation | `bearer_token_file` | `/etc/prometheus/secrets` |
| Alertmanager Telegram | `bot_token_file` | `/etc/alertmanager/secrets` |
| Alertmanager email | `auth_password_file` | `/etc/alertmanager/secrets` |
| Alertmanager webhook | `url_file` | `/etc/alertmanager/secrets` |
| Alertmanager Slack | `api_url_file` | `/etc/alertmanager/secrets` |

Note that a webhook and a Slack integration reference the whole URL through a
file, because a webhook URL with an embedded key is a credential regardless of
which field it lives in. There is no rendering path that emits an inline token,
password or URL-with-key, and no code path in `dotmac_observability` that opens
a secrets file or contacts OpenBao. Whether the file exists is the deployment's
problem, checked at promotion time, not this package's.

`.gitignore` refuses `secrets/`, `*.token`, `*.key` and `*.pem` as a second
line, so a value fetched into a working tree by hand is not accidentally
staged.

## The secret scanner

`validate.scan_for_secret_material` reads every file Git tracks and reports any
line that looks like it carries a secret value. `make secret-scan` runs it and
is part of `make check`.

The file list comes from `git ls-files -z` rather than a filesystem walk
(`cli._tracked_files`). A walk would have to reimplement `.gitignore` to avoid
scanning a virtualenv, and a scanner that skips files for reasons nobody wrote
down is how a real finding gets lost.

### Shape, not entropy

The detector is a fixed set of shape patterns:

| Code | Shape |
| --- | --- |
| `SECRET-PEM-PRIVATE-KEY` | A PEM private-key header |
| `SECRET-TELEGRAM-BOT-TOKEN` | An 8-to-10 digit id, a colon, and 35 token characters |
| `SECRET-SLACK-WEBHOOK` | A `hooks.slack.com/services/` URL |
| `SECRET-AWS-ACCESS-KEY` | `AKIA` followed by 16 uppercase alphanumerics |
| `SECRET-ASSIGNED-CREDENTIAL` | A credential-shaped key name assigned a value of 16 or more characters |

It is deliberately not entropy-based, and this is a decision rather than an
omission. An entropy threshold flags high-entropy strings, and this repository
is made of high-entropy strings that are not secrets: every `sha256:` image
digest in `inventory/control-plane.toml`, every `rules_sha256` and
`metrics_manifest_sha256` in a bundle lock, every 40-character
`source_revision`, and every `rendered_digest` in a receipt. A bundle lock is
close to nothing but digests.

The consequence is predictable and it is the real argument. A detector that
cries wolf on legitimate content acquires an allowlist, the allowlist grows
with each new lock file, and the endpoint is a detector that detects nothing
while still appearing in `make check`. Shape patterns produce few false
positives on this corpus, so the allowlist has no pressure to grow, so the
detector stays honest. A missed exotic credential shape is a gap to close by
adding a pattern; a disabled detector is not recoverable by anything short of
noticing.

### The two exclusions, and their premise

`validate.SECRET_SCAN_EXCLUSIONS` is exactly two paths:

```
src/dotmac_observability/validate.py
tests/mutations/test_secret_detector_bites.py
```

`AGENTS.md` rule 15 requires that an exemption state an enforceable premise
rather than a convenience. The premise here is that these two files are the
detector and its sensitivity proof: they must contain the shapes being
detected, because the patterns live in one and the evidence that the patterns
bite lives in the other. Excluding them is not a relaxation of the rule; it is
the only way the rule can have evidence at all. A check over a corpus that
contains none of the thing it detects passes for the wrong reason.

Nothing else may be added to that tuple. The list is asserted exactly, not
merely bounded, by `tests/architecture/test_no_secret_material.py`, so widening
it fails the build rather than passing quietly; and the second excluded path,
`tests/mutations/test_secret_detector_bites.py`, is the sensitivity proof
itself. Both exist. A scanner whose corpus contains none of the shapes it looks
for cannot demonstrate that it bites, and an undemonstrated detector is an
unmonitored region wearing a green tick.

## The receipt carries no secret

`contracts/promotion-receipt.schema.json` sets `additionalProperties: false` at
every level, and every field it does permit is a count, a boolean, a digest, a
revision, a version string, a host identity, a receiver name or a timestamp.
There is no free-text field a value could be pasted into and no field whose
type would accept one.

This matters more than it looks, because a receipt is the artifact most likely
to be attached to a ticket, pasted into a channel or archived somewhere with
weaker access control than the repository. `canary.delivered` is a boolean and
`canary.receiver` is a receiver name: the receipt records that a named receiver
was reached, never how it was reached.

## Runtime posture of the rendered stack

- **Loopback-bound listeners.** `model.Evaluator.listen` carries a full
  host-and-port, and the reference inventory binds both evaluators to
  `127.0.0.1`. The rendered compose publishes
  `${PROMETHEUS_LISTEN:-<listen>}:<port>`, so the default keeps the port off
  every non-loopback interface and reaching it is an explicit act (an SSH
  tunnel, or a reverse proxy the host owns). Overriding the variable to
  `0.0.0.0` is possible and is a decision an operator makes deliberately, not a
  default anyone can inherit.
- **Read-only mounts.** Every configuration and secrets mount in the rendered
  compose is `:ro`. Only the named data volumes (`prometheus_data`,
  `alertmanager_data`) are writable. A compromised evaluator process cannot
  rewrite its own rules or read anything outside the two directories mounted
  into it.
- **Unprivileged users.** Both services run as `${PROMETHEUS_USER:-65534:65534}`
  and `${ALERTMANAGER_USER:-65534:65534}`, that is, `nobody` by default.
- **Digest-pinned images.** Images are `image@sha256:...`, never a tag. A tag is
  a mutable pointer, so a restart under a tag can silently change the running
  binary; the receipt could then name a version that is not what ran.
- **One required variable.** `OBSERVABILITY_RELEASE` is rendered as
  `${OBSERVABILITY_RELEASE:?release directory is required}` with no default,
  because a stack that silently starts against the wrong release is worse than
  one that refuses to start.

## Promotion authority

A promotion targets a host a human named in the authorizing request
(`AGENTS.md` rule 17). It is never inferred from an inventory row, and this is
worth stating precisely because the inventory does contain a plausible-looking
target: `inventory/control-plane.toml` declares `host.identity` and
`host.ssh_alias`, and `model.Host` carries both. Those fields exist so the
receipt can record which host was promoted to and so an operator can check that
the named target and the declared one agree. They are not an instruction to
connect anywhere.

The same rule governs the delivery train. PR 2's census is blocked, not
delayed, because it needs Michael to name the Observer SSH target explicitly.
PR 5 rehearses on a disposable host, 85.190.246.211, and PR 7's production
bootstrap is authorized separately from the PR that writes it.

Every promotion also targets an exact protected-`main` SHA reasserted as
current at promotion time (`AGENTS.md` rule 3). A branch name, a tag alone or
"latest" is not a promotion target: a repository-local claim may be derived
from repository-local facts, but a claim that a bundle is published requires an
external oracle carrying immutable coordinates. Enforcement is PR 6.

## What this repository does not defend against

**A host operator with root.** Somebody with root on the Observer host can edit
a staged release directory, replace a secrets file, swap the release pointer,
or run a different compose file entirely. Nothing here prevents that, and no
amount of Git ownership can: the host is where the bytes finally live.

What the design provides instead is detection. Because the desired state, the
live state and the last verified receipt are three independently readable
artifacts (`docs/ARCHITECTURE.md` §"Three independently comparable artifacts"),
an edit made on the host shows up as a disagreement between them, with enough
detail to say which of the three moved. `AGENTS.md` rule 2 then makes the
response unambiguous: a change made on the host is drift to be reported and
reverted, never a fix to be kept. Drift comparison is PR 6; until it exists,
this repository detects nothing on the host at all, and saying otherwise would
be the exact overclaim rule 15 exists to prevent.

Also out of scope: the security of the products being scraped, the contents of
product alert bundles (the product repository owns those and their review), the
OpenBao deployment itself, and network reachability between the Observer host
and its scrape targets.
