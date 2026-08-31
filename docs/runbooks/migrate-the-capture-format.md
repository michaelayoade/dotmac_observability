# Migrate the stored private inventory out of the capture format

Lands with the capability it describes (`inventory-classify`,
`inventory-migrate`, and the `migrate-capture` branch of
`.github/workflows/private-inventory-supersede.yml`), per
`docs/runbooks/README.md`'s rule.

**Read `docs/adr/0008-the-observability-bundle.md` §5 first.** This procedure is
mechanical; the reasoning is there.

## What this is for

The stored production private inventory declares
`schema_version = "observability-private-inventory.v1 (PROPOSED)"` — the shape
PR #2's census produced, three PRs before ADR-0006 accepted the contract. It
yields 68 errors against the accepted contract
(`docs/inventories/observer-as-built.md` §15).

Both mutation tools load the previous version through the accepted contract as
their first act, so **every retirement is blocked** until this runs. It is not
itself a retirement and cannot be done by `retire-a-target.md`.

## Before you start: verify these three prerequisites

Checked 2026-08-30 and true then. Confirm each before dispatching, because the
failures are silent or confusing rather than loud:

| Prerequisite | State on 2026-08-30 | What its absence looks like |
| --- | --- | --- |
| A runner labelled `[self-hosted, dotmac-control-runner, dotmac-observability-control]` | **registered 2026-08-31**; both private-inventory workflows now run a hosted, fail-closed preflight first | Missing, offline, busy or unreadable runner state refuses before the store-touching job is queued |
| The `private-inventory` environment | **does not exist** (`gh api repos/:owner/:repo/environments` → 0) | The job runs with **no human gate at all**. The workflow's own comment describes a named required reviewer; that is setup, not evidence. Until the environment exists the only thing preventing an unapproved production write is the document failing to load, which is an accident rather than a control |
| `OPENBAO_ADDR`, `OPENBAO_INVENTORY_WRITER_TOKEN`, `OBSERVABILITY_PRIVATE_INVENTORY_MOUNT`, `OBSERVABILITY_PRIVATE_INVENTORY_PATH`, and for this procedure `OBSERVABILITY_HOST_BINDING` | **none configured** | The read step exits on its own `is not configured` check |

Only a repository administrator can supply these. Nothing in this repository
can, and nothing in it should pretend to.

## 1. Confirm what the store holds, without reading it

Run `private-inventory-discover.yml`. It reports the storage shape and stops.

Then, in the same run's log, the classification line:

```
format observability-private-inventory.v1 (PROPOSED)
```

That is the whole output. It reads one field and prints one line — no key name,
no length, no value. Exit code **2** means the capture format, **0** means the
accepted contract (nothing to do), **3** means a shape this repository does not
recognise.

**A `3` stops here.** The two known formats are migrated by different code, and
being wrong about which one is holding a production estate is the risk this
exit code exists to prevent. Do not guess from the key set.

## 2. Read the digest you will name

The capture's digest, which becomes the compare-and-set precondition. Take it
from the discovery run; do not compute it by opening the document.

## 3. Write the request, and have it reviewed

A `migrate-capture` request against
`contracts/supersession-request.schema.json`. Every field is a logical name:

```toml
schema_version = "observability-supersession-request.v1"
kind = "migrate-capture"
document = "<the stable name every future receipt will use>"
rationale = "..."

[previous]
version = 1
sha256 = "<the digest from step 2>"
format = "observability-private-inventory.v1 (PROPOSED)"

[storage]
shape = "<from discovery>"

[migrate]
document = "<the same stable name>"
host_target_id = "dotmac-observe"    # must equal inventory/control-plane.toml
federations = ["dotmac-sub-federation"]
```

`federations` names which of the capture's folded-in `targets` entries are
federations — the capture holds one flat array and the accepted contract holds
two. It is **cross-checked against the public inventory** and refused on
disagreement; it is never inferred from a name.

Merge it to protected `main`. The merge is the review.

## 4. Configure the host binding

The one value the capture does not hold: the accepted contract requires
`host.identity` and `host.ssh_alias` and the capture has no `host` key.

Set the repository secret `OBSERVABILITY_HOST_BINDING` to a JSON object:

```json
{"target_id": "…", "identity": "…", "ssh_alias": "…"}
```

**A secret, not a dispatch input.** A `workflow_dispatch` input is recorded with
the run, visible in the summary and the API and in `github.event.inputs` for
every later step. The secret exists in one step, lands in a mode-0600 file under
`$RUNNER_TEMP`, and is shredded in that same step —
`tests/architecture/test_supersession_workflow_cannot_leak.py` asserts all
three.

## 5. Dispatch

`private-inventory-supersede.yml`, `request` = the merged request's path. It
will:

1. refuse a hosted runner, a path escaping the repository, and a missing public
   inventory;
2. verify the tool **before** any credential is introduced, and read the kind
   and declared format out of the request through the contract's own parser;
3. read the stored document and **classify it with `--expect`** — refusing if
   the store's format is not the one the reviewed request declared;
4. migrate, then `validate --private-inventory`, which checks resolution in both
   directions;
5. write with KV `cas`, then read the stored bytes **back** and compare against
   the digest that was meant to be stored — the only check that can fail on a
   truncated write;
6. shred the working copies, on success and on failure.

## 6. What a refusal means

| Finding | Meaning |
| --- | --- |
| `REQUEST-PREVIOUS-DIGEST` | The store does not hash to the digest the request names. **Run `inventory-classify` before assuming a lost update:** if it now reports the accepted contract, the migration already ran and this request has been applied. If it still reports the capture format, somebody else moved the store |
| `MIGRATE-CREDENTIAL-SHAPE` | A stored credential is not an object carrying `openbao_path` and `file_name`. The migration will not guess one — complete the entry in the store's own shape first |
| `MIGRATE-TLS-CONFIG` | A target carries a `tls_config`, which the accepted contract has no field for. Refused rather than dropped: losing it silently weakens how a live target is verified. It needs a contract decision |
| `MIGRATE-RECEIVER-CREDENTIAL` | The capture holds a credential file with no store path. The migration cannot invent one |
| `MIGRATE-FEDERATION-SPLIT` | The request and the public inventory disagree about which entries are federations |
| `MIGRATE-HOST-TARGET` / `MIGRATE-HOST-INCOMPLETE` | The supplied host binding is for a different logical host, or is missing a field |
| `MIGRATE-UNCARRIED` | The capture holds `alertmanager_endpoints`, which the accepted contract has no field for. Confirm in the rationale that the rendered compose file already names the alertmanager service, and remove the key from the store in the same migration |

## 7. Afterwards

The digest has changed. **Any retirement request written before the migration
is now stale** and must be rewritten against the new digest and reviewed again.
That is the whole reason `retire-a-target.md` says not to pre-write one.

Record the new version and digest — never its values — wherever the previous
one was cited.
