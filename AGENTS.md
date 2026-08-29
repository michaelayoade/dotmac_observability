# dotmac_observability — hard rules

Canonical and tool-neutral. `README.md` explains the shape;
`docs/ARCHITECTURE.md` is as-built truth; `docs/adr/` holds decisions;
`docs/CONTROL_EXCEPTIONS.md` names every region that is declared **unmonitored**
rather than exempt. If this file and any other disagree, this file wins — fix
the drift.

Each rule names its enforcement. `enforcement: none yet (PR n)` is a stated
review discipline, not a guard, and it is a defect to describe it as enforced.

---

1. **Secrets are referenced, never stored.** Nothing in this repository may
   contain a token, password, webhook URL with an embedded key, bearer
   credential or certificate. An input declares an OpenBao path and the
   *logical file name* the evaluator will read; the value is host state placed
   by the deployment. Rendered configuration therefore contains
   `bearer_token_file: /etc/prometheus/secrets/<name>` and never a token.
   — `tests/architecture/test_no_secret_material.py`

2. **No direct production file editing.** `/opt/observability` is not an
   editing surface. Every live byte is rendered here, staged as an immutable
   release directory and activated atomically. A change made on the host is
   drift to be reported and reverted, never a fix to be kept.
   — enforcement: drift detection, `none yet (PR 6)`

3. **Every promotion targets an exact protected-main SHA**, reasserted as
   current at promotion time. A branch name, a tag alone or "latest" is not a
   promotion target. A repository-local claim is derived from repository-local
   facts; a claim that a bundle is published requires an external oracle
   carrying immutable coordinates (Governance ADR 0013).
   — enforcement: `none yet (PR 6)`

4. **Every bundle is immutable and digest-pinned.** A bundle lock names the
   product, environment, source revision, image digest, product-manifest
   digest, rules artifact pointer, `rules_sha256`, `metrics_manifest_sha256`
   and rule count. Promotion fetches the artifact and verifies the digest
   before anything is rendered. A version STRING is not an identity.
   — `contracts/bundle-lock.schema.json`; verification `none yet (PR 3)`

5. **Product rules stay product-owned.** This repository pins and assembles;
   it never authors a product alert expression, and it never edits a fetched
   bundle. If a rule is wrong, the product repository fixes it and publishes a
   new bundle. A local patch would make one version name two contracts.
   — enforcement: `none yet (PR 3)` (fetched bundles are byte-compared to their digest)

6. **Duplicate alert names, duplicate recording rules, or incompatible label
   vocabularies fail the build.** Two products may not both own `WorkerStalled`,
   and two bundles may not disagree about what `severity` can be.
   — enforcement: `none yet (PR 3)`

7. **Every `warning` and `critical` route reaches a declared receiver**, or an
   explicitly reviewed null policy that says in words why this class of alert
   is deliberately not delivered. A route falling through to a default that
   nobody reads is the failure this rule exists to prevent.
   — `tests/unit/test_routing_coverage.py`

8. **Every rule carries an owner, a severity, a summary, a runbook and producer
   proof.** Producer proof means the alert's metric appears in the product's
   metrics manifest with a declared type, unit and bounded label vocabulary.
   Prometheus returning no series is not health — an alert over a metric nobody
   emits is permanently silent and indistinguishable from "all clear".
   — enforcement: `none yet (PR 3)`

9. **Federated `up` and `scrape_*` series are renamed on import.** A central
   rule must never confuse an imported upstream's health with the health of a
   target this control plane owns. Every federation declares a rename prefix
   and the renderer emits the relabelling; a federation that does not rename is
   refused.
   — `tests/unit/test_federation_rename.py`

10. **"Rule inactive" is not recovery evidence.** Recovery requires that the
    rule EXISTS and is healthy, AND that its target is present and healthy. A
    deleted rule, a failed evaluation and a vanished target all present as
    "not firing". Any verification that accepts absence as success is wrong.
    — enforcement: `none yet (PR 5)`

11. **Promotion failure restores the exact preceding release.** The previous
    release pointer is preserved before activation and restored on any failure
    before `ACCEPTED`. There is no partial-promotion state an operator is
    expected to finish by hand.
    — enforcement: `none yet (PR 6)`

12. **Desired state, live state and the last verified receipt are three
    independently comparable artifacts.** Drift is the disagreement between
    them. A design that can only read one of the three cannot detect drift.
    — enforcement: `none yet (PR 6)`

13. **Rendered bytes are committed, never hand-edited, and deterministic.**
    `make render-check` re-renders every declared inventory and compares
    BYTES. Same inputs, same bytes, on any machine, in any order — no
    timestamps, no hostnames, no set iteration, no locale.
    — `tests/unit/test_render_determinism.py`, `make render-check`

14. **Everything by config.** Every environment-specific value is an
    overridable knob with a documented default (Make `?=`, compose
    `${VAR:-default}`, `: "${VAR:=default}"`). Never hardcode a host, port,
    image, path or retention.
    — `tests/architecture/test_repository_contract.py`

15. **A guard exemption states an ENFORCEABLE premise** (Starter ADR-0018).
    A region with no guard is recorded in `docs/CONTROL_EXCEPTIONS.md` as
    unmonitored, with the PR that will monitor it. "Grandfathered" and
    "reviewed and correct" stay distinct, and every detector carries a
    sensitivity proof — a check that cannot demonstrate it bites is not
    enforcement.
    — `tests/mutations/`, `tests/architecture/test_control_exceptions.py`

16. **Cross-repository engineering governance is pinned by exact commit**, and
    the workflow executes that same accepted revision.
    — `.dotmac/standards-profile.json`, `.github/workflows/engineering-standards.yml`

17. **Branch before committing; never commit to `main`.** Merge only on green.
    Only an explicitly authorized promotion touches a live host, and the target
    host must be named by a human in the authorizing request — never inferred
    from an inventory row.

---

## The line this repository must not cross

It is tempting, once a repository owns the evaluator, to let it own the alert
too — to "just fix" a threshold centrally. Doing so silently moves a product
decision out of the product, and the product's tests then prove something the
fleet no longer runs. Assembly is not authorship. The only alert expressions
this repository may contain are its own control-plane meta-alerts (deadman,
evaluator health, bundle-digest mismatch), which it genuinely owns because no
product can observe them.
