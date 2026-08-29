# ADR-0004: Public logical inventory, private promotion material

- **Status:** Accepted
- **Date:** 2026-08-29
- **Supersedes:** nothing
- **Related:** `docs/adr/0001-observability-control-plane-has-one-git-owner.md`,
  `docs/adr/0003-the-control-plane-repository-is-public.md`,
  `AGENTS.md` rules 1, 4 and 18, `docs/SECURITY.md`

## Context

ADR-0003 made this repository public, and named the price precisely: everything
committed here is world-readable the moment it lands. It then declined to
answer the question that price raises, on the grounds that answering it well
needed PR 2's census rather than a guess. The open question was recorded as
`public-inventory-endpoint-exposure` — the enforcement line of `AGENTS.md`
rule 18 and the single row in the decisions table of
`docs/CONTROL_EXCEPTIONS.md`. This ADR answers it.

The question is not the one rule 1 answers. Rule 1 asks whether a value is a
secret: a token, a password, a webhook URL with an embedded key, a bearer
credential, a certificate. It is enforced, it has a sensitivity proof, and it
remains sufficient for what it covers. Public visibility asks a second
question that rule 1 was never meant to answer — whether a NON-secret fact is
still something to publish. A production scrape endpoint, an internal
hostname, a port, a host identity and the store path at which a credential is
kept are each non-secret under rule 1. Together they are a map of the estate,
drawn by the people who know it best, kept current by a gate that fails when
it drifts.

Timing is what forces the answer now rather than later. Today's corpus is
contracts, code, tests and one reference fixture whose hosts are `.invalid`
names and whose digests are placeholders; nothing in it describes a real
target. PR 3 writes production inventory. The moment it does, the material is
published, and **Git history is not retractable**: a value committed to a
public repository and removed in the next commit has still been published, has
been served to every clone, mirror and archival crawler that touched the
repository in between, and cannot be recalled. A credential responds to that
by being rotated. A hostname, a port and a network route do not — the estate
would have to change, not the file. So the classification must precede the
first production inventory commit. There is no version of this decision that
can be corrected afterwards.

## Decision

Public Git carries the LOGICAL description of the control plane. Resolved
network and identity material is private, and reaches the render only at
promotion time.

### Public Git

| Published | Notes |
| --- | --- |
| Logical target ID | For example `erp-production`. The name a document refers to, resolved elsewhere. |
| Service owner and environment | Rule 8's accountability, and which plane a document belongs to. |
| Metric and alert contracts | Metric names, types, units, bounded label vocabularies, alert names, severities. |
| Expected capabilities | What a target must be able to do, including the `expected` up-count a job asserts. |
| Scrape protocol | Scheme and the protocol-level shape of the scrape, not where it points. |
| Health semantics | What counts as healthy, and what "not firing" is not (rule 10). |
| Bundle and inventory schema | Everything under `contracts/`. |
| Synthetic CI endpoints | The `.invalid` fixture material CI renders and byte-compares against. |
| Private-inventory version and digest | The identity of the private document a render consumed — never its values. |

### Private promotion material

| Withheld | Notes |
| --- | --- |
| Resolved hostname or IP | The value a logical target ID resolves to. |
| Port and complete scrape URL | Including any port carried alongside a host. |
| TLS and server identity | Server names, pinned certificate identities, verification overrides. |
| Credential-file binding | Which credential a target uses and where that credential is kept, `openbao_path` included. |
| Federation endpoint | The upstream a federation imports from. |
| Network-route details | Reachability, proxying, tunnels, and anything describing the path taken. |

This material is stored under an approved OpenBao deployment-inventory path,
or under another private inventory source with an explicitly named owner. It is
not stored in this repository in any form.

### Promotion

At promotion time, and only there:

1. Resolve the logical target against the private inventory.
2. Validate the resolved document against the public schema.
3. Render deterministically, on the same terms as every other render
   (ADR-0002, `AGENTS.md` rule 13).
4. Record the private inventory's version and digest — not its values — in the
   promotion receipt.
5. Compare live drift by digest, without printing an endpoint.

### Cleartext is never the default

A production endpoint may be published deliberately, and there are legitimate
reasons to want one — a target that is already on the public internet gains
nothing from indirection. That is an explicit per-target exception, declared
in the target's own document with a rationale and a named approver, and
refused by a gate when the declaration is absent. It is never a default and
never an omission that passes quietly.

### Two classifications this decision does not settle

Both fall between the lists above, and both are named here rather than decided
silently. The judgement stated is the one to take into PR 3; neither is
settled, and both need confirmation in that PR.

**`metrics_path`.** A path, and paths are not on either list. It is
universally `/metrics`, which argues it is scrape protocol rather than
topology: publishing it discloses nothing an attacker could not assume. The
judgement to take is therefore PUBLIC. It is genuinely ambiguous because a
non-default value — a path chosen precisely because it is not guessable — is
topology wearing a protocol field's name, and the contract cannot currently
tell the two apart.

**The evaluators' `listen` addresses.** `model.Evaluator.listen` carries a
full host and port, and the reference inventory binds both evaluators to
`127.0.0.1`. By the letter of the rule a port is private material. But
`127.0.0.1:9090` and `127.0.0.1:9093` are the documented defaults of the
public software being run, they describe the control plane's own loopback
posture rather than any target's location, and `docs/SECURITY.md` cites them
as evidence that the rendered stack keeps its ports off every non-loopback
interface — evidence that disappears if the value is withheld. The judgement
to take is PUBLIC while the address is a loopback address, and private
otherwise. That conditional is exactly the kind of rule that needs writing
down as a gate rather than a habit, which is why it is flagged rather than
assumed.

## Consequences

### What changes in this repository

This is PR 3's opening work, before it writes any production inventory. None
of it is enforced today, because the contracts that would carry it do not yet
exist: not yet enforced (PR 3).

- **Public target and federation documents carry a logical `target_id`, and
  never `endpoints`, a port, or a credential binding.**
  `contracts/target.schema.json` currently requires `endpoints` on every
  `scrape_job` and `source.endpoint` on every federation, and permits
  `credential` on both. Those fields leave the public contract.
- **`host.identity` and `host.ssh_alias` leave the public control-plane
  document.** They exist so a receipt can record which host was promoted to
  and so an operator can check that the named target and the declared one
  agree (`docs/SECURITY.md`, "Promotion authority"). Both purposes are served
  by the private inventory plus a digest in the receipt; neither requires the
  values in Git.
- **A new private-inventory contract holds the resolved material,** and public
  Git records only its version and digest. The contract itself is public — it
  is a schema, not an instance — while every document written against it is
  private.
- **The secret scanner's `openbao_path` check inverts.**
  `tests/architecture/test_no_secret_material.py::test_every_committed_credential_reference_is_a_pointer_not_a_value`
  today REQUIRES every committed `openbao_path` assignment to start with
  `"secret/"`, on the premise that a store path is safe to commit and only a
  pasted value would look different. This decision reverses that premise: a
  secret path is itself private material, because it describes credential
  custody layout. The check becomes the opposite assertion — no `openbao_path`
  may appear in public inventory at all. The three fixture assignments in
  `tests/fixtures/reference/inventory/targets/erp.toml`,
  `tests/fixtures/reference/inventory/federations/sub.toml` and
  `tests/fixtures/reference/routing/receivers.toml` are fabricated paths
  against `.invalid` hosts, so they are not themselves a disclosure, but they
  are written against a contract that no longer holds. The detector's
  sensitivity proof in `tests/mutations/test_secret_detector_bites.py` inverts
  with it: the shape it must demonstrate biting on is now the presence of the
  key, not the shape of its value.
- **The per-target exception is a declared block, not an absence.** It carries
  a rationale and a named approver, and a gate refuses a public endpoint that
  has no such block. An exception that can be taken by leaving a field out is
  the default this decision exists to remove.

### What it costs

A public reader can no longer reproduce a render. `make render-check` over
public inputs alone renders the synthetic fixture and nothing else; a
production render requires private material the reader does not have. That is
a real loss — reproducibility by a stranger was one of the things a public
control plane bought — and it is not recovered later. The fixture and CI keep
synthetic `.invalid` endpoints permanently, not as a placeholder awaiting real
values. ADR-0003 described the fixture's `.invalid` hosts as "today's" corpus,
implying real hosts would follow; under this decision they never do.

Two consequences follow from that, and both are improvements rather than
consolations. The byte-comparison gate keeps working unchanged, because
determinism is a property of the renderer and its inputs, not of whether the
inputs are real. And drift comparison gains a property it would not otherwise
have: comparing by digest means a drift report can be pasted into a ticket or
a channel without disclosing an endpoint, which is the same argument
`docs/SECURITY.md` already makes about the promotion receipt carrying no
free-text field a value could be pasted into.

The cost that is not an improvement: a promotion now depends on a second
system being reachable and correct. If the private inventory is unavailable,
nothing can be promoted. That is the same dependency credentials already carry
— the value is host state sourced from OpenBao — extended to a wider set of
fields, and it is a failure that stops a promotion rather than one that
corrupts a release.

`AGENTS.md` rule 18 now states this split as a hard rule, and its enforcement
line becomes `none yet (PR 3)`. The `public-inventory-endpoint-exposure` row
leaves the decisions table of `docs/CONTROL_EXCEPTIONS.md` and rule 18 joins
the unmonitored table, monitored by PR 3.

## Alternatives considered

**Cleartext by default, in a private repository instead.** Rejected, and
already rejected: ADR-0003 documents that a private repository on this account
has no branch protection and no CI minutes, so it is a directory with a
remote. Choosing it to protect endpoint values would trade every gate this
repository exists to run for the concealment of a hostname list, and would
reproduce the ungated edit path ADR-0001 removed.

**Split into two repositories: public mechanics, private inventory.**
Rejected. ADR-0003 named this as the obvious escape and declined it for the
right reason: it reintroduces the failure ADR-0001 removed — two
repositories, two review paths, and a rendered artefact whose inputs live in
different places under different gates. A private inventory source that is
resolved at promotion time is not a second repository: it holds values, not
documents under review, and every reviewable decision stays in one place with
one gate.

**Encrypt the values in Git, with SOPS, git-crypt or similar.** Rejected. A
committed ciphertext is still a published artefact: it is served to every
clone and mirror, its plaintext is one key compromise away, and — the
decisive property — its history cannot be retracted any more than cleartext's
can, so a key compromise in 2028 discloses the 2026 estate. It also puts key
custody inside a repository whose entire posture is that it holds no key
material and dereferences nothing (`AGENTS.md` rule 1, `docs/SECURITY.md`).
Adding a decryption key to the promotion path would make that claim false for
the sake of a weaker guarantee than not committing the values at all.

**Redact at render time only.** Rejected, because it does not address the
problem. Rendering from committed values and suppressing them in output leaves
the values in Git, world-readable, in the inputs the whole repository is built
to make reviewable. It protects the artefact that was never the exposure and
leaves the one that was.
