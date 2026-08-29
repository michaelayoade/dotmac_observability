## What this changes

<!-- The control-plane effect, not the diff. "Edits routing/policies.toml" is
     the diff; "critical alerts for ERP now page on-call instead of falling
     through to platform mail" is the effect. -->

## Blast radius

- [ ] No live host is touched by merging this
- [ ] This change alters what a future promotion will render onto a host
- [ ] This change is itself a promotion (name the host, named by a human, in
      the authorizing request — never inferred from an inventory row)

## Checklist

- [ ] No secret values in the diff — OpenBao paths and logical file names only
      (AGENTS.md rule 1); `make secret-scan` passes
- [ ] Rendered bytes re-rendered and committed (`make render-check` is a byte
      comparison; hand-editing `deploy/rendered/` is AGENTS.md rule 13)
- [ ] Any new unenforced region recorded in `docs/CONTROL_EXCEPTIONS.md` as
      **unmonitored**, with the PR that will monitor it — never described as
      exempt, never described as enforced (AGENTS.md rule 15)
- [ ] Any new detector carries a sensitivity proof under `tests/mutations/` —
      a check that cannot demonstrate it bites is not enforcement
- [ ] No product alert expression authored here; only control-plane
      meta-alerts this repository genuinely owns (AGENTS.md rule 5)
- [ ] Every new `warning` or `critical` route reaches a declared receiver, or
      a reviewed null policy saying in words why it is not delivered
      (AGENTS.md rule 7)
- [ ] Every bundle reference is digest-pinned and immutable; no version STRING
      used as an identity (AGENTS.md rule 4)
- [ ] Every environment-specific value is an overridable knob with a
      documented default — no hardcoded host, port, image, path or retention
      (AGENTS.md rule 14)
- [ ] Any claim that something is released, published or adopted cites an
      external oracle with immutable coordinates, not a value on `main`
      (Governance ADR 0013)
- [ ] `make check` passes on CI, not only locally
- [ ] Anything left undecided is recorded in `docs/CONTROL_EXCEPTIONS.md` or an
      ADR rather than assumed

## Approval

Owner (named human):

Approver (named human):

If any part of this pull request was drafted by an AI agent, the approver is
attesting to the content on their own reading. An agent's review does not
satisfy this line — see `AGENTS.md`.
