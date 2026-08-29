# ADR-0003: The control-plane repository is public

- **Status:** Accepted
- **Date:** 2026-08-29
- **Supersedes:** nothing
- **Related:** `docs/adr/0001-observability-control-plane-has-one-git-owner.md`,
  `docs/SECURITY.md`, `AGENTS.md` rules 1, 17 and 18

## Context

The repository was created private. That choice cost two things at once, and
neither was apparent until the first pull request ran.

**Branch protection is unavailable.** Both the branch-protection API and the
newer repository-rulesets API return HTTP 403 on a private repository under
this account's plan: `Upgrade to GitHub Pro or make this repository public`.
There is no partial version — no linear-history requirement, no force-push
refusal, no pull-request requirement. `main` accepts a direct push from anyone
with write access, which is precisely the property `AGENTS.md` rule 17 exists
to remove, and precisely the property this repository was created to give the
Observer configuration in the first place.

**CI cannot run.** Every job on the first pull request failed in under a
second with `The job was not started because recent account payments have
failed or your spending limit needs to be increased`. Private-repository
Actions minutes on this account are exhausted. Public repositories are not
metered.

So a private control-plane repository has no protected branch and no automated
gates. It is a directory with a remote. Every mechanism in this repository —
the render byte-comparison, the secret scanner, the sensitivity proofs,
`promtool` and `amtool` acceptance, the governance conformance check — exists
to fail a change before it reaches a host, and none of them can fail anything
if no gate runs and any commit can land on `main` unreviewed.

The other Dotmac repositories do not have this problem because they are
already public. `dotmac_erp` reports `private: false`, as do `dotmac_sub`,
`dotmac_starter_mt` and `dotmac_governance`. Private was a departure from an
existing fleet norm, not the norm.

## Decision

The repository is public.

Michael made this call explicitly, after the trade below was stated.

## Consequences

The two capabilities are recovered immediately: `main` now requires linear
history, refuses force-pushes and deletions, and takes changes only through a
pull request; CI runs unmetered.

The cost is real and is not waved away. Everything committed here is
world-readable the moment it lands. Today that is contracts, code, tests and a
fixture whose hosts are `.invalid` names and whose digests are placeholders —
nothing an attacker gains from. From PR 3 it will include Observer's actual
scrape topology: production endpoints, internal hostnames, host identities,
and the OpenBao paths at which credentials live.

None of that is a secret under `AGENTS.md` rule 1, and rule 1 remains
sufficient for what it covers — no token, password, webhook URL with an
embedded key, bearer credential or certificate may ever be committed, public
or not, and the scanner and its sensitivity proof enforce it. But rule 1
answers "is this a secret value", and public visibility asks a second question
it was never meant to answer: **is this non-secret fact still something to
publish?** An endpoint list is a map. An OpenBao path names where a credential
is kept, which is useful to someone who has already got into the store and
useless to someone who has not — but the endpoint list is useful to someone
who has got nowhere yet.

That question is deliberately left open rather than answered here, because
answering it well needs the census PR 2 produces: the actual list, not a guess
about it. It is recorded as `public-inventory-endpoint-exposure` in
`docs/CONTROL_EXCEPTIONS.md` and as the enforcement line of `AGENTS.md` rule
18, and it must be resolved **before** PR 3 writes production inventory, not
after. Git history is not retractable; a value committed to a public
repository and removed in the next commit has still been published.

## Alternatives considered

**Keep it private and accept an unprotected `main` with no CI.** Rejected. It
inverts the purpose of the repository. The whole argument of ADR-0001 is that
an ungated edit path cannot be trusted with production configuration; a
repository that is itself an ungated edit path would reproduce the Observer
problem one layer up, with better documentation.

**Keep it private and move the account to a paid plan.** Not rejected on
merit — it is the option that keeps both properties — but it is a billing
decision with fleet-wide scope, and it was not the one taken. If the account
moves to a paid plan later, this ADR can be revisited: the visibility choice is
reversible in the direction of privacy for future commits, though not for
anything already published.

**Keep it private and enforce the branch discipline by convention.** Rejected.
A stated working agreement with no platform enforcement is exactly what
`AGENTS.md` rule 15 forbids describing as enforcement, and this repository
cannot credibly hold other systems to that standard while exempting itself.

**Split the repository: public mechanics, private inventory.** Rejected for
now, and worth naming because it is the obvious escape from the trade. It
reintroduces the failure ADR-0001 removed: two repositories, two review paths,
and a rendered artefact whose inputs live in different places with different
gates. If `public-inventory-endpoint-exposure` resolves towards secrecy, the
better shape is promotion-time substitution of a small number of values — the
mechanism credentials already use — rather than a second repository.
