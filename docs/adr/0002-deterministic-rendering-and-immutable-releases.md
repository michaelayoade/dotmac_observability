# ADR-0002: Deterministic rendering and immutable releases

- **Status:** Accepted
- **Date:** 2026-08-29
- **Related:** `docs/adr/0001-observability-control-plane-has-one-git-owner.md`,
  `AGENTS.md` rules 11, 12 and 13

## Context

ADR-0001 gives the Observer control plane one Git owner. That decides where the
configuration is authored; it does not decide what the repository contains, how
a reviewer sees a change, or how a change reaches the host without a window in
which the evaluator is reading half of it.

Three constraints shaped the answer.

A reviewer must be able to see the effect of a change, not just its cause. A
diff of `routing/policies.toml` says a matcher moved; it does not say what
Alertmanager will now do, unless the reviewer runs the renderer in their head
or on their laptop. Most will do neither.

Drift detection needs a fixed thing to compare against. `AGENTS.md` rule 12
requires desired state, live state and the last verified receipt to be three
independently comparable artifacts. "Desired state" has to be a value someone
can compute identically twice, or the comparison reports noise.

And activation has to be atomic, for the reason ADR-0001 documented in detail:
the Observer host's configuration files were single-file bind mounts, bound to
an inode. A `sed -i` or an `mv` writes a new inode, the mount stays pointed at
the old one, and the container keeps reading the file the operator believes
they replaced. The only reliable in-place gesture is appending to the existing
inode with `cat >>`, which is exactly the unreviewable path this project
exists to remove. Any activation scheme that rewrites individual mounted files
inherits that hazard.

## Decision

**Inputs are typed inventory.** `inventory/`, `bundles/` and `routing/` hold
TOML documents governed by the JSON Schemas in `contracts/`. `validate.load`
schema-validates every document and then constructs frozen `model` records from
it; nothing is constructed from an unvalidated document. Collections are tuples
in declaration order and directory globs are `sorted()`, so ordering is the
author's and not the filesystem's.

**Rendered bytes are committed.** `render.render_control_plane` produces the
whole file tree in one fixed-order call, and the result is committed under
`deploy/rendered/`. A reviewer therefore sees a routing change as a diff of the
actual Alertmanager configuration, and an operator with a checkout and no
network has working configuration.

**`render --check` is a byte comparison.** `make render-check` re-renders from
the inventory and compares bytes against the committed tree. `render.differences`
reports three conditions: `missing`, `differs` and `unexpected`. The third is
not optional, because a stale file left behind in a release directory is still
mounted into the evaluator.

**Rendering is dependency-free and the YAML emitter is hand-written.**
`yaml_emit.emit` implements the small closed subset of YAML the control plane
needs. `jsonschema` is the only runtime dependency and it validates rather than
renders.

**Releases are immutable directories, activated atomically, with the previous
pointer preserved.** A release is a whole directory tree under
`release_root`. Activation moves the pointer the mount resolves through; the
previous release directory and pointer are captured before activation and
restored on any failure before `ACCEPTED` (`AGENTS.md` rule 11, receipt fields
`release.previous` and `release.current`). There is no partial-promotion state
an operator is expected to finish by hand.

**The rendered compose mounts directories, read-only.** Each service mounts
`${OBSERVABILITY_RELEASE:?release directory is required}/<service>` at its fixed
`/etc/<service>` path with `:ro`, plus the shared secrets directory, also
`:ro`. `OBSERVABILITY_RELEASE` has no default: a stack that silently starts
against the wrong release is worse than one that refuses to start.

**Identity is a digest.** Images are pinned `image@sha256:...`, never by tag.
`render.tree_digest` hashes rendered paths and contents together, so a render
that moved a file without changing a byte inside it is a different deployment.

## Consequences

**A rendering change becomes visible in review.** Changing the renderer changes
the committed bytes of the reference fixture, so a reviewer sees exactly what
moved in the output. This is why `tests/fixtures/reference/rendered/` is
committed rather than generated at test time: without a committed expectation,
a determinism test only proves the renderer agrees with itself.

**`make render` becomes a required step.** Changing inventory without
re-rendering fails `render-check`. The CLI says so directly ("run `make render`
and commit the result").

**Determinism becomes a property under test.** Same inputs, same bytes, on any
machine, in any order: no timestamps, no hostnames, no set iteration, no
locale-dependent sort. `tests/unit/test_render_determinism.py` and
`tests/unit/test_yaml_emit.py` hold it today.

**Rollback becomes mechanical.** Restoring a preserved pointer is one act with
one outcome, not a reconstruction from memory of what the file used to contain.

**Disk is consumed by retained releases,** and retention is a policy the
promotion facility will need (PR 6). An immutable-release scheme that garbage
collects the previous release before acceptance would defeat rule 11, so the
policy has to be expressed in terms of accepted receipts rather than age
alone.

**Not yet enforced.** `render-check` and `schema-check` are not in `make check`,
because PR 1 ships no production inventory; they are exercised against the
reference fixture by the test suite and join `check` in PR 3. Immutable
releases, atomic activation and pointer preservation are described by
`contracts/promotion-receipt.schema.json` and implemented by nothing: the
promotion facility is PR 6.

## Alternatives considered

### Use PyYAML (or another YAML library) instead of a hand-written emitter

Rejected, and this is the decision most likely to be questioned, because
writing a YAML emitter is obviously the wrong default.

The gate is a byte comparison. That makes the emitter's output an artifact
under version control, not an implementation detail, and a general YAML library
does not promise byte stability across versions. Quoting style, key ordering,
line width, flow-versus-block selection and scalar-type inference are all
internal choices a library is free to change in a minor release, and they have
moved before. When they move, every committed file in `deploy/rendered/` and
`tests/fixtures/reference/rendered/` changes at once, in a diff no reviewer can
read, for no reason connected to any inventory change. The predictable outcome
is not a careful review; it is a bulk re-render, and after the second one
nobody trusts `render-check` enough to investigate a real failure. A gate
people have learned to re-baseline is worse than no gate, because it still
appears in `make check`.

The counter-argument is that a hand-written emitter can be wrong in ways a
mature library is not. That is true, and it is bounded here in three ways. The
subset is closed and small: nested mappings, sequences, and scalars, with two
special cases for the empty collections `{}` and `[]` that have no block
spelling. The quoting rule is deliberately conservative and uniform rather than
minimal, so anything that is not an unambiguous identifier is double-quoted;
"sometimes quoted" is both a diff nobody can review and the shape of most YAML
type-inference bugs. And the emitter is not the oracle for correctness:
`promtool check config`, `promtool check rules` and `amtool check-config` are,
and the promotion receipt reserves a field for each
(`validation.promtool_config`, `validation.promtool_rules`,
`validation.amtool_config`, `validation.compose_config`). The emitter's job is
to be stable; the evaluator's own tools decide whether the output is valid.

Two details in the module are there because the naive version is wrong in a way
that reaches production: `bool` is checked before `int`, because `bool` is an
`int` in Python and `True` would otherwise emit as `1`; and a plain scalar is
refused for anything that parses as a float, so `1e5` cannot slip out unquoted.

Pinning a YAML library by exact version was considered as a middle path. It
narrows the problem to upgrade time rather than removing it, it makes a routine
dependency bump a re-baseline event, and it adds a runtime dependency to the
one component that must work from a bare checkout.

### Generate the configuration at deploy time and commit nothing

Rejected. It removes the reviewable diff, which is the property ADR-0001 was
created to obtain. It also means the desired state exists only as a function
that has to be run to be known, so the drift comparison in rule 12 would have
to trust that the deploy-time run and the comparison run produced the same
thing, with no committed artifact to check either against. An operator with a
checkout and no network would have nothing to apply.

### Template the configuration with Jinja rather than emitting from a typed model

Rejected. A template renders whatever it is given, so the semantic gates in
`validate.py` would have to be reimplemented as template-time conditionals or
skipped. Structural correctness would be checked, if at all, after the fact by
parsing the output. The typed model gives the semantic layer a value to reason
about, gives mypy something to check, and gives the drift comparison in PR 6 an
object rather than a string to compare.

### Patch the mounted configuration files in place and reload

Rejected. This is the inode hazard from the Context section, restated as a
design. Rewriting a bind-mounted file either detaches the mount or produces a
window in which the evaluator can read a partially written file. There is also
no atomic multi-file update: `prometheus.yml`, the rules tree and
`alertmanager.yml` change together or the evaluator loads a combination that
never existed in any commit. Swapping a directory pointer makes the whole tree
change at once and makes the preceding release a thing that still exists on
disk, which is what rollback needs.

### Mount individual files from an immutable release directory

Rejected as a partial fix. It solves atomicity for the contents of each file
but keeps the per-file inode binding, so activation is still N separate
rebindings, and it cannot add or remove a file (a new rule bundle, a retired
one) without changing the compose definition. Mounting the directory means
`rule_files: /etc/prometheus/rules/*.yml` can stay a glob and the release
decides what is in it.
