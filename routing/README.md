# routing/

Who is paged, when, and what suppresses what. Three documents, all governed by
`contracts/routing.schema.json` and distinguished by `kind`, split because they
change for different reasons and have different reviewers.

- `receivers.toml` (`kind = "receivers"`) — declared notification
  destinations. Each integration carries an OpenBao path and a logical secret
  file name, never a value. A receiver with no integrations must carry a
  reviewed `null_policy` saying in words why this class of alert is
  deliberately undelivered.
- `policies.toml` (`kind = "policies"`) — the root `[defaults]` and the ordered
  `[[routes]]` tree, each route with an `id`, quoted matchers and a receiver.
- `inhibition.toml` (`kind = "inhibition"`) — suppression rules, each with a
  mandatory `rationale` and a mandatory `equal` list.

Cross-document gates in `validate.semantic_findings` refuse an undeclared
receiver, a duplicate route id, a receiver nothing reaches, and any `warning`
or `critical` class that routes nowhere real.

**Populated by PR 3.** The reference fixture at
`tests/fixtures/reference/routing/` shows all three shapes.

**Trap:** `equal` on an inhibition is not optional and not a formality. An
inhibition without it suppresses the target alert everywhere rather than only
where the cause applies, which is the commonest way one outage silences an
unrelated one. Pin it to the labels that make the two alerts the same
incident.

## Repeat intervals and the removed inhibition rule (2026-09-13)

`policies.toml` gives `critical` and `warning` different `repeat_interval`
values rather than sharing the root default: critical reminders repeat every
hour (a firing critical alert should keep re-paging until it is acknowledged
or resolved), and warning reminders repeat every 12 hours (hourly restatement
of a still-firing warning was paging noise, not new information).

`inhibition.toml` no longer declares any rule. The one it used to carry
suppressed a warning alert only when a critical alert shared the same
`alertname` — a condition no pair of live critical/warning rules ever
satisfies, so the rule was structurally dead and never suppressed anything.
It was removed rather than reworked; there is currently no live inhibition
rule.
