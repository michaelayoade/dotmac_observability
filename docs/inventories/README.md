# Inventories

Dated, as-built characterizations of what actually exists on the hosts and in
the repositories this control plane touches.

These documents are **facts, not mandates**. An inventory records what was
observed, on a stated date, by a stated method. It does not decide anything, it
does not authorize anything, and finding a shape written down here is not
approval to copy it. Decisions live in `docs/adr/`; the enforceable rules live
in `AGENTS.md`; as-built truth about this repository's own design lives in
`docs/ARCHITECTURE.md`.

An inventory that is not dated is not usable, because the reader cannot tell
whether it still describes the host. Every document here carries the date of
observation in its front matter and in its filename where that helps.

## Present

Nothing yet.

## Expected

`observer-as-built.md` arrives with **PR 2**: a read-only census of the Observer
host's `/opt/observability` stack, recording what is running, what each service
loads, which files are bind-mounted and how, which scrape jobs and rule files
exist, and where the current configuration disagrees with itself.

That census is the input to PR 3's production inventory, which is why it is
read-only and why it comes first: writing inventory from memory would encode
the assumptions this repository exists to check. PR 2 is blocked until Michael
names the Observer SSH target explicitly (`AGENTS.md` rule 17).
