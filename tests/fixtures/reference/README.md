# reference fixture

A complete, realistic inventory that exercises every rendering path: a plain
scrape job, a credentialed one, per-job overrides, a federation with its
mandatory rename, a delivering receiver, a reviewed null receiver, both
severity routes, and an inhibition.

It is **not** the production inventory. Hosts are `.invalid` names, the
digests are placeholders, and no value here is a secret. Production inventory
arrives in PR 3, imported from the read-only census in PR 2.

`rendered/` holds the committed bytes this fixture must produce. It is the
sensitivity proof for AGENTS.md rule 13: without a committed expectation, a
determinism test only proves the renderer agrees with itself.
