"""Refuse before dispatch when the exact self-hosted runner is unavailable."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from collections.abc import Sequence

EXIT_REFUSED = 3


def _labels(runner: dict[str, object]) -> set[str]:
    raw = runner.get("labels")
    if not isinstance(raw, list):
        return set()
    return {
        str(entry.get("name")) for entry in raw if isinstance(entry, dict) and entry.get("name")
    }


def _query(repository: str, token: str) -> tuple[int, bytes]:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/actions/runners",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        error.close()
        return error.code, b""


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--label", action="append", required=True, dest="labels")
    args = parser.parse_args(argv)

    token = os.environ.get("RUNNER_QUERY_TOKEN", "").strip()
    if not token:
        print(
            "REFUSED: RUNNER_QUERY_TOKEN is absent; availability is unknown",
            file=sys.stderr,
        )
        return EXIT_REFUSED

    status, body = _query(args.repository, token)
    if status != 200:
        print(
            f"REFUSED: runner inventory returned HTTP {status}, not 200",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    try:
        document = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        print("REFUSED: runner inventory is not JSON", file=sys.stderr)
        return EXIT_REFUSED
    runners = document.get("runners") if isinstance(document, dict) else None
    if not isinstance(runners, list):
        print("REFUSED: response has no runner list", file=sys.stderr)
        return EXIT_REFUSED

    wanted = set(args.labels)
    matching = [
        runner for runner in runners if isinstance(runner, dict) and wanted <= _labels(runner)
    ]
    if not matching:
        print(
            f"REFUSED: no runner carries every required label {sorted(wanted)}",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    online = [runner for runner in matching if runner.get("status") == "online"]
    if not online:
        print("REFUSED: matching runner is offline", file=sys.stderr)
        return EXIT_REFUSED
    idle = [runner for runner in online if not runner.get("busy")]
    if not idle:
        print("REFUSED: every matching online runner is busy", file=sys.stderr)
        return EXIT_REFUSED

    names = sorted(str(runner.get("name")) for runner in idle)
    print(f"runner available for {sorted(wanted)}: {names}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
