#!/usr/bin/env python3
"""Consumer drift check — the enforcement arm of line-canon rule 4.

For every consumer in scripts/consumers.json (fetched from its recorded
branch on GitHub):

  1. the vendored vectors.json must exist,
  2. a LOCK file must exist and record a sha256,
  3. sha256(vendored copy) == the LOCK-recorded sha256 (local consistency —
     the vendored bytes were not hand-edited), and
  4. the LOCK-recorded upstream commit must exist in THIS repo's history
     and the canonical vectors.json at that commit must hash to the same
     sha256 (the pin points at a real canonical generation — no fabricated
     locks, no silent upgrades).

Consumers pin a generation; they are NOT forced onto HEAD. When
vectors.json changes here, consumers stay valid until their same-wave
refresh (canon: "land consumer updates in the same wave").

An optional LOCK line `release: vectors-vN` is verified when the tag
exists: the release asset must hash to the same sha256.

Exit 0 = all consumers clean; exit 1 = any drift (CI fails).
"""

import hashlib
import json
import os
import pathlib
import sys
import urllib.request

VECTORS_REPO = "Amperstrand/ntag424-vectors"
GITHUB_API = "https://api.github.com"
GITHUB_RAW = "https://raw.githubusercontent.com"
ROOT = pathlib.Path(__file__).resolve().parent.parent

TOKEN = os.environ.get("GITHUB_TOKEN", "")


def _headers(accept: str) -> dict:
    h = {"Accept": accept, "User-Agent": "ntag424-vectors-drift-check"}
    if TOKEN:
        h["Authorization"] = f"Bearer {TOKEN}"
    return h


def _get(url: str, accept: str, binary: bool = False):
    req = urllib.request.Request(url, headers=_headers(accept))
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
    except urllib.error.HTTPError as e:
        return None, e.code
    return (data if binary else data.decode()), 200


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def default_branch(repo: str) -> str:
    doc, code = _get(f"{GITHUB_API}/repos/{repo}", "application/vnd.github+json")
    if code != 200:
        raise RuntimeError(f"cannot resolve default branch of {repo}: HTTP {code}")
    return json.loads(doc)["default_branch"]


def canonical_sha_at(commit: str) -> "tuple[str | None, str | None]":
    """sha256 of vectors.json at a historical commit of this repo."""
    data, code = _get(
        f"{GITHUB_API}/repos/{VECTORS_REPO}/contents/vectors.json?ref={commit}",
        "application/vnd.github.raw",
        binary=True,
    )
    if code != 200:
        return None, f"upstream commit {commit} not reachable: HTTP {code}"
    return _sha256(data), None


def release_asset_sha(tag: str) -> "tuple[str | None, str | None]":
    doc, code = _get(
        f"{GITHUB_API}/repos/{VECTORS_REPO}/releases/tags/{tag}",
        "application/vnd.github+json",
    )
    if code == 404:
        return None, None  # tag not cut yet — treated as informational
    if code != 200:
        return None, f"release {tag}: HTTP {code}"
    for asset in json.loads(doc).get("assets", []):
        if asset["name"] == "vectors.json":
            digest = (asset.get("digest") or "").replace("sha256:", "")
            if digest:
                return digest, None
            data, c = _get(
                asset["browser_download_url"], "application/octet-stream", binary=True
            )
            if c != 200:
                return None, f"asset download {tag}: HTTP {c}"
            return _sha256(data), None
    return None, f"release {tag} has no vectors.json asset"


def check_consumer(entry: dict) -> "tuple[bool, list[str]]":
    name = entry["repo"]
    problems: list[str] = []
    branch = entry.get("branch") or default_branch(name)
    base = f"{GITHUB_RAW}/{name}/{branch}"

    vendored, code = _get(f"{base}/{entry['vectors_path']}", "text/plain", binary=True)
    if code != 200:
        return False, [f"vendored {entry['vectors_path']} missing on {branch}: HTTP {code}"]
    vendored_sha = _sha256(vendored)

    lock, code = _get(f"{base}/{entry['lock_path']}", "text/plain")
    if code != 200:
        return False, [f"LOCK {entry['lock_path']} missing on {branch}: HTTP {code}"]

    lock_sha = None
    upstream_commit = None
    release = None
    for line in lock.splitlines():
        if line.startswith("vectors.json sha256:"):
            lock_sha = line.split(":", 1)[1].strip()
        elif line.startswith("upstream commit:"):
            upstream_commit = line.split(":", 1)[1].strip()
        elif line.startswith("release:"):
            release = line.split(":", 1)[1].strip()

    if not lock_sha:
        problems.append("LOCK records no 'vectors.json sha256:' line")
    elif vendored_sha != lock_sha:
        problems.append(
            f"vendored copy drifts from its own LOCK: vendored {vendored_sha} vs LOCK {lock_sha}"
        )
    if not upstream_commit:
        problems.append("LOCK records no 'upstream commit:' line")
    else:
        canonical_sha, err = canonical_sha_at(upstream_commit)
        if err:
            problems.append(err)
        elif lock_sha and canonical_sha != lock_sha:
            problems.append(
                f"LOCK sha {lock_sha} does not match canonical vectors.json "
                f"at {upstream_commit} ({canonical_sha}) — fabricated or stale pin"
            )
    if release:
        asset_sha, err = release_asset_sha(release)
        if err:
            problems.append(err)
        elif asset_sha and lock_sha and asset_sha != lock_sha:
            problems.append(
                f"release {release} asset sha {asset_sha} != LOCK {lock_sha}"
            )

    return not problems, problems


def main() -> int:
    consumers = json.loads((ROOT / "scripts" / "consumers.json").read_text())
    failures = 0
    for entry in consumers:
        ok, problems = check_consumer(entry)
        status = "OK " if ok else "DRIFT"
        print(f"[{status}] {entry['repo']}" + (f" @ {entry.get('branch')}" if entry.get("branch") else ""))
        for p in problems:
            print(f"         {p}")
        failures += 0 if ok else 1

    if failures:
        print(f"\n{failures} consumer(s) drifted — see above", file=sys.stderr)
        return 1
    print(f"\nall {len(consumers)} consumers clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
