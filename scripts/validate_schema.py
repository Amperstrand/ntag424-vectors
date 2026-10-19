#!/usr/bin/env python3
"""Validate the canonical vectors.json against schema/vectors.schema.json.

Enforces, beyond the machine schema:
  - unique vector ids
  - negative vectors only where the line canon defines rejection semantics
    (sdm_full today)
  - the suite-size assertion the README records (46 vectors: 26 derivation,
    12 sdm, 8 an12196 — 3 negative). Growing the suite is a conformance
    wave: this assertion, the README counts, and every consumer's
    size/skip assertions move together.

Exit code 0 = valid; anything else = invalid, with reasons on stderr.
"""

import json
import pathlib
import sys

import jsonschema

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXPECTED_COUNTS = {
    "total": 46,
    "derivation": 26,
    "sdm": 12,
    "an12196": 8,
    "negative": 3,
}
NEGATIVE_ALLOWED_OPS = {"sdm_full"}


def main() -> int:
    vectors_path = ROOT / "vectors.json"
    schema_path = ROOT / "schema" / "vectors.schema.json"

    doc = json.loads(vectors_path.read_text())
    schema = json.loads(schema_path.read_text())

    errors: list[str] = []

    validator = jsonschema.Draft202012Validator(schema)
    for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path)):
        loc = "/".join(str(p) for p in err.absolute_path) or "<root>"
        errors.append(f"schema: /{loc}: {err.message}")

    ids = [v["id"] for v in doc["vectors"]]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        errors.append(f"duplicate vector ids: {sorted(dupes)}")

    counts = {"total": len(ids), "negative": 0}
    for v in doc["vectors"]:
        counts[v["category"]] = counts.get(v["category"], 0) + 1
        if v.get("negative"):
            counts["negative"] += 1
            if v["input"]["op"] not in NEGATIVE_ALLOWED_OPS:
                errors.append(
                    f"{v['id']}: negative vectors are only defined for ops "
                    f"{sorted(NEGATIVE_ALLOWED_OPS)} (got {v['input']['op']}) — "
                    "extend the canon doc first if this is a new rejection class"
                )
        if v["category"] not in ("an12196", "sdm", "derivation"):
            errors.append(f"{v['id']}: unknown category {v['category']}")

    for key, expected in EXPECTED_COUNTS.items():
        if counts.get(key) != expected:
            errors.append(
                f"count drift: {key} = {counts.get(key)} but README/assertions "
                f"say {expected} — a suite-size change is a conformance wave: "
                "update README.md counts, go-consumer assertions, and every "
                "consumer suite in the same wave"
            )

    if errors:
        print(f"vectors.json: {len(errors)} problem(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(
        f"vectors.json valid: {counts['total']} vectors "
        f"({counts['derivation']} derivation / {counts['sdm']} sdm / "
        f"{counts['an12196']} an12196, {counts['negative']} negative), "
        "schema + counts + unique ids OK"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
