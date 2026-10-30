# ntag424-vectors

Byte-exact cross-language test vectors for the NTAG424 DNA / boltcard
cryptography stack (AES-CMAC, AN12196 SDM secure dynamic messaging, and
deterministic card key derivation).

One canonical `vectors.json` is consumed by independent implementations
(Rust, TypeScript, Go). Every implementation must pass every vector its
public API can express; categories an API cannot express are skipped with
an explicit count.

## Vector sources (provenance)

Vectors are **lifted only** from verified sources; the `origin` field of
each vector records where the bytes came from:

| Source | What it contributes |
|---|---|
| NXP AN12196 tables (via [ntag424-crypto](https://github.com/Amperstrand/ntag424-crypto) `test/an12196-vectors.test.ts`) | SDM session-key derivation (§3.3 Table 1), PICC data decryption (§3.4.2.1 Table 2), full SUN MAC verification (§3.4.4.2.1 Table 4) |
| RFC 4493 §4 (via ntag424-crypto `test/aes-cmac.test.ts`) | AES-CMAC known-answer examples (multi-block) |
| [bolty-rs](https://github.com/Amperstrand/bolty-rs) `tests/fixtures/derivation/boltcard_deterministic.toml` | Deterministic key derivation (tags `2D003F75`..`2D003F7B`), extracted from Bolty C++ `KeyDerivation.h`, one vector hardware-proven, one cross-validated against boltcard-cloudflareworker |
| bolty-rs `tests/fixtures/picc/valid_picc.toml` | End-to-end SDM decrypt + CMAC fixtures (`p`/`c`, derived MAC key, full CMAC) |
| bolty-rs `crates/bolty-core/src/picc.rs` tests, `AGENTS.md` "Card Recovery" | SV2 construction byte values and the issuer-key `0000…0001` derivation worked example |
| Cross-implementation audit (2026-08-31; bolty-rs audit evidence task-3/task-4) | 21 `derive_keys` vectors executed on two independent references (bolty-cpp `KeyDerivation.h` and boltcard-cloudflareworker `keygenerator.js`, byte-identical outputs, versions incl. 0/2/255/0x01020304/0x12345678 edges) and 9 `sdm_full` vectors transcription-derived from the Go boltcard reference (`lnurlw_request.go` + `crypto.go`, line-cited, validated byte-for-byte against pre-existing reference vectors) — 6 positive (counter max, endianness pair, zero keys, non-zero PICC tail, all-FF UID) + 3 negative |

## Schema

```jsonc
{
  "schema_version": 1,
  "vectors": [
    {
      "id": "unique-stable-id",
      "category": "an12196" | "sdm" | "derivation",
      "negative": true,              // OPTIONAL, reject vectors only (see below)
      "input":  { "op": "<operation>", ...operation fields },
      "expected": { ...expected fields },
      "origin": "where these bytes were lifted from"
    }
  ]
}
```

Conventions:

- All hex strings are **lowercase**; consumers normalize before comparing.
- `counter_bytes` is the 3-byte SDMReadCtr exactly as stored in
  `PICCData[8..11]` — `SV2[13..16]` copies those bytes verbatim. The
  vectors pin the BYTES: libraries expose different integer conventions
  (e.g. the Rust `ntag424` crate reads them little-endian via
  `u32::from_le_bytes`, the TS lib takes them reversed as
  `[b2, b1, b0]`), so no integer field is used.
- Absent keys in `expected` mean the source did not publish that value;
  consumers verify only the fields present.
- `"negative": true` marks a REJECT vector: a conforming SDM
  verification chain MUST refuse the input `p`/`c` — either the PICC
  decrypt gate fails (PICCDataTag ≠ 0xC7) or the SUN-MAC verification
  fails. Consumers assert rejection instead of comparing intermediates;
  `expected` (if present) is documentation of the plaintext, never an
  assertion target. Suite counts: 46 vectors (26 derivation, 12 sdm,
  8 an12196), of which 3 are negative.

### Operations

| category | `input.op` | input fields | expected fields |
|---|---|---|---|
| an12196 | `aes_cmac` | `key`, `message` | `cmac` |
| an12196 | `picc_decrypt` | `key`, `picc_enc_data` | `decrypted`, `uid`, `counter_bytes` |
| an12196 | `sv2_build` | `uid`, `counter_bytes` | `sv2` |
| an12196 | `sun_mac` | `key`, `uid`, `counter_bytes` | `cmac_truncated` |
| derivation | `derive_keys` | `issuer_key`, `uid`, `version` | `card_key`, `k0`..`k4`, `card_id` (subset allowed) |
| sdm | `sdm_full` | `k1`, `k2`, `p`, `c` | `decrypted_p`, `uid`, `counter_bytes`, `sv2`, `derived_mac_key`, `full_cmac` |
| sdm | `sv2_build` | `uid`, `counter_bytes` | `sv2` |

Crypto definitions (all AES-128):

- `aes_cmac`: CMAC per RFC 4493.
- `picc_decrypt`: AES decrypt of `picc_enc_data` (single 16-byte block,
  zero IV / ECB as used by AN12196 §3.4.2.1) → plaintext is
  `PICCDataTag(1) || UID(7) || SDMReadCtr(3) || padding(5)`.
- `sv2_build`: `SV2 = 3C C3 00 01 00 80 || UID(7) || counter_bytes(3, verbatim PICCData bytes)`.
- `sun_mac`: `Ks = CMAC(key, SV2)`, `MACt = odd-index bytes (1,3,..15) of
  CMAC(Ks, empty)`.
- `derive_keys` (boltcard deterministic scheme):
  `card_key = CMAC(issuer_key, 2D003F75 || UID || version_u32_le)`,
  `k0 = CMAC(card_key, 2D003F76)`, `k1 = CMAC(issuer_key, 2D003F77)`,
  `k2 = CMAC(card_key, 2D003F78)`, `k3 = CMAC(card_key, 2D003F79)`,
  `k4 = CMAC(card_key, 2D003F7A)`,
  `card_id = CMAC(issuer_key, 2D003F7B || UID)`.
- `sdm_full`: `decrypted_p = AES-decrypt(k1, p)`;
  `sv2 = sv2_build(uid, counter)`; `derived_mac_key = CMAC(k2, sv2)`;
  `full_cmac = CMAC(derived_mac_key, empty)`; `c` = odd-index bytes of
  `full_cmac`.

## Cross-vector format & regeneration

Self-contained reference for `vectors.json`: what each field contains
(with one real vector per suite class), how the file comes to be, and how
to verify it locally. The [Schema](#schema) section above stays normative.

### Field-by-field format

`vectors.json` has exactly three top-level fields — the JSON Schema
(`schema/vectors.schema.json`, Draft 2020-12) allows no others
(`additionalProperties: false`; `schema_version` and `vectors` required):

| field | type | notes |
|---|---|---|
| `schema_version` | integer | pinned to `1` (`"const": 1`); bumps only when the shape moves, as part of a conformance wave |
| `notes` | string (optional) | prose conventions; present in the current file |
| `vectors` | array | the payload — one entry per test vector (46 today) |

Each entry in `vectors` has exactly these six fields
(`schema/vectors.schema.json` `$defs.vector`; `id`, `category`, `input`,
`expected`, `origin` required, `additionalProperties: false`):

| field | type | notes |
|---|---|---|
| `id` | string | stable, unique, `^[a-z0-9][a-z0-9-]*$`; uniqueness is asserted by `scripts/validate_schema.py` |
| `category` | `"an12196"` \| `"sdm"` \| `"derivation"` | suite class; per-class counts are asserted by the validator |
| `negative` | boolean (optional, default `false`) | marks a REJECT vector; only legal on `sdm_full` operations (`NEGATIVE_ALLOWED_OPS` in `scripts/validate_schema.py`) |
| `input` | object | operation request; `input.op` selects one of six shapes — `aes_cmac`, `picc_decrypt`, `sv2_build`, `sun_mac`, `derive_keys`, `sdm_full` (field lists in the Operations table above) |
| `expected` | object | expected outputs; consumers verify only the fields present — absent keys mean the source did not publish that value |
| `origin` | string (≥ 8 chars) | provenance: the verified source the bytes were lifted from |

Hex string shapes are pinned by the schema's `$defs` patterns: 16-byte
values (keys, CMACs, SV2, …) are 32 lowercase hex chars; `uid` is 14 hex
chars (7 bytes); `counter_bytes` is 6 hex chars (3 bytes); `version` is an
integer 0…2³²−1.

### One real vector per suite class

Suite counts are asserted, not decorative — 46 vectors: 26 `derivation` /
12 `sdm` / 8 `an12196`, of which 3 `negative` (`EXPECTED_COUNTS` in
`scripts/validate_schema.py`). One real, unedited vector per class:

`an12196` — op `aes_cmac`:

```json
{
  "id": "an12196-table1-sv1-session-enc-key",
  "category": "an12196",
  "input": {
    "op": "aes_cmac",
    "key": "5ace7e50ab65d5d51fd5bf5a16b8205b",
    "message": "c33c0001008004c767f2066180010000"
  },
  "expected": {
    "cmac": "66da61797e23deca5d8eca13bbadf7a9"
  },
  "origin": "NXP AN12196 §3.3 Table 1 (SV1 -> KSesSDMFileReadENC), via Amperstrand/ntag424-crypto test/an12196-vectors.test.ts"
}
```

`derivation` — op `derive_keys` (full expected set):

```json
{
  "id": "derivation-bolty-cpp-vector1",
  "category": "derivation",
  "input": {
    "op": "derive_keys",
    "issuer_key": "00000000000000000000000000000000",
    "uid": "041065fa967380",
    "version": 1
  },
  "expected": {
    "card_key": "1a3888508f11ba44942bda56b928cc4b",
    "k0": "24d449c0c1d166827c05b8bb4a5798da",
    "k1": "dfea2649f9ce19d0556d0c04cef56fa2",
    "k2": "d41a0289deb7d573b700b135965cd1ea",
    "k3": "fc5d413a564a0b415e3fd410fd19bc55",
    "k4": "f4801a4d53d8784090aa44bbd7c89e95",
    "card_id": "6110dea4c91ed081c43daad898a28548"
  },
  "origin": "bolty-rs tests/fixtures/derivation/boltcard_deterministic.toml Vector 1 (behavioral truth extracted from Bolty C++ KeyDerivation.h)"
}
```

`sdm` — op `sdm_full` (positive):

```json
{
  "id": "sdm-valid-picc-counter0",
  "category": "sdm",
  "input": {
    "op": "sdm_full",
    "k1": "55da174c9608993dc27bb3f30a4a7314",
    "k2": "2ab74abc1273fb43cae97553a36d4d08",
    "p": "e61cb056f52d34f9368f079d1814d2cf",
    "c": "fcc9a22201ea2298"
  },
  "expected": {
    "decrypted_p": "c70425607a8f69800000000000000000",
    "uid": "0425607a8f6980",
    "counter_bytes": "000000",
    "sv2": "3cc3000100800425607a8f6980000000",
    "derived_mac_key": "85f6155e3414e60874534940a44703a2",
    "full_cmac": "90fc61c953a2c922e50129eae4221998"
  },
  "origin": "bolty-rs tests/fixtures/picc/valid_picc.toml fixture 'Recovered card synthetic SDM vector, read counter 0' (behavioral truth extracted from Bolty C++ PiccData.h)"
}
```

`negative` — `"negative": true` on an `sdm_full` vector; consumers assert
rejection instead of comparing intermediates, and `expected` documents the
plaintext without being an assertion target:

```json
{
  "id": "sdm-a3-neg-corrupt-c",
  "category": "sdm",
  "negative": true,
  "input": {
    "op": "sdm_full",
    "k1": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
    "k2": "f0e1d2c3b4a5968778695a4b3c2d1e0f",
    "p": "60fcf1396f08fdca4a261e49b42c5fbb",
    "c": "9b60324f845d7684"
  },
  "expected": {
    "decrypted_p": "c704a39493cc8680ffffff0000000000"
  },
  "origin": "cross-impl audit A3 transcription-derived (Go lnurlw/lnurlw_request.go + crypto/crypto.go transcription, validated byte-for-byte against pre-existing reference vectors); negative: c= corrupted in its first byte (vs valid 9a60324f845d7684) — the SDM verification chain MUST reject"
}
```

### How the file comes to be: manual lift + wave, no generator

**There is no generator script** — nothing in this repo, past or present,
computes or writes `vectors.json` (the entire script inventory is
`scripts/validate_schema.py`, `scripts/drift_check.py`, and
`scripts/consumers.json`). That is by design: the lift-only doctrine
(canon rule 1 in `AGENTS.md`) requires vectors to be lifted byte-exact
from verified external sources and forbids generating them by running an
implementation under test ("that oracles the impl against itself"). Where
each vector's bytes came from is recorded per-vector in `origin` and
summarized in the provenance table at the top of this README.

A new generation therefore comes to be through the **manual lift + wave
process** (full checklist in
[Adding vectors](#adding-vectors-the-wave-process)):

1. Lift the bytes from a verified source (an NXP AN12196 table, RFC 4493
   §4, a hardware-proven capture, or a line-cited cross-implementation
   audit) and land the new vector here first, with its `origin`.
2. The validator's suite-count assertion then fails on purpose — update
   the counts in this README, `scripts/validate_schema.py`, and
   `go-consumer`'s assertions together.
3. In the same wave, re-vendor `vectors.json` and refresh the LOCK files
   in every consumer of the affected categories; the drift check stays
   red until each one is refreshed.
4. `.github/workflows/release.yml` cuts the immutable `vectors-vN` tag
   once the new generation lands on `main`.

### Verify locally

Copy-pasteable, exactly as CI runs them (`.github/workflows/ci.yml`, jobs
`schema` and `drift`; what each check means is in
[Enforcement](#enforcement-ci)):

```bash
# schema + unique ids + suite counts (46 = 26 derivation / 12 sdm / 8 an12196, 3 negative)
pip install --quiet jsonschema
python3 scripts/validate_schema.py vectors.json

# reference consumer (CI also asserts go-consumer/vectors.json is byte-identical to the canonical blob)
sha256sum vectors.json go-consumer/vectors.json
(cd go-consumer && go test ./...)

# consumer drift check across the line (needs GITHUB_TOKEN; fetches consumers.json entries live)
python3 scripts/drift_check.py
```

`scripts/drift_check.py` reads its token from the `GITHUB_TOKEN`
environment variable (CI supplies `secrets.GITHUB_TOKEN`); it exits `0`
when every consumer's vendored copy matches its LOCK and the LOCK points
at a real canonical generation, and `1` on any drift.

## Consumer update flow

1. Vendor-copy the canonical `vectors.json` into the consumer repo
   (e.g. `tests/vectors.json`). Never edit the vendored copy by hand —
   its sha256 must equal the canonical file's. Add a `LOCK` file next to
   it recording where the bytes came from:
   ```
   Vendored from https://github.com/Amperstrand/ntag424-vectors
   release: vectors-v1
   upstream commit: 3c35b1ead9cd560bd7f526c943706c2b2e8d8ebd
   vectors.json sha256: 522cab963c3f7db1ab9249c0d4e207b43abc0b4061323fd5c55755959a4ff65f
   Refresh: <the consumer's vectors-check command>
   ```
   (`release:` is optional; `upstream commit:` + sha256 are required —
   the drift job validates both.)
2. Add/refresh the test that loads it (`include_str!` + `serde_json` in
   Rust, plain import in vitest, `os.ReadFile` + `encoding/json` in Go).
   Assert the sha256 of the vendored file in-suite so count-preserving
   edits cannot pass silently.
3. Run every category the public API can express; skip the rest with an
   explicit counted comment/assertion.
4. A new vector lands here first (with `origin`), then is re-vendored
   into each consumer.

### Consumers

| Language | Repo | Entry point |
|---|---|---|
| TypeScript | Amperstrand/ntag424-crypto | `test/shared-vectors.test.ts` |
| Rust | Amperstrand/ntag424 (branch `ai-experiments`) | `tests/shared_vectors.rs` |
| Go | this repo, `go-consumer/` | `go test ./go-consumer/...` |
| TypeScript | Amperstrand/boltcard-cloudflareworker | `tests/ntag424Vectors.test.ts` |
| Rust | Amperstrand/bolty-rs | `crates/bolty-core/tests/ntag424_vectors.rs` |
| TypeScript (write path) | Amperstrand/bolt-card-programmer | `tests/ntag424Vectors.test.ts` |
| JavaScript (legacy write path) | Amperstrand/bolt-nfc-android-app | `__tests__/ntag424-vectors.test.js` |

## Enforcement (CI)

`.github/workflows/ci.yml` runs on every PR and push to `main`:

1. **Schema + counts** — `scripts/validate_schema.py` validates
   `vectors.json` against `schema/vectors.schema.json` (the machine form
   of the schema section above), asserts unique ids, negative-vector
   placement, and the suite-size counts (46 = 26 derivation / 12 sdm /
   8 an12196, 3 negative). A suite-size change is a conformance wave:
   the counts move here, in the README, in `go-consumer`, and in every
   consumer suite together.
2. **Reference consumer** — `go test ./go-consumer/...` runs every
   expressible vector, with the in-repo copy checked byte-identical to
   the canonical blob first.
3. **Consumer drift check** — `scripts/drift_check.py` walks every
   consumer in `scripts/consumers.json` (fetched live from GitHub) and
   fails if a vendored copy no longer hashes to its LOCK sha256, or the
   LOCK pin does not match the canonical `vectors.json` at the recorded
   upstream commit. Consumers pin a generation — they are not forced
   onto HEAD — so this catches hand-edits, fabricated locks, and silent
   partial refreshes, not legitimate pinned-old generations.

Adding a consumer to the line = add it to `scripts/consumers.json` once
its LOCK + suite have landed.

## Versioned releases

Every canonical `vectors.json` generation is published as an immutable
release tag `vectors-vN` (`.github/workflows/release.yml`; also
dispatchable by hand). Never move or delete a `vectors-vN` tag — cut the
next one instead. Release assets: `vectors.json`, `SHA256SUMS`, and a
ready-to-vendor `LOCK` snippet for the generation.

## Adding vectors (the wave process)

1. Land the new vector here first — lift-only from a verified source
   (AN12196 table, RFC 4493 §4, hardware-proven capture, or a
   cross-implementation audit), with an `origin` field naming it. Never
   generate vectors by running an implementation under test.
2. The validator's suite-count assertion fails on purpose: update the
   counts in this README, in `scripts/validate_schema.py`, and in
   `go-consumer`'s assertions.
3. Same wave, re-vendor + refresh LOCKs in every consumer of the
   affected categories (the drift job is the checklist — it stays red
   until each consumer is refreshed).
4. The release workflow cuts the next `vectors-vN` when the new
   generation lands on `main`.
