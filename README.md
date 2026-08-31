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

## Consumer update flow

1. Vendor-copy the canonical `vectors.json` into the consumer repo
   (e.g. `tests/vectors.json`). Never edit the vendored copy by hand —
   its sha256 must equal the canonical file's.
2. Add/refresh the test that loads it (`include_str!` + `serde_json` in
   Rust, plain import in vitest, `os.ReadFile` + `encoding/json` in Go).
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
