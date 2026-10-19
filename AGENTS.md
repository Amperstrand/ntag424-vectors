# AGENTS.md — ntag424-vectors + the boltcard line canon

This repo is small on purpose: it holds the **canonical crypto test vectors**
for the whole boltcard line. Because it is the line's neutral ground, its
AGENTS.md is also the **canonical doctrine document** for the line — the
other five repos carry an AGENTS.md with repo-specific build/test plus a
pointer here. Keep both roles in sync: a line-level rule change lands here
first, then the pointers.

## Purpose of this repo

Byte-exact cross-language NTAG424 DNA / boltcard test vectors (AES-CMAC
per RFC 4493, SDM secure dynamic messaging per NXP AN12196, deterministic
card-key derivation). One `vectors.json` consumed by independent
implementations (Rust, TypeScript, Go) — this repo is the **oracle**: when
two implementations disagree, the vectors decide, and when the vectors must
grow, the provenance rule below decides how.

## The boltcard line (repo map)

| Repo | Role | Write path / read path |
|---|---|---|
| [boltcard-cloudflareworker](https://github.com/Amperstrand/boltcard-cloudflareworker) | Verification + payment service (LNURL-withdraw/pay) | **Read path** (SUN verify) |
| [ntag424-crypto](https://github.com/Amperstrand/ntag424-crypto) | TS crypto primitives (`@ntag424/crypto`) — SDM decrypt, CMAC, key derivation | Read path (library) |
| [ntag424](https://github.com/Amperstrand/ntag424) | Rust crate: NTAG424 DNA command/transport layer (fork of jannschu/ntag424) | Both (embedded readers + host) |
| **ntag424-vectors** (this repo) | The oracle: canonical vectors + consumer drift checks | Both (conformance) |
| [bolt-card-programmer](https://github.com/Amperstrand/bolt-card-programmer) | React Native / Expo card provisioning app (fork) | **Write path** (keys + NDEF onto card) |
| [bolt-nfc-android-app](https://github.com/Amperstrand/bolt-nfc-android-app) | Legacy Android provisioning app (fork; upstream consolidated into bolt-card-programmer) | Write path (legacy) |

Adjacent hardware consumers (not part of this canon but they consume the
same oracle): [bolty-rs](https://github.com/Amperstrand/bolty-rs) (Bolt Card
programmer + the vertical test rig, evidence hub bolty-rs#101) and
[ccid-firmware-rs](https://github.com/Amperstrand/ccid-firmware-rs) (CCID
reader firmware). Both hardware-verified with real NTAG 424 DNA cards.

## SUN read-path architecture (the one diagram to hold in your head)

```
NTAG424 DNA card                 reader / POS / wallet          Cloudflare Worker
┌────────────────┐              ┌──────────────────┐           ┌─────────────────────────┐
│ SDM configured │   NFC tap    │ reads NDEF URL   │  GET /?p= │ handleLnurlw()          │
│ K1 = MAC key   │ ───────────► │ p=<enc PICC>     │ ────────► │ deterministic key       │
│ K2 = ENC key   │  (SUN only:  │ c=<CMAC>         │           │ derivation (keygen) →   │
│ ctr, UID       │   no keys on │                  │           │ decrypt p (ntag424-     │
└────────────────┘   the air)   └──────────────────┘           │ crypto) → verify c →    │
                                                               │ 200 withdrawRequest(k1) │
                                                               │ 403 CMAC validation     │
                                                               └─────────────────────────┘
```

- The card never exposes keys over RF: **SUN** (Secure Unique Number) = the
  SDM-injected `p=`/`c=` pair in the NDEF URL. `c=` is the CMAC over the
  counter-mixed SV2 (tamper evidence), `p=` is AES-ECB-encrypted PICC data
  (UID + counter).
- Card keys are **derived** (UID + issuer key → K1..K4), so the worker needs
  no per-card store for deterministic cards; the derivation semantics live in
  the worker's `keygenerator.ts` and are mirrored by the rig's `sun.py` and
  by every `derivation` vector here.
- The write path is the mirror image: programmer app / bolty-rs authenticate
  (key 0), change keys 1–4, set file settings + NDEF URL, enable SDM.
- Verification verdicts the worker may return: `200` withdrawRequest /
  `403 CMAC validation failed` — the rig's tamper leg pins the 403.

## The vectors-as-oracle conformance rule (LINE-WIDE)

1. **Lift-only provenance.** Vectors are lifted byte-exact from verified
   sources only (NXP AN12196 tables, RFC 4493 §4, hardware-proven
   derivations from bolty-rs, cross-implementation audits). Every vector's
   `origin` field records where the bytes came from. Never invent vectors by
   running an implementation under test — that oracles the impl against
   itself.
2. **Consume everything expressible.** Every implementation must pass every
   vector its public API can express. Categories an API cannot express are
   skipped **with an explicit count** — a silent partial pass is a failure.
3. **Negative vectors are first-class.** Malformed lengths / counters /
   MACs / ciphertext get `negative: true` entries; implementations must
   reject them, not merely not-crash.
4. **Vendored copies may not drift.** Consumers carry a copy (or a pinned
   release) of `vectors.json`; CI compares against the canonical blob. A
   drifted vendored copy fails CI unless it rides an intentional
   vector-version bump. Enforced since the enforcement arm landed
   (schema/vectors.schema.json + scripts/validate_schema.py +
   scripts/drift_check.py + release tags `vectors-vN`; issue #1).
   First live consumer wiring: boltcard-cloudflareworker#68 — reference-locked
   vendored copy + `LOCK` + sha256 assert + `npm run vectors:check` (46
   vectors across aes_cmac / sv2_build / picc_decrypt / sun_mac /
   sdm_full, skips counted aloud per the rule).
5. **Disagreements escalate to provenance.** If two green implementations
   disagree on real hardware behavior, neither wins by vote: a new vector
   is lifted from the documented source (AN12196 table, RFC, or a
   hardware-proven capture) and both are fixed to it.

## Build / test (this repo)

- Structure: `vectors.json` (canonical) + `go-consumer/` (reference
  consumer: `go test ./...` — reads `vectors.json`, asserts every
  expressible vector, prints skip counts) + `schema/` (machine form of
  the README schema) + `scripts/` (`validate_schema.py`,
  `drift_check.py`, `consumers.json` — the consumer manifest).
- CI (`.github/workflows/ci.yml`): schema + unique ids + suite counts,
  go-consumer run against the canonical blob, and the consumer drift
  check across the whole line. `release.yml` cuts an immutable
  `vectors-vN` tag per generation.
- A vectors change is a **conformance change**: bump `schema_version` if
  the shape moves, update `go-consumer`, and land consumer updates
  (ntag424-crypto test copy, Rust consumer branch) in the same wave.
- No secrets in vectors: the `0000…0001` issuer key appearing in
  derivation vectors is the documented **dev fallback** (public by
  definition); production keys never appear here.

## Bench touchpoints

- **Vertical test rig** (bolty-rs#101, worker-side anchor #65): full
  card → reader-logic → worker round-trip against a local offline
  `wrangler dev` (KV + DO emulated). Fresh green baseline 2026-10-17:
  worker 2183 unit / 52 DO / 86 integration; rig ROUND-TRIP PASS including
  the tamper → 403 leg.
- Physical NFC readers on the bench: labgrid places `ref-acr1252` +
  `ref-cardman` (exporter `ai-legion-nfc`). Known blocker: ACR1252
  firmware-wedged (needs USB replug) — the rig falls back to the software
  SUN emulator, which exercises the same worker verification path.
- Hardware changes on the Rust side (ntag424 fork) must be
  hardware-verified with real NTAG 424 DNA cards before the fork branch
  reshapes (see ntag424 AGENTS.md).

## Cross-references — lane B1 conformance work (2026-10)

- ntag424-vectors **#1** — canonical vector CI + consumer drift checks +
  versioned releases (the enforcement arm of rule 4). **Landed**: schema
  + validator + drift job + `vectors-vN` release automation; residual —
  length-class negative vectors (malformed p/c lengths) are a tracked
  follow-up wave.
- Canon-set completion (2026-10-19): bolt-card-programmer **#20** and
  bolt-nfc-android-app **#12** wire the oracle into both write-path apps
  (via the extracted `sunVerify` core — the apps' real `testPAndC` chain,
  20 expressible vectors, 26 `derive_keys` skipped aloud);
  ntag424-crypto **#7** and ntag424 `ai-experiments` add LOCK +
  sha256 asserts pinning `vectors-v1`. All six canon repos now consume
  the oracle with reference-locked vendored copies.
- ntag424 **#3 / #4 / PR5 / PR6** — LenCap=0x03 hardware-compat fix, fork
  strategy (ai-experiments integration branch, upstream-feedback intent),
  AES auth fixtures.
- ntag424-crypto **#3 / #5** — CI gate (test + typecheck + publish
  dry-run); package graduation (license, security policy, releases).
- boltcard-cloudflareworker **#64 / #65** — worker local-rig contract;
  vertical test lane cross-link. **#59** (K4/CardKey doc example must be
  synthetic), **#54** (percard→deterministic migration).

## Rules for agents

- Read the current README (schema + provenance tables) before touching
  `vectors.json`; the schema section there is normative.
- No secrets, ever — vectors and docs carry only public dev keys.
- A PR here that changes vectors without touching consumers, or vice
  versa, is incomplete; say which wave it belongs to.
