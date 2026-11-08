# IronMesh Wire Format v1

Byte-level specification of every structure exchanged between IronMesh devices and the cloud:
canonical CBOR, the COSE profiles, the message envelope, attestation, the encrypted `Config`
message, the firmware manifest, and the identifiers/topics they reference. It refines
[`docs/DESIGN_CONTRACT.md`](../../docs/DESIGN_CONTRACT.md) (§1, §3, §4, §5, §6); where the
contract leaves a detail open this document fixes it, and where this document and the contract
disagree the contract wins (see Appendix B for the clarifications made here).

The reference implementation is `libs/python/ironmesh-wire` (`ironmesh_wire`); the conformance
vectors are in [`vectors/`](vectors/README.md). The Rust (`device/agent-rs`) and C
(`device/esp32`) implementations MUST produce byte-identical output for deterministic operations
and MUST report the error codes of §8 for the listed rejections.

Conventions: `h'..'` is hex; CDDL per RFC 8610; "canonical CBOR" means §1 of this document;
MUST / SHOULD per RFC 2119. Byte strings in prose are big-endian unless stated otherwise.

---

## 1. Canonical CBOR profile

All CBOR in IronMesh - COSE structures, headers, payloads, manifests - is encoded in the **core
deterministic encoding** of RFC 8949 §4.2.1, and every decoder is **strict**: it rejects anything
that is not the unique canonical encoding. There is exactly one byte string for every value.

### 1.1 Encoder rules

1. **Shortest argument.** The argument of every item (integer value, string/array/map length, tag
   number) uses the shortest form: `0..23` inline, `24..255` one byte (`0x18`), `256..65535` two
   bytes (`0x19`), `65536..2^32-1` four bytes (`0x1a`), otherwise eight bytes (`0x1b`).
2. **Integers** are major type 0 (`0 <= n <= 2^64-1`) or major type 1 (`-2^64 <= n <= -1`, encoded
   as `-1 - n`). Bignums (tags 2/3) are not used; out-of-range integers are an error.
3. **Floating point** uses the shortest of IEEE 754 half (`0xf9`), single (`0xfa`), double
   (`0xfb`) that represents the value exactly (`1.0` -> `f93c00`, `100000.0` -> `fa47c35000`,
   `1.1` -> `fb3ff199999999999a`). `+Inf`/`-Inf` are `f97c00`/`f9fc00`. **NaN is always
   `f97e00`** (no payloads, no sign). `-0.0` is `f98000` and is distinct from `0.0`.
4. **No indefinite-length** strings, arrays or maps (additional information 31 never appears).
5. **Maps**: keys MUST be unique and sorted in **bytewise lexicographic order of their encoded
   form** (shorter is *not* automatically first: `{100: 0, -1: 0}` encodes `a2 1864 00 20 00`
   because `18 64 < 20`; `{1000: 0, "a": 0}` puts `1903e8` before `6161`). This is RFC 8949 and
   deliberately *not* the length-first order of RFC 7049 §3.9. Only integers, text strings and
   byte strings may be keys.
6. **Simple values**: only `false` (`f4`), `true` (`f5`), `null` (`f6`). `undefined` and all other
   simple values never appear.
7. **Tags**: only 16 (`COSE_Encrypt0`), 18 (`COSE_Sign1`) and 98 (`COSE_Sign`) are used.
8. Text strings are valid UTF-8.

### 1.2 Decoder rules and limits

A strict decoder MUST reject, with the code shown, any input that violates §1.1 or these limits:

| Condition                                                      | Code                     |
|----------------------------------------------------------------|--------------------------|
| input longer than `max_size` (default 65536 bytes)             | `CBOR_SIZE`              |
| item ends past the end of input, or empty input                | `CBOR_TRUNCATED`         |
| bytes remain after the single top-level item                   | `CBOR_TRAILING`          |
| additional information 31 on major types 2-5                   | `CBOR_INDEFINITE`        |
| additional information 28, 29, 30                              | `CBOR_RESERVED`          |
| a break code (`0xff`) anywhere                                 | `CBOR_BREAK`             |
| argument not in shortest form (any major type)                 | `CBOR_NON_MINIMAL_INT`   |
| float not in shortest exact form, or a NaN other than `f97e00` | `CBOR_NON_MINIMAL_FLOAT` |
| simple value other than false/true/null (incl. `0xf8 xx`)      | `CBOR_SIMPLE`            |
| invalid UTF-8 in a text string                                 | `CBOR_UTF8`              |
| map key that is not int / tstr / bstr                          | `CBOR_KEY_TYPE`          |
| map keys not in canonical order                                | `CBOR_KEY_ORDER`         |
| duplicate map key                                              | `CBOR_DUPLICATE_KEY`     |
| nesting depth over `max_depth` (default 16)                    | `CBOR_DEPTH`             |
| a tag other than 16 / 18 / 98                                  | `CBOR_TAG`               |

**Depth**: the top-level item has depth 1; the children of an array, map or tag have the depth of
their parent plus one; an item whose depth exceeds `max_depth` is rejected. `[[...[0]...]]` with 15
brackets is accepted, with 16 it is `CBOR_DEPTH`. Payloads inside COSE are byte strings that are
decoded separately and start again at depth 1.

Decoders MUST apply these rules to the COSE message, to every protected header, and to every
payload. Vectors: `vectors/cbor_canonical.json`.

---

## 2. COSE profiles

### 2.1 Algorithms and header parameters

| Purpose                         | COSE alg label | Value | Notes                                                    |
|---------------------------------|----------------|------:|----------------------------------------------------------|
| device signatures               | ES256          | -7    | ECDSA P-256 / SHA-256, signature = `r || s` (64 bytes)    |
| tenant & firmware signatures    | EdDSA          | -8    | Ed25519 (RFC 8032), 64-byte signature                     |
| firmware PQ signature           | ML-DSA-65      | -49   | FIPS 204 pure mode, empty context; 3309-byte signature (IANA COSE registration) |
| Config content encryption       | A256GCM        | 3     | AES-256-GCM, 12-byte IV, 16-byte tag                      |

| Header parameter      | Label   | Where                  | Type                                       |
|-----------------------|--------:|------------------------|--------------------------------------------|
| `alg`                 | 1       | protected              | int                                        |
| `kid`                 | 4       | protected              | bstr or tstr (§3.3, §6.2)                  |
| `IV`                  | 5       | unprotected (Encrypt0) | bstr(12)                                   |
| IronMesh HPKE wrap    | -70000  | unprotected (Encrypt0) | `{1: enc(bstr 65), 2: wrapped_key(bstr 48)}` |

Protected headers are serialized as canonical CBOR maps wrapped in a bstr. In every IronMesh
profile the protected header map contains **exactly** the listed parameters - no more, no fewer -
and unprotected headers contain exactly what the profile lists. Decoders MUST reject other header
content with `COSE_HEADER`, unknown or wrong algorithm values with `COSE_ALG`, and malformed kids
with `COSE_KID`.

### 2.2 COSE_Sign1 (every envelope, §3)

```cddl
Envelope_Sign1 = #6.18([
  protected:   bstr .cbor Sign1_Protected,
  unprotected: {},                 ; MUST be the empty map (a0)
  payload:     bstr,               ; canonical CBOR envelope map (§3.1); detached (nil) is not allowed
  signature:   bstr                ; 64 bytes for both ES256 and EdDSA
])
Sign1_Protected = { 1: -7 / -8, 4: kid }   ; exactly these two keys
kid = bstr .size (1..20) / tstr            ; §3.3
```

Serialized: `d2 84 <protected bstr> a0 <payload bstr> <signature bstr>`. A device protected header
is `a2 01 26 04 50 <16-byte serial>` (`43 ...` wrapper bytes aside); a tenant protected header is
`a2 01 27 04 78 2f "tenant-cmd-<uuid>"`.

The signature is computed over `Sig_structure` (RFC 9052 §4.4) with **empty external_aad**:

```cddl
Sig_structure = ["Signature1", protected: bstr, external_aad: bstr .size 0, payload: bstr]
```

i.e. the bytes `84 6a 5369676e617475726531 <protected bstr> 40 <payload bstr>`. ES256 signs the
SHA-256 of these bytes (ECDSA), EdDSA signs the bytes directly (PureEdDSA).

Parsing (`sign1_decode`) MUST check, in order: the tag is 18 (`COSE_TAG`); the content is a
4-element array (`COSE_STRUCTURE`); `protected` is a non-empty bstr whose content is a canonical
map with exactly keys 1 and 4 (`COSE_HEADER`), `alg` is -7 or -8 (`COSE_ALG`), `kid` is a bstr or
tstr of 1..255 bytes (`COSE_KID`); `unprotected` is the empty map (`COSE_HEADER`); `payload` is a
bstr (`COSE_STRUCTURE`, detached payloads are rejected); `signature` is a 64-byte bstr
(`COSE_SIGNATURE`). Verification (`sign1_verify`) MUST check that the algorithm matches the key type
(`COSE_ALG`) and the signature (`COSE_SIGNATURE`). Vectors: `cose_sign1_es256.json`,
`cose_sign1_eddsa.json`.

### 2.3 COSE_Sign (firmware manifest, §6)

```cddl
Manifest_Sign = #6.98([
  protected:   bstr .size 0,       ; empty body protected header, encoded as h'' (40)
  unprotected: {},                 ; a0
  payload:     bstr,               ; canonical CBOR manifest (§6.1)
  signatures:  [+ Manifest_Signature]  ; 1 or 2 entries, at most one per algorithm
])
Manifest_Signature = [
  protected:   bstr .cbor { 1: -8 / -49, 4: bstr .size 8 },
  unprotected: {},
  signature:   bstr                ; 64 bytes (EdDSA) or 3309 bytes (ML-DSA-65)
]
Sig_structure = ["Signature", body_protected: bstr .size 0, sign_protected: bstr,
                 external_aad: bstr .size 0, payload: bstr]
```

Serialized: `d8 62 84 40 a0 <payload bstr> 8n [ 83 <protected> a0 <signature> ]...`. The
`Sig_structure` bytes are `85 69 5369676e6174757265 40 <sign_protected bstr> 40 <payload bstr>`.
The order of signatures is Ed25519 first, ML-DSA-65 second when present.

**Key identifier**: `kid = SHA-256(raw public key)[0:8]`, where the raw key is the 32-byte Ed25519
public key or the 1952-byte ML-DSA-65 public key - exactly the bstr values of the bundle's
`fw_signing_pubkeys` (contract §3 step 6). A verifier derives the kid of each trusted key and
matches on it; the manifest's `signing_key_id` text field (§6.1) is informational and MUST NOT be
used for key selection.

Structural checks (`sign_decode`): tag 98 (`COSE_TAG`), 4-element array (`COSE_STRUCTURE`), body
protected header exactly `h''` and body unprotected exactly `{}` (`COSE_HEADER`), payload bstr,
non-empty signatures array; each signature: 3-element array, protected header exactly
`{1: alg, 4: kid}` with `alg` in {-8, -49} (`COSE_ALG`), `kid` an 8-byte bstr (`COSE_KID`),
unprotected `{}`, signature length matching the algorithm (`COSE_SIGNATURE`), no two signatures
with the same algorithm (`COSE_DUPLICATE_ALG`). Verification rules are in §6.3.

### 2.4 COSE_Encrypt0 (Config, §5)

```cddl
Config_Encrypt0 = #6.16([
  protected:   bstr .cbor { 1: 3 },                ; exactly a1 01 03 -> bstr 43 a1 01 03
  unprotected: { 5: bstr .size 12,                 ; AES-256-GCM IV
                 -70000: { 1: bstr .size 65,       ; HPKE enc (ephemeral P-256 point, uncompressed)
                           2: bstr .size 48 } },   ; HPKE-sealed CEK (32-byte key + 16-byte tag)
  ciphertext:  bstr                                ; AES-256-GCM(plaintext) || tag, >= 16 bytes
])
Enc_structure = ["Encrypt0", protected: bstr, external_aad: bstr .size 0]
```

Serialized: `d0 83 43 a10103 a2 05 4c <12 bytes> 3a 0001116f a2 01 5841 <65 bytes> 02 5830 <48
bytes> <ciphertext bstr>`. Note the canonical order of the unprotected map: key `5` (`05`) sorts
before key `-70000` (`3a 00 01 11 6f`). The `Enc_structure` is the fixed byte string
`83 68 456e637279707430 43 a10103 40` and is used both as the AES-256-GCM AAD and as the HPKE
`aad` (§5). Structural checks produce `COSE_TAG`, `COSE_STRUCTURE`, `COSE_HEADER`, `COSE_ALG`
exactly as for Sign1; a ciphertext shorter than 16 bytes is `COSE_STRUCTURE`.

### 2.5 Signature encodings

* **ES256**: `r || s`, each a 32-byte big-endian integer, zero-padded (RFC 9053 §2.1). Verifiers
  convert to the library's native form; `r` or `s` equal to 0 or >= n is `COSE_SIGNATURE`.
* **EdDSA**: the 64-byte RFC 8032 Ed25519 signature.
* **ML-DSA-65**: the 3309-byte FIPS 204 signature, pure mode (`ML-DSA.Sign(sk, M, ctx = "")`)
  over the `Sig_structure` bytes. Signing is hedged, so signatures are not reproducible.

---

## 3. Envelope

### 3.1 Payload

```cddl
Envelope = {
  1: seq:   uint,          ; 0..2^64-1, strictly increasing per (sender kid, direction)
  2: ts:    uint,          ; Unix seconds
  3: type:  1..10,         ; §3.2
  4: body:  Body,          ; §3.4, integer-keyed map
  ? 5: nonce: bstr .size 16 ; present iff type is 5 (Command) or 6 (CommandAck)
}
```

The payload is the canonical CBOR encoding of this map (keys in order `01 02 03 04 [05]`). Unknown
keys, missing keys or wrong types are rejected (`ENV_STRUCTURE` for the key set, `ENV_FIELD` for
`seq`/`ts`, `ENV_TYPE` for `type`, `ENV_NONCE` for the nonce rule).

### 3.2 Message types and directions

| type | Name           | Direction | Topic (§7)        | Signer / kid                                   |
|-----:|----------------|-----------|-------------------|------------------------------------------------|
| 1    | Telemetry      | uplink    | `telemetry`       | device, ES256, kid = cert serial               |
| 2    | Event          | uplink    | `events`          | device                                         |
| 3    | ShadowReported | uplink    | `shadow/reported` | device                                         |
| 4    | ShadowDesired  | downlink  | `shadow/desired`  | tenant, EdDSA, kid = `tenant-cmd-<tenant>`     |
| 5    | Command        | downlink  | `cmd/req`         | tenant                                         |
| 6    | CommandAck     | uplink    | `cmd/ack`         | device                                         |
| 7    | OtaNotify      | downlink  | `ota/notify`      | tenant                                         |
| 8    | OtaStatus      | uplink    | `ota/status`      | device                                         |
| 9    | Config         | downlink  | `config`          | tenant; the Sign1 is wrapped in Encrypt0 (§5)  |
| 10   | Attestation    | uplink    | (EST header, §4)  | device (current identity key)                  |

**Uplink** messages MUST be signed with ES256 by the device certificate key and carry a bstr kid;
**downlink** messages MUST be signed with EdDSA by the tenant command key and carry a tstr kid. A
receiver infers the header direction from the kid type (bstr -> uplink, tstr -> downlink), checks
the profile, and after decoding checks that the message type belongs to that direction
(`ENV_DIRECTION`).

### 3.3 Key identifiers

* **Device kid** = the certificate serial number as an unsigned big-endian integer in minimal
  length: no leading `0x00` bytes, 1..20 bytes (RFC 5280 limits serials to 20 octets; a DER
  `INTEGER` content octet string with a leading `00` has it stripped). Violations: `ENV_KID`.
* **Tenant kid** = the text string `tenant-cmd-<tenant uuid>` where the uuid is a lower-case
  hyphenated UUIDv4 (§7). Violations: `ENV_KID`.
* kid/algorithm mismatches (bstr kid with EdDSA, tstr kid with ES256): `ENV_DIRECTION`.

### 3.4 Bodies

All maps use integer keys; `*` marks optional keys (omitted when absent - never encoded as `null`
unless stated). Free-form "application maps" (`args`, `result`, `state`, `data`, `settings`) MUST
have text-string keys and may hold any canonical CBOR values within the decoder limits. UUIDs are
36-character lower-case hyphenated text; `campaign_id` MUST be a UUIDv4, `cmd_id` any UUID version.
Strings marked `semver` MUST match Semantic Versioning 2.0.0. `bstr32` = 32 bytes.

```cddl
Telemetry = {                      ; type 1
  1: cpu_pct: float, 2: mem_pct: float, 3: net_rx_bytes: uint, 4: net_tx_bytes: uint,
  5: temp_c: float, 6: uptime_s: uint, 7: auth_failures: uint, 8: fw_hash: bstr32,
  9: fw_version: tstr .size (1..64) (semver),
  ? 10: proc_count: uint,                     ; Linux
  ? 11: top_procs: [0*10 tstr],               ; Linux, at most 10 entries
  ? 12: rssi: int,                            ; ESP32, -2^63..2^63-1
  ? 13: free_heap: uint,                      ; ESP32
  ? 14: lat: float, ? 15: lon: float }
Event = { 1: name: tstr .size (1..64), 2: severity: 0..4, 3: data: AppMap }      ; type 2
                                     ; severity: 0 debug, 1 info, 2 warning, 3 error, 4 critical
ShadowReported = { 1: state: AppMap, 2: version: uint }                           ; type 3
ShadowDesired  = { 1: state: AppMap, 2: version: uint }                           ; type 4
Command = { 1: cmd_id: tstr .size 36 (uuid), 2: name: tstr .size (1..64), 3: args: AppMap,
            4: idempotency_key: tstr .size (1..128), 5: expires_at: uint }       ; type 5
CommandAck = { 1: cmd_id: tstr .size 36, 2: status: 0..3,                        ; type 6
               ? 3: result: AppMap, ? 4: error: tstr .size (1..1024) }
                                     ; status: 0 ok, 1 rejected, 2 failed, 3 expired
OtaNotify = { 1: campaign_id: tstr .size 36 (uuid4), 2: manifest: bstr .size (1..),  ; type 7
              3: url: tstr .size (1..2048), 4: delta_from: bstr32 / null }        ; key 4 always present
OtaStatus = { 1: campaign_id: tstr .size 36 (uuid4), 2: state: 0..7, 3: progress_pct: 0..100,
              ? 4: error: tstr .size (1..1024), ? 5: fw_hash: bstr32 }           ; type 8
          ; state: 0 received, 1 downloading, 2 verifying, 3 applying, 4 rebooting, 5 success,
          ;        6 rolled_back, 7 rejected
Config = { 1: version: uint, 2: settings: AppMap }                               ; type 9
Attestation = { 1: nonce: bstr32, 2: csr_hash: bstr32, 3: fw_hash: bstr32,       ; type 10
                4: fw_version: tstr .size (1..64) (semver),
                5: se_type: "atecc608" / "tpm2" / "optee" / "software",
                6: evidence: null / Tpm2Evidence }                               ; key 6 always present
Tpm2Evidence = { 1: quote: bstr .size (1..), 2: signature: bstr .size (1..), 3: ak_cert_der: bstr .size (1..) }
AppMap = { * tstr => any }
```

Float fields MUST be CBOR floats (major type 7); an integer in a float field is `ENV_FIELD`.
`evidence` MUST be a `Tpm2Evidence` map iff `se_type == "tpm2"` and `null` otherwise. Every body
violation is `ENV_FIELD`.

### 3.5 Direction/nonce rules

* `nonce` MUST be present (16 bytes) on Command and CommandAck and MUST be absent on every other
  type (`ENV_NONCE`).
* A CommandAck MUST echo the Command's nonce and `cmd_id`. A receiver that knows the outstanding
  command verifies with `expected_nonce`; a mismatch (or an `expected_nonce` supplied for a
  non-ack message) is `ENV_NONCE`; a `cmd_id` mismatch is `ENV_FIELD`.

### 3.6 Verification algorithm (`decode`)

Given the message bytes, a key resolver (kid -> public key), a replay store, `now`, `max_skew`
(default 300 s) and optional `expected_direction`, `expected_tenant`, `expected_nonce`:

1. Parse the COSE_Sign1 per §2.2 (CBOR_* / COSE_* codes).
2. Header direction := uplink if kid is a bstr, downlink if tstr. Check the kid format
   (`ENV_KID`) and the algorithm for that direction (`ENV_DIRECTION`).
3. If `expected_direction` is given and differs: `ENV_DIRECTION`.
4. For downlink, if `expected_tenant` is given and the kid's tenant differs: `ENV_TENANT`.
5. Resolve the public key; unknown kid: `ENV_UNKNOWN_KEY`.
6. Verify the signature: `COSE_SIGNATURE` (or `COSE_ALG` if the key type does not match).
7. Decode the payload per §3.1/§3.4.
8. The type's direction (§3.2) must equal the header direction: `ENV_DIRECTION`.
9. `|now - ts| <= max_skew`, else `ENV_TS_SKEW` (both 300 s early and 300 s late are accepted;
   301 s is rejected). **Exception (retainable types):** downlink ShadowDesired (4), OtaNotify (7)
   and Config (9) may arrive as retained MQTT messages long after they were signed, so for them only
   `ts - now <= max_skew` is enforced (a message dated in the future is still rejected); `seq`
   ordering prevents replay of older versions. Commands (5) are never retained and keep the full
   window.
10. Nonce echo (§3.5): `ENV_NONCE`.
11. Replay: atomically accept `seq` iff it is strictly greater than the last accepted sequence for
    the message's **replay stream** (or none exists) and record it; otherwise `ENV_REPLAY`. The
    replay stream is the device kid for uplink, and the text string `"<tenant kid>/<type>"` (type
    in decimal, e.g. `tenant-cmd-<uuid>/5`) for downlink. Downlink sequences are per type because
    different cloud services sign different downlink types with the same tenant key (registry:
    4, 5, 9; OTA service: 7) and must not consume each other's sequence numbers. **The store is
    updated only when every previous step passed**; rejected messages never advance it.

The first failing step determines the error code; `vectors/replay_cases.json` exercises the
order. Receivers count `ENV_REPLAY` rejections in `ironmesh_replay_rejected_total`.

### 3.7 Replay store semantics

The store maps `(sender kid, direction)` to the last accepted `seq`. The server keeps it in
Postgres per device (an `UPDATE ... SET last_seq = $1 WHERE kid = $2 AND last_seq < $1` style
compare-and-set), the device in NVS/keyring per tenant key. Devices persist their own next `seq`
before sending so a reboot never reuses a value; a certificate renewal changes the device kid but
the device counter keeps increasing, so a receiver MAY additionally key its store by device id.

---

## 4. Attestation (type 10)

The attestation of contract §3 is an ordinary envelope: `COSE_Sign1` signed by the device's
**current** identity key (bootstrap key on first enrollment), kid = that certificate's serial,
payload `{1: seq, 2: ts, 3: 10, 4: Attestation}` with the body of §3.4
(`csr_hash = SHA-256(csr_der)`). It travels base64-encoded in the `X-IronMesh-Attestation` header
of `POST /.well-known/est/simpleenroll`.

The EST server verifies it with `verify_attestation`: §3.6 with the TLS client certificate's
public key as the resolver result and `expected_direction = uplink` (a replay store is optional
because the nonce is single-use); then `type == 10` (`ATT_TYPE`), kid == serial of the TLS client
certificate (`ENV_KID`), `nonce == issued nonce` (`ATT_NONCE`), `csr_hash == SHA-256(submitted
CSR)` (`ATT_CSR_HASH`), `se_type` allowed by tenant policy (`ATT_SE_TYPE`). For `tpm2` the
`quote` MUST parse as a `TPMS_ATTEST` (TPM 2.0 Part 2 §10.12) with `magic = 0xff544347`, `type =
TPM_ST_ATTEST_QUOTE (0x8018)`, `extraData == nonce`, and a PCR selection for `TPM_ALG_SHA256
(0x000b)` that selects **exactly** PCRs {0, 2, 4, 7} (`ATT_EVIDENCE`). Verifying the quote signature
with `ak_cert_der` and the PCR digest policy is the server's responsibility (`quote_verifier`
hook). `optee` uses `evidence = null` in v1. Assurance level: `software` for `se_type ==
"software"`, `hardware` otherwise. Vectors: `attestation_software.json`.

---

## 5. Config (type 9): COSE_Encrypt0 with HPKE key wrap

A Config message is **sign-then-encrypt**: the plaintext of the Encrypt0 is the complete
tenant-signed `COSE_Sign1` envelope of type 9 (so the device gets authenticity, replay protection
and timestamps exactly like every other downlink message), and the Encrypt0 provides
confidentiality towards the broker.

Encryption (`wrap_config(plaintext, device_cert_pubkey)`):

1. `CEK` := 32 random bytes; `IV` := 12 random bytes.
2. `protected` := `a1 01 03`; `Enc_structure` := `83 68 "Encrypt0" 43 a10103 40` (§2.4).
3. HPKE (RFC 9180) **base mode**, `DHKEM(P-256, HKDF-SHA256)` (kem_id 0x0010), `HKDF-SHA256`
   (kdf_id 0x0001), `AES-128-GCM` (aead_id 0x0001):
   `enc, ctx = SetupBaseS(pkR = device certificate public key, info = "ironmesh-config-cek-v1")`
   (`info` is the 22-byte ASCII string `69726f6e6d6573682d636f6e6669672d63656b2d7631`);
   `wrapped_key = ctx.Seal(aad = Enc_structure, pt = CEK)` - 48 bytes; `enc` is the 65-byte
   uncompressed ephemeral public key.
4. `ciphertext = AES-256-GCM(key = CEK, nonce = IV, aad = Enc_structure, plaintext) || tag`.
5. Emit the Encrypt0 of §2.4.

Decryption (`unwrap_config`): parse per §2.4; `CEK = Open(enc, skR, info, aad = Enc_structure,
wrapped_key)` - failure is `HPKE_OPEN` (a malformed `enc` is `HPKE_KEY`); then AES-256-GCM
decrypt - failure is `COSE_DECRYPT`. The resulting plaintext MUST then be processed as a downlink
envelope (§3.6) and MUST be of type 9. Plaintext config is never retained on the broker; the
Encrypt0 may be retained.

The HPKE implementation MUST reproduce RFC 9180 Appendix A.3.1 (included in
`vectors/hpke_rfc9180_a3.json`). `DeriveKeyPair` for P-256 (RFC 9180 §7.1.3) is required only to
check those vectors and to produce deterministic test messages.

---

## 6. Firmware manifest

### 6.1 Manifest map

```cddl
Manifest = {
  1: product: tstr .size (1..64),          ; ^[a-z0-9][a-z0-9-]{0,63}$
  2: version: tstr .size (1..64),          ; semver 2.0.0
  3: version_code: uint,                   ; monotonic anti-rollback counter
  4: image_sha256: bstr32,
  5: image_size: uint,
  6: created_at: uint,                     ; Unix seconds
  7: min_version_code: uint,               ; <= version_code; oldest current image allowed to upgrade
  8: delta: null / { 1: base_sha256: bstr32, 2: patch_sha256: bstr32, 3: patch_size: uint },
  9: signing_key_id: tstr .size (1..64)    ; informational (KMS key name); not used for key selection
}
```

Key 8 is always present (`null` for full images). Violations: `MF_FIELD`; a payload that is not a
canonical CBOR map: `MF_STRUCTURE`.

### 6.2 Signed form

`manifest.sig` = the `COSE_Sign` of §2.3 with the canonical manifest as embedded payload; the
`OtaNotify.manifest` field carries exactly these bytes, and `manifest.cbor` in the artifact store
is the payload. The Ed25519 signature is mandatory; the ML-DSA-65 signature is optional. kids are
derived from the raw public keys (§2.3).

### 6.3 Verification (`verify_manifest(bytes, fw_signing_pubkeys, require_pq)`)

1. Parse per §2.3.
2. Index the trusted keys by length: 32 bytes -> Ed25519, 1952 bytes -> ML-DSA-65, anything else
   is a configuration error (`MF_STRUCTURE`). kid := `SHA-256(key)[0:8]`.
3. The Ed25519 signature MUST be present (`COSE_SIGNATURE`), its kid MUST match a trusted Ed25519
   key (`COSE_UNKNOWN_KEY`), and it MUST verify over `Sig_structure` (`COSE_SIGNATURE`).
4. If `require_pq` (device built with `IRONMESH_PQ_REQUIRED`): the ML-DSA-65 signature MUST be
   present (`COSE_PQ_REQUIRED`), the verifier MUST have an ML-DSA backend (`MLDSA_NOT_AVAILABLE`
   is a configuration error), its kid MUST match a trusted ML-DSA key (`COSE_UNKNOWN_KEY`) and it
   MUST verify (`COSE_SIGNATURE`).
5. If not `require_pq` and an ML-DSA-65 signature is present: an implementation that *can* verify
   it and has the matching trusted key MUST verify it and reject an invalid one
   (`COSE_SIGNATURE`); implementations without ML-DSA support, or without the key, ignore it.
6. Decode the payload as a manifest (§6.1).

### 6.4 Acceptance (`accept_image(manifest, image, current_version_code, product)`)

A pure function evaluated after §6.3, in this order; the first failure is the reason:

| Rule                                                | Reason              |
|-----------------------------------------------------|---------------------|
| `manifest.product == product`                       | `MF_PRODUCT`        |
| `manifest.version_code > current_version_code`      | `MF_ROLLBACK`       |
| `current_version_code >= manifest.min_version_code` | `MF_MIN_VERSION`    |
| `len(image) == manifest.image_size`                 | `MF_SIZE_MISMATCH`  |
| `SHA-256(image) == manifest.image_sha256`           | `MF_HASH_MISMATCH`  |

Delta pre-checks (`accept_patch(manifest, patch, current_fw_hash)`): `delta` present
(`MF_NO_DELTA`), `delta.base_sha256 == current_fw_hash` (`DELTA_BASE_HASH`), `len(patch) ==
delta.patch_size` (`MF_SIZE_MISMATCH`), `SHA-256(patch) == delta.patch_sha256`
(`MF_HASH_MISMATCH`). The patch format is [`DELTA_FORMAT.md`](DELTA_FORMAT.md). ESP32 additionally
enforces the eFuse secure version; the A/B health-check logic is outside this document.

---

## 7. Identifiers and topics

| Entity        | Rule                                                                              |
|---------------|-----------------------------------------------------------------------------------|
| tenant id     | `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$` (UUIDv4, lower-case) |
| device id     | `^dev-[0-9a-f]{16}$`                                                              |
| group slug    | `^[a-z0-9-]{1,48}$`                                                               |
| campaign id   | UUIDv4 as tenant id                                                               |
| cmd id        | `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`                  |
| product       | `^[a-z0-9][a-z0-9-]{0,63}$`                                                       |
| firmware id   | `<product>/<semver>`                                                              |

Violations are `ID_FORMAT`. Topics are `im/v1/<tenant>/<device>/<suffix>` with the suffixes of
§3.2; `parse_topic` rejects (`TOPIC_FORMAT`) anything that is not exactly one of the nine topics for
a valid tenant and device (wildcards included). A device may publish only to its own uplink topics
and subscribe only to its own downlink topics; retained messages are allowed only on
`shadow/desired`, `ota/notify` and `config`; QoS is 1 everywhere; the bridge uses
`$share/bridge/im/v1/#`. Vectors: `ids_topics.json`.

---

## 8. Error codes

| Prefix   | Codes                                                                                   |
|----------|-----------------------------------------------------------------------------------------|
| `CBOR_`  | `SIZE TRUNCATED TRAILING INDEFINITE RESERVED BREAK NON_MINIMAL_INT NON_MINIMAL_FLOAT SIMPLE UTF8 KEY_TYPE KEY_ORDER DUPLICATE_KEY DEPTH TAG TYPE INT_RANGE` (the last two are encoder-side) |
| `COSE_`  | `TAG STRUCTURE HEADER ALG KID KEY_TYPE SIGNATURE UNKNOWN_KEY DUPLICATE_ALG PQ_REQUIRED DECRYPT` |
| `ENV_`   | `STRUCTURE TYPE FIELD KID UNKNOWN_KEY DIRECTION TS_SKEW NONCE REPLAY TENANT`             |
| `ATT_`   | `TYPE NONCE CSR_HASH SE_TYPE EVIDENCE`                                                   |
| `MF_`    | `STRUCTURE FIELD HASH_MISMATCH SIZE_MISMATCH ROLLBACK PRODUCT MIN_VERSION NO_DELTA`      |
| `DELTA_` | see `DELTA_FORMAT.md` §6                                                                 |
| `HPKE_`  | `KEY OPEN DERIVE SEQ`                                                                    |
| other    | `ID_FORMAT`, `TOPIC_FORMAT`, `MLDSA_NOT_AVAILABLE`                                       |

Codes are stable identifiers: logs, metrics labels and the conformance vectors use them verbatim.

## 9. Test vectors

See [`vectors/README.md`](vectors/README.md). Deterministic vectors (canonical CBOR, Ed25519
signatures, HPKE with fixed ephemeral keys, deltas) MUST be reproduced byte-for-byte; ES256 and
ML-DSA-65 signatures are verification vectors.

---

## Appendix A. Worked example: Telemetry envelope

From `vectors/envelope_telemetry.json` (`seq = 1001`, `ts = 1767225598`):

```
d2                                   tag 18
  84                                 array(4)
  55 a2 01 26 04 50 3fa1b2c3d4e5f60718293a4b5c6d7e8f    protected: {1: -7, 4: h'3fa1..7e8f'}
  a0                                 unprotected: {}
  58 ..                              payload (canonical envelope map, see below)
  58 40 <64 bytes>                   signature r||s
payload:
  a4 01 1903e9 02 1a6955b8fe 03 01 04 ad 01 f94a40 ..   {1: 1001, 2: 1767225598, 3: 1, 4: {1: 12.5, ... 13 entries}}
Sig_structure:
  84 6a 5369676e617475726531 55 a2012604503fa1b2c3d4e5f60718293a4b5c6d7e8f 40 58 .. <payload>
```

## Appendix B. Clarifications relative to the design contract

These are the points the contract leaves open or states inconsistently; this document resolves
them without contradicting any binding rule:

1. **ML-DSA-65 algorithm value.** ML-DSA-65 uses COSE alg `-49`, the value registered by
   draft-ietf-cose-dilithium (`-48` is ML-DSA-44). The design contract was amended to match.
2. **Config content algorithm.** The contract writes `{1: 1 (A128GCM)}` but also says the config
   is encrypted with AES-256-GCM under a 256-bit key and defers the header layout to this
   document. The content algorithm is `A256GCM (3)`; AES-128-GCM is the HPKE AEAD used to wrap the
   CEK.
3. **Attestation payload.** The contract describes the attestation as "a COSE_Sign1 (see §5) over
   a CBOR map {1: nonce, ...}" and lists type 10 in §5. Here the map is the *body* of a regular
   type-10 envelope, so one codec covers everything and timestamps/replay apply.
4. **Bodies the contract does not define** (Event, ShadowReported, ShadowDesired, Config) are
   defined in §3.4. `min_version_code` gets the acceptance rule of §6.4.
5. **Config plaintext** is the signed envelope (sign-then-encrypt); the contract only says the
   config is "inside Encrypt0".
6. **Firmware kid derivation** (`SHA-256(raw key)[0:8]`) and the `-70000` header parameter are
   IronMesh-specific choices in the private-use space.
7. **Device kid** is the minimal big-endian serial (no leading zero), matching Go's
   `big.Int.Bytes()`, Rust's `BigUint::to_bytes_be()` and mbedTLS after stripping a leading `00`.
