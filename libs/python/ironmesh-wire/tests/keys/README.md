# Fixed test keys (PUBLIC - never use outside tests and vectors)

| File                           | Role in the vectors                                             |
|--------------------------------|-----------------------------------------------------------------|
| `device_p256.pem`              | device identity key (ES256); cert serial `3fa1b2c3d4e5f60718293a4b5c6d7e8f`; also the HPKE recipient for Config |
| `attacker_p256.pem`            | a second P-256 key for wrong-key / forged-message cases          |
| `tenant_ed25519.pem`           | tenant command key (`kid = tenant-cmd-7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11`) |
| `fw_ed25519.pem`               | trusted firmware signing key (Ed25519, mandatory manifest signature) |
| `fw_ed25519_untrusted.pem`     | a firmware key that is *not* in `fw_signing_pubkeys`             |
| `fw_mldsa65.seed.hex`          | 32-byte FIPS 204 seed of the trusted ML-DSA-65 firmware key      |

`*.pub.pem` files are the matching SubjectPublicKeyInfo encodings.

All keys were derived deterministically from fixed labels (SHA-256 of
`ironmesh-test-vectors/<name>/v1`); regenerating them yields the same keys. The private halves are
intentionally committed: the Rust and C implementations need them to reproduce the Ed25519 vectors
byte-for-byte.
