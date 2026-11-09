#![no_main]
use ironmesh_agent::wire::cbor::DecodeLimits;
use ironmesh_agent::wire::hpke;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Full Config unwrap path (structure, HPKE decap, AEAD) with a fixed recipient key.
    let sk = p256_key();
    let _ = hpke::unwrap_config(data, &sk, DecodeLimits::default());
});

fn p256_key() -> p256::SecretKey {
    p256::SecretKey::from_slice(&[7u8; 32]).expect("valid scalar")
}
