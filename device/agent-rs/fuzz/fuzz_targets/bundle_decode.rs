#![no_main]
use ironmesh_agent::est::bundle;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Signed path (seeds are bundles signed with this key) and the payload decoder directly, so
    // mutations that break the signature still exercise the payload rules.
    let key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]).verifying_key().to_bytes();
    let _ = bundle::verify_bundle(data, &key);
    let _ = bundle::decode_payload(data);
});
