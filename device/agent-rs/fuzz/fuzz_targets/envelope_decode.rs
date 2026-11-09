#![no_main]
use ironmesh_agent::wire::cbor::DecodeLimits;
use ironmesh_agent::wire::cose::Kid;
use ironmesh_agent::wire::envelope::{self, DecodeOptions, InMemoryReplayStore};
use ironmesh_agent::wire::keys::PublicKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Payload decoder directly, and the full verification pipeline with any-key resolver.
    let _ = envelope::decode_payload(data, DecodeLimits::default());
    let ed = PublicKey::ed25519_from_raw(&[0x3b; 32]).ok();
    let resolver = |k: &Kid| match k {
        Kid::Text(_) => ed.clone(),
        Kid::Bytes(_) => None,
    };
    let mut store = InMemoryReplayStore::new();
    let opts = DecodeOptions { now: 1_767_225_600, expected_tenant: Some("7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"), ..Default::default() };
    let _ = envelope::decode(data, &resolver, &mut store, &opts);
});
