#![no_main]
use ironmesh_agent::wire::cbor::DecodeLimits;
use ironmesh_agent::wire::cose;
use ironmesh_agent::wire::keys::PublicKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = cose::sign1_decode(data, DecodeLimits::default()) {
        let _ = m.to_be_signed();
        let key = PublicKey::ed25519_from_raw(&[0x3b; 32]);
        if let Ok(k) = key {
            let _ = cose::sign1_verify(&m, &k);
        }
    }
});
