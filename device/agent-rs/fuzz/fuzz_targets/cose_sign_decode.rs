#![no_main]
use ironmesh_agent::wire::cbor::DecodeLimits;
use ironmesh_agent::wire::cose;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = cose::sign_decode(data, DecodeLimits::default()) {
        for s in &m.signatures {
            let _ = m.to_be_signed(s);
        }
    }
});
