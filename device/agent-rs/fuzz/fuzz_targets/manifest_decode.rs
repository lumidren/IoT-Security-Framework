#![no_main]
use ironmesh_agent::wire::cbor::DecodeLimits;
use ironmesh_agent::wire::manifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = manifest::decode_manifest(data, DecodeLimits::default());
    let trusted = vec![vec![0x3b; 32]];
    let _ = manifest::verify_manifest(data, &trusted, false, DecodeLimits::default());
    let _ = manifest::verify_manifest(data, &trusted, true, DecodeLimits::default());
});
