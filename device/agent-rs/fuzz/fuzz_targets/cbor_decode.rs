#![no_main]
use ironmesh_agent::wire::cbor;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Strict decode; anything accepted must re-encode to exactly the same bytes (canonical).
    if let Ok(v) = cbor::decode(data) {
        let enc = cbor::encode(&v).expect("decoded values are encodable");
        assert_eq!(enc, data, "accepted CBOR is not canonical");
    }
});
