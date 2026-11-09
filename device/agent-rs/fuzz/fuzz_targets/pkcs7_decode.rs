#![no_main]
use ironmesh_agent::est::pkcs7;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(certs) = pkcs7::decode_certs_only(data) {
        for c in certs {
            let _ = ironmesh_agent::x509::parse_cert(&c);
        }
    }
    let _ = ironmesh_agent::est::decode_b64_body(data);
});
