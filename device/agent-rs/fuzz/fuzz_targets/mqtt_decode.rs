#![no_main]
use ironmesh_agent::mqtt::codec;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    // Decode a stream of packets; every accepted packet must survive an encode/decode round trip.
    while let Ok(Some((p, n))) = codec::decode(buf, 1 << 20) {
        if let Ok(enc) = p.encode() {
            let (again, m) = codec::decode(&enc, 1 << 20).expect("re-decode").expect("complete");
            assert_eq!(m, enc.len());
            assert_eq!(again, p);
        }
        buf = &buf[n..];
    }
});
