#![no_main]
use ironmesh_agent::wire::delta::{self, DeltaApplier};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First byte selects the chunk size, the next two the base length; the base is derived from
    // the input so COPY/hash paths are reachable. Output is bounded by a small target limit.
    if data.len() < 3 {
        return;
    }
    let chunk = usize::from(data[0]).max(1);
    let base_len = (usize::from(u16::from_be_bytes([data[1], data[2]])) % 12_289).min(data.len() * 64);
    let base: Vec<u8> = (0..base_len).map(|i| (i as u8).wrapping_mul(31) ^ data[i % data.len()]).collect();
    let patch = &data[3..];
    let mut produced = 0usize;
    let mut a = DeltaApplier::new(&base[..], base.len() as u64, |d: &[u8]| {
        produced += d.len();
        Ok(())
    }, 1 << 20);
    for c in patch.chunks(chunk) {
        if a.feed(c).is_err() {
            return;
        }
    }
    let _ = a.finish();
    assert!(produced <= 1 << 20);
    let _ = delta::inspect_delta(patch);
});
