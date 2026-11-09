//! IMDELTA1 streaming applier. Input = 1 selector byte (chunk size, work-buffer size, header
//! fix-up) + patch. With bit 7 set the header gets the real base size/hash so the op loop is
//! reachable. Invariants: output never exceeds max_target, writes are sequential.
#![no_main]
use core::ffi::c_void;
use im_host::ffi::*;
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};

struct Io {
    base: Vec<u8>,
    out: Vec<u8>,
}

unsafe extern "C" fn rd(ctx: *mut c_void, off: u64, buf: *mut u8, len: usize) -> i32 {
    let io = &*(ctx as *const Io);
    let off = off as usize;
    if off + len > io.base.len() {
        return 1;
    }
    core::slice::from_raw_parts_mut(buf, len).copy_from_slice(&io.base[off..off + len]);
    0
}

unsafe extern "C" fn wr(ctx: *mut c_void, off: u64, d: *const u8, len: usize) -> i32 {
    let io = &mut *(ctx as *mut Io);
    assert_eq!(off as usize, io.out.len(), "sequential writes");
    io.out.extend_from_slice(core::slice::from_raw_parts(d, len));
    0
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    let base: Vec<u8> = (0..8292u32).map(|i| (i * 7 + 3) as u8).collect();
    let mut patch = rest.to_vec();
    if sel & 0x80 != 0 && patch.len() >= 92 {
        patch[12..20].copy_from_slice(&(base.len() as u64).to_be_bytes());
        patch[20..52].copy_from_slice(&Sha256::digest(&base));
    }
    let mut io = Box::new(Io { base, out: Vec::new() });
    let fio = im_delta_io_t { read_base: Some(rd), write: Some(wr), ctx: (&mut *io as *mut Io).cast() };
    let mut ctx = im_host::Opaque::new(unsafe { im_delta_ctx_size() });
    let mut work = vec![0u8; 64 + (sel as usize & 0x3f) * 64];
    let max_target = 1u64 << 20;
    unsafe {
        assert_eq!(im_delta_init(ctx.ptr(), &fio, io.base.len() as u64, max_target, work.as_mut_ptr(), work.len()), 0);
        let chunk = 1 + (sel as usize & 0x1f) * 37;
        for c in patch.chunks(chunk) {
            if im_delta_feed(ctx.ptr(), c.as_ptr(), c.len()) != 0 {
                break;
            }
        }
        let _ = im_delta_finish(ctx.ptr());
        im_delta_abort(ctx.ptr());
    }
    assert!(io.out.len() as u64 <= max_target);
});
