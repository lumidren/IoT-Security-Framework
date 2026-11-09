//! Offline ring buffer over simulated NOR flash: ordering, persistence across reboots, wrap with
//! overwrite-oldest, torn writes and delivery acknowledgements.

use im_host::err::*;
use im_host::err_name;
use im_host::ffi2::*;
use im_host::sim::NorFlash;

fn mount(f: &mut NorFlash, slot: u32) -> Box<im_ringbuf_t> {
    let st = f.storage();
    let mut rb: Box<im_ringbuf_t> = Box::new(unsafe { core::mem::zeroed() });
    assert_eq!(unsafe { im_rb_init(&mut *rb, &st, slot) }, IM_OK);
    rb
}

fn push(rb: &mut im_ringbuf_t, data: &[u8]) {
    assert_eq!(unsafe { im_rb_push(rb, data.as_ptr(), data.len()) }, IM_OK);
}

fn peek(rb: &mut im_ringbuf_t) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let mut n = 0usize;
    let mut id = 0u32;
    let r = unsafe { im_rb_peek(rb, buf.as_mut_ptr(), buf.len(), &mut n, &mut id) };
    if r == IM_ERR_EMPTY {
        return None;
    }
    assert_eq!(r, IM_OK);
    buf.truncate(n);
    Some(buf)
}

fn pop(rb: &mut im_ringbuf_t) {
    assert_eq!(unsafe { im_rb_pop(rb) }, IM_OK);
}

#[test]
fn fifo_order_and_ack() {
    let mut f = NorFlash::new(64 * 1024, 4096);
    let mut rb = mount(&mut f, 256);
    assert!(peek(&mut rb).is_none());
    for i in 0..20u8 {
        push(&mut rb, &[i; 10]);
    }
    assert_eq!(unsafe { im_rb_count(&*rb) }, 20);
    for i in 0..20u8 {
        assert_eq!(peek(&mut rb).unwrap(), vec![i; 10]);
        pop(&mut rb);
    }
    assert!(peek(&mut rb).is_none());
    assert_eq!(err_name(unsafe { im_rb_pop(&mut *rb) }), "EMPTY");
}

#[test]
fn survives_reboot_and_continues_in_order() {
    let mut f = NorFlash::new(64 * 1024, 4096);
    {
        let mut rb = mount(&mut f, 256);
        for i in 0..10u8 {
            push(&mut rb, &[i; 33]);
        }
        pop(&mut rb);
        pop(&mut rb); // 0 and 1 delivered
    }
    let mut rb = mount(&mut f, 256); // "reboot"
    assert_eq!(unsafe { im_rb_count(&*rb) }, 8);
    push(&mut rb, &[100; 5]);
    let mut got = vec![];
    while let Some(v) = peek(&mut rb) {
        got.push(v[0]);
        pop(&mut rb);
    }
    assert_eq!(got, vec![2, 3, 4, 5, 6, 7, 8, 9, 100]);
}

#[test]
fn wrap_drops_oldest_sector() {
    // 4 sectors of 8 slots = 32 slots
    let mut f = NorFlash::new(4 * 4096, 4096);
    let mut rb = mount(&mut f, 512);
    for i in 0..40u32 {
        push(&mut rb, &i.to_be_bytes());
    }
    // the 33rd write erased sector 0 (the 8 oldest undelivered records)
    assert_eq!(rb.dropped, 8);
    assert_eq!(unsafe { im_rb_count(&*rb) }, 32);
    let first = peek(&mut rb).unwrap();
    assert_eq!(u32::from_be_bytes(first.try_into().unwrap()), 8);
    // remount keeps the same view
    let mut rb2 = mount(&mut f, 512);
    assert_eq!(unsafe { im_rb_count(&*rb2) }, 32);
    let mut last = 0;
    while let Some(v) = peek(&mut rb2) {
        let x = u32::from_be_bytes(v.try_into().unwrap());
        assert!(x >= last);
        last = x;
        pop(&mut rb2);
    }
    assert_eq!(last, 39);
}

#[test]
fn torn_write_is_skipped_after_reboot() {
    let mut f = NorFlash::new(16 * 1024, 4096);
    {
        let mut rb = mount(&mut f, 256);
        push(&mut rb, b"one");
        push(&mut rb, b"two");
        f.fail_after_writes = Some(f.writes + 1); // payload lands, header is torn
        let r = unsafe { im_rb_push(&mut *rb, b"three".as_ptr(), 5) };
        assert_eq!(err_name(r), "IO");
        f.fail_after_writes = None;
    }
    let mut rb = mount(&mut f, 256);
    assert_eq!(unsafe { im_rb_count(&*rb) }, 2);
    push(&mut rb, b"four");
    let mut got = vec![];
    while let Some(v) = peek(&mut rb) {
        got.push(String::from_utf8(v).unwrap());
        pop(&mut rb);
    }
    assert_eq!(got, vec!["one", "two", "four"]);
}

#[test]
fn corruption_detected_by_crc_and_limits() {
    let mut f = NorFlash::new(16 * 1024, 4096);
    {
        let mut rb = mount(&mut f, 256);
        push(&mut rb, b"payload-a");
        push(&mut rb, b"payload-b");
        assert_eq!(err_name(unsafe { im_rb_push(&mut *rb, [0u8; 241].as_ptr(), 241) }), "BUFFER");
    }
    f.data[16 + 3] &= 0x00; // flip bits inside the first payload
    let mut rb = mount(&mut f, 256);
    assert_eq!(unsafe { im_rb_count(&*rb) }, 1);
    assert_eq!(peek(&mut rb).unwrap(), b"payload-b");
    // invalid geometry
    let st = f.storage();
    let mut bad: im_ringbuf_t = unsafe { core::mem::zeroed() };
    assert_eq!(err_name(unsafe { im_rb_init(&mut bad, &st, 3000) }), "ARG");
    assert_eq!(err_name(unsafe { im_rb_init(&mut bad, &st, 32) }), "ARG");
    // CRC-32 check value
    assert_eq!(unsafe { im_crc32(0, b"123456789".as_ptr(), 9) }, 0xCBF4_3926);
}
