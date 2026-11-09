//! MQTT 5 framer + strict decoder on arbitrary bytes, and the client session fed the same bytes as
//! if they came from the broker (after a successful CONNACK).
#![no_main]
use core::ffi::c_void;
use im_host::ffi2::*;
use libfuzzer_sys::fuzz_target;

unsafe extern "C" fn send(_c: *mut c_void, _d: *const u8, _n: usize) -> i32 {
    0
}

fuzz_target!(|data: &[u8]| {
    unsafe {
        let mut flen = 0usize;
        if im_mqtt_frame(data.as_ptr(), data.len(), 1 << 20, &mut flen) == 0 {
            let mut p = im_mqtt_packet_t::default();
            if im_mqtt_decode(data.as_ptr(), flen, &mut p) == 0 && p.type_ == 3 {
                assert!(p.payload_len <= flen);
            }
        }
        let cb = im_mqtt_session_cb_t {
            send: Some(send),
            on_connack: None,
            on_publish: None,
            on_puback: None,
            on_suback: None,
            on_disconnect: None,
            ctx: core::ptr::null_mut(),
        };
        let mut s = im_host::Opaque::new(im_abi_size(2));
        im_mqtt_session_init(s.ptr(), &cb);
        let c = im_mqtt_connect_t {
            client_id: c"dev-0000000000000000".as_ptr(),
            keep_alive: 60,
            clean_start: false,
            session_expiry: 0,
            receive_maximum: 32,
            maximum_packet_size: 16384,
            username: core::ptr::null(),
            user: core::ptr::null(),
            n_user: 0,
        };
        im_mqtt_session_connect(s.ptr(), &c, 0);
        let ack = [0x20u8, 0x03, 0x00, 0x00, 0x00];
        im_mqtt_session_input(s.ptr(), ack.as_ptr(), ack.len(), 1);
        for chunk in data.chunks(97) {
            if im_mqtt_session_input(s.ptr(), chunk.as_ptr(), chunk.len(), 2) != 0 {
                break;
            }
        }
    }
});
