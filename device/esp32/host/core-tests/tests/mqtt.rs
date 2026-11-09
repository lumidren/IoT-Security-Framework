//! MQTT 5 codec and client session tests (C implementation).

use core::ffi::c_void;
use im_host::err::*;
use im_host::ffi2::*;
use im_host::{err_name, Opaque};
use std::ptr;

fn decode(b: &[u8]) -> Result<im_mqtt_packet_t, &'static str> {
    let mut p = im_mqtt_packet_t::default();
    let r = unsafe { im_mqtt_decode(b.as_ptr(), b.len(), &mut p) };
    if r == IM_OK {
        Ok(p)
    } else {
        Err(err_name(r))
    }
}

fn s(p: *const core::ffi::c_char, n: u16) -> String {
    String::from_utf8(unsafe { core::slice::from_raw_parts(p as *const u8, n as usize) }.to_vec()).unwrap()
}

fn connect_bytes() -> Vec<u8> {
    let cid = c"dev-8f3a1c2b9d4e5f60";
    let up = [im_mqtt_user_prop_t {
        key: c"traceparent".as_ptr(),
        key_len: 11,
        val: c"00-ab".as_ptr(),
        val_len: 5,
    }];
    let c = im_mqtt_connect_t {
        client_id: cid.as_ptr(),
        keep_alive: 60,
        clean_start: false,
        session_expiry: 7 * 24 * 3600,
        receive_maximum: 32,
        maximum_packet_size: 16384,
        username: ptr::null(),
        user: up.as_ptr(),
        n_user: 1,
    };
    let mut out = [0u8; 256];
    let mut n = 0;
    assert_eq!(unsafe { im_mqtt_enc_connect(&c, out.as_mut_ptr(), out.len(), &mut n) }, IM_OK);
    out[..n].to_vec()
}

#[test]
fn connect_roundtrip_contract_session_settings() {
    let b = connect_bytes();
    let p = decode(&b).unwrap();
    assert_eq!(p.type_, 1);
    assert_eq!(p.keep_alive, 60);
    assert!(!p.clean_start, "contract §4: clean_start=false");
    assert_eq!(s(p.client_id, p.client_id_len), "dev-8f3a1c2b9d4e5f60");
    assert!(p.props.has_session_expiry && p.props.session_expiry == 604800);
    assert!(p.props.has_receive_maximum && p.props.receive_maximum == 32);
    assert!(p.props.has_maximum_packet_size && p.props.maximum_packet_size == 16384);
    assert_eq!(p.props.n_user, 1);
    assert_eq!(s(p.props.user[0].key, p.props.user[0].key_len), "traceparent");
}

#[test]
fn publish_puback_subscribe_suback_roundtrip() {
    let topic = "im/v1/7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11/dev-8f3a1c2b9d4e5f60/telemetry";
    let mut out = [0u8; 512];
    let mut n = 0;
    let r = unsafe {
        im_mqtt_enc_publish(
            topic.as_ptr().cast(),
            topic.len(),
            1,
            false,
            false,
            7,
            ptr::null(),
            0,
            b"hello".as_ptr(),
            5,
            out.as_mut_ptr(),
            out.len(),
            &mut n,
        )
    };
    assert_eq!(r, IM_OK);
    let p = decode(&out[..n]).unwrap();
    assert_eq!((p.type_, p.qos, p.packet_id, p.retain), (3, 1, 7, false));
    assert_eq!(s(p.topic, p.topic_len), topic);
    assert_eq!(unsafe { core::slice::from_raw_parts(p.payload, p.payload_len) }, b"hello");
    // large payload needs a multi-byte remaining length
    let big = vec![0xAAu8; 300];
    let mut out2 = vec![0u8; 1024];
    let r = unsafe {
        im_mqtt_enc_publish(
            topic.as_ptr().cast(),
            topic.len(),
            0,
            true,
            false,
            0,
            ptr::null(),
            0,
            big.as_ptr(),
            big.len(),
            out2.as_mut_ptr(),
            out2.len(),
            &mut n,
        )
    };
    assert_eq!(r, IM_OK);
    let p = decode(&out2[..n]).unwrap();
    assert_eq!((p.qos, p.retain, p.payload_len), (0, true, 300));

    assert_eq!(unsafe { im_mqtt_enc_puback(7, 0x87, out.as_mut_ptr(), out.len(), &mut n) }, IM_OK);
    let p = decode(&out[..n]).unwrap();
    assert_eq!((p.type_, p.packet_id, p.reason_code), (4, 7, 0x87));
    assert_eq!(unsafe { im_mqtt_enc_puback(9, 0, out.as_mut_ptr(), out.len(), &mut n) }, IM_OK);
    assert_eq!(&out[..n], &[0x40, 0x02, 0x00, 0x09]);

    let f = "im/v1/7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11/dev-8f3a1c2b9d4e5f60/cmd/req";
    assert_eq!(
        unsafe { im_mqtt_enc_subscribe(3, f.as_ptr().cast(), f.len(), 1, out.as_mut_ptr(), out.len(), &mut n) },
        IM_OK
    );
    let p = decode(&out[..n]).unwrap();
    assert_eq!((p.type_, p.flags, p.packet_id, p.n_reason_codes), (8, 2, 3, 1));
    assert_eq!(s(p.filter, p.filter_len), f);
    let codes = [0x87u8];
    assert_eq!(
        unsafe { im_mqtt_enc_suback(3, codes.as_ptr(), 1, out.as_mut_ptr(), out.len(), &mut n) },
        IM_OK
    );
    let p = decode(&out[..n]).unwrap();
    assert_eq!((p.type_, p.packet_id, unsafe { *p.reason_codes }), (9, 3, 0x87));

    assert_eq!(
        unsafe { im_mqtt_enc_connack(true, 0, 32, out.as_mut_ptr(), out.len(), &mut n) },
        IM_OK
    );
    let p = decode(&out[..n]).unwrap();
    assert!(p.session_present && p.props.receive_maximum == 32);
    assert_eq!(unsafe { im_mqtt_enc_disconnect(0x8E, out.as_mut_ptr(), out.len(), &mut n) }, IM_OK);
    assert_eq!(decode(&out[..n]).unwrap().reason_code, 0x8E);
    assert_eq!(decode(&[0xC0, 0x00]).unwrap().type_, 12);
    assert_eq!(decode(&[0xD0, 0x00]).unwrap().type_, 13);
    assert_eq!(decode(&[0xE0, 0x00]).unwrap().reason_code, 0);
}

#[test]
fn strict_decoder_rejections() {
    let cases: &[(&str, &[u8], &str)] = &[
        ("empty", &[], "MQTT_MALFORMED"),
        ("non-minimal remaining length", &[0xC0, 0x80, 0x00], "MQTT_MALFORMED"),
        ("5-byte remaining length", &[0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F], "MQTT_MALFORMED"),
        ("truncated", &[0x30, 0x05, 0x00], "MQTT_MALFORMED"),
        ("trailing bytes in pingresp", &[0xD0, 0x01, 0x00], "MQTT_MALFORMED"),
        ("pingresp flags", &[0xD1, 0x00], "MQTT_MALFORMED"),
        ("publish qos 3", &[0x36, 0x05, 0x00, 0x01, b'a', 0x00, 0x01], "MQTT_MALFORMED"),
        ("publish qos0 dup", &[0x38, 0x04, 0x00, 0x01, b'a', 0x00], "MQTT_MALFORMED"),
        ("publish wildcard topic", &[0x30, 0x04, 0x00, 0x01, b'#', 0x00], "MQTT_PROTOCOL"),
        (
            "publish packet id 0",
            &[0x32, 0x06, 0x00, 0x01, b'a', 0x00, 0x00, 0x00],
            "MQTT_PROTOCOL",
        ),
        ("publish NUL in topic", &[0x30, 0x04, 0x00, 0x01, 0x00, 0x00], "MQTT_MALFORMED"),
        (
            "publish invalid utf-8 topic",
            &[0x30, 0x05, 0x00, 0x02, 0xC3, 0x28, 0x00],
            "MQTT_MALFORMED",
        ),
        (
            "publish empty topic without alias",
            &[0x30, 0x03, 0x00, 0x00, 0x00],
            "MQTT_PROTOCOL",
        ),
        (
            "publish duplicate payload format",
            &[0x30, 0x08, 0x00, 0x01, b'a', 0x04, 0x01, 0x00, 0x01, 0x00],
            "MQTT_PROTOCOL",
        ),
        (
            "publish property not allowed (session expiry)",
            &[0x30, 0x09, 0x00, 0x01, b'a', 0x05, 0x11, 0, 0, 0, 1],
            "MQTT_MALFORMED",
        ),
        (
            "publish unknown property",
            &[0x30, 0x06, 0x00, 0x01, b'a', 0x02, 0x7F, 0x00],
            "MQTT_MALFORMED",
        ),
        (
            "publish property length past end",
            &[0x30, 0x05, 0x00, 0x01, b'a', 0x09, 0x01],
            "MQTT_MALFORMED",
        ),
        ("connack reserved flag", &[0x20, 0x03, 0x02, 0x00, 0x00], "MQTT_MALFORMED"),
        ("connack bad reason", &[0x20, 0x03, 0x00, 0x05, 0x00], "MQTT_MALFORMED"),
        (
            "connack error with session present",
            &[0x20, 0x03, 0x01, 0x87, 0x00],
            "MQTT_PROTOCOL",
        ),
        (
            "connack receive maximum 0",
            &[0x20, 0x06, 0x00, 0x00, 0x03, 0x21, 0x00, 0x00],
            "MQTT_PROTOCOL",
        ),
        ("puback id 0", &[0x40, 0x02, 0x00, 0x00], "MQTT_PROTOCOL"),
        ("puback bad reason", &[0x40, 0x03, 0x00, 0x01, 0x05], "MQTT_MALFORMED"),
        (
            "subscribe flags 0",
            &[0x80, 0x08, 0x00, 0x01, 0x00, 0x00, 0x01, b'a', 0x01, 0x00],
            "MQTT_MALFORMED",
        ),
        ("subscribe no filter", &[0x82, 0x03, 0x00, 0x01, 0x00], "MQTT_PROTOCOL"),
        (
            "subscribe reserved option bits",
            &[0x82, 0x07, 0x00, 0x01, 0x00, 0x00, 0x01, b'a', 0xC0],
            "MQTT_MALFORMED",
        ),
        ("suback invalid code", &[0x90, 0x04, 0x00, 0x01, 0x00, 0x05], "MQTT_MALFORMED"),
        ("type 0", &[0x00, 0x00], "MQTT_MALFORMED"),
        ("pubrec unsupported", &[0x50, 0x02, 0x00, 0x01], "MQTT_PROTOCOL"),
        ("disconnect bad reason", &[0xE0, 0x01, 0x05], "MQTT_MALFORMED"),
    ];
    for (name, bytes, want) in cases {
        assert_eq!(decode(bytes).err(), Some(*want), "{name}");
    }
    // CONNECT with the wrong protocol level / reserved flag
    let mut b = connect_bytes();
    b[8] = 4;
    assert_eq!(decode(&b).err(), Some("MQTT_PROTOCOL"));
    let mut b = connect_bytes();
    b[9] |= 1;
    assert_eq!(decode(&b).err(), Some("MQTT_MALFORMED"));
}

#[test]
fn frame_detection() {
    let mut n = 0usize;
    assert_eq!(
        err_name(unsafe { im_mqtt_frame([0x30u8].as_ptr(), 1, 1 << 20, &mut n) }),
        "MQTT_INCOMPLETE"
    );
    assert_eq!(
        err_name(unsafe { im_mqtt_frame([0x30u8, 0x80].as_ptr(), 2, 1 << 20, &mut n) }),
        "MQTT_INCOMPLETE"
    );
    assert_eq!(
        err_name(unsafe { im_mqtt_frame([0x30u8, 0x05, 0, 0].as_ptr(), 4, 1 << 20, &mut n) }),
        "MQTT_INCOMPLETE"
    );
    assert_eq!(unsafe { im_mqtt_frame([0xC0u8, 0x00, 0xD0].as_ptr(), 3, 1 << 20, &mut n) }, IM_OK);
    assert_eq!(n, 2);
    let big = [0x30u8, 0xFF, 0x7F];
    assert_eq!(err_name(unsafe { im_mqtt_frame(big.as_ptr(), 3, 1024, &mut n) }), "MQTT_PROTOCOL");
}

// ---- session -----------------------------------------------------------------------------------

#[derive(Default)]
struct Wire {
    sent: Vec<Vec<u8>>,
    connacks: Vec<(bool, u8)>,
    publishes: Vec<(String, Vec<u8>)>,
    pubacks: Vec<(u16, u8)>,
    subacks: Vec<(u16, u8)>,
    disconnects: Vec<(u8, bool)>,
}

unsafe extern "C" fn w_send(ctx: *mut c_void, d: *const u8, n: usize) -> i32 {
    (*(ctx as *mut Wire)).sent.push(core::slice::from_raw_parts(d, n).to_vec());
    IM_OK
}
unsafe extern "C" fn w_connack(ctx: *mut c_void, sp: bool, r: u8) {
    (*(ctx as *mut Wire)).connacks.push((sp, r));
}
unsafe extern "C" fn w_publish(ctx: *mut c_void, p: *const im_mqtt_packet_t) {
    let p = &*p;
    (*(ctx as *mut Wire)).publishes.push((
        s(p.topic, p.topic_len),
        core::slice::from_raw_parts(p.payload, p.payload_len).to_vec(),
    ));
}
unsafe extern "C" fn w_puback(ctx: *mut c_void, id: u16, r: u8) {
    (*(ctx as *mut Wire)).pubacks.push((id, r));
}
unsafe extern "C" fn w_suback(ctx: *mut c_void, id: u16, r: u8) {
    (*(ctx as *mut Wire)).subacks.push((id, r));
}
unsafe extern "C" fn w_disc(ctx: *mut c_void, r: u8, peer: bool) {
    (*(ctx as *mut Wire)).disconnects.push((r, peer));
}

fn session() -> (Opaque, Box<Wire>) {
    let mut wire = Box::<Wire>::default();
    let cb = im_mqtt_session_cb_t {
        send: Some(w_send),
        on_connack: Some(w_connack),
        on_publish: Some(w_publish),
        on_puback: Some(w_puback),
        on_suback: Some(w_suback),
        on_disconnect: Some(w_disc),
        ctx: (&mut *wire as *mut Wire).cast(),
    };
    let mut s = Opaque::new(unsafe { im_abi_size(2) });
    unsafe { im_mqtt_session_init(s.ptr(), &cb) };
    (s, wire)
}

#[test]
fn session_flow_qos1_keepalive_and_protocol_errors() {
    let (mut s, wire) = session();
    let cid = c"dev-8f3a1c2b9d4e5f60";
    let c = im_mqtt_connect_t {
        client_id: cid.as_ptr(),
        keep_alive: 60,
        clean_start: false,
        session_expiry: 604800,
        receive_maximum: 32,
        maximum_packet_size: 16384,
        username: ptr::null(),
        user: ptr::null(),
        n_user: 0,
    };
    assert_eq!(unsafe { im_mqtt_session_connect(s.ptr(), &c, 0) }, IM_OK);
    assert_eq!(wire.sent.len(), 1);
    // publishing before CONNACK is refused
    let mut pid = 0u16;
    let topic = c"im/v1/7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11/dev-8f3a1c2b9d4e5f60/telemetry";
    assert_eq!(
        err_name(unsafe { im_mqtt_session_publish(s.ptr(), topic.as_ptr(), b"x".as_ptr(), 1, 1, false, ptr::null(), 0, &mut pid, 0) }),
        "STATE"
    );
    // CONNACK split across two reads with receive maximum 2
    let connack = [0x20u8, 0x06, 0x01, 0x00, 0x03, 0x21, 0x00, 0x02];
    assert_eq!(unsafe { im_mqtt_session_input(s.ptr(), connack.as_ptr(), 3, 10) }, IM_OK);
    assert!(wire.connacks.is_empty());
    assert_eq!(unsafe { im_mqtt_session_input(s.ptr(), connack[3..].as_ptr(), 5, 10) }, IM_OK);
    assert_eq!(wire.connacks, vec![(true, 0)]);
    // QoS1 publishes respect the broker's receive maximum
    let mut ids = vec![];
    for _ in 0..2 {
        assert_eq!(
            unsafe { im_mqtt_session_publish(s.ptr(), topic.as_ptr(), b"x".as_ptr(), 1, 1, false, ptr::null(), 0, &mut pid, 20) },
            IM_OK
        );
        ids.push(pid);
    }
    assert_eq!(
        err_name(unsafe { im_mqtt_session_publish(s.ptr(), topic.as_ptr(), b"x".as_ptr(), 1, 1, false, ptr::null(), 0, &mut pid, 20) }),
        "BUSY"
    );
    let ack = [0x40u8, 0x02, 0x00, ids[0] as u8];
    assert_eq!(unsafe { im_mqtt_session_input(s.ptr(), ack.as_ptr(), ack.len(), 30) }, IM_OK);
    assert_eq!(wire.pubacks, vec![(ids[0], 0)]);
    assert_eq!(unsafe { im_mqtt_session_inflight(s.ptr()) }, 1);
    // inbound QoS1 publish is delivered and acknowledged
    let mut buf = [0u8; 256];
    let mut n = 0;
    let t2 = "im/v1/7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11/dev-8f3a1c2b9d4e5f60/cmd/req";
    unsafe {
        im_mqtt_enc_publish(
            t2.as_ptr().cast(),
            t2.len(),
            1,
            false,
            false,
            99,
            ptr::null(),
            0,
            b"cmd".as_ptr(),
            3,
            buf.as_mut_ptr(),
            buf.len(),
            &mut n,
        )
    };
    let before = wire.sent.len();
    assert_eq!(unsafe { im_mqtt_session_input(s.ptr(), buf.as_ptr(), n, 40) }, IM_OK);
    assert_eq!(wire.publishes, vec![(t2.to_string(), b"cmd".to_vec())]);
    assert_eq!(wire.sent[before], vec![0x40, 0x02, 0x00, 99]);
    // keep-alive: PINGREQ after 60 s idle, timeout after 1.5x without PINGRESP
    assert_eq!(unsafe { im_mqtt_session_tick(s.ptr(), 40 + 60_000) }, IM_OK);
    assert_eq!(wire.sent.last().unwrap(), &vec![0xC0, 0x00]);
    assert_eq!(unsafe { im_mqtt_session_input(s.ptr(), [0xD0u8, 0x00].as_ptr(), 2, 60_100) }, IM_OK);
    assert_eq!(unsafe { im_mqtt_session_tick(s.ptr(), 200_000) }, IM_OK);
    assert_eq!(err_name(unsafe { im_mqtt_session_tick(s.ptr(), 400_000) }), "TIMEOUT");
    assert_eq!(wire.disconnects.last(), Some(&(0x8D, false)));
}

#[test]
fn session_rejects_server_sending_client_packets() {
    let (mut s, wire) = session();
    let cid = c"dev-8f3a1c2b9d4e5f60";
    let c = im_mqtt_connect_t {
        client_id: cid.as_ptr(),
        keep_alive: 0,
        clean_start: true,
        session_expiry: 0,
        receive_maximum: 0,
        maximum_packet_size: 0,
        username: ptr::null(),
        user: ptr::null(),
        n_user: 0,
    };
    unsafe { im_mqtt_session_connect(s.ptr(), &c, 0) };
    unsafe { im_mqtt_session_input(s.ptr(), [0x20u8, 0x03, 0x00, 0x00, 0x00].as_ptr(), 5, 1) };
    let r = unsafe { im_mqtt_session_input(s.ptr(), [0xC0u8, 0x00].as_ptr(), 2, 2) };
    assert_eq!(err_name(r), "MQTT_PROTOCOL");
    assert_eq!(wire.sent.last().unwrap(), &vec![0xE0, 0x01, 0x82], "DISCONNECT protocol error sent");
    // a refused CONNACK leaves the session disconnected
    let (mut s2, w2) = session();
    unsafe { im_mqtt_session_connect(s2.ptr(), &c, 0) };
    unsafe { im_mqtt_session_input(s2.ptr(), [0x20u8, 0x03, 0x00, 0x87, 0x00].as_ptr(), 5, 1) };
    assert_eq!(w2.connacks, vec![(false, 0x87)]);
    let mut pid = 0;
    assert_eq!(
        err_name(unsafe { im_mqtt_session_publish(s2.ptr(), c"im/x".as_ptr(), ptr::null(), 0, 0, false, ptr::null(), 0, &mut pid, 2) }),
        "STATE"
    );
}
