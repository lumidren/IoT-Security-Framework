//! The DUT_PROTOCOL.md conformance cases that can run without a network, against the shim's
//! simulated cloud. Every decision below is made by the C core; the cloud side (broker ACLs,
//! EST, tenant/firmware signatures) is simulated in Rust.

use im_host::ffi::*;
use im_host::testkit::{self, ManifestSpec};
use im_shim::{Device, DeviceConfig};
use serde_json::{json, Value};
use std::ffi::CString;

struct T {
    dev: Device,
    id: u64,
    events: Vec<Value>,
}

impl T {
    fn new() -> Self {
        Self::with(DeviceConfig::sim())
    }

    fn with(cfg: DeviceConfig) -> Self {
        let mut t = T {
            dev: Device::new(cfg).unwrap(),
            id: 0,
            events: vec![],
        };
        t.collect();
        t
    }

    fn collect(&mut self) {
        for e in self.dev.take_events() {
            self.events
                .push(serde_json::from_str(&e).unwrap_or_else(|_| panic!("event is JSON: {e}")));
        }
    }

    fn req(&mut self, op: &str, args: Value) -> Value {
        self.id += 1;
        let line = json!({"id": self.id, "op": op, "args": args}).to_string();
        let r: Value = serde_json::from_str(&self.dev.handle_line(&line)).unwrap();
        assert_eq!(r["id"], self.id);
        self.collect();
        r
    }

    fn ok(&mut self, op: &str, args: Value) -> Value {
        let r = self.req(op, args);
        assert_eq!(r["ok"], true, "{op}: {r}");
        r["result"].clone()
    }

    fn take(&mut self, name: &str) -> Vec<Value> {
        self.collect();
        let (hit, rest): (Vec<Value>, Vec<Value>) = std::mem::take(&mut self.events).into_iter().partition(|e| e["event"] == name);
        self.events = rest;
        hit.into_iter().map(|e| e["data"].clone()).collect()
    }

    fn online(&mut self) {
        self.ok("enroll", json!({}));
        assert_eq!(self.take("enrolled").len(), 1);
        self.ok("connect", json!({}));
        assert_eq!(self.take("connected").len(), 1);
    }

    fn topic(&self, suffix: &str) -> String {
        format!("im/v1/{}/{}/{}", self.dev.tenant_id(), self.dev.device_id(), suffix)
    }

    /// Tenant-signed downlink message from the simulated cloud.
    fn downlink(
        &mut self,
        ty: u8,
        nonce: Option<[u8; 16]>,
        seq: Option<u64>,
        ts: Option<u64>,
        body: impl FnOnce(*mut im_cbor_enc_t),
    ) -> Vec<u8> {
        let tenant = self.dev.tenant_id();
        let now = self.dev.now();
        let seq = seq.unwrap_or_else(|| self.dev.sim().next_seq());
        let sim = self.dev.sim();
        testkit::tenant_envelope(&sim.pki.keys.tenant, &tenant, seq, ts.unwrap_or(now), ty, nonce.as_ref(), body)
    }

    fn command(&mut self, name: &str, idem: &str, seq: Option<u64>, ts: Option<u64>) -> Vec<u8> {
        let expires = self.dev.now() + 600;
        let (cmd_id, n, k) = (
            CString::new("123e4567-e89b-12d3-a456-426614174000").unwrap(),
            CString::new(name).unwrap(),
            CString::new(idem).unwrap(),
        );
        self.downlink(5, Some([7u8; 16]), seq, ts, |e| unsafe {
            im_body_command(e, cmd_id.as_ptr(), n.as_ptr(), std::ptr::null(), 0, k.as_ptr(), expires)
        })
    }

    fn published(&mut self, suffix: &str) -> Vec<Vec<u8>> {
        let t = self.topic(suffix);
        self.dev
            .sim()
            .broker
            .log
            .iter()
            .filter(|p| p.topic == t)
            .map(|p| p.payload.clone())
            .collect()
    }
}

/// Decode an uplink envelope with the device's current key (cloud-side verification in C).
fn uplink_seq(dev: &Device, wire: &[u8]) -> (u64, u8) {
    let mut s: im_sign1_t = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe { im_cose_sign1_decode(wire.as_ptr(), wire.len(), std::ptr::null(), &mut s) },
        0
    );
    let mut k = im_pubkey_t::default();
    let pk = dev.identity_public();
    unsafe { im_pubkey_p256(&mut k, pk.as_ptr(), 65) };
    assert_eq!(
        unsafe { im_cose_sign1_verify(&s, &k, std::ptr::null_mut(), 0) },
        0,
        "uplink signature verifies with the device key"
    );
    let mut m = im_env_msg_t::default();
    assert_eq!(
        unsafe { im_env_decode_payload(s.payload, s.payload_len, std::ptr::null(), &mut m) },
        0
    );
    (m.seq, m.type_)
}

#[test]
fn hello_and_status_shapes() {
    let mut t = T::new();
    let h = t.ok("hello", json!({}));
    assert_eq!(h["target"], "esp32-host");
    assert_eq!(h["protocol_version"], 1);
    assert_eq!(h["se_type"], "software");
    let s = t.ok("status", json!({}));
    for k in [
        "state",
        "cert_serial_hex",
        "cert_not_after",
        "seq_out",
        "buffered",
        "active_slot",
        "pending_slot",
        "version_code",
        "connected_broker",
    ] {
        assert!(s.get(k).is_some(), "status.{k}");
    }
    assert_eq!(s["state"], "unprovisioned");
    assert_eq!(t.req("connect", json!({}))["error"]["code"], "not_provisioned");
    assert_eq!(t.req("send_telemetry", json!({"count": 0}))["error"]["code"], "invalid_args");
    assert_eq!(t.req("frobnicate", json!({}))["error"]["code"], "unsupported");
}

#[test]
fn c_enr_1_and_c_enr_2_enrollment() {
    let mut t = T::new();
    let before = t.dev.identity_public();
    t.ok("enroll", json!({}));
    let e = t.take("enrolled");
    assert_eq!(e.len(), 1, "attestation verified by the (simulated) EST server");
    assert_eq!(e[0]["se_type"], "software");
    assert_ne!(t.dev.identity_public(), before, "a fresh key was generated for the CSR");
    let s = t.ok("status", json!({}));
    assert_eq!(s["cert_serial_hex"], e[0]["cert_serial_hex"]);

    let mut q = T::new();
    q.dev.sim().pki.quarantined = true;
    q.ok("enroll", json!({}));
    let f = q.take("enroll_failed");
    assert_eq!(f[0]["http_status"], 403);
}

#[test]
fn c_rot_1_and_c_rot_2_rotation() {
    let mut t = T::new();
    t.online();
    let old_key = t.dev.identity_public();
    let old_serial = t.ok("status", json!({}))["cert_serial_hex"].clone();
    t.ok("renew", json!({}));
    let r = t.take("cert_renewed");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0]["old_serial_hex"], old_serial);
    assert_ne!(r[0]["new_serial_hex"], old_serial);
    assert_ne!(t.dev.identity_public(), old_key, "new SPKI");
    t.ok("disconnect", json!({}));
    t.ok("connect", json!({}));
    assert_eq!(t.take("connected").len(), 1, "reconnect with the rotated identity");
    let r = t.ok("send_telemetry", json!({"count": 1}));
    let wire = t.published("telemetry").pop().unwrap();
    assert_eq!(uplink_seq(&t.dev, &wire).0, r["last_seq"].as_u64().unwrap());

    // automatic renewal at 50 % (+ <= 10 % jitter) of a short lifetime
    let mut a = T::new();
    a.dev.sim().pki.cert_ttl = 1000;
    a.online();
    a.dev.advance(400_000);
    assert!(a.take("cert_renewed").is_empty());
    a.dev.advance(220_000);
    assert_eq!(a.take("cert_renewed").len(), 1, "renewed between 50 % and 60 % of the lifetime");
}

#[test]
fn c_acl_publish_subscribe_retain() {
    let mut t = T::new();
    t.online();
    let other = format!("im/v1/{}/dev-0000000000000001/telemetry", t.dev.tenant_id());
    t.ok(
        "publish_raw",
        json!({"topic": other, "payload_b64": "aGk=", "qos": 1, "retain": false}),
    );
    let r = t.take("publish_result");
    assert_eq!(r[0]["ok"], false);
    assert_eq!(r[0]["reason_code"], 0x87);
    assert!(
        t.dev.sim().broker.log.iter().all(|p| p.topic != other),
        "subscriber receives nothing"
    );

    for f in [
        format!("im/v1/{}/dev-0000000000000001/cmd/req", t.dev.tenant_id()),
        format!("im/v1/{}/#", t.dev.tenant_id()),
        t.topic("telemetry"),
    ] {
        t.ok("subscribe_raw", json!({"topic": f}));
        let s = t.take("subscribe_result");
        assert_eq!(s[0]["granted"], false, "{f}");
    }
    let own = t.topic("telemetry");
    t.ok(
        "publish_raw",
        json!({"topic": own, "payload_b64": "aGk=", "qos": 1, "retain": true}),
    );
    assert_eq!(t.take("publish_result")[0]["ok"], false, "C-ACL-3 retained telemetry rejected");
    t.ok(
        "publish_raw",
        json!({"topic": own, "payload_b64": "aGk=", "qos": 1, "retain": false}),
    );
    assert_eq!(t.take("publish_result")[0]["ok"], true);
}

#[test]
fn c_rpl_replay_skew_signature_and_seq_across_reboot() {
    let mut t = T::new();
    t.online();
    let cmd = t.command("blink", "idem-1", Some(500), None);
    t.dev.inject("cmd/req", &cmd, false);
    assert_eq!(t.take("command_executed").len(), 1);
    assert_eq!(t.published("cmd/ack").len(), 1);
    // C-RPL-1 exact replay
    t.dev.inject("cmd/req", &cmd, false);
    let rej = t.take("message_rejected");
    assert_eq!(rej[0]["code"], "ENV_REPLAY");
    assert!(t.take("command_executed").is_empty(), "not executed twice");
    assert_eq!(t.dev.state().executed_commands.len(), 1);
    // same idempotency key, fresh seq: acknowledged again but not re-executed
    let again = t.command("blink", "idem-1", Some(501), None);
    t.dev.inject("cmd/req", &again, false);
    assert_eq!(t.dev.state().executed_commands.len(), 1);
    assert_eq!(t.published("cmd/ack").len(), 2);
    // C-RPL-2 stale timestamp
    let now = t.dev.now();
    let stale = t.command("blink", "idem-2", Some(600), Some(now - 301));
    t.dev.inject("cmd/req", &stale, false);
    assert_eq!(t.take("message_rejected")[0]["code"], "ENV_TS_SKEW");
    // C-RPL-3 signed by a non-tenant key
    let tenant = t.dev.tenant_id();
    let rogue = im_host::EdSigner::from_seed(&[0x66; 32]);
    let (cid, n, k) = (
        CString::new("123e4567-e89b-12d3-a456-426614174000").unwrap(),
        CString::new("blink").unwrap(),
        CString::new("idem-3").unwrap(),
    );
    let exp = now + 600;
    let forged = testkit::tenant_envelope(&rogue, &tenant, 700, now, 5, Some(&[1u8; 16]), |e| unsafe {
        im_body_command(e, cid.as_ptr(), n.as_ptr(), std::ptr::null(), 0, k.as_ptr(), exp)
    });
    t.dev.inject("cmd/req", &forged, false);
    assert_eq!(t.take("message_rejected")[0]["code"], "COSE_SIGNATURE");
    let items = t.ok("rejections", json!({}))["items"].as_array().unwrap().clone();
    let codes: Vec<&str> = items.iter().map(|i| i["code"].as_str().unwrap()).collect();
    assert_eq!(codes, ["ENV_REPLAY", "ENV_TS_SKEW", "COSE_SIGNATURE"]);
    // wrong topic for the type, and a message on another device's topic
    let shadow = t.downlink(4, None, None, None, |e| unsafe { im_body_shadow(e, std::ptr::null(), 0, 3) });
    t.dev.inject("cmd/req", &shadow, false);
    assert_eq!(t.take("message_rejected")[0]["code"], "ENV_TYPE");
    // C-RPL-4: seq strictly increases across reboot
    t.ok("send_telemetry", json!({"count": 2}));
    let before = t.ok("status", json!({}))["seq_out"].as_u64().unwrap();
    t.ok("reboot", json!({}));
    let rb = t.take("rebooted");
    assert_eq!(rb[0]["reason"], "requested");
    let after = t.ok("status", json!({}))["seq_out"].as_u64().unwrap();
    assert!(after > before, "{after} > {before}");
    // the downlink replay window also survived the reboot
    t.dev.inject("cmd/req", &again, false);
    assert_eq!(t.take("message_rejected")[0]["code"], "ENV_REPLAY");
}

#[test]
fn c_off_1_offline_buffering_and_ordered_resync() {
    let mut t = T::new();
    t.online();
    t.ok("send_telemetry", json!({"count": 2}));
    t.ok("net_down", json!({}));
    assert_eq!(t.take("disconnected").len(), 1);
    let r = t.ok("send_telemetry", json!({"count": 25}));
    let (first, last) = (r["first_seq"].as_u64().unwrap(), r["last_seq"].as_u64().unwrap());
    assert_eq!(t.ok("status", json!({}))["buffered"], 25);
    t.ok("net_up", json!({}));
    t.dev.poll();
    t.collect();
    assert_eq!(t.take("connected").len(), 1);
    let f = t.take("buffer_flushed");
    assert_eq!(f.len(), 1);
    assert_eq!(f[0]["count"], 25);
    assert_eq!(f[0]["first_seq"].as_u64(), Some(first));
    assert_eq!(f[0]["last_seq"].as_u64(), Some(last));
    let seqs: Vec<u64> = t.published("telemetry").iter().map(|w| uplink_seq(&t.dev, w).0).collect();
    assert_eq!(seqs.len(), 27);
    assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1), "in order, no gaps: {seqs:?}");
    assert_eq!(t.ok("status", json!({}))["buffered"], 0);
}

fn campaign(t: &mut T, image: &[u8], vc: u64, signer_seed: Option<[u8; 32]>, delta: Option<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    let cfg_product = "sensor-esp32";
    let url = format!("https://ota.example/fw-{vc}.bin");
    let manifest = {
        let sim = t.dev.sim();
        let own;
        let signer = match signer_seed {
            Some(s) => {
                own = im_host::EdSigner::from_seed(&s);
                &own
            }
            None => &sim.pki.keys.firmware,
        };
        let d = delta.as_ref().map(|(base, patch)| (testkit::sha256(base), patch.as_slice()));
        testkit::signed_manifest(
            &ManifestSpec {
                product: cfg_product,
                version: "1.1.0",
                version_code: vc,
                min_version_code: 0,
                image,
                delta: d,
            },
            signer,
        )
    };
    let artifact = delta.as_ref().map(|(_, p)| p.clone()).unwrap_or_else(|| image.to_vec());
    t.dev.sim().artifacts.insert(url.clone(), artifact);
    let base_hash = delta.as_ref().map(|(b, _)| testkit::sha256(b));
    let (camp, u) = (
        CString::new("5f0c6a3e-2b1d-4c8e-9a7f-1e2d3c4b5a69").unwrap(),
        CString::new(url).unwrap(),
    );
    t.downlink(7, None, None, None, |e| unsafe {
        im_body_ota_notify(
            e,
            camp.as_ptr(),
            manifest.as_ptr(),
            manifest.len(),
            u.as_ptr(),
            base_hash.as_ref().map_or(std::ptr::null(), |h| h.as_ptr()),
        )
    })
}

fn ota_states(t: &mut T) -> Vec<(String, Value)> {
    t.take("ota_state")
        .into_iter()
        .map(|d| (d["state"].as_str().unwrap().to_string(), d["error"].clone()))
        .collect()
}

#[test]
fn c_ota_1_to_4_rejections_keep_the_active_slot() {
    let mut t = T::new();
    t.online();
    let mut img = DeviceConfig::sim().firmware;
    img[10] ^= 1;
    // C-OTA-1 unsigned: the OtaNotify carries the bare manifest map
    let signed = campaign(&mut t, &img, 10001, None, None);
    let _ = signed;
    let (camp, u) = (
        CString::new("5f0c6a3e-2b1d-4c8e-9a7f-1e2d3c4b5a69").unwrap(),
        CString::new("https://ota.example/x").unwrap(),
    );
    let bare = [0xa1u8, 0x01, 0x61, b'x'];
    let unsigned = t.downlink(7, None, None, None, |e| unsafe {
        im_body_ota_notify(e, camp.as_ptr(), bare.as_ptr(), bare.len(), u.as_ptr(), std::ptr::null())
    });
    t.dev.inject("ota/notify", &unsigned, false);
    assert_eq!(ota_states(&mut t).last().unwrap().0, "rejected");
    // C-OTA-2 tampered image (valid manifest)
    let notify = campaign(&mut t, &img, 10001, None, None);
    let url = "https://ota.example/fw-10001.bin".to_string();
    t.dev.sim().artifacts.get_mut(&url).unwrap()[100] ^= 0xFF;
    t.dev.inject("ota/notify", &notify, false);
    let st = ota_states(&mut t);
    assert_eq!(st.last().unwrap(), &("rejected".to_string(), json!("image_hash")));
    // C-OTA-3 untrusted signing key
    let n3 = campaign(&mut t, &img, 10002, Some([0x44; 32]), None);
    t.dev.inject("ota/notify", &n3, false);
    assert_eq!(
        ota_states(&mut t).last().unwrap(),
        &("rejected".to_string(), json!("untrusted_key"))
    );
    // C-OTA-4 downgrade
    let n4 = campaign(&mut t, &img, 10000, None, None);
    t.dev.inject("ota/notify", &n4, false);
    assert_eq!(ota_states(&mut t).last().unwrap(), &("rejected".to_string(), json!("downgrade")));
    let slots = t.ok("ota_slots", json!({}));
    assert_eq!(slots["active_slot"], "ota_0");
    assert_eq!(slots["pending_slot"], Value::Null);
    assert!(t.take("rebooted").is_empty());
    // OtaStatus messages were published for the cloud
    assert!(t.published("ota/status").len() >= 4);
}

#[test]
fn c_ota_5_valid_update_and_c_ota_7_delta() {
    let mut t = T::new();
    t.online();
    let base = DeviceConfig::sim().firmware;
    let mut img = base.clone();
    img[5000] ^= 0x5A;
    img.extend_from_slice(&[0xEE; 5000]);
    let n = campaign(&mut t, &img, 10100, None, None);
    t.dev.inject("ota/notify", &n, false);
    let st: Vec<String> = ota_states(&mut t).into_iter().map(|s| s.0).collect();
    assert!(
        st.ends_with(&["verifying".into(), "applying".into(), "rebooting".into(), "success".into()]),
        "{st:?}"
    );
    let rb = t.take("rebooted");
    assert_eq!(rb[0]["reason"], "ota_apply");
    assert_eq!(rb[0]["version_code"], 10100);
    assert_eq!(rb[0]["active_slot"], "ota_1");
    assert_eq!(t.ok("status", json!({}))["version_code"], 10100);
    let slots = t.ok("ota_slots", json!({}));
    assert_eq!(slots["slots"][1]["state"], "valid", "marked healthy after telemetry was acked");
    assert_eq!(slots["slots"][1]["sha256_hex"], hex(&testkit::sha256(&img)));

    // C-OTA-7: delta from the now-running image
    let mut img2 = img.clone();
    img2[100] ^= 1;
    let patch = testkit::make_delta(&img, &img2);
    assert!(patch.len() < img2.len() / 4);
    let n = campaign(&mut t, &img2, 10200, None, Some((img.clone(), patch)));
    t.dev.inject("ota/notify", &n, false);
    assert_eq!(ota_states(&mut t).last().unwrap().0, "success");
    let slots = t.ok("ota_slots", json!({}));
    assert_eq!(slots["active_slot"], "ota_0");
    assert_eq!(
        slots["slots"][0]["sha256_hex"],
        hex(&testkit::sha256(&img2)),
        "applied image hash == full image hash"
    );
}

#[test]
fn c_ota_6_failed_health_check_rolls_back() {
    let mut t = T::new();
    t.online();
    let mut img = DeviceConfig::sim().firmware;
    img[1] ^= 1;
    let n = campaign(&mut t, &img, 10100, None, None);
    // the new image never gets a broker connection, so the health check cannot pass
    t.dev.sim().broker.refuse_connect = true;
    t.dev.inject("ota/notify", &n, false);
    assert_eq!(t.take("rebooted")[0]["reason"], "ota_apply");
    t.dev.advance(121_000);
    t.collect();
    let rb = t.take("rebooted");
    assert_eq!(rb.last().unwrap()["reason"], "rollback");
    assert_eq!(rb.last().unwrap()["active_slot"], "ota_0");
    assert_eq!(rb.last().unwrap()["version_code"], 10000);
    assert_eq!(ota_states(&mut t).last().unwrap().0, "rolled_back");
    assert_eq!(t.ok("status", json!({}))["version_code"], 10000);
}

#[test]
fn c_cfg_1_encrypted_config() {
    let mut t = T::new();
    t.online();
    let settings = [
        0xa1u8, 0x69, b'l', b'o', b'g', b'_', b'l', b'e', b'v', b'e', b'l', 0x64, b'i', b'n', b'f', b'o',
    ];
    let settings = &settings[..];
    let inner = t.downlink(9, None, None, None, |e| unsafe {
        im_body_config(e, 12, settings.as_ptr(), settings.len())
    });
    let wrapped = testkit::wrap_config(&t.dev.identity_public(), &inner);
    t.dev.inject("config", &wrapped, true);
    assert!(t.take("message_rejected").is_empty(), "config accepted");
    let cfg_topic = t.topic("config");
    let retained = t.dev.sim().broker.retained.get(&cfg_topic).cloned().unwrap();
    assert!(!retained.windows(9).any(|w| w == b"log_level"), "retained copy is ciphertext only");
    // the same ciphertext for another key is rejected (HPKE)
    let other = im_host::SoftIdentity::random();
    let w2 = testkit::wrap_config(&other.public_raw(), &inner);
    t.dev.inject("config", &w2, false);
    assert_eq!(t.take("message_rejected")[0]["code"], "HPKE_OPEN");
}

#[test]
fn c_rev_1_and_c_tls_5_revoked_device_cannot_reconnect_and_backs_off() {
    let mut t = T::new();
    t.online();
    t.dev.sim().broker.refuse_connect = true; // revoked: broker refuses the certificate
    t.ok("disconnect", json!({}));
    t.ok("connect", json!({}));
    let f = t.take("connect_failed");
    assert_eq!(f[0]["reason"], "not_authorized");
    assert_eq!(t.ok("status", json!({}))["state"], "backoff");
    // bounded backoff: retries happen within base*2^n (full jitter), capped at 300 s
    let mut attempts = 0;
    for _ in 0..12 {
        t.dev.advance(300_000);
        attempts += t.take("connect_failed").len();
    }
    assert!((10..=12).contains(&attempts), "one attempt per <= 300 s window, got {attempts}");
    t.dev.sim().broker.refuse_connect = false;
    t.dev.advance(300_000);
    assert_eq!(t.take("connected").len(), 1);
    assert_eq!(t.take("connected").len(), 0);
}

#[test]
fn c_tls_4_session_resumption_reported() {
    let mut t = T::new();
    t.online();
    t.ok("disconnect", json!({}));
    t.ok("connect", json!({}));
    let c = t.take("connected");
    assert_eq!(c[0]["resumed"], true);
    assert_eq!(c[0]["session_present"], true, "clean_start=false, 7 day session expiry");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn downlink_replay_streams_are_per_type_and_retained_messages_may_be_old() {
    let mut t = T::new();
    t.online();
    let cmd = t.command("blink", "idem-s", Some(900), None);
    t.dev.inject("cmd/req", &cmd, false);
    assert_eq!(t.take("command_executed").len(), 1);
    // the OTA service / registry streams are independent: a lower seq on another type is fine
    let now = t.dev.now();
    let shadow = t.downlink(4, None, Some(5), Some(now - 3600), |e| unsafe {
        im_body_shadow(e, std::ptr::null(), 0, 1)
    });
    t.dev.inject("shadow/desired", &shadow, true);
    assert!(
        t.take("message_rejected").is_empty(),
        "retained ShadowDesired an hour old is accepted"
    );
    assert_eq!(t.published("shadow/reported").len(), 1);
    // but its replay is not
    t.dev.inject("shadow/desired", &shadow, false);
    assert_eq!(t.take("message_rejected")[0]["code"], "ENV_REPLAY");
    // a future-dated retainable message is still rejected; an old command is too
    let fut = t.downlink(4, None, Some(6), Some(now + 301), |e| unsafe {
        im_body_shadow(e, std::ptr::null(), 0, 2)
    });
    t.dev.inject("shadow/desired", &fut, false);
    assert_eq!(t.take("message_rejected")[0]["code"], "ENV_TS_SKEW");
    let old_cmd = t.command("blink", "idem-t", Some(901), Some(now - 3600));
    t.dev.inject("cmd/req", &old_cmd, false);
    assert_eq!(t.take("message_rejected")[0]["code"], "ENV_TS_SKEW");
}
