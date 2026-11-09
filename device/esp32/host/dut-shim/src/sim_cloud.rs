//! In-process simulated cloud for `--sim` runs and the shim's tests: an MQTT 5 broker that
//! enforces the contract §4 ACLs (own uplink topics only, own downlink subscriptions only, no
//! wildcards, retained only on shadow/desired, ota/notify, config, client id == CN), a PKI/EST
//! responder that verifies the attestation with the C core, and an artifact store for OTA.
//!
//! This exercises the protocol core end to end without a network; the real TLS/EST path is in
//! `net.rs` and the real broker/PKI are covered by the HIL job.

use im_host::err::*;
use im_host::ffi::*;
use im_host::ffi2::*;
use im_host::{testkit, EdSigner};
use std::collections::{BTreeMap, VecDeque};
use std::ffi::CStr;

/// Test keys of the simulated tenant/PKI (public test material, never used outside tests).
pub struct SimKeys {
    pub bundle: Box<EdSigner>,
    pub tenant: Box<EdSigner>,
    pub firmware: Box<EdSigner>,
}

impl SimKeys {
    pub fn new() -> Self {
        Self {
            bundle: EdSigner::from_seed(&[0x11; 32]),
            tenant: EdSigner::from_seed(&[0x22; 32]),
            firmware: EdSigner::from_seed(&[0x33; 32]),
        }
    }
}

impl Default for SimKeys {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct Published {
    pub topic: String,
    pub payload: Vec<u8>,
    pub retain: bool,
    pub qos: u8,
}

/// The simulated broker's view of one device connection.
#[derive(Default)]
pub struct SimBroker {
    pub expected_client_id: String,
    pub connected: bool,
    pub had_session: bool,
    pub subs: Vec<String>,
    pub retained: BTreeMap<String, Vec<u8>>,
    pub to_device: VecDeque<Vec<u8>>,
    pub log: Vec<Published>,
    pub denied_publishes: Vec<String>,
    pub denied_subscribes: Vec<String>,
    next_pid: u16,
    rx: Vec<u8>,
    /// Reject the next CONNECT with "not authorized" (revocation / quarantine simulation).
    pub refuse_connect: bool,
}

fn s(p: *const core::ffi::c_char, n: u16) -> String {
    if p.is_null() {
        return String::new();
    }
    String::from_utf8_lossy(unsafe { core::slice::from_raw_parts(p as *const u8, n as usize) }).into_owned()
}

impl SimBroker {
    fn reply(&mut self, f: impl FnOnce(*mut u8, usize, *mut usize) -> i32) {
        let mut out = vec![0u8; 20_000];
        let mut n = 0usize;
        if f(out.as_mut_ptr(), out.len(), &mut n) == IM_OK {
            out.truncate(n);
            self.to_device.push_back(out);
        }
    }

    /// Bytes written by the device. Returns false when the broker closes the connection.
    pub fn ingest(&mut self, data: &[u8]) -> bool {
        self.rx.extend_from_slice(data);
        loop {
            let mut flen = 0usize;
            let r = unsafe { im_mqtt_frame(self.rx.as_ptr(), self.rx.len(), 1 << 20, &mut flen) };
            if r == IM_ERR_MQTT_INCOMPLETE {
                return true;
            }
            if r != IM_OK {
                self.connected = false;
                return false;
            }
            let frame: Vec<u8> = self.rx.drain(..flen).collect();
            let mut p = im_mqtt_packet_t::default();
            if unsafe { im_mqtt_decode(frame.as_ptr(), frame.len(), &mut p) } != IM_OK {
                self.connected = false;
                return false; // malformed packet from the client: broker closes
            }
            if !self.handle(&p) {
                return false;
            }
        }
    }

    fn handle(&mut self, p: &im_mqtt_packet_t) -> bool {
        match p.type_ {
            1 => {
                let cid = s(p.client_id, p.client_id_len);
                if cid != self.expected_client_id || self.refuse_connect {
                    self.reply(|o, c, n| unsafe { im_mqtt_enc_connack(false, 0x87, 0, o, c, n) });
                    self.connected = false;
                    return false;
                }
                let sp = !p.clean_start && self.had_session;
                self.had_session = true;
                self.connected = true;
                self.reply(|o, c, n| unsafe { im_mqtt_enc_connack(sp, 0, 32, o, c, n) });
            }
            8 => {
                let topic = s(p.filter, p.filter_len);
                let ok = unsafe {
                    im_topic_device_may_subscribe(
                        topic.as_ptr().cast(),
                        topic.len(),
                        format!("{}\0", self.expected_client_id).as_ptr().cast(),
                    )
                };
                let code = if ok { 0x01u8 } else { 0x87u8 };
                let pid = p.packet_id;
                self.reply(|o, c, n| unsafe { im_mqtt_enc_suback(pid, &code, 1, o, c, n) });
                if ok {
                    if !self.subs.contains(&topic) {
                        self.subs.push(topic.clone());
                    }
                    if let Some(m) = self.retained.get(&topic).cloned() {
                        self.deliver(&topic, &m, true);
                    }
                } else {
                    self.denied_subscribes.push(topic);
                }
            }
            3 => {
                let topic = s(p.topic, p.topic_len);
                let dev = format!("{}\0", self.expected_client_id);
                let mut ok = unsafe { im_topic_device_may_publish(topic.as_ptr().cast(), topic.len(), dev.as_ptr().cast()) };
                if ok && p.retain {
                    let mut t = im_topic_t {
                        tenant: std::ptr::null(),
                        device: std::ptr::null(),
                        cls: 0,
                    };
                    ok = unsafe { im_topic_parse(topic.as_ptr().cast(), topic.len(), &mut t) } == IM_OK
                        && unsafe { im_topic_retained_allowed(t.cls) };
                }
                let payload = unsafe { im_host::crypto::cslice(p.payload, p.payload_len) }.to_vec();
                if ok {
                    self.log.push(Published {
                        topic,
                        payload,
                        retain: p.retain,
                        qos: p.qos,
                    });
                } else {
                    self.denied_publishes.push(topic);
                }
                if p.qos == 1 {
                    let pid = p.packet_id;
                    let rc = if ok { 0 } else { 0x87 };
                    self.reply(|o, c, n| unsafe { im_mqtt_enc_puback(pid, rc, o, c, n) });
                }
            }
            12 => self.reply(|o, c, n| unsafe { im_mqtt_enc_pingresp(o, c, n) }),
            4 => {} // device acknowledged a downlink publish
            14 => {
                self.connected = false;
                return false;
            }
            _ => {
                self.connected = false;
                return false;
            }
        }
        true
    }

    fn deliver(&mut self, topic: &str, payload: &[u8], retain: bool) {
        self.next_pid = self.next_pid.wrapping_add(1).max(1);
        let pid = self.next_pid;
        self.reply(|o, c, n| unsafe {
            im_mqtt_enc_publish(
                topic.as_ptr().cast(),
                topic.len(),
                1,
                retain,
                false,
                pid,
                std::ptr::null(),
                0,
                payload.as_ptr(),
                payload.len(),
                o,
                c,
                n,
            )
        });
    }

    /// Cloud-side publish to a device topic (delivered when subscribed and connected).
    pub fn inject(&mut self, topic: &str, payload: &[u8], retain: bool) {
        if retain {
            self.retained.insert(topic.to_string(), payload.to_vec());
        }
        if self.connected && self.subs.iter().any(|t| t == topic) {
            self.deliver(topic, payload, false);
        }
    }

    pub fn reset_connection(&mut self) {
        self.connected = false;
        self.rx.clear();
        self.to_device.clear();
    }
}

/// Simulated PKI: certificate serials, trust bundle, quarantine.
pub struct SimPki {
    pub keys: SimKeys,
    pub next_serial: u64,
    pub quarantined: bool,
    pub cert_ttl: u64,
    pub broker_host: String,
    pub pins: Vec<[u8; 32]>,
    pub issued: Vec<Vec<u8>>,
}

impl SimPki {
    pub fn new() -> Self {
        Self {
            keys: SimKeys::new(),
            next_serial: 0x4a00_0000_0000_0001,
            quarantined: false,
            cert_ttl: 14 * 86_400,
            broker_host: "mqtt.ironmesh.local".into(),
            pins: vec![testkit::sha256(b"sim services ca spki")],
            issued: vec![],
        }
    }

    pub fn bundle(&self) -> Vec<u8> {
        let fw = self.keys.firmware.public();
        testkit::bundle(
            &self.keys.bundle,
            &self.keys.tenant.public(),
            &[&fw],
            &self.broker_host,
            8883,
            &self.pins,
        )
    }

    /// Verify the attestation exactly like the EST server would (with the C verifier).
    pub fn verify_attestation(
        &self,
        att: &[u8],
        tls_key: &[u8; 65],
        nonce: &[u8; 32],
        csr: &[u8],
        kid: &[u8],
        now: u64,
    ) -> Result<(), &'static str> {
        let mut key = im_pubkey_t::default();
        unsafe { im_pubkey_p256(&mut key, tls_key.as_ptr(), 65) };
        let o = im_attest_verify_opts_t {
            expected_nonce: nonce.as_ptr(),
            csr_der: csr.as_ptr(),
            csr_len: csr.len(),
            now,
            max_skew: 300,
            expected_kid: kid.as_ptr(),
            expected_kid_len: kid.len(),
            allowed_se_types: 0,
            replay: std::ptr::null(),
        };
        let mut msg = im_env_msg_t::default();
        im_host::check(unsafe { im_attest_verify(att.as_ptr(), att.len(), &key, &o, &mut msg) })
    }

    pub fn issue_serial(&mut self) -> Vec<u8> {
        self.next_serial += 1;
        let s = self.next_serial.to_be_bytes().to_vec();
        self.issued.push(s.clone());
        s
    }
}

impl Default for SimPki {
    fn default() -> Self {
        Self::new()
    }
}

/// Everything simulated on the cloud side.
pub struct SimCloud {
    pub broker: SimBroker,
    pub pki: SimPki,
    pub artifacts: BTreeMap<String, Vec<u8>>,
    pub tenant_seq: u64,
}

impl SimCloud {
    pub fn new(device_id: &str) -> Self {
        Self {
            broker: SimBroker {
                expected_client_id: device_id.into(),
                ..Default::default()
            },
            pki: SimPki::new(),
            artifacts: BTreeMap::new(),
            tenant_seq: 100,
        }
    }

    /// Next tenant-side sequence number (the cloud's downlink counter).
    pub fn next_seq(&mut self) -> u64 {
        self.tenant_seq += 1;
        self.tenant_seq
    }
}

/// Error string from a C code (for messages).
pub fn cname(code: i32) -> String {
    unsafe { CStr::from_ptr(im_err_str(code)) }.to_string_lossy().into_owned()
}
