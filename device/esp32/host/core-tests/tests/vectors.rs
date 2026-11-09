//! Runs every conformance vector file in `device/common/vectors/` through the C protocol core.
//!
//! Deterministic vectors (canonical CBOR, Ed25519-signed messages, the manifest, HPKE, deltas)
//! are reproduced byte for byte by the C encoders; ES256 / ML-DSA vectors are verification
//! vectors. Error codes are compared verbatim with the `error` fields.

mod common;

use common::*;
use im_host::err::*;
use im_host::ffi::*;
use im_host::{EdSigner, SoftIdentity, StaticResolver};
use serde_json::Value;
use std::ptr;

const OK: i32 = IM_OK;

#[test]
fn every_vector_file_is_covered() {
    let covered = [
        "attestation_software.json",
        "cbor_canonical.json",
        "cose_sign1_eddsa.json",
        "cose_sign1_es256.json",
        "delta_both_empty.json",
        "delta_empty_base.json",
        "delta_empty_target.json",
        "delta_identical.json",
        "delta_insert_shift.json",
        "delta_invalid.json",
        "delta_partial_tail.json",
        "delta_small_change.json",
        "envelope_command_ack.json",
        "envelope_telemetry.json",
        "hpke_rfc9180_a3.json",
        "ids_topics.json",
        "manifest_signed.json",
        "replay_cases.json",
    ];
    let mut found: Vec<String> = std::fs::read_dir(vectors_dir())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    found.sort();
    assert_eq!(
        found,
        covered.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        "new vector file needs a test"
    );
}

// ---- cbor_canonical.json ------------------------------------------------------------------

#[test]
fn cbor_canonical() {
    let v = load("cbor_canonical.json");
    assert_eq!(u(&v["limits"]["max_size"]), 65536);
    assert_eq!(u(&v["limits"]["max_depth"]), 16);
    let mut n = 0;
    for case in v["valid"].as_array().unwrap() {
        let bytes = hx(&case["hex"]);
        let mut top = im_cbor_val_t::default();
        let r = unsafe { im_cbor_decode(bytes.as_ptr(), bytes.len(), ptr::null(), &mut top) };
        assert_eq!(name(r), "OK", "valid case {} rejected", s(&case["name"]));
        let mut enc = Enc::new(bytes.len() + 16);
        let r = unsafe { im_cbor_reencode(&top, &mut enc.e) };
        assert_eq!(r, OK, "{}", s(&case["name"]));
        assert_eq!(hex::encode(enc.bytes()), s(&case["hex"]), "re-encode of {}", s(&case["name"]));
        n += 1;
    }
    for case in v["invalid"].as_array().unwrap() {
        let bytes = hx(&case["hex"]);
        let r = unsafe { im_cbor_validate(bytes.as_ptr(), bytes.len(), ptr::null()) };
        assert_eq!(name(r), s(&case["error"]), "invalid case {}", s(&case["name"]));
        n += 1;
    }
    assert_eq!(n, 100);
}

// ---- cose_sign1_*.json --------------------------------------------------------------------

fn pubkey(alg: &str, raw: &[u8]) -> im_pubkey_t {
    let mut k = im_pubkey_t::default();
    let r = unsafe {
        if alg == "ES256" {
            im_pubkey_p256(&mut k, raw.as_ptr(), raw.len())
        } else {
            im_pubkey_ed25519(&mut k, raw.as_ptr(), raw.len())
        }
    };
    assert_eq!(r, OK);
    k
}

fn sign1_decode_verify(msg: &[u8], key: &im_pubkey_t) -> Result<im_sign1_t, &'static str> {
    let mut m: im_sign1_t = unsafe { core::mem::zeroed() };
    let r = unsafe { im_cose_sign1_decode(msg.as_ptr(), msg.len(), ptr::null(), &mut m) };
    if r != OK {
        return Err(name(r));
    }
    let mut work = vec![0u8; msg.len() + 64];
    let r = unsafe { im_cose_sign1_verify(&m, key, work.as_mut_ptr(), work.len()) };
    if r != OK {
        return Err(name(r));
    }
    Ok(m)
}

fn bytes_of(p: *const u8, n: usize) -> Vec<u8> {
    unsafe { im_host::crypto::cslice(p, n).to_vec() }
}

fn run_sign1_file(file: &str) {
    let v = load(file);
    let alg = s(&v["key"]["algorithm"]).to_string();
    let key = pubkey(&alg, &hx(&v["key"]["public_raw_hex"]));
    let wrong = pubkey(&alg, &hx(&v["wrong_key"]["public_raw_hex"]));
    let deterministic = v["deterministic"].as_bool().unwrap();
    for case in v["cases"].as_array().unwrap() {
        let msg = hx(&case["message_hex"]);
        let m = sign1_decode_verify(&msg, &key).unwrap_or_else(|e| panic!("{}: {e}", s(&case["name"])));
        assert_eq!(bytes_of(m.protected_raw, m.protected_len), hx(&case["protected_hex"]));
        assert_eq!(bytes_of(m.payload, m.payload_len), hx(&case["payload_hex"]));
        assert_eq!(bytes_of(m.sig, m.sig_len), hx(&case["signature_hex"]));
        let mut sig_struct = vec![0u8; 4096];
        let mut n = 0usize;
        let r = unsafe {
            im_cose_sig1_structure(
                m.protected_raw,
                m.protected_len,
                m.payload,
                m.payload_len,
                sig_struct.as_mut_ptr(),
                sig_struct.len(),
                &mut n,
            )
        };
        assert_eq!(r, OK);
        assert_eq!(hex::encode(&sig_struct[..n]), s(&case["sig_structure_hex"]));

        // Re-sign with the C encoder: byte-identical for Ed25519, verifiable for ES256.
        let payload = hx(&case["payload_hex"]);
        let (kid, kid_text): (Vec<u8>, bool) = if alg == "ES256" {
            (hx(&v["kid_hex"]), false)
        } else {
            (s(&v["kid"]).as_bytes().to_vec(), true)
        };
        let mut out = vec![0u8; 4096];
        let mut work = vec![0u8; 4096];
        let mut olen = 0usize;
        let id = SoftIdentity::from_scalar(&hx(&v["key"]
            .get("private_scalar_hex")
            .cloned()
            .unwrap_or(Value::String("01".repeat(32)))));
        let ed = EdSigner::from_seed(&hx(&v["key"]
            .get("private_seed_hex")
            .cloned()
            .unwrap_or(Value::String("01".repeat(32)))));
        let idf = id.ffi();
        let mut signer: im_signer_t = unsafe { core::mem::zeroed() };
        if alg == "ES256" {
            unsafe { im_identity_signer(&idf, &mut signer) };
        } else {
            signer = ed.ffi();
        }
        let r = unsafe {
            im_cose_sign1_encode(
                &signer,
                kid.as_ptr(),
                kid.len(),
                kid_text,
                payload.as_ptr(),
                payload.len(),
                work.as_mut_ptr(),
                work.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut olen,
            )
        };
        assert_eq!(r, OK);
        let produced = &out[..olen];
        if deterministic {
            assert_eq!(
                hex::encode(produced),
                s(&case["message_hex"]),
                "deterministic re-sign {}",
                s(&case["name"])
            );
        } else {
            sign1_decode_verify(produced, &key).expect("re-signed ES256 verifies");
        }
    }
    for case in v["negative"].as_array().unwrap() {
        let msg = hx(&case["message_hex"]);
        let k = if s(&case["verify_with"]) == "key" { &key } else { &wrong };
        let r = sign1_decode_verify(&msg, k).err().unwrap_or("OK");
        assert_eq!(r, s(&case["error"]), "{} / {}", file, s(&case["name"]));
    }
}

#[test]
fn cose_sign1_es256() {
    run_sign1_file("cose_sign1_es256.json");
}

#[test]
fn cose_sign1_eddsa() {
    run_sign1_file("cose_sign1_eddsa.json");
}

// ---- envelopes ------------------------------------------------------------------------------

struct Decoder {
    resolver: Box<StaticResolver>,
    store: Box<im_replay_mem_t>,
}

impl Decoder {
    fn new(resolver: StaticResolver) -> Self {
        let mut store: Box<im_replay_mem_t> = Box::new(unsafe { core::mem::zeroed() });
        unsafe { im_replay_mem_init(&mut *store) };
        Self {
            resolver: Box::new(resolver),
            store,
        }
    }

    fn decode(
        &mut self,
        wire: &[u8],
        now: u64,
        tenant: Option<&str>,
        nonce: Option<&[u8]>,
        max_skew: u64,
    ) -> Result<im_env_msg_t, &'static str> {
        let res = self.resolver.ffi();
        let mut st: im_replay_store_t = unsafe { core::mem::zeroed() };
        unsafe { im_replay_mem_store(&mut *self.store, &mut st) };
        let mut o: im_env_decode_opts_t = unsafe { core::mem::zeroed() };
        unsafe { im_env_decode_opts_init(&mut o) };
        let tenant_c = tenant.map(cstr);
        let mut work = vec![0u8; wire.len() + 128];
        o.resolver = &res;
        o.replay = &st;
        o.now = now;
        o.max_skew = max_skew;
        o.expected_tenant = tenant_c.as_ref().map_or(ptr::null(), |c| c.as_ptr());
        o.expected_nonce = nonce.map_or(ptr::null(), |n| n.as_ptr());
        o.work = work.as_mut_ptr();
        o.work_len = work.len();
        let mut msg = im_env_msg_t::default();
        let r = unsafe { im_env_decode(wire.as_ptr(), wire.len(), &o, &mut msg) };
        if r == OK {
            Ok(msg)
        } else {
            Err(name(r))
        }
    }

    fn last(&self, kid: &[u8], dir: i32) -> Option<u64> {
        let mut seq = 0u64;
        unsafe { im_replay_mem_last(&*self.store, kid.as_ptr(), kid.len(), dir, &mut seq) }.then_some(seq)
    }
}

#[test]
fn envelope_telemetry() {
    let v = load("envelope_telemetry.json");
    let m = &v["message"];
    let b = &m["body"];
    let fwv = cstr(s(&b["fw_version"]));
    let procs: Vec<std::ffi::CString> = b["top_procs"].as_array().unwrap().iter().map(|p| cstr(s(p))).collect();
    let proc_ptrs: Vec<*const core::ffi::c_char> = procs.iter().map(|c| c.as_ptr()).collect();
    let mut fw_hash = [0u8; 32];
    fw_hash.copy_from_slice(&hx(&b["fw_hash_hex"]));
    let t = im_telemetry_t {
        cpu_pct: b["cpu_pct"].as_f64().unwrap(),
        mem_pct: b["mem_pct"].as_f64().unwrap(),
        net_rx_bytes: u(&b["net_rx_bytes"]),
        net_tx_bytes: u(&b["net_tx_bytes"]),
        temp_c: b["temp_c"].as_f64().unwrap(),
        uptime_s: u(&b["uptime_s"]),
        auth_failures: u(&b["auth_failures"]),
        fw_hash,
        fw_version: fwv.as_ptr(),
        has_proc_count: true,
        proc_count: u(&b["proc_count"]),
        top_procs: proc_ptrs.as_ptr(),
        n_top_procs: proc_ptrs.len(),
        has_rssi: !b["rssi"].is_null(),
        rssi: 0,
        has_free_heap: !b["free_heap"].is_null(),
        free_heap: 0,
        has_lat: true,
        lat: b["lat"].as_f64().unwrap(),
        has_lon: true,
        lon: b["lon"].as_f64().unwrap(),
    };
    let mut enc = Enc::new(1024);
    let mut n = 0usize;
    unsafe {
        im_env_payload_begin(&mut enc.e, u(&m["seq"]), u(&m["ts"]), 1, false);
        im_body_telemetry(&mut enc.e, &t);
        assert_eq!(im_env_payload_end(&mut enc.e, ptr::null(), &mut n), OK);
    }
    assert_eq!(hex::encode(enc.bytes()), s(&m["payload_hex"]));

    let mut r = StaticResolver::default();
    r.add_p256(&hx(&v["kid_hex"]), &hx(&v["device_key"]["public_raw_hex"]));
    let mut d = Decoder::new(r);
    let msg = d
        .decode(&hx(&m["wire_hex"]), u(&v["now"]), None, None, 300)
        .expect("telemetry accepted");
    assert_eq!(msg.seq, u(&m["seq"]));
    assert_eq!(msg.ts, u(&m["ts"]));
    assert_eq!(msg.type_, 1);
    assert_eq!(msg.direction, 0);
    // The device can sign the same payload and it verifies with the published key.
    let id = SoftIdentity::from_scalar(&hx(&v["device_key"]["private_scalar_hex"]));
    let idf = id.ffi();
    let kid = hx(&v["kid_hex"]);
    let mut out = vec![0u8; 1024];
    let mut olen = 0usize;
    let payload = hx(&m["payload_hex"]);
    let rc = unsafe {
        im_env_sign_uplink(
            &idf,
            kid.as_ptr(),
            kid.len(),
            payload.as_ptr(),
            payload.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut olen,
        )
    };
    assert_eq!(rc, OK);
    let mut r2 = StaticResolver::default();
    r2.add_p256(&kid, &hx(&v["device_key"]["public_raw_hex"]));
    Decoder::new(r2)
        .decode(&out[..olen], u(&v["now"]), None, None, 300)
        .expect("C-signed telemetry verifies");
}

#[test]
fn envelope_command_ack() {
    let v = load("envelope_command_ack.json");
    let c = &v["command"];
    let b = &c["body"];
    let args = cbor_json(&b["args"]);
    let (cmd_id, cname, idem) = (cstr(s(&b["cmd_id"])), cstr(s(&b["name"])), cstr(s(&b["idempotency_key"])));
    let nonce = hx(&c["nonce_hex"]);
    let mut enc = Enc::new(1024);
    let mut n = 0usize;
    unsafe {
        im_env_payload_begin(&mut enc.e, u(&c["seq"]), u(&c["ts"]), 5, true);
        im_body_command(
            &mut enc.e,
            cmd_id.as_ptr(),
            cname.as_ptr(),
            args.as_ptr(),
            args.len(),
            idem.as_ptr(),
            u(&b["expires_at"]),
        );
        assert_eq!(im_env_payload_end(&mut enc.e, nonce.as_ptr(), &mut n), OK);
    }
    let payload = enc.bytes();
    assert_eq!(hex::encode(&payload), s(&c["payload_hex"]));
    // Deterministic tenant signature
    let ed = EdSigner::from_seed(&hx(&v["tenant_key"]["private_seed_hex"]));
    let signer = ed.ffi();
    let kid = s(&v["tenant_kid"]);
    let mut out = vec![0u8; 1024];
    let mut work = vec![0u8; 1024];
    let mut olen = 0usize;
    let r = unsafe {
        im_cose_sign1_encode(
            &signer,
            kid.as_ptr(),
            kid.len(),
            true,
            payload.as_ptr(),
            payload.len(),
            work.as_mut_ptr(),
            work.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut olen,
        )
    };
    assert_eq!(r, OK);
    assert_eq!(hex::encode(&out[..olen]), s(&c["wire_hex"]));

    let mut res = StaticResolver::default();
    res.add_ed25519(kid, &hx(&v["tenant_key"]["public_raw_hex"]));
    res.add_p256(&hx(&v["device_kid_hex"]), &hx(&v["device_key"]["public_raw_hex"]));
    let mut d = Decoder::new(res);
    let now = u(&v["now"]);
    let tenant = s(&v["tenant_id"]);
    let msg = d
        .decode(&hx(&c["wire_hex"]), now, Some(tenant), None, 300)
        .expect("command accepted");
    assert_eq!(msg.type_, 5);
    assert_eq!(bytes_of(msg.nonce, 16), nonce);

    // Ack payload reproduced and the device-signed ack verified with the nonce echo
    let a = &v["ack"];
    let result = cbor_json(&a["body"]["result"]);
    let mut enc = Enc::new(512);
    unsafe {
        im_env_payload_begin(&mut enc.e, u(&a["seq"]), u(&a["ts"]), 6, true);
        im_body_command_ack(&mut enc.e, cmd_id.as_ptr(), 0, result.as_ptr(), result.len(), ptr::null());
        assert_eq!(im_env_payload_end(&mut enc.e, nonce.as_ptr(), &mut n), OK);
    }
    assert_eq!(hex::encode(enc.bytes()), s(&a["payload_hex"]));
    d.decode(&hx(&a["wire_hex"]), now, Some(tenant), Some(&nonce), 300)
        .expect("ack accepted");
    let bad = &v["ack_bad_nonce"];
    let r = d.decode(&hx(&bad["wire_hex"]), now, Some(tenant), Some(&hx(&bad["expected_nonce_hex"])), 300);
    assert_eq!(r.err(), Some(s(&bad["error"])));
}

// ---- replay_cases.json -----------------------------------------------------------------------

#[test]
fn replay_cases() {
    let v = load("replay_cases.json");
    let mut res = StaticResolver::default();
    let dkid = hx(&v["device_kid_hex"]);
    let tkid = s(&v["tenant_kid"]);
    res.add_p256(&dkid, &hx(&v["device_key"]["public_raw_hex"]));
    res.add_ed25519(tkid, &hx(&v["tenant_key"]["public_raw_hex"]));
    let mut d = Decoder::new(res);
    let tenant = s(&v["tenant_id"]);
    let max_skew = u(&v["max_skew"]);
    let steps = v["steps"].as_array().unwrap();
    assert!(steps.len() >= 24);
    for step in steps {
        let nonce = step.get("expected_nonce_hex").map(hx);
        let r = d.decode(&hx(&step["wire_hex"]), u(&step["now"]), Some(tenant), nonce.as_deref(), max_skew);
        let label = s(&step["name"]);
        if s(&step["expect"]) == "accept" {
            assert!(r.is_ok(), "{label}: {:?}", r.err());
        } else {
            assert_eq!(r.err(), Some(s(&step["error"])), "{label}");
        }
        let after = &step["store_after"];
        assert_eq!(d.last(&dkid, 0), after["uplink_last_seq"].as_u64(), "{label} uplink store");
        // downlink replay streams are "<tenant kid>/<type>" (WIRE_FORMAT.md §3.6 step 11)
        let stream = |t: &str| format!("{tkid}/{t}").into_bytes();
        let by_type = after["downlink_last_seq_by_type"].as_object().expect("downlink_last_seq_by_type");
        assert!(!by_type.is_empty());
        for (t, v) in by_type {
            assert_eq!(d.last(&stream(t), 1), v.as_u64(), "{label} downlink stream /{t}");
        }
        assert_eq!(
            d.last(&stream("5"), 1),
            after["downlink_last_seq"].as_u64(),
            "{label} legacy downlink_last_seq (commands)"
        );
        assert_eq!(d.last(tkid.as_bytes(), 1), None, "{label}: no bare tenant-kid stream");
    }
}

// ---- attestation_software.json ------------------------------------------------------------------

fn attest_verify(v: &Value, wire: &[u8], nonce: &[u8], csr: &[u8], allowed: u32) -> Result<(), &'static str> {
    let key = pubkey("ES256", &hx(&v["device_key"]["public_raw_hex"]));
    let kid = hx(&v["kid_hex"]);
    let o = im_attest_verify_opts_t {
        expected_nonce: nonce.as_ptr(),
        csr_der: csr.as_ptr(),
        csr_len: csr.len(),
        now: u(&v["now"]),
        max_skew: 300,
        expected_kid: kid.as_ptr(),
        expected_kid_len: kid.len(),
        allowed_se_types: allowed,
        replay: ptr::null(),
    };
    let mut msg = im_env_msg_t::default();
    let r = unsafe { im_attest_verify(wire.as_ptr(), wire.len(), &key, &o, &mut msg) };
    if r == OK {
        Ok(())
    } else {
        Err(name(r))
    }
}

#[test]
fn attestation_software() {
    let v = load("attestation_software.json");
    let m = &v["message"];
    let wire = hx(&m["wire_hex"]);
    let nonce = hx(&v["nonce_hex"]);
    let csr = hx(&v["csr_der_hex"]);
    attest_verify(&v, &wire, &nonce, &csr, 0).expect("attestation accepted");
    for neg in v["negative"].as_array().unwrap() {
        let n2 = neg.get("expected_nonce_hex").map(hx).unwrap_or(nonce.clone());
        let c2 = neg.get("csr_der_hex").map(hx).unwrap_or(csr.clone());
        let mut allowed = 0u32;
        if let Some(list) = neg.get("allowed_se_types") {
            for t in list.as_array().unwrap() {
                allowed |= match s(t) {
                    "atecc608" => 1,
                    "tpm2" => 2,
                    "optee" => 4,
                    "software" => 8,
                    other => panic!("{other}"),
                };
            }
        }
        assert_eq!(
            attest_verify(&v, &wire, &n2, &c2, allowed).err(),
            Some(s(&neg["error"])),
            "{}",
            s(&neg["name"])
        );
    }
    // The C builder produces the identical payload (only the ES256 signature differs).
    let id = SoftIdentity::from_scalar(&hx(&v["device_key"]["private_scalar_hex"]));
    let idf = id.ffi();
    let kid = hx(&v["kid_hex"]);
    let fw = hx(&m["body"]["fw_hash_hex"]);
    let fwv = cstr(s(&m["body"]["fw_version"]));
    let mut out = vec![0u8; 1024];
    let mut olen = 0usize;
    let r = unsafe {
        im_attest_build(
            &idf,
            kid.as_ptr(),
            kid.len(),
            u(&m["seq"]),
            u(&m["ts"]),
            nonce.as_ptr(),
            csr.as_ptr(),
            csr.len(),
            fw.as_ptr(),
            fwv.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            &mut olen,
        )
    };
    assert_eq!(r, OK);
    let built = &out[..olen];
    let mut s1: im_sign1_t = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe { im_cose_sign1_decode(built.as_ptr(), built.len(), ptr::null(), &mut s1) },
        OK
    );
    assert_eq!(hex::encode(bytes_of(s1.payload, s1.payload_len)), s(&m["payload_hex"]));
    assert_eq!(hex::encode(bytes_of(s1.protected_raw, s1.protected_len)), s(&m["protected_hex"]));
    attest_verify(&v, built, &nonce, &csr, 8).expect("C-built attestation verifies");
}

// ---- manifest_signed.json -------------------------------------------------------------------------

fn manifest_from_json(m: &Value, keep: &mut Vec<Vec<u8>>) -> im_manifest_t {
    let product = s(&m["product"]).as_bytes().to_vec();
    let version = s(&m["version"]).as_bytes().to_vec();
    let kid = s(&m["signing_key_id"]).as_bytes().to_vec();
    let sha = hx(&m["image_sha256_hex"]);
    let mut out = im_manifest_t {
        product: product.as_ptr().cast(),
        product_len: product.len(),
        version: version.as_ptr().cast(),
        version_len: version.len(),
        version_code: u(&m["version_code"]),
        image_sha256: sha.as_ptr(),
        image_size: u(&m["image_size"]),
        created_at: u(&m["created_at"]),
        min_version_code: u(&m["min_version_code"]),
        signing_key_id: kid.as_ptr().cast(),
        signing_key_id_len: kid.len(),
        ..Default::default()
    };
    assert!(m["delta"].is_null());
    out.has_delta = false;
    keep.extend([product, version, kid, sha]);
    out
}

fn verify_manifest(signed: &[u8], trusted: &[Vec<u8>], require_pq: bool) -> Result<(im_manifest_t, bool), &'static str> {
    let mut keys = im_fw_keys_t {
        key: [ptr::null(); 4],
        len: [0; 4],
        n: trusted.len(),
    };
    for (i, k) in trusted.iter().enumerate() {
        keys.key[i] = k.as_ptr();
        keys.len[i] = k.len();
    }
    let mut work = vec![0u8; signed.len() + 128];
    let mut out = im_manifest_t::default();
    let mut pq = false;
    let r = unsafe {
        im_manifest_verify(
            signed.as_ptr(),
            signed.len(),
            &keys,
            require_pq,
            ptr::null(),
            work.as_mut_ptr(),
            work.len(),
            &mut out,
            &mut pq,
        )
    };
    if r == OK {
        Ok((out, pq))
    } else {
        Err(name(r))
    }
}

#[test]
fn manifest_signed() {
    let v = load("manifest_signed.json");
    let mut keep = Vec::new();
    let m = manifest_from_json(&v["manifest"], &mut keep);
    let mut buf = vec![0u8; 512];
    let mut n = 0usize;
    assert_eq!(unsafe { im_manifest_encode(&m, buf.as_mut_ptr(), buf.len(), &mut n) }, OK);
    assert_eq!(hex::encode(&buf[..n]), s(&v["manifest_hex"]));
    let payload = buf[..n].to_vec();

    // kid derivation and the deterministic Ed25519-only signed manifest
    let ed = EdSigner::from_seed(&hx(&v["ed25519_key"]["private_seed_hex"]));
    assert_eq!(hex::encode(ed.public()), s(&v["ed25519_key"]["public_raw_hex"]));
    let mut kid = [0u8; 8];
    assert_eq!(unsafe { im_cose_key_id(ed.public().as_ptr(), 32, kid.as_mut_ptr()) }, OK);
    assert_eq!(hex::encode(kid), s(&v["ed25519_key"]["kid_hex"]));
    let mldsa_pub = hx(&v["mldsa65_key"]["public_raw_hex"]);
    assert_eq!(unsafe { im_cose_key_id(mldsa_pub.as_ptr(), mldsa_pub.len(), kid.as_mut_ptr()) }, OK);
    assert_eq!(hex::encode(kid), s(&v["mldsa65_key"]["kid_hex"]));
    let ed_kid = hx(&v["ed25519_key"]["kid_hex"]);
    let signer = ed.ffi();
    let mut out = vec![0u8; 1024];
    let mut work = vec![0u8; 1024];
    let mut olen = 0usize;
    let r = unsafe {
        im_cose_sign_encode_ed25519(
            &signer,
            ed_kid.as_ptr(),
            payload.as_ptr(),
            payload.len(),
            work.as_mut_ptr(),
            work.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut olen,
        )
    };
    assert_eq!(r, OK);
    assert_eq!(hex::encode(&out[..olen]), s(&v["signed_ed25519_only_hex"]));
    // Sig_structure of the Ed25519 signature
    let es = &v["ed25519_signature"];
    let sp = hx(&es["protected_hex"]);
    let mut ss = vec![0u8; 1024];
    let r = unsafe {
        im_cose_sig_structure(
            sp.as_ptr(),
            sp.len(),
            payload.as_ptr(),
            payload.len(),
            ss.as_mut_ptr(),
            ss.len(),
            &mut olen,
        )
    };
    assert_eq!(r, OK);
    assert_eq!(hex::encode(&ss[..olen]), s(&es["sig_structure_hex"]));

    let trusted: Vec<Vec<u8>> = v["trusted_pubkeys_hex"].as_array().unwrap().iter().map(hx).collect();
    for case in v["verify_cases"].as_array().unwrap() {
        let r = verify_manifest(&hx(&case["signed_hex"]), &trusted, case["require_pq"].as_bool().unwrap());
        let label = s(&case["name"]);
        if s(&case["expect"]) == "accept" {
            let (mf, pq) = r.unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(mf.version_code, 20401);
            if case["require_pq"].as_bool().unwrap() {
                assert!(pq, "{label}: ML-DSA verified");
            }
        } else {
            assert_eq!(r.err(), Some(s(&case["error"])), "{label}");
        }
    }
    // trusted key of unsupported size is a configuration error
    let bad = vec![vec![0u8; 31]];
    assert_eq!(
        verify_manifest(&hx(&v["signed_ed25519_only_hex"]), &bad, false).err(),
        Some("MF_STRUCTURE")
    );

    let mut dm = im_manifest_t::default();
    assert_eq!(
        unsafe { im_manifest_decode(payload.as_ptr(), payload.len(), ptr::null(), &mut dm) },
        OK
    );
    for case in v["acceptance_cases"].as_array().unwrap() {
        let img = hx(&case["image_hex"]);
        let product = cstr(s(&case["product"]));
        let r = unsafe { im_manifest_accept_image_bytes(&dm, img.as_ptr(), img.len(), u(&case["current_version_code"]), product.as_ptr()) };
        let label = s(&case["name"]);
        if case["accepted"].as_bool().unwrap() {
            assert_eq!(name(r), "OK", "{label}");
        } else {
            assert_eq!(name(r), s(&case["reason"]), "{label}");
        }
    }
}

// ---- delta_*.json ------------------------------------------------------------------------------

struct DeltaIo {
    base: Vec<u8>,
    out: Vec<u8>,
}

unsafe extern "C" fn d_read(ctx: *mut core::ffi::c_void, off: u64, buf: *mut u8, len: usize) -> i32 {
    let io = &*(ctx as *const DeltaIo);
    let off = off as usize;
    if off + len > io.base.len() {
        return IM_ERR_IO;
    }
    core::slice::from_raw_parts_mut(buf, len).copy_from_slice(&io.base[off..off + len]);
    IM_OK
}

unsafe extern "C" fn d_write(ctx: *mut core::ffi::c_void, off: u64, data: *const u8, len: usize) -> i32 {
    let io = &mut *(ctx as *mut DeltaIo);
    assert_eq!(off as usize, io.out.len(), "writes are sequential");
    io.out.extend_from_slice(core::slice::from_raw_parts(data, len));
    IM_OK
}

/// Apply a patch with the C streaming applier, feeding `chunk` bytes at a time.
pub fn apply_c(base: &[u8], patch: &[u8], chunk: usize, work_len: usize) -> Result<Vec<u8>, &'static str> {
    let mut io = Box::new(DeltaIo {
        base: base.to_vec(),
        out: Vec::new(),
    });
    let fio = im_delta_io_t {
        read_base: Some(d_read),
        write: Some(d_write),
        ctx: (&mut *io as *mut DeltaIo).cast(),
    };
    let mut ctx = im_host::Opaque::new(unsafe { im_delta_ctx_size() });
    let mut work = vec![0u8; work_len];
    let r = unsafe { im_delta_init(ctx.ptr(), &fio, base.len() as u64, 0, work.as_mut_ptr(), work.len()) };
    assert_eq!(r, OK);
    for c in patch.chunks(chunk.max(1)) {
        let r = unsafe { im_delta_feed(ctx.ptr(), c.as_ptr(), c.len()) };
        if r != OK {
            unsafe { im_delta_abort(ctx.ptr()) };
            return Err(name(r));
        }
    }
    let r = unsafe { im_delta_finish(ctx.ptr()) };
    unsafe { im_delta_abort(ctx.ptr()) };
    if r != OK {
        return Err(name(r));
    }
    Ok(io.out)
}

const CHUNKS: [usize; 7] = [1, 2, 3, 91, 92, 4097, usize::MAX];

#[test]
fn delta_valid_files() {
    for f in [
        "delta_both_empty",
        "delta_empty_base",
        "delta_empty_target",
        "delta_identical",
        "delta_insert_shift",
        "delta_partial_tail",
        "delta_small_change",
    ] {
        let v = load(&format!("{f}.json"));
        let (old, new, patch) = (hx(&v["old_hex"]), hx(&v["new_hex"]), hx(&v["patch_hex"]));
        for chunk in CHUNKS {
            for work in [64usize, 1000, 4096] {
                let out = apply_c(&old, &patch, chunk.min(patch.len().max(1)), work).unwrap_or_else(|e| panic!("{f} chunk {chunk}: {e}"));
                assert_eq!(out, new, "{f} chunk {chunk} work {work}");
            }
        }
        assert_eq!(u(&v["header"]["target_size"]) as usize, new.len());
    }
}

#[test]
fn delta_invalid() {
    let v = load("delta_invalid.json");
    let shared = hx(&v["old_hex"]);
    assert_eq!(apply_c(&shared, &hx(&v["valid_patch_hex"]), 4096, 4096).unwrap(), hx(&v["new_hex"]));
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 16);
    for case in cases {
        let old = if case["old_hex"].is_null() {
            shared.clone()
        } else {
            hx(&case["old_hex"])
        };
        let patch = hx(&case["patch_hex"]);
        for chunk in CHUNKS {
            let r = apply_c(&old, &patch, chunk, 512);
            assert_eq!(r.err(), Some(s(&case["error"])), "{} (chunk {chunk})", s(&case["name"]));
        }
    }
}

// ---- hpke_rfc9180_a3.json ---------------------------------------------------------------------

fn pub_of(scalar: &[u8]) -> [u8; 65] {
    SoftIdentity::from_scalar(scalar).public_raw()
}

#[test]
fn hpke_rfc9180_a3_1() {
    let v = load("hpke_rfc9180_a3.json");
    let a = &v["rfc9180_a3_1"];
    // DeriveKeyPair (C) for both key pairs
    for (ikm, sk, pk) in [("ikmE", "skEm", "pkEm"), ("ikmR", "skRm", "pkRm")] {
        let ikm = hx(&a[ikm]);
        let mut out = [0u8; 32];
        assert_eq!(unsafe { im_hpke_derive_sk(ikm.as_ptr(), ikm.len(), out.as_mut_ptr()) }, OK);
        assert_eq!(hex::encode(out), s(&a[sk]));
        assert_eq!(hex::encode(pub_of(&out)), s(&a[pk]));
    }
    // Decap with the recipient identity (ECDH happens "inside the secure element")
    let id = SoftIdentity::from_scalar(&hx(&a["skRm"]));
    let idf = id.ffi();
    let enc = hx(&a["enc"]);
    let mut shared = [0u8; 32];
    assert_eq!(unsafe { im_hpke_decap(&idf, enc.as_ptr(), shared.as_mut_ptr()) }, OK);
    assert_eq!(hex::encode(shared), s(&a["shared_secret"]));
    let info = hx(&a["info"]);
    let mut ctx = im_hpke_ctx_t::default();
    assert_eq!(
        unsafe { im_hpke_key_schedule(shared.as_ptr(), info.as_ptr(), info.len(), &mut ctx) },
        OK
    );
    assert_eq!(hex::encode(ctx.key), s(&a["key"]));
    assert_eq!(hex::encode(ctx.base_nonce), s(&a["base_nonce"]));
    assert_eq!(hex::encode(ctx.exporter_secret), s(&a["exporter_secret"]));
    for e in a["encryptions"].as_array().unwrap() {
        let (pt, aad, ct) = (hx(&e["pt"]), hx(&e["aad"]), hx(&e["ct"]));
        let mut c2 = ctx;
        c2.seq = u(&e["sequence_number"]);
        let mut out = vec![0u8; pt.len() + 16];
        assert_eq!(
            unsafe { im_hpke_seal(&mut c2, aad.as_ptr(), aad.len(), pt.as_ptr(), pt.len(), out.as_mut_ptr()) },
            OK
        );
        assert_eq!(hex::encode(&out), s(&e["ct"]));
        let mut c3 = ctx;
        c3.seq = u(&e["sequence_number"]);
        let mut back = vec![0u8; pt.len()];
        assert_eq!(
            unsafe { im_hpke_open(&mut c3, aad.as_ptr(), aad.len(), ct.as_ptr(), ct.len(), back.as_mut_ptr()) },
            OK
        );
        assert_eq!(back, pt);
        assert_eq!(c3.seq, u(&e["sequence_number"]) + 1);
        // wrong aad -> HPKE_OPEN
        let mut c4 = ctx;
        c4.seq = u(&e["sequence_number"]);
        let r = unsafe { im_hpke_open(&mut c4, b"x".as_ptr(), 1, ct.as_ptr(), ct.len(), back.as_mut_ptr()) };
        assert_eq!(name(r), "HPKE_OPEN");
    }
    for e in a["exports"].as_array().unwrap() {
        let ec = hx(&e["exporter_context"]);
        let mut out = vec![0u8; u(&e["L"]) as usize];
        assert_eq!(
            unsafe { im_hpke_export(&ctx, ec.as_ptr(), ec.len(), out.as_mut_ptr(), out.len()) },
            OK
        );
        assert_eq!(hex::encode(&out), s(&e["exported_value"]));
    }
    // malformed enc
    let mut bad = enc.clone();
    bad[0] = 0x02;
    assert_eq!(name(unsafe { im_hpke_decap(&idf, bad.as_ptr(), shared.as_mut_ptr()) }), "HPKE_KEY");
    let mut bad = enc.clone();
    bad[64] ^= 1;
    assert_eq!(name(unsafe { im_hpke_decap(&idf, bad.as_ptr(), shared.as_mut_ptr()) }), "HPKE_KEY");
}

#[test]
fn hpke_config_encrypt0() {
    let v = load("hpke_rfc9180_a3.json");
    let c = &v["config_encrypt0"];
    let id = SoftIdentity::from_scalar(&hx(&c["device_key"]["private_scalar_hex"]));
    let idf = id.ffi();
    let wire = hx(&c["encrypt0_hex"]);
    let mut pt = vec![0u8; wire.len()];
    let mut n = 0usize;
    assert_eq!(
        unsafe { im_config_unwrap(wire.as_ptr(), wire.len(), &idf, pt.as_mut_ptr(), pt.len(), &mut n) },
        OK
    );
    assert_eq!(hex::encode(&pt[..n]), s(&c["plaintext_hex"]));
    for neg in c["negative"].as_array().unwrap() {
        let w = hx(&neg["encrypt0_hex"]);
        let key = if s(&neg["name"]).contains("wrong recipient") {
            &c["wrong_device_key"]
        } else {
            &c["device_key"]
        };
        let id2 = SoftIdentity::from_scalar(&hx(&key["private_scalar_hex"]));
        let idf2 = id2.ffi();
        let r = unsafe { im_config_unwrap(w.as_ptr(), w.len(), &idf2, pt.as_mut_ptr(), pt.len(), &mut n) };
        assert_eq!(name(r), s(&neg["error"]), "{}", s(&neg["name"]));
    }
    // Reproduce the Encrypt0 byte for byte: ephemeral key from ikm (C DeriveKeyPair), shared
    // secret via the recipient decap (DH is symmetric), C key schedule + seal, C encoder.
    let ikm = hx(&c["ephemeral_ikm_hex"]);
    let mut ske = [0u8; 32];
    assert_eq!(unsafe { im_hpke_derive_sk(ikm.as_ptr(), ikm.len(), ske.as_mut_ptr()) }, OK);
    let enc = pub_of(&ske);
    assert_eq!(hex::encode(enc), s(&c["enc_hex"]));
    let mut shared = [0u8; 32];
    assert_eq!(unsafe { im_hpke_decap(&idf, enc.as_ptr(), shared.as_mut_ptr()) }, OK);
    let info = hx(&c["hpke_info_hex"]);
    let mut ctx = im_hpke_ctx_t::default();
    assert_eq!(
        unsafe { im_hpke_key_schedule(shared.as_ptr(), info.as_ptr(), info.len(), &mut ctx) },
        OK
    );
    let aad = hx(&c["enc_structure_hex"]);
    let cek = hx(&c["cek_hex"]);
    let mut wrapped = [0u8; 48];
    assert_eq!(
        unsafe { im_hpke_seal(&mut ctx, aad.as_ptr(), aad.len(), cek.as_ptr(), cek.len(), wrapped.as_mut_ptr()) },
        OK
    );
    assert_eq!(hex::encode(wrapped), s(&c["wrapped_key_hex"]));
    let ct = hx(&c["ciphertext_hex"]);
    let iv = hx(&c["iv_hex"]);
    let mut out = vec![0u8; wire.len() + 16];
    let r = unsafe {
        im_cose_encrypt0_encode(
            iv.as_ptr(),
            enc.as_ptr(),
            wrapped.as_ptr(),
            ct.as_ptr(),
            ct.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut n,
        )
    };
    assert_eq!(r, OK);
    assert_eq!(hex::encode(&out[..n]), s(&c["encrypt0_hex"]));
    // The plaintext is a tenant-signed Config envelope: verify it as a downlink message.
    let pm = &c["plaintext_message"];
    let tenant = load("envelope_command_ack.json");
    let mut res = StaticResolver::default();
    res.add_ed25519(s(&tenant["tenant_kid"]), &hx(&tenant["tenant_key"]["public_raw_hex"]));
    let mut d = Decoder::new(res);
    let msg = d
        .decode(&hx(&c["plaintext_hex"]), u(&pm["ts"]), Some(s(&tenant["tenant_id"])), None, 300)
        .expect("config envelope");
    assert_eq!(msg.type_, 9);
    // and the payload is reproduced by the C body encoder
    let settings = cbor_json(&pm["body"]["settings"]);
    let mut e = Enc::new(256);
    unsafe {
        im_env_payload_begin(&mut e.e, u(&pm["seq"]), u(&pm["ts"]), 9, false);
        im_body_config(&mut e.e, u(&pm["body"]["version"]), settings.as_ptr(), settings.len());
        assert_eq!(im_env_payload_end(&mut e.e, ptr::null(), &mut n), OK);
    }
    assert_eq!(hex::encode(e.bytes()), s(&pm["payload_hex"]));
}

// ---- ids_topics.json ----------------------------------------------------------------------------

fn id_ok(f: unsafe extern "C" fn(*const core::ffi::c_char, usize) -> bool, x: &str) -> bool {
    unsafe { f(x.as_ptr().cast(), x.len()) }
}

#[test]
fn ids_topics() {
    let v = load("ids_topics.json");
    let ids = &v["identifiers"];
    type IdFn = unsafe extern "C" fn(*const core::ffi::c_char, usize) -> bool;
    let table: [(&str, IdFn); 4] = [
        ("tenant", im_id_is_uuid4),
        ("device", im_id_is_device_id),
        ("group", im_id_is_group_slug),
        ("firmware_id", im_id_is_firmware_id),
    ];
    for (k, f) in table {
        for x in ids[format!("{k}_valid")].as_array().unwrap() {
            assert!(id_ok(f, s(x)), "{k} valid {x}");
        }
        for x in ids[format!("{k}_invalid")].as_array().unwrap() {
            assert!(!id_ok(f, s(x)), "{k} invalid {x}");
        }
    }
    let k = &v["key_ids"];
    let serial = hx(&k["device_serial_hex"]);
    let mut kid = [0u8; 20];
    let mut n = 0usize;
    assert_eq!(
        unsafe { im_id_kid_from_serial(serial.as_ptr(), serial.len(), kid.as_mut_ptr(), 20, &mut n) },
        OK
    );
    assert_eq!(hex::encode(&kid[..n]), s(&k["device_kid_hex"]));
    let lz = [0x00u8, 0xff];
    assert_eq!(unsafe { im_id_kid_from_serial(lz.as_ptr(), 2, kid.as_mut_ptr(), 20, &mut n) }, OK);
    assert_eq!(hex::encode(&kid[..n]), s(&k["device_kid_leading_zero_stripped_hex"]));
    assert!(unsafe { im_id_is_device_kid(kid.as_ptr(), n) });
    assert!(!unsafe { im_id_is_device_kid(lz.as_ptr(), 2) });
    let tenant = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11";
    let mut tk = [0i8; 64];
    assert_eq!(
        unsafe { im_id_tenant_kid(tenant.as_ptr().cast(), tenant.len(), tk.as_mut_ptr().cast(), 64) },
        OK
    );
    let built = unsafe { std::ffi::CStr::from_ptr(tk.as_ptr().cast()) }
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(built, s(&k["tenant_kid"]));

    let topics = v["topics"].as_array().unwrap();
    assert_eq!(topics.len(), 9);
    let device = "dev-8f3a1c2b9d4e5f60";
    for t in topics {
        let topic = s(&t["topic"]);
        let mut parsed = im_topic_t {
            tenant: ptr::null(),
            device: ptr::null(),
            cls: -1,
        };
        assert_eq!(
            unsafe { im_topic_parse(topic.as_ptr().cast(), topic.len(), &mut parsed) },
            OK,
            "{topic}"
        );
        let suffix = unsafe { std::ffi::CStr::from_ptr(im_topic_suffix(parsed.cls)) }.to_str().unwrap();
        assert_eq!(suffix, s(&t["suffix"]));
        assert_eq!(unsafe { im_topic_message_type(parsed.cls) } as u64, u(&t["message_type"]));
        assert_eq!(
            unsafe { im_topic_device_publishes(parsed.cls) },
            t["device_publishes"].as_bool().unwrap()
        );
        assert_eq!(
            unsafe { im_topic_retained_allowed(parsed.cls) },
            t["retained_allowed"].as_bool().unwrap()
        );
        assert_eq!(s(&t["direction"]) == "uplink", t["device_publishes"].as_bool().unwrap());
        assert_eq!(u(&t["qos"]), 1);
        let (tc, dc) = (cstr(tenant), cstr(device));
        let mut out = [0i8; 128];
        let mut olen = 0usize;
        assert_eq!(
            unsafe { im_topic_build(tc.as_ptr(), dc.as_ptr(), parsed.cls, out.as_mut_ptr().cast(), out.len(), &mut olen) },
            OK
        );
        let b = unsafe { std::ffi::CStr::from_ptr(out.as_ptr().cast()) }.to_str().unwrap();
        assert_eq!(b, topic);
        let pubs = unsafe { im_topic_device_may_publish(topic.as_ptr().cast(), topic.len(), dc.as_ptr()) };
        let subs = unsafe { im_topic_device_may_subscribe(topic.as_ptr().cast(), topic.len(), dc.as_ptr()) };
        assert_eq!(pubs, t["device_publishes"].as_bool().unwrap());
        assert_eq!(subs, !t["device_publishes"].as_bool().unwrap());
        let other = cstr("dev-0000000000000000");
        assert!(!unsafe { im_topic_device_may_publish(topic.as_ptr().cast(), topic.len(), other.as_ptr()) });
    }
    for t in v["invalid_topics"].as_array().unwrap() {
        let topic = s(t);
        let mut parsed = im_topic_t {
            tenant: ptr::null(),
            device: ptr::null(),
            cls: -1,
        };
        let r = unsafe { im_topic_parse(topic.as_ptr().cast(), topic.len(), &mut parsed) };
        assert_eq!(name(r), "TOPIC_FORMAT", "{topic}");
    }
    assert_eq!(s(&v["bridge_shared_subscription"]), "$share/bridge/im/v1/#");
}
