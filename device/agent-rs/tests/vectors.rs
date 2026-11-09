//! Conformance: every file in `device/common/vectors/` (see its README for the expected use of
//! each field). Deterministic vectors are reproduced byte-for-byte; ES256 / ML-DSA vectors are
//! verified.

use std::path::PathBuf;

use ironmesh_agent::wire::attestation::{self, VerifyAttestation};
use ironmesh_agent::wire::cbor::{self, DecodeLimits, Value};
use ironmesh_agent::wire::cose::{self, Kid};
use ironmesh_agent::wire::delta;
use ironmesh_agent::wire::envelope::SeType;
use ironmesh_agent::wire::envelope::{self, Body, Command, CommandAck, Config, DecodeOptions, InMemoryReplayStore, Message, Telemetry};
use ironmesh_agent::wire::hpke;
use ironmesh_agent::wire::ids::{self, Direction, TopicClass};
use ironmesh_agent::wire::keys::{CoseSigner, PublicKey};
use ironmesh_agent::wire::manifest::{self, DeltaInfo, Manifest};
use ironmesh_agent::wire::ErrorCode;
use serde_json::Value as J;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("common").join("vectors")
}

fn load(name: &str) -> J {
    let path = vectors_dir().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let v: J = serde_json::from_str(&text).unwrap();
    assert_eq!(v["schema_version"], 1, "{name}");
    v
}

fn hx(v: &J) -> Vec<u8> {
    hex::decode(v.as_str().unwrap_or_else(|| panic!("not a hex string: {v}"))).unwrap()
}

fn s(v: &J) -> &str {
    v.as_str().unwrap()
}

fn u(v: &J) -> u64 {
    v.as_u64().unwrap()
}

fn p256_signer(key: &J) -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&hx(&key["private_scalar_hex"])).unwrap()
}

fn p256_public(key: &J) -> PublicKey {
    let pk = PublicKey::p256_from_sec1(&hx(&key["public_raw_hex"])).unwrap();
    // The PEM and the raw form must agree.
    use p256::pkcs8::DecodePublicKey;
    let pem = p256::ecdsa::VerifyingKey::from_public_key_pem(s(&key["public_pem"])).unwrap();
    assert_eq!(PublicKey::P256(pem), pk);
    assert_eq!(PublicKey::P256(*p256_signer(key).verifying_key()), pk);
    pk
}

fn ed_signer(key: &J) -> ed25519_dalek::SigningKey {
    let seed: [u8; 32] = hx(&key["private_seed_hex"]).try_into().unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    assert_eq!(sk.verifying_key().to_bytes().to_vec(), hx(&key["public_raw_hex"]));
    sk
}

fn ed_public(key: &J) -> PublicKey {
    PublicKey::ed25519_from_raw(&hx(&key["public_raw_hex"])).unwrap()
}

fn json_to_cbor(v: &J) -> Value {
    match v {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => {
            n.as_i64().map(Value::int).or_else(|| n.as_u64().map(Value::int)).unwrap_or_else(|| Value::Float(n.as_f64().unwrap()))
        }
        J::String(t) => Value::text(t.clone()),
        J::Array(a) => Value::Array(a.iter().map(json_to_cbor).collect()),
        J::Object(o) => Value::Map(o.iter().map(|(k, v)| (Value::text(k.clone()), json_to_cbor(v))).collect()),
    }
}

fn app_map(v: &J) -> Vec<(String, Value)> {
    // Canonical order, exactly as a decoder would return it.
    let enc = cbor::encode(&json_to_cbor(v)).unwrap();
    match cbor::decode(&enc).unwrap() {
        Value::Map(m) => m.into_iter().map(|(k, v)| (k.as_text().unwrap().to_owned(), v)).collect(),
        _ => unreachable!(),
    }
}

fn opt_u(v: &J) -> Option<u64> {
    v.as_u64()
}

fn lim() -> DecodeLimits {
    DecodeLimits::default()
}

// ---------------------------------------------------------------------------------------------

#[test]
fn cbor_canonical() {
    let v = load("cbor_canonical.json");
    assert_eq!(u(&v["limits"]["max_size"]) as usize, cbor::DEFAULT_MAX_SIZE);
    assert_eq!(u(&v["limits"]["max_depth"]) as usize, cbor::DEFAULT_MAX_DEPTH);
    let tags: Vec<u64> = v["limits"]["allowed_tags"].as_array().unwrap().iter().map(u).collect();
    assert_eq!(tags, vec![16, 18, 98]);
    let valid = v["valid"].as_array().unwrap();
    assert!(!valid.is_empty());
    for case in valid {
        let name = s(&case["name"]);
        let bytes = hx(&case["hex"]);
        let decoded = cbor::decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(cbor::encode(&decoded).unwrap(), bytes, "{name}: re-encode");
        let parsed = cbor::parse_diagnostic(s(&case["diag"])).unwrap_or_else(|e| panic!("{name}: diag {e}"));
        assert_eq!(cbor::encode(&parsed).unwrap(), bytes, "{name}: encode(diag)");
    }
    let invalid = v["invalid"].as_array().unwrap();
    assert!(!invalid.is_empty());
    for case in invalid {
        let name = s(&case["name"]);
        let e = cbor::decode(&hx(&case["hex"])).expect_err(name);
        assert_eq!(e.code().as_str(), s(&case["error"]), "{name}: {e}");
    }
}

fn cose_sign1_file(file: &str, eddsa: bool) {
    let v = load(file);
    let kid = if eddsa { Kid::Text(s(&v["kid"]).to_owned()) } else { Kid::Bytes(hx(&v["kid_hex"])) };
    let (key, wrong) =
        if eddsa { (ed_public(&v["key"]), ed_public(&v["wrong_key"])) } else { (p256_public(&v["key"]), p256_public(&v["wrong_key"])) };
    let cases = v["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let name = s(&case["name"]);
        let msg = cose::sign1_decode(&hx(&case["message_hex"]), lim()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(msg.protected, hx(&case["protected_hex"]), "{name}");
        assert_eq!(msg.payload, hx(&case["payload_hex"]), "{name}");
        assert_eq!(msg.signature, hx(&case["signature_hex"]), "{name}");
        assert_eq!(msg.to_be_signed().unwrap(), hx(&case["sig_structure_hex"]), "{name}");
        assert_eq!(msg.kid, kid, "{name}");
        cose::sign1_verify(&msg, &key).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(cose::encode_protected(key.alg(), &kid).unwrap(), msg.protected);
        if eddsa {
            let sk = ed_signer(&v["key"]);
            assert_eq!(cose::sign1_encode(&msg.payload, &sk, &kid).unwrap(), hx(&case["message_hex"]), "{name}: deterministic");
        } else {
            // Regenerate (randomised) and verify our own output.
            let sk = p256_signer(&v["key"]);
            let ours = cose::sign1_encode(&msg.payload, &sk, &kid).unwrap();
            cose::sign1_verify(&cose::sign1_decode(&ours, lim()).unwrap(), &key).unwrap();
        }
    }
    let negative = v["negative"].as_array().unwrap();
    assert!(!negative.is_empty());
    for case in negative {
        let name = s(&case["name"]);
        let k = if s(&case["verify_with"]) == "key" { &key } else { &wrong };
        let result = cose::sign1_decode(&hx(&case["message_hex"]), lim()).and_then(|m| cose::sign1_verify(&m, k));
        let e = result.expect_err(name);
        assert_eq!(e.code().as_str(), s(&case["error"]), "{name}: {e}");
    }
}

#[test]
fn cose_sign1_es256() {
    cose_sign1_file("cose_sign1_es256.json", false);
}

#[test]
fn cose_sign1_eddsa() {
    cose_sign1_file("cose_sign1_eddsa.json", true);
}

fn telemetry_from(b: &J) -> Telemetry {
    Telemetry {
        cpu_pct: b["cpu_pct"].as_f64().unwrap(),
        mem_pct: b["mem_pct"].as_f64().unwrap(),
        net_rx_bytes: u(&b["net_rx_bytes"]),
        net_tx_bytes: u(&b["net_tx_bytes"]),
        temp_c: b["temp_c"].as_f64().unwrap(),
        uptime_s: u(&b["uptime_s"]),
        auth_failures: u(&b["auth_failures"]),
        fw_hash: hx(&b["fw_hash_hex"]).try_into().unwrap(),
        fw_version: s(&b["fw_version"]).to_owned(),
        proc_count: opt_u(&b["proc_count"]),
        top_procs: b["top_procs"].as_array().map(|a| a.iter().map(|x| s(x).to_owned()).collect()),
        rssi: b["rssi"].as_i64(),
        free_heap: opt_u(&b["free_heap"]),
        lat: b["lat"].as_f64(),
        lon: b["lon"].as_f64(),
    }
}

#[test]
fn envelope_telemetry() {
    let v = load("envelope_telemetry.json");
    let m = &v["message"];
    let msg = Message { seq: u(&m["seq"]), ts: u(&m["ts"]), body: Body::Telemetry(telemetry_from(&m["body"])), nonce: None };
    assert_eq!(u(&m["type"]), 1);
    assert_eq!(envelope::encode_payload(&msg).unwrap(), hx(&m["payload_hex"]));
    let key = p256_public(&v["device_key"]);
    let kid = hx(&v["kid_hex"]);
    assert_eq!(ids::kid_from_serial(&hx(&v["cert_serial_hex"])).unwrap(), kid);
    let mut store = InMemoryReplayStore::new();
    let opts = DecodeOptions { now: u(&v["now"]), ..Default::default() };
    let verified = envelope::decode(&hx(&m["wire_hex"]), &|_| Some(key.clone()), &mut store, &opts).unwrap();
    assert_eq!(verified.message, msg);
    assert_eq!(verified.sender_kid, Kid::Bytes(kid.clone()));
    assert_eq!(s(&v["expect"]), "accept");
    let parsed = cose::sign1_decode(&hx(&m["wire_hex"]), lim()).unwrap();
    assert_eq!(parsed.protected, hx(&m["protected_hex"]));
    assert_eq!(parsed.to_be_signed().unwrap(), hx(&m["sig_structure_hex"]));
    assert_eq!(parsed.signature, hx(&m["signature_hex"]));
    let topic = ids::build_topic(s(&v["tenant_id"]), s(&v["device_id"]), TopicClass::Telemetry).unwrap();
    assert_eq!(topic, s(&v["topic"]));
    // Our own (randomised) signature verifies too.
    let ours = envelope::encode(&msg, &p256_signer(&v["device_key"]), &Kid::Bytes(kid)).unwrap();
    let mut store = InMemoryReplayStore::new();
    envelope::decode(&ours, &|_| Some(key.clone()), &mut store, &opts).unwrap();
}

#[test]
fn envelope_command_ack() {
    let v = load("envelope_command_ack.json");
    let tenant = s(&v["tenant_id"]);
    let tkid = Kid::Text(s(&v["tenant_kid"]).to_owned());
    assert_eq!(ids::tenant_kid(tenant).unwrap(), s(&v["tenant_kid"]));
    let tsk = ed_signer(&v["tenant_key"]);
    let tpk = ed_public(&v["tenant_key"]);
    let dpk = p256_public(&v["device_key"]);
    let now = u(&v["now"]);

    let c = &v["command"];
    let b = &c["body"];
    let nonce: [u8; 16] = hx(&c["nonce_hex"]).try_into().unwrap();
    let command = Message {
        seq: u(&c["seq"]),
        ts: u(&c["ts"]),
        body: Body::Command(Command {
            cmd_id: s(&b["cmd_id"]).to_owned(),
            name: s(&b["name"]).to_owned(),
            args: app_map(&b["args"]),
            idempotency_key: s(&b["idempotency_key"]).to_owned(),
            expires_at: u(&b["expires_at"]),
        }),
        nonce: Some(nonce),
    };
    assert_eq!(envelope::encode_payload(&command).unwrap(), hx(&c["payload_hex"]));
    let wire = envelope::encode(&command, &tsk, &tkid).unwrap();
    assert_eq!(wire, hx(&c["wire_hex"]), "deterministic tenant signature");
    let mut store = InMemoryReplayStore::new();
    let opts = DecodeOptions { now, expected_tenant: Some(tenant), expected_direction: Some(Direction::Downlink), ..Default::default() };
    let got = envelope::decode(&wire, &|_| Some(tpk.clone()), &mut store, &opts).unwrap();
    assert_eq!(got.message, command);

    let a = &v["ack"];
    let ab = &a["body"];
    let ack = Message {
        seq: u(&a["seq"]),
        ts: u(&a["ts"]),
        body: Body::CommandAck(CommandAck {
            cmd_id: s(&ab["cmd_id"]).to_owned(),
            status: u(&ab["status"]) as u8,
            result: (!ab["result"].is_null()).then(|| app_map(&ab["result"])),
            error: ab["error"].as_str().map(str::to_owned),
        }),
        nonce: Some(hx(&a["nonce_hex"]).try_into().unwrap()),
    };
    assert_eq!(envelope::encode_payload(&ack).unwrap(), hx(&a["payload_hex"]));
    let opts = DecodeOptions { now, expected_nonce: Some(nonce), expected_direction: Some(Direction::Uplink), ..Default::default() };
    let got = envelope::decode(&hx(&a["wire_hex"]), &|_| Some(dpk.clone()), &mut store, &opts).unwrap();
    assert_eq!(got.message, ack);
    envelope::check_ack(&command, &got.message).unwrap();

    let bad = &v["ack_bad_nonce"];
    let opts = DecodeOptions { now, expected_nonce: Some(hx(&bad["expected_nonce_hex"]).try_into().unwrap()), ..Default::default() };
    let mut store = InMemoryReplayStore::new();
    let e = envelope::decode(&hx(&bad["wire_hex"]), &|_| Some(dpk.clone()), &mut store, &opts).unwrap_err();
    assert_eq!(e.code().as_str(), s(&bad["error"]));
    assert_eq!(store.last_for_direction(Direction::Uplink), None, "rejected messages never advance the store");
}

#[test]
fn manifest_signed() {
    let v = load("manifest_signed.json");
    let mj = &v["manifest"];
    let m = Manifest {
        product: s(&mj["product"]).to_owned(),
        version: s(&mj["version"]).to_owned(),
        version_code: u(&mj["version_code"]),
        image_sha256: hx(&mj["image_sha256_hex"]).try_into().unwrap(),
        image_size: u(&mj["image_size"]),
        created_at: u(&mj["created_at"]),
        min_version_code: u(&mj["min_version_code"]),
        delta: (!mj["delta"].is_null()).then(|| DeltaInfo {
            base_sha256: hx(&mj["delta"]["base_sha256_hex"]).try_into().unwrap(),
            patch_sha256: hx(&mj["delta"]["patch_sha256_hex"]).try_into().unwrap(),
            patch_size: u(&mj["delta"]["patch_size"]),
        }),
        signing_key_id: s(&mj["signing_key_id"]).to_owned(),
    };
    let bytes = manifest::encode_manifest(&m).unwrap();
    assert_eq!(bytes, hx(&v["manifest_hex"]));
    assert_eq!(manifest::decode_manifest(&bytes, lim()).unwrap(), m);
    let sk = ed_signer(&v["ed25519_key"]);
    assert_eq!(hex::encode(ironmesh_agent::wire::keys::fw_key_id(sk.verifying_key().as_bytes())), s(&v["ed25519_key"]["kid_hex"]));
    assert_eq!(
        hex::encode(ironmesh_agent::wire::keys::fw_key_id(&hx(&v["mldsa65_key"]["public_raw_hex"]))),
        s(&v["mldsa65_key"]["kid_hex"])
    );
    let signed = manifest::sign_manifest(&bytes, &sk, None).unwrap();
    assert_eq!(signed, hx(&v["signed_ed25519_only_hex"]), "deterministic Ed25519 manifest");
    let parsed = cose::sign_decode(&signed, lim()).unwrap();
    let sig = parsed.signature_for(-8).unwrap();
    assert_eq!(sig.protected, hx(&v["ed25519_signature"]["protected_hex"]));
    assert_eq!(parsed.to_be_signed(sig).unwrap(), hx(&v["ed25519_signature"]["sig_structure_hex"]));
    assert_eq!(sig.signature, hx(&v["ed25519_signature"]["signature_hex"]));
    assert_eq!(sk.sign(&parsed.to_be_signed(sig).unwrap()).unwrap(), sig.signature);

    let trusted: Vec<Vec<u8>> = v["trusted_pubkeys_hex"].as_array().unwrap().iter().map(hx).collect();
    let mut ran_hybrid = false;
    for case in v["verify_cases"].as_array().unwrap() {
        let name = s(&case["name"]);
        let require_pq = case["require_pq"].as_bool().unwrap();
        let result = manifest::verify_manifest(&hx(&case["signed_hex"]), &trusted, require_pq, lim());
        if name.contains("hybrid") {
            ran_hybrid = true;
        }
        if s(&case["expect"]) == "accept" {
            let vm = result.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(vm.manifest, m, "{name}");
            assert_eq!(vm.pq_verified, require_pq, "{name}");
        } else {
            let e = result.expect_err(name);
            assert_eq!(e.code().as_str(), s(&case["error"]), "{name}: {e}");
        }
    }
    assert!(ran_hybrid && !v["signed_hybrid_hex"].is_null(), "the hybrid ML-DSA-65 vectors must be exercised");
    // Hybrid without require_pq: ML-DSA is verified opportunistically.
    let hybrid = manifest::verify_manifest(&hx(&v["signed_hybrid_hex"]), &trusted, false, lim()).unwrap();
    assert!(hybrid.pq_verified);

    let image = hx(&v["image_hex"]);
    assert_eq!(manifest::accept_image(&m, &image, 20400, "gateway-rpi"), Ok(()));
    for case in v["acceptance_cases"].as_array().unwrap() {
        let name = s(&case["name"]);
        let r = manifest::accept_image(&m, &hx(&case["image_hex"]), u(&case["current_version_code"]), s(&case["product"]));
        if case["accepted"].as_bool().unwrap() {
            assert_eq!(r, Ok(()), "{name}");
        } else {
            assert_eq!(r.unwrap_err().as_str(), s(&case["reason"]), "{name}");
        }
    }
}

#[test]
fn delta_vectors() {
    let mut files: Vec<_> = std::fs::read_dir(vectors_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("delta_") && n != "delta_invalid.json")
        .collect();
    files.sort();
    assert!(files.len() >= 7, "{files:?}");
    for file in files {
        let v = load(&file);
        let old = hx(&v["old_hex"]);
        let new = hx(&v["new_hex"]);
        let patch = hx(&v["patch_hex"]);
        assert_eq!(u(&v["block_size"]) as usize, delta::BLOCK_SIZE);
        assert_eq!(delta::make_delta(&old, &new), patch, "{file}: reference encoder");
        assert_eq!(delta::apply_delta(&old, &patch, delta::DEFAULT_MAX_TARGET_SIZE).unwrap(), new, "{file}");
        let (h, copies, literal) = delta::inspect_delta(&patch).unwrap();
        assert_eq!(copies, u(&v["copy_ops"]), "{file}");
        assert_eq!(literal, u(&v["literal_bytes"]), "{file}");
        assert_eq!(h.base_size, u(&v["header"]["base_size"]));
        assert_eq!(h.target_size, u(&v["header"]["target_size"]));
        assert_eq!(h.base_sha256.to_vec(), hx(&v["header"]["base_sha256_hex"]));
        assert_eq!(h.target_sha256.to_vec(), hx(&v["header"]["target_sha256_hex"]));
        for chunk in [1usize, 2, 3, 7, 64, 91, 92, 93, 4095, 4096, 4097, 65536] {
            let mut out = Vec::new();
            let mut a = delta::DeltaApplier::new(
                &old[..],
                old.len() as u64,
                |d: &[u8]| {
                    out.extend_from_slice(d);
                    Ok(())
                },
                delta::DEFAULT_MAX_TARGET_SIZE,
            );
            for c in patch.chunks(chunk) {
                a.feed(c).unwrap();
            }
            a.finish().unwrap();
            assert_eq!(out, new, "{file} chunk {chunk}");
        }
    }

    let v = load("delta_invalid.json");
    let shared_old = hx(&v["old_hex"]);
    assert_eq!(delta::apply_delta(&shared_old, &hx(&v["valid_patch_hex"]), delta::DEFAULT_MAX_TARGET_SIZE).unwrap(), hx(&v["new_hex"]));
    for case in v["cases"].as_array().unwrap() {
        let name = s(&case["name"]);
        let old = if case["old_hex"].is_null() { shared_old.clone() } else { hx(&case["old_hex"]) };
        let patch = hx(&case["patch_hex"]);
        for chunk in [1usize, 5, 92, 1000, patch.len().max(1)] {
            let mut a = delta::DeltaApplier::new(&old[..], old.len() as u64, |_d: &[u8]| Ok(()), delta::DEFAULT_MAX_TARGET_SIZE);
            let mut result = Ok(());
            for c in patch.chunks(chunk) {
                result = a.feed(c);
                if result.is_err() {
                    break;
                }
            }
            let code = match result {
                Err(e) => e.code(),
                Ok(()) => a.finish().err().and_then(|e| e.code()),
            };
            assert_eq!(code.map(ErrorCode::as_str), Some(s(&case["error"])), "{name} chunk {chunk}");
        }
    }
}

#[test]
fn hpke_rfc9180_a3() {
    let v = load("hpke_rfc9180_a3.json");
    let r = &v["rfc9180_a3_1"];
    assert_eq!((u(&r["mode"]), u(&r["kem_id"]), u(&r["kdf_id"]), u(&r["aead_id"])), (0, 16, 1, 1));
    let sk_r = hpke::derive_key_pair(&hx(&r["ikmR"])).unwrap();
    assert_eq!(sk_r.to_bytes().to_vec(), hx(&r["skRm"]));
    assert_eq!(hpke::EcdhRecipient::public_key_sec1(&sk_r), hx(&r["pkRm"]));
    let sk_e = hpke::derive_key_pair(&hx(&r["ikmE"])).unwrap();
    assert_eq!(sk_e.to_bytes().to_vec(), hx(&r["skEm"]));
    assert_eq!(hpke::EcdhRecipient::public_key_sec1(&sk_e), hx(&r["pkEm"]));
    let (ss, enc) = hpke::encap(&sk_r.public_key(), Some(&hx(&r["ikmE"]))).unwrap();
    assert_eq!(enc, hx(&r["enc"]));
    assert_eq!(ss.to_vec(), hx(&r["shared_secret"]));
    assert_eq!(hpke::decap(&enc, &sk_r).unwrap().to_vec(), hx(&r["shared_secret"]));
    let info = hx(&r["info"]);
    assert_eq!(hpke::key_schedule_context(&info), hx(&r["key_schedule_context"]));
    assert_eq!(hpke::key_schedule_secret(&ss), hx(&r["secret"]));
    let (_, mut sender) = hpke::setup_base_s(&sk_r.public_key(), &info, Some(&hx(&r["ikmE"]))).unwrap();
    let mut receiver = hpke::setup_base_r(&enc, &sk_r, &info).unwrap();
    assert_eq!(sender.key(), hx(&r["key"]));
    assert_eq!(sender.base_nonce(), hx(&r["base_nonce"]));
    assert_eq!(sender.exporter_secret(), hx(&r["exporter_secret"]));
    for e in r["encryptions"].as_array().unwrap() {
        let seq = u128::from(u(&e["sequence_number"]));
        sender.set_seq(seq);
        receiver.set_seq(seq);
        let ct = sender.seal(&hx(&e["aad"]), &hx(&e["pt"])).unwrap();
        assert_eq!(ct, hx(&e["ct"]), "seq {seq}");
        assert_eq!(receiver.open(&hx(&e["aad"]), &ct).unwrap().to_vec(), hx(&e["pt"]));
    }
    for e in r["exports"].as_array().unwrap() {
        let out = sender.export(&hx(&e["exporter_context"]), u(&e["L"]) as usize).unwrap();
        assert_eq!(out.to_vec(), hx(&e["exported_value"]));
    }

    let c = &v["config_encrypt0"];
    assert_eq!(hx(&c["hpke_info_hex"]), hpke::CONFIG_HPKE_INFO);
    assert_eq!(s(&c["hpke_info_ascii"]).as_bytes(), hpke::CONFIG_HPKE_INFO);
    let dev = p256::SecretKey::from_slice(&hx(&c["device_key"]["private_scalar_hex"])).unwrap();
    assert_eq!(cose::enc_structure0(&hx(&c["protected_hex"])).unwrap(), hx(&c["enc_structure_hex"]));
    let pt = hpke::unwrap_config(&hx(&c["encrypt0_hex"]), &dev, lim()).unwrap();
    assert_eq!(pt.to_vec(), hx(&c["plaintext_hex"]));
    let wrapped = hpke::wrap_config(
        &hx(&c["plaintext_hex"]),
        &dev.public_key(),
        Some(&hx(&c["cek_hex"])),
        Some(&hx(&c["iv_hex"])),
        Some(&hx(&c["ephemeral_ikm_hex"])),
    )
    .unwrap();
    assert_eq!(wrapped, hx(&c["encrypt0_hex"]), "deterministic Encrypt0");
    let parsed = cose::encrypt0_decode(&wrapped, lim()).unwrap();
    assert_eq!(parsed.enc, hx(&c["enc_hex"]));
    assert_eq!(parsed.wrapped_key, hx(&c["wrapped_key_hex"]));
    assert_eq!(parsed.ciphertext, hx(&c["ciphertext_hex"]));
    let wrong = p256::SecretKey::from_slice(&hx(&c["wrong_device_key"]["private_scalar_hex"])).unwrap();
    for n in c["negative"].as_array().unwrap() {
        // The file carries no key selector; like the reference consumer, key on the case name.
        let key = if s(&n["name"]) == "wrong recipient key" { &wrong } else { &dev };
        let e = hpke::unwrap_config(&hx(&n["encrypt0_hex"]), key, lim()).unwrap_err();
        assert_eq!(e.code().as_str(), s(&n["error"]), "{}", s(&n["name"]));
    }
    // The plaintext is a tenant-signed Config envelope (deterministic).
    let tenant = load("envelope_command_ack.json");
    let tsk = ed_signer(&tenant["tenant_key"]);
    let pm = &c["plaintext_message"];
    let cfg = Message {
        seq: u(&pm["seq"]),
        ts: u(&pm["ts"]),
        body: Body::Config(Config { version: u(&pm["body"]["version"]), settings: app_map(&pm["body"]["settings"]) }),
        nonce: None,
    };
    assert_eq!(envelope::encode_payload(&cfg).unwrap(), hx(&pm["payload_hex"]));
    let tkid = Kid::Text(s(&tenant["tenant_kid"]).to_owned());
    assert_eq!(envelope::encode(&cfg, &tsk, &tkid).unwrap(), hx(&c["plaintext_hex"]));
    let tpk = ed_public(&tenant["tenant_key"]);
    let mut store = InMemoryReplayStore::new();
    let opts = DecodeOptions { now: u(&pm["ts"]), expected_direction: Some(Direction::Downlink), ..Default::default() };
    let got = envelope::decode(&pt, &|_| Some(tpk.clone()), &mut store, &opts).unwrap();
    assert_eq!(got.message, cfg);
}

#[test]
fn attestation_software() {
    let v = load("attestation_software.json");
    let key = p256_public(&v["device_key"]);
    let nonce = hx(&v["nonce_hex"]);
    let csr = hx(&v["csr_der_hex"]);
    let kid = hx(&v["kid_hex"]);
    let wire = hx(&v["message"]["wire_hex"]);
    let base = VerifyAttestation {
        identity_public_key: &key,
        expected_nonce: &nonce,
        csr_der: &csr,
        now: u(&v["now"]),
        expected_kid: Some(&kid),
        allowed_se_types: None,
    };
    let got = attestation::verify_attestation(&wire, &base).unwrap();
    let Body::Attestation(body) = &got.message.body else { panic!() };
    assert_eq!(body.csr_hash.to_vec(), hx(&v["csr_hash_hex"]));
    assert_eq!(body.se_type, SeType::Software);
    let mb = &v["message"]["body"];
    // Rebuild the payload deterministically.
    let ours = attestation::build_attestation(
        &p256_signer(&v["device_key"]),
        &Kid::Bytes(kid.clone()),
        u(&v["message"]["seq"]),
        u(&v["message"]["ts"]),
        &nonce.clone().try_into().unwrap(),
        &csr,
        &hx(&mb["fw_hash_hex"]).try_into().unwrap(),
        s(&mb["fw_version"]),
        SeType::parse(s(&mb["se_type"])).unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(cose::sign1_decode(&ours, lim()).unwrap().payload, hx(&v["message"]["payload_hex"]));
    attestation::verify_attestation(&ours, &base).unwrap();
    for n in v["negative"].as_array().unwrap() {
        let name = s(&n["name"]);
        let nonce2 = n.get("expected_nonce_hex").map(hx).unwrap_or_else(|| nonce.clone());
        let csr2 = n.get("csr_der_hex").map(hx).unwrap_or_else(|| csr.clone());
        let allowed: Option<Vec<SeType>> =
            n.get("allowed_se_types").map(|a| a.as_array().unwrap().iter().map(|x| SeType::parse(s(x)).unwrap()).collect());
        let opts = VerifyAttestation { expected_nonce: &nonce2, csr_der: &csr2, allowed_se_types: allowed.as_deref(), ..base };
        let e = attestation::verify_attestation(&wire, &opts).expect_err(name);
        assert_eq!(e.code().as_str(), s(&n["error"]), "{name}");
    }
}

#[test]
fn replay_cases() {
    let v = load("replay_cases.json");
    let tenant = s(&v["tenant_id"]).to_owned();
    let dkid = Kid::Bytes(hx(&v["device_kid_hex"]));
    let tkid = Kid::Text(s(&v["tenant_kid"]).to_owned());
    let dpk = p256_public(&v["device_key"]);
    let tpk = ed_public(&v["tenant_key"]);
    let _attacker = p256_public(&v["attacker_key"]);
    let resolver = |k: &Kid| {
        if *k == dkid {
            Some(dpk.clone())
        } else if *k == tkid {
            Some(tpk.clone())
        } else {
            None
        }
    };
    let mut store = InMemoryReplayStore::new();
    let steps = v["steps"].as_array().unwrap();
    assert!(steps.len() >= 20);
    for step in steps {
        let name = s(&step["name"]);
        let opts = DecodeOptions {
            now: u(&step["now"]),
            max_skew: Some(u(&v["max_skew"])),
            expected_tenant: Some(&tenant),
            expected_nonce: step.get("expected_nonce_hex").map(|n| hx(n).try_into().unwrap()),
            ..Default::default()
        };
        let result = envelope::decode(&hx(&step["wire_hex"]), &resolver, &mut store, &opts);
        match s(&step["expect"]) {
            "accept" => {
                result.unwrap_or_else(|e| panic!("{name}: {e}"));
            }
            _ => {
                let e = result.expect_err(name);
                assert_eq!(e.code().as_str(), s(&step["error"]), "{name}: {e}");
            }
        }
        use ironmesh_agent::wire::envelope::ReplayStore;
        assert_eq!(store.last_seq(&dkid, Direction::Uplink), opt_u(&step["store_after"]["uplink_last_seq"]), "{name}: uplink store");
        let stream = |t: &str| envelope::replay_stream(&tkid, Direction::Downlink, t.parse().unwrap());
        assert_eq!(
            store.last_seq(&stream("5"), Direction::Downlink),
            opt_u(&step["store_after"]["downlink_last_seq"]),
            "{name}: command stream"
        );
        let by_type = step["store_after"]["downlink_last_seq_by_type"].as_object().expect("downlink_last_seq_by_type");
        assert!(!by_type.is_empty());
        for (t, expected) in by_type {
            assert_eq!(store.last_seq(&stream(t), Direction::Downlink), opt_u(expected), "{name}: downlink stream {t}");
        }
        assert_eq!(store.last_seq(&tkid, Direction::Downlink), None, "{name}: no bare tenant-kid stream");
    }
}

#[test]
fn ids_topics() {
    let v = load("ids_topics.json");
    let ids_v = &v["identifiers"];
    let check = |key: &str, f: &dyn Fn(&str) -> bool, expect: bool| {
        let list = ids_v[key].as_array().unwrap();
        assert!(!list.is_empty(), "{key}");
        for x in list {
            assert_eq!(f(s(x)), expect, "{key}: {x}");
        }
    };
    check("tenant_valid", &ids::is_tenant_id, true);
    check("tenant_invalid", &ids::is_tenant_id, false);
    check("device_valid", &ids::is_device_id, true);
    check("device_invalid", &ids::is_device_id, false);
    check("group_valid", &ids::is_group_slug, true);
    check("group_invalid", &ids::is_group_slug, false);
    check("firmware_id_valid", &|x| ids::parse_firmware_id(x).is_ok(), true);
    check("firmware_id_invalid", &|x| ids::parse_firmware_id(x).is_ok(), false);
    let k = &v["key_ids"];
    assert_eq!(ids::kid_from_serial(&hx(&k["device_serial_hex"])).unwrap(), hx(&k["device_kid_hex"]));
    assert_eq!(ids::kid_from_serial(&[0x00, 0xff]).unwrap(), hx(&k["device_kid_leading_zero_stripped_hex"]));
    assert!(ids::is_tenant_kid(s(&k["tenant_kid"])));
    let topics = v["topics"].as_array().unwrap();
    assert_eq!(topics.len(), 9);
    for t in topics {
        let parsed = ids::parse_topic(s(&t["topic"])).unwrap();
        assert_eq!(parsed.class.suffix(), s(&t["suffix"]));
        assert_eq!(parsed.class.direction().as_str(), s(&t["direction"]));
        assert_eq!(parsed.class.direction() == Direction::Uplink, t["device_publishes"].as_bool().unwrap());
        assert_eq!(u64::from(parsed.class.message_type()), u(&t["message_type"]));
        assert_eq!(parsed.class.retained_allowed(), t["retained_allowed"].as_bool().unwrap());
        assert_eq!(u(&t["qos"]), 1);
        assert_eq!(ids::build_topic(&parsed.tenant_id, &parsed.device_id, parsed.class).unwrap(), s(&t["topic"]));
        assert_eq!(format!("{:?}", parsed.class).to_uppercase(), s(&t["class"]).replace('_', ""));
    }
    for bad in v["invalid_topics"].as_array().unwrap() {
        assert_eq!(ids::parse_topic(s(bad)).unwrap_err().code(), ErrorCode::TopicFormat, "{bad}");
    }
    assert_eq!(s(&v["bridge_shared_subscription"]), ids::BRIDGE_SHARED_SUBSCRIPTION);
}

#[test]
fn every_vector_file_is_covered() {
    let covered = [
        "attestation_software.json",
        "cbor_canonical.json",
        "cose_sign1_eddsa.json",
        "cose_sign1_es256.json",
        "envelope_command_ack.json",
        "envelope_telemetry.json",
        "hpke_rfc9180_a3.json",
        "ids_topics.json",
        "manifest_signed.json",
        "replay_cases.json",
    ];
    for entry in std::fs::read_dir(vectors_dir()).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if !name.ends_with(".json") {
            continue;
        }
        assert!(covered.contains(&name.as_str()) || name.starts_with("delta_"), "vector file {name} has no consumer");
    }
}
