//! Alternating operational key slots (ATECC608B slots 2/3, bootstrap slot 0) driven by the C
//! pure function `im_keyslot_plan` and the atomic identity record, on a simulated device whose
//! "NVS" is the host KV store. Covers: renewal flips the slot, a power loss before the record is
//! written keeps the old slot/cert pair, and the bootstrap fallback after expiry.

use im_host::err::*;
use im_host::ffi2::*;
use im_host::sim::Kv;
use im_host::testkit::sha256;
use im_host::{err_name, SoftIdentity};

const REC: &str = "id_rec";
const TTL: u64 = 14 * 86_400;

fn plan(active: u8, provisioned: bool, now: u64, not_after: u64) -> im_keyslot_plan_t {
    let mut p = im_keyslot_plan_t::default();
    assert_eq!(unsafe { im_keyslot_plan(active, provisioned, now, not_after, &mut p) }, IM_OK);
    p
}

fn encode(slot: u8, cert: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 12 + cert.len()];
    let mut n = 0usize;
    assert_eq!(
        unsafe { im_keyslot_record_encode(slot, cert.as_ptr(), cert.len(), out.as_mut_ptr(), out.len(), &mut n) },
        IM_OK
    );
    out.truncate(n);
    out
}

fn decode(rec: &[u8]) -> Result<(u8, Vec<u8>), &'static str> {
    let mut slot = 0u8;
    let mut cert = std::ptr::null();
    let mut len = 0usize;
    let r = unsafe { im_keyslot_record_decode(rec.as_ptr(), rec.len(), &mut slot, &mut cert, &mut len) };
    if r != IM_OK {
        return Err(err_name(r));
    }
    Ok((slot, unsafe { core::slice::from_raw_parts(cert, len) }.to_vec()))
}

/// A device with an ATECC-like key store: four slots, GenKey only, keys never exported; the
/// identity record (active slot + operational certificate) lives in the KV store.
struct Device {
    slots: [Option<Box<SoftIdentity>>; 4],
    kv: Kv,
    not_after: u64,
}

/// The (simulated) EST server's view of one enrollment.
#[derive(Debug)]
struct Enrollment {
    tls_key: [u8; 65],
    attestation_key: [u8; 65],
    presented_cert: Vec<u8>,
    op: &'static str,
    new_key: [u8; 65],
}

/// Certificates are modelled as "issued for this public key".
fn cert_for(pubkey: &[u8; 65]) -> Vec<u8> {
    let mut c = b"CERT:".to_vec();
    c.extend_from_slice(&sha256(pubkey));
    c
}

const BOOTSTRAP_CERT: &[u8] = b"BOOTSTRAP-CERT";

impl Device {
    fn factory() -> Self {
        Self {
            slots: [Some(SoftIdentity::random()), None, None, None],
            kv: Kv::default(),
            not_after: 0,
        }
    }

    fn record(&self) -> Option<(u8, Vec<u8>)> {
        self.kv.map.get(REC).map(|r| decode(r).expect("valid record"))
    }

    fn active(&self) -> u8 {
        self.record().map_or(IM_SLOT_BOOTSTRAP, |r| r.0)
    }

    fn pubkey(&self, slot: u8) -> [u8; 65] {
        self.slots[slot as usize].as_ref().expect("key in slot").public_raw()
    }

    /// One enrollment attempt following im_keyslot_plan. With `power_loss` the device dies after
    /// the server answered but before the record write (the only commit point).
    fn enroll(&mut self, now: u64, power_loss: bool) -> Enrollment {
        let rec = self.record();
        let active = self.active();
        let p = plan(active, rec.is_some(), now, self.not_after);
        // genkey in the target slot - never the slot of the live certificate
        assert_ne!(p.new_slot, active, "renewal must not overwrite the active key");
        assert_ne!(p.new_slot, IM_SLOT_BOOTSTRAP);
        self.slots[p.new_slot as usize] = Some(SoftIdentity::random());
        let presented = if p.bootstrap_cert {
            BOOTSTRAP_CERT.to_vec()
        } else {
            rec.unwrap().1
        };
        let e = Enrollment {
            tls_key: self.pubkey(p.tls_slot),
            attestation_key: self.pubkey(p.tls_slot), // signed by the TLS client key
            presented_cert: presented,
            op: if p.reenroll { "simplereenroll" } else { "simpleenroll" },
            new_key: self.pubkey(p.new_slot),
        };
        if !power_loss {
            // single atomic KV write of (new slot, new cert)
            let new_cert = cert_for(&e.new_key);
            self.kv.map.insert(REC.into(), encode(p.new_slot, &new_cert));
            self.not_after = now + TTL;
        }
        e
    }

    /// The key a TLS connection would use right now and the cert it presents.
    fn tls_identity(&self, now: u64) -> ([u8; 65], Vec<u8>) {
        match self.record() {
            Some((slot, cert)) if unsafe { im_keyslot_operational_valid(slot, true, now, self.not_after) } => (self.pubkey(slot), cert),
            _ => (self.pubkey(IM_SLOT_BOOTSTRAP), BOOTSTRAP_CERT.to_vec()),
        }
    }
}

#[test]
fn plan_function_cases() {
    // first enrollment
    assert_eq!(
        plan(0, false, 100, 0),
        im_keyslot_plan_t {
            tls_slot: 0,
            bootstrap_cert: true,
            reenroll: false,
            new_slot: 2
        }
    );
    // renewal from either slot flips
    assert_eq!(
        plan(2, true, 100, 1000),
        im_keyslot_plan_t {
            tls_slot: 2,
            bootstrap_cert: false,
            reenroll: true,
            new_slot: 3
        }
    );
    assert_eq!(
        plan(3, true, 100, 1000),
        im_keyslot_plan_t {
            tls_slot: 3,
            bootstrap_cert: false,
            reenroll: true,
            new_slot: 2
        }
    );
    // expiry boundary: not_after itself is expired
    assert_eq!(
        plan(3, true, 1000, 1000),
        im_keyslot_plan_t {
            tls_slot: 0,
            bootstrap_cert: true,
            reenroll: false,
            new_slot: 2
        }
    );
    // invalid slot numbers
    let mut p = im_keyslot_plan_t::default();
    for bad in [1u8, 4, 255] {
        assert_eq!(err_name(unsafe { im_keyslot_plan(bad, true, 0, 10, &mut p) }), "ARG");
    }
    assert_eq!(unsafe { im_keyslot_inactive(0) }, 2);
}

#[test]
fn normal_renewal_flips_the_active_slot() {
    let mut d = Device::factory();
    let boot = d.pubkey(0);
    let e = d.enroll(1000, false);
    assert_eq!(
        (e.op, e.tls_key, e.presented_cert.as_slice()),
        ("simpleenroll", boot, BOOTSTRAP_CERT)
    );
    assert_eq!(d.active(), 2);
    let slot2 = d.pubkey(2);
    assert_eq!(d.tls_identity(2000), (slot2, cert_for(&slot2)));

    // renewal at 50 % lifetime: TLS + attestation by the active slot-2 key, new key in slot 3
    let e = d.enroll(1000 + TTL / 2, false);
    assert_eq!(e.op, "simplereenroll");
    assert_eq!(e.tls_key, slot2);
    assert_eq!(e.attestation_key, slot2, "attestation signed by the TLS client key");
    assert_eq!(e.presented_cert, cert_for(&slot2));
    assert_eq!(d.active(), 3, "slot flipped after the certificate was stored");
    let slot3 = d.pubkey(3);
    assert_ne!(slot3, slot2);
    assert_eq!(e.new_key, slot3);
    assert_eq!(d.tls_identity(1000 + TTL / 2 + 1).0, slot3);

    // and back again
    let e = d.enroll(1000 + TTL, false);
    assert_eq!((e.tls_key, d.active()), (slot3, 2));
    assert_eq!(d.pubkey(0), boot, "bootstrap key never touched");
}

#[test]
fn power_loss_before_commit_keeps_the_old_slot_and_cert() {
    let mut d = Device::factory();
    d.enroll(1000, false);
    let slot2 = d.pubkey(2);
    let rec_before = d.kv.map.get(REC).cloned().unwrap();

    // renewal: new key generated in slot 3, server answered, power lost before the record write
    let e = d.enroll(1000 + TTL / 2, true);
    assert_eq!(e.new_key, d.pubkey(3));
    // "reboot": the persisted record is unchanged, so the old slot/cert pair is still in force
    assert_eq!(d.kv.map.get(REC), Some(&rec_before));
    assert_eq!(d.active(), 2);
    assert_eq!(d.pubkey(2), slot2, "the live key was never overwritten");
    assert_eq!(d.tls_identity(1000 + TTL / 2 + 5), (slot2, cert_for(&slot2)));

    // the retry regenerates slot 3 (the orphaned key is simply replaced) and then commits
    let e = d.enroll(1000 + TTL / 2 + 60, false);
    assert_eq!(e.tls_key, slot2);
    assert_eq!(d.active(), 3);

    // a torn/corrupted record is rejected rather than half-applied
    let mut bad = d.kv.map.get(REC).cloned().unwrap();
    let l = bad.len();
    bad[l / 2] ^= 1;
    assert_eq!(decode(&bad).err(), Some("STORAGE"));
    assert_eq!(decode(&bad[..l - 1]).err(), Some("STORAGE"));
}

#[test]
fn bootstrap_fallback_after_expiry() {
    let mut d = Device::factory();
    let boot = d.pubkey(0);
    d.enroll(1000, false);
    d.enroll(1000 + TTL / 2, false);
    assert_eq!(d.active(), 3);
    let slot3 = d.pubkey(3);
    // renewal never succeeded and the certificate expired
    let expired = 1000 + TTL / 2 + TTL;
    assert_eq!(d.tls_identity(expired), (boot, BOOTSTRAP_CERT.to_vec()));
    let e = d.enroll(expired, false);
    assert_eq!(e.op, "simpleenroll");
    assert_eq!(e.tls_key, boot, "TLS with the bootstrap key");
    assert_eq!(e.attestation_key, boot);
    assert_eq!(e.presented_cert, BOOTSTRAP_CERT);
    assert_eq!(d.active(), 2, "new key went to the inactive slot");
    assert_eq!(d.pubkey(3), slot3, "the previous operational key is left alone until reused");
    // operational again afterwards
    let e = d.enroll(expired + TTL / 2, false);
    assert_eq!((e.op, d.active()), ("simplereenroll", 3));
}

#[test]
fn record_encoding() {
    let cert = vec![0x30u8; 700];
    let r = encode(3, &cert);
    assert_eq!(&r[..6], b"IMKS\x01\x03");
    assert_eq!(decode(&r).unwrap(), (3, cert.clone()));
    let mut out = vec![0u8; 4096];
    let mut n = 0usize;
    for (slot, len) in [(0u8, 10usize), (1, 10), (2, 0), (2, 2049)] {
        let c = vec![1u8; len];
        assert_eq!(
            err_name(unsafe { im_keyslot_record_encode(slot, c.as_ptr(), c.len(), out.as_mut_ptr(), out.len(), &mut n) }),
            "ARG"
        );
    }
    assert_eq!(
        err_name(unsafe { im_keyslot_record_encode(2, cert.as_ptr(), cert.len(), out.as_mut_ptr(), 100, &mut n) }),
        "BUFFER"
    );
    let mut wrong_slot = r.clone();
    wrong_slot[5] = 0;
    assert_eq!(decode(&wrong_slot).err(), Some("STORAGE"));
}
