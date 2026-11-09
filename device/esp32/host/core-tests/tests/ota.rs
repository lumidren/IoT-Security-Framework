//! OTA state machine (C) against simulated A/B slots: valid update + health check, tampered
//! image, downgrade, untrusted key, unsigned manifest, health-check rollback, delta update.

use core::ffi::{c_char, c_int, c_void, CStr};
use im_host::err::*;
use im_host::ffi::*;
use im_host::ffi2::*;
use im_host::sim::{Kv, Slots};
use im_host::testkit::*;
use im_host::{err_name, EdSigner, Opaque};
use std::ptr;

const PRODUCT: &str = "sensor-esp32";
const CAMPAIGN: &str = "5f0c6a3e-2b1d-4c8e-9a7f-1e2d3c4b5a69";

struct Dev {
    slots: Slots,
    kv: Box<Kv>,
    reports: Vec<(String, Option<String>)>,
    finish_ok: bool,
    reboots: usize,
}

unsafe fn dev<'a>(ctx: *mut c_void) -> &'a mut Dev {
    &mut *(ctx as *mut Dev)
}

unsafe extern "C" fn s_begin(ctx: *mut c_void, _size: u64) -> i32 {
    let d = dev(ctx);
    d.slots.writing.clear();
    IM_OK
}
unsafe extern "C" fn s_write(ctx: *mut c_void, off: u64, p: *const u8, n: usize) -> i32 {
    let d = dev(ctx);
    assert_eq!(off as usize, d.slots.writing.len());
    d.slots.writing.extend_from_slice(core::slice::from_raw_parts(p, n));
    IM_OK
}
unsafe extern "C" fn s_finish(ctx: *mut c_void) -> i32 {
    if dev(ctx).finish_ok {
        IM_OK
    } else {
        IM_ERR_CRYPTO
    }
}
unsafe extern "C" fn s_abort(ctx: *mut c_void) {
    dev(ctx).slots.writing.clear();
}
unsafe extern "C" fn s_set_boot(ctx: *mut c_void, vc: u64) -> i32 {
    let d = dev(ctx);
    let i = d.slots.inactive();
    d.slots.slots[i].image = std::mem::take(&mut d.slots.writing);
    d.slots.slots[i].version_code = vc;
    d.slots.slots[i].state = "new".into();
    d.slots.boot_next = Some(i);
    IM_OK
}
unsafe extern "C" fn s_read(ctx: *mut c_void, off: u64, buf: *mut u8, n: usize) -> i32 {
    let img = &dev(ctx).slots.running().image;
    let off = off as usize;
    if off + n > img.len() {
        return IM_ERR_IO;
    }
    core::slice::from_raw_parts_mut(buf, n).copy_from_slice(&img[off..off + n]);
    IM_OK
}
unsafe extern "C" fn s_valid(ctx: *mut c_void) -> i32 {
    let d = dev(ctx);
    let a = d.slots.active;
    d.slots.slots[a].state = "valid".into();
    IM_OK
}
unsafe extern "C" fn s_rollback(ctx: *mut c_void) -> i32 {
    let d = dev(ctx);
    let a = d.slots.active;
    d.slots.slots[a].state = "invalid".into();
    d.slots.active = 1 - a;
    d.reboots += 1;
    IM_OK
}
unsafe extern "C" fn s_report(ctx: *mut c_void, _c: *const c_char, state: c_int, _p: u32, err: *const c_char, _h: *const u8) {
    let name = CStr::from_ptr(im_ota_state_name(state)).to_string_lossy().into_owned();
    let e = if err.is_null() {
        None
    } else {
        Some(CStr::from_ptr(err).to_string_lossy().into_owned())
    };
    dev(ctx).reports.push((name, e));
}

struct Rig {
    dev: Box<Dev>,
    ota: Opaque,
    work: Vec<u8>,
    keys: Vec<Vec<u8>>,
    product: std::ffi::CString,
}

impl Rig {
    fn new(running: Vec<u8>, vc: u64, trusted: &[[u8; 32]]) -> Self {
        let dev = Box::new(Dev {
            slots: Slots::new(running, "1.0.0", vc),
            kv: Box::default(),
            reports: vec![],
            finish_ok: true,
            reboots: 0,
        });
        let mut r = Rig {
            dev,
            ota: Opaque::new(unsafe { im_ota_ctx_size() }),
            work: vec![0u8; 4096],
            keys: trusted.iter().map(|k| k.to_vec()).collect(),
            product: std::ffi::CString::new(PRODUCT).unwrap(),
        };
        r.init();
        r
    }

    fn init(&mut self) {
        let ctx: *mut c_void = (&mut *self.dev as *mut Dev).cast();
        let running = self.dev.slots.running().clone();
        let mut keys = im_fw_keys_t {
            key: [ptr::null(); 4],
            len: [0; 4],
            n: self.keys.len(),
        };
        for (i, k) in self.keys.iter().enumerate() {
            keys.key[i] = k.as_ptr();
            keys.len[i] = k.len();
        }
        let cfg = im_ota_config_t {
            pf: im_ota_platform_t {
                slot_begin: Some(s_begin),
                slot_write: Some(s_write),
                slot_finish: Some(s_finish),
                slot_abort: Some(s_abort),
                set_boot: Some(s_set_boot),
                read_running: Some(s_read),
                mark_valid: Some(s_valid),
                rollback: Some(s_rollback),
                report: Some(s_report),
                ctx,
            },
            kv: self.dev.kv.ffi(),
            product: self.product.as_ptr(),
            current_version_code: running.version_code,
            current_fw_hash: sha256(&running.image),
            running_size: running.image.len() as u64,
            slot_size: 1 << 20,
            require_pq: false,
            keys,
            work: self.work.as_mut_ptr(),
            work_len: self.work.len(),
        };
        assert_eq!(unsafe { im_ota_init(self.ota.ptr(), &cfg) }, IM_OK);
    }

    fn notify(&mut self, manifest: &[u8], delta_from: Option<[u8; 32]>) -> Result<(), &'static str> {
        let url = "https://ota.example/fw.bin";
        let n = im_ota_notify_t {
            campaign_id: CAMPAIGN.as_ptr().cast(),
            manifest: manifest.as_ptr(),
            manifest_len: manifest.len(),
            url: url.as_ptr().cast(),
            url_len: url.len(),
            delta_from: delta_from.as_ref().map_or(ptr::null(), |d| d.as_ptr()),
        };
        im_host::check(unsafe { im_ota_on_notify(self.ota.ptr(), &n) })
    }

    fn download(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        for c in bytes.chunks(777) {
            im_host::check(unsafe { im_ota_on_data(self.ota.ptr(), c.as_ptr(), c.len()) })?;
        }
        im_host::check(unsafe { im_ota_on_complete(self.ota.ptr()) })
    }

    /// Simulate the reboot after apply/rollback and re-run the boot check. Returns the reason.
    fn reboot(&mut self) -> c_int {
        self.dev.slots.reset();
        self.init();
        let mut reason = 0;
        assert_eq!(unsafe { im_ota_boot(self.ota.ptr(), 0, &mut reason) }, IM_OK);
        reason
    }

    fn states(&self) -> Vec<String> {
        self.dev.reports.iter().map(|(s, _)| s.clone()).collect()
    }

    fn last_error(&self) -> Option<String> {
        self.dev.reports.last().and_then(|(_, e)| e.clone())
    }
}

fn image(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn fw_key() -> Box<EdSigner> {
    EdSigner::from_seed(&[7u8; 32])
}

#[test]
fn valid_update_applies_and_is_marked_healthy() {
    let key = fw_key();
    let mut rig = Rig::new(image(1, 10_000), 100, &[key.public()]);
    let new = image(2, 20_000);
    let m = signed_manifest(
        &ManifestSpec {
            product: PRODUCT,
            version: "1.1.0",
            version_code: 101,
            min_version_code: 0,
            image: &new,
            delta: None,
        },
        &key,
    );
    rig.notify(&m, None).unwrap();
    rig.download(&new).unwrap();
    assert_eq!(
        rig.states(),
        [
            "received",
            "downloading",
            "downloading",
            "downloading",
            "downloading",
            "downloading",
            "downloading",
            "downloading",
            "downloading",
            "downloading",
            "downloading",
            "downloading",
            "verifying",
            "applying",
            "rebooting"
        ]
        .map(String::from)
        .to_vec()
    );
    assert_eq!(rig.reboot(), 1, "IM_BOOT_OTA_APPLY");
    assert_eq!(rig.dev.slots.running().image, new);
    assert_eq!(rig.dev.slots.running().state, "pending_verify");
    assert_eq!(unsafe { im_ota_health_ok(rig.ota.ptr()) }, IM_OK);
    assert_eq!(rig.dev.slots.running().state, "valid");
    assert_eq!(rig.states().last().unwrap(), "success");
    assert!(rig.dev.kv.map.is_empty(), "campaign record cleared");
}

#[test]
fn tampered_image_is_rejected_and_active_slot_unchanged() {
    let key = fw_key();
    let mut rig = Rig::new(image(1, 5000), 100, &[key.public()]);
    let new = image(3, 8000);
    let m = signed_manifest(
        &ManifestSpec {
            product: PRODUCT,
            version: "1.1.0",
            version_code: 101,
            min_version_code: 0,
            image: &new,
            delta: None,
        },
        &key,
    );
    rig.notify(&m, None).unwrap();
    let mut bad = new.clone();
    bad[4000] ^= 1;
    assert_eq!(rig.download(&bad).err(), Some("MF_HASH_MISMATCH"));
    assert_eq!(rig.last_error().as_deref(), Some("image_hash"), "C-OTA-2 error=image_hash");
    assert_eq!(rig.states().last().unwrap(), "rejected");
    assert_eq!(rig.dev.slots.active, 0);
    assert!(rig.dev.slots.boot_next.is_none());
    // truncated image and oversize image
    rig.notify(&m, None).unwrap();
    assert_eq!(rig.download(&new[..7000]).err(), Some("MF_SIZE_MISMATCH"));
    rig.notify(&m, None).unwrap();
    let mut long = new.clone();
    long.push(0);
    assert_eq!(rig.download(&long).err(), Some("MF_SIZE_MISMATCH"));
    // platform image verification (secure boot signature in esp_ota_end) failing
    rig.dev.finish_ok = false;
    rig.notify(&m, None).unwrap();
    assert!(rig.download(&new).is_err());
    assert_eq!(rig.dev.slots.active, 0);
}

#[test]
fn downgrade_untrusted_unsigned_product_rejected_before_download() {
    let key = fw_key();
    let other = EdSigner::from_seed(&[9u8; 32]);
    let mut rig = Rig::new(image(1, 5000), 100, &[key.public()]);
    let new = image(4, 3000);
    let spec = |vc: u64, product: &'static str| ManifestSpec {
        product,
        version: "1.1.0",
        version_code: vc,
        min_version_code: 0,
        image: &new,
        delta: None,
    };
    let cases: Vec<(Vec<u8>, &str, &str)> = vec![
        (signed_manifest(&spec(100, PRODUCT), &key), "MF_ROLLBACK", "downgrade"),
        (signed_manifest(&spec(99, PRODUCT), &key), "MF_ROLLBACK", "downgrade"),
        (signed_manifest(&spec(101, PRODUCT), &other), "COSE_UNKNOWN_KEY", "untrusted_key"),
        (signed_manifest(&spec(101, "gateway-rpi"), &key), "MF_PRODUCT", "product"),
    ];
    for (m, code, reason) in cases {
        assert_eq!(rig.notify(&m, None).err(), Some(code));
        assert_eq!(rig.last_error().as_deref(), Some(reason));
        assert_eq!(rig.states().last().unwrap(), "rejected");
    }
    // unsigned: the bare manifest map instead of a COSE_Sign
    let signed = signed_manifest(&spec(101, PRODUCT), &key);
    let mut s1: im_sign_t = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe { im_cose_sign_decode(signed.as_ptr(), signed.len(), ptr::null(), &mut s1) },
        IM_OK
    );
    let bare = unsafe { core::slice::from_raw_parts(s1.payload, s1.payload_len) }.to_vec();
    assert_eq!(rig.notify(&bare, None).err(), Some("COSE_TAG"));
    assert_eq!(rig.last_error().as_deref(), Some("unsigned"));
    // signature byte flipped
    let mut forged = signed.clone();
    let l = forged.len();
    forged[l - 3] ^= 0x40;
    assert_eq!(rig.notify(&forged, None).err(), Some("COSE_SIGNATURE"));
    // min_version_code above the running version
    let m = signed_manifest(
        &ManifestSpec {
            product: PRODUCT,
            version: "2.0.0",
            version_code: 200,
            min_version_code: 150,
            image: &new,
            delta: None,
        },
        &key,
    );
    assert_eq!(rig.notify(&m, None).err(), Some("MF_MIN_VERSION"));
    assert_eq!(rig.dev.slots.active, 0);
    assert!(rig.dev.slots.slots[1].image.is_empty(), "inactive slot never written");
}

#[test]
fn failed_health_check_rolls_back() {
    let key = fw_key();
    let old = image(1, 4000);
    let mut rig = Rig::new(old.clone(), 100, &[key.public()]);
    let new = image(5, 4500);
    let m = signed_manifest(
        &ManifestSpec {
            product: PRODUCT,
            version: "1.1.0",
            version_code: 101,
            min_version_code: 0,
            image: &new,
            delta: None,
        },
        &key,
    );
    rig.notify(&m, None).unwrap();
    rig.download(&new).unwrap();
    assert_eq!(rig.reboot(), 1);
    // no health confirmation within 120 s -> rollback
    assert_eq!(unsafe { im_ota_tick(rig.ota.ptr(), 119_999) }, IM_OK);
    assert_eq!(rig.dev.reboots, 0);
    assert_eq!(unsafe { im_ota_tick(rig.ota.ptr(), 120_000) }, IM_OK);
    assert_eq!(rig.dev.reboots, 1);
    // previous image boots again and reports rolled_back
    rig.init();
    let mut reason = 0;
    assert_eq!(unsafe { im_ota_boot(rig.ota.ptr(), 0, &mut reason) }, IM_OK);
    assert_eq!(reason, 2, "IM_BOOT_ROLLBACK");
    assert_eq!(rig.dev.slots.running().image, old);
    assert_eq!(rig.states().last().unwrap(), "rolled_back");
    // the bootloader path: reboot while still pending_verify also reverts
    let mut rig2 = Rig::new(old.clone(), 100, &[key.public()]);
    rig2.notify(&m, None).unwrap();
    rig2.download(&new).unwrap();
    assert_eq!(rig2.reboot(), 1);
    assert_eq!(rig2.reboot(), 2);
    assert_eq!(rig2.dev.slots.running().image, old);
}

#[test]
fn delta_update_produces_the_full_image() {
    let key = fw_key();
    let old = image(1, 4096 * 6 + 100);
    let mut new = old.clone();
    new[4096 * 2 + 10] ^= 0xFF; // one block changes
    new.extend_from_slice(&[0x55; 3000]);
    let patch = make_delta(&old, &new);
    assert!(patch.len() < new.len() / 2);
    let base = sha256(&old);
    let mut rig = Rig::new(old.clone(), 100, &[key.public()]);
    let m = signed_manifest(
        &ManifestSpec {
            product: PRODUCT,
            version: "1.2.0",
            version_code: 102,
            min_version_code: 0,
            image: &new,
            delta: Some((base, &patch)),
        },
        &key,
    );
    rig.notify(&m, Some(base)).unwrap();
    rig.download(&patch).unwrap();
    assert_eq!(rig.reboot(), 1);
    assert_eq!(
        sha256(&rig.dev.slots.running().image),
        sha256(&new),
        "C-OTA-7: delta result == full image"
    );
    // delta against the wrong running image is refused up front
    let mut rig2 = Rig::new(image(9, 4096 * 6 + 100), 100, &[key.public()]);
    assert_eq!(rig2.notify(&m, Some(base)).err(), Some("DELTA_BASE_HASH"));
    // corrupted patch -> rejected, nothing applied
    let mut rig3 = Rig::new(old.clone(), 100, &[key.public()]);
    rig3.notify(&m, Some(base)).unwrap();
    let mut bad = patch.clone();
    let l = bad.len();
    bad[l - 10] ^= 1;
    // streaming: the applier's END check (target hash) fires before the whole-patch hash check
    let e = rig3.download(&bad).err();
    assert!(matches!(e, Some("DELTA_TARGET_HASH") | Some("MF_HASH_MISMATCH")), "{e:?}");
    assert!(matches!(rig3.last_error().as_deref(), Some("delta") | Some("image_hash")));
    assert!(rig3.dev.slots.boot_next.is_none());
    let _ = err_name(0);
}
