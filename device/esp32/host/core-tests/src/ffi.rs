//! Hand-written FFI declarations for `components/im_core/include/*.h`.
//!
//! Layouts are `#[repr(C)]` mirrors of the C structs (C enums are `int` = `i32` on every
//! supported ABI, `bool` is one byte). Large or purely internal contexts (delta applier, agent)
//! are allocated opaquely with their `*_ctx_size()` functions instead of being mirrored.
#![allow(non_camel_case_types, missing_docs)]

use core::ffi::{c_char, c_int, c_uint, c_void};

pub type im_err_t = c_int;

// ---- im_cbor.h ------------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct im_cbor_limits_t {
    pub max_size: usize,
    pub max_depth: c_uint,
}

pub const IM_CBOR_UINT: c_int = 0;
pub const IM_CBOR_NINT: c_int = 1;
pub const IM_CBOR_BSTR: c_int = 2;
pub const IM_CBOR_TSTR: c_int = 3;
pub const IM_CBOR_ARRAY: c_int = 4;
pub const IM_CBOR_MAP: c_int = 5;
pub const IM_CBOR_TAG: c_int = 6;
pub const IM_CBOR_FLOAT: c_int = 7;
pub const IM_CBOR_FALSE: c_int = 8;
pub const IM_CBOR_TRUE: c_int = 9;
pub const IM_CBOR_NULL: c_int = 10;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct im_cbor_val_t {
    pub type_: c_int,
    pub arg: u64,
    pub f: f64,
    pub data: *const u8,
    pub raw: *const u8,
    pub raw_len: usize,
}

impl Default for im_cbor_val_t {
    fn default() -> Self {
        Self {
            type_: 0,
            arg: 0,
            f: 0.0,
            data: core::ptr::null(),
            raw: core::ptr::null(),
            raw_len: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct im_cbor_enc_t {
    pub buf: *mut u8,
    pub cap: usize,
    pub len: usize,
    pub err: im_err_t,
}

impl im_cbor_enc_t {
    pub fn new(buf: &mut [u8]) -> Self {
        let mut e = Self {
            buf: core::ptr::null_mut(),
            cap: 0,
            len: 0,
            err: 0,
        };
        unsafe { im_cbor_enc_init(&mut e, buf.as_mut_ptr(), buf.len()) };
        e
    }
}

extern "C" {
    pub fn im_err_str(err: im_err_t) -> *const c_char;
    pub fn im_cbor_validate(buf: *const u8, len: usize, lim: *const im_cbor_limits_t) -> im_err_t;
    pub fn im_cbor_decode(buf: *const u8, len: usize, lim: *const im_cbor_limits_t, top: *mut im_cbor_val_t) -> im_err_t;
    pub fn im_cbor_parse(p: *const u8, end: *const u8, v: *mut im_cbor_val_t) -> im_err_t;
    pub fn im_cbor_reencode(v: *const im_cbor_val_t, e: *mut im_cbor_enc_t) -> im_err_t;
    pub fn im_cbor_enc_init(e: *mut im_cbor_enc_t, buf: *mut u8, cap: usize);
    pub fn im_cbor_enc_uint(e: *mut im_cbor_enc_t, v: u64);
    pub fn im_cbor_enc_int(e: *mut im_cbor_enc_t, v: i64);
    pub fn im_cbor_enc_bstr(e: *mut im_cbor_enc_t, p: *const u8, n: usize);
    pub fn im_cbor_enc_tstr(e: *mut im_cbor_enc_t, p: *const c_char, n: usize);
    pub fn im_cbor_enc_map(e: *mut im_cbor_enc_t, n: u64);
    pub fn im_cbor_enc_array(e: *mut im_cbor_enc_t, n: u64);
    pub fn im_cbor_enc_float(e: *mut im_cbor_enc_t, v: f64);
    pub fn im_cbor_enc_bool(e: *mut im_cbor_enc_t, v: bool);
    pub fn im_cbor_enc_null(e: *mut im_cbor_enc_t);
    pub fn im_cbor_enc_raw(e: *mut im_cbor_enc_t, p: *const u8, n: usize);
    pub fn im_cbor_enc_finish(e: *const im_cbor_enc_t, len: *mut usize) -> im_err_t;
}

// ---- im_crypto.h / im_cose.h ------------------------------------------------------------------

pub type GetPubkeyFn = unsafe extern "C" fn(ctx: *mut c_void, pub_: *mut u8) -> im_err_t;
pub type SignDigestFn = unsafe extern "C" fn(ctx: *mut c_void, digest: *const u8, sig: *mut u8) -> im_err_t;
pub type EcdhFn = unsafe extern "C" fn(ctx: *mut c_void, peer: *const u8, shared: *mut u8) -> im_err_t;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_identity_t {
    pub ctx: *mut c_void,
    pub get_pubkey: Option<GetPubkeyFn>,
    pub sign_digest: Option<SignDigestFn>,
    pub ecdh: Option<EcdhFn>,
    pub se_type: *const c_char,
}

pub const IM_KEY_NONE: c_int = 0;
pub const IM_KEY_P256: c_int = 1;
pub const IM_KEY_ED25519: c_int = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_pubkey_t {
    pub type_: c_int,
    pub raw: [u8; 65],
}

impl Default for im_pubkey_t {
    fn default() -> Self {
        Self {
            type_: IM_KEY_NONE,
            raw: [0; 65],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_sign1_t {
    pub protected_raw: *const u8,
    pub protected_len: usize,
    pub alg: c_int,
    pub kid: *const u8,
    pub kid_len: usize,
    pub kid_text: bool,
    pub payload: *const u8,
    pub payload_len: usize,
    pub sig: *const u8,
    pub sig_len: usize,
}

pub type SignFn = unsafe extern "C" fn(ctx: *mut c_void, data: *const u8, len: usize, sig: *mut u8) -> im_err_t;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_signer_t {
    pub alg: c_int,
    pub sign: Option<SignFn>,
    pub ctx: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_cose_signature_t {
    pub protected_raw: *const u8,
    pub protected_len: usize,
    pub alg: c_int,
    pub kid: *const u8,
    pub sig: *const u8,
    pub sig_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_sign_t {
    pub payload: *const u8,
    pub payload_len: usize,
    pub sigs: [im_cose_signature_t; 2],
    pub nsigs: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_encrypt0_t {
    pub protected_raw: *const u8,
    pub protected_len: usize,
    pub iv: *const u8,
    pub enc: *const u8,
    pub wrapped: *const u8,
    pub ct: *const u8,
    pub ct_len: usize,
}

extern "C" {
    pub fn im_sha256(data: *const u8, len: usize, out: *mut u8) -> im_err_t;
    pub fn im_pubkey_p256(k: *mut im_pubkey_t, raw: *const u8, len: usize) -> im_err_t;
    pub fn im_pubkey_ed25519(k: *mut im_pubkey_t, raw: *const u8, len: usize) -> im_err_t;
    pub fn im_identity_signer(id: *const im_identity_t, out: *mut im_signer_t);
    pub fn im_cose_sign1_decode(buf: *const u8, len: usize, lim: *const im_cbor_limits_t, out: *mut im_sign1_t) -> im_err_t;
    pub fn im_cose_sign1_verify(m: *const im_sign1_t, key: *const im_pubkey_t, work: *mut u8, work_len: usize) -> im_err_t;
    pub fn im_cose_sig1_structure(
        prot: *const u8,
        prot_len: usize,
        payload: *const u8,
        payload_len: usize,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> im_err_t;
    pub fn im_cose_sign1_encode(
        signer: *const im_signer_t,
        kid: *const u8,
        kid_len: usize,
        kid_text: bool,
        payload: *const u8,
        payload_len: usize,
        work: *mut u8,
        work_len: usize,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> im_err_t;
    pub fn im_cose_sign_decode(buf: *const u8, len: usize, lim: *const im_cbor_limits_t, out: *mut im_sign_t) -> im_err_t;
    pub fn im_cose_sig_structure(
        sprot: *const u8,
        sprot_len: usize,
        payload: *const u8,
        payload_len: usize,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> im_err_t;
    pub fn im_cose_sign_encode_ed25519(
        signer: *const im_signer_t,
        kid: *const u8,
        payload: *const u8,
        payload_len: usize,
        work: *mut u8,
        work_len: usize,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> im_err_t;
    pub fn im_cose_encrypt0_decode(buf: *const u8, len: usize, lim: *const im_cbor_limits_t, out: *mut im_encrypt0_t) -> im_err_t;
    pub fn im_cose_encrypt0_encode(
        iv: *const u8,
        enc: *const u8,
        wrapped: *const u8,
        ct: *const u8,
        ct_len: usize,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> im_err_t;
    pub fn im_cose_key_id(raw: *const u8, len: usize, kid: *mut u8) -> im_err_t;
}

// ---- im_ids.h ---------------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_topic_t {
    pub tenant: *const c_char,
    pub device: *const c_char,
    pub cls: c_int,
}

extern "C" {
    pub fn im_id_is_uuid(s: *const c_char, n: usize) -> bool;
    pub fn im_id_is_uuid4(s: *const c_char, n: usize) -> bool;
    pub fn im_id_is_device_id(s: *const c_char, n: usize) -> bool;
    pub fn im_id_is_group_slug(s: *const c_char, n: usize) -> bool;
    pub fn im_id_is_product(s: *const c_char, n: usize) -> bool;
    pub fn im_id_is_semver(s: *const c_char, n: usize) -> bool;
    pub fn im_id_is_firmware_id(s: *const c_char, n: usize) -> bool;
    pub fn im_id_is_device_kid(kid: *const u8, n: usize) -> bool;
    pub fn im_id_is_tenant_kid(kid: *const c_char, n: usize, tenant: *mut *const c_char) -> bool;
    pub fn im_id_kid_from_serial(serial: *const u8, n: usize, kid: *mut u8, cap: usize, kid_len: *mut usize) -> im_err_t;
    pub fn im_id_tenant_kid(tenant: *const c_char, n: usize, out: *mut c_char, cap: usize) -> im_err_t;
    pub fn im_topic_suffix(cls: c_int) -> *const c_char;
    pub fn im_topic_message_type(cls: c_int) -> u8;
    pub fn im_topic_device_publishes(cls: c_int) -> bool;
    pub fn im_topic_retained_allowed(cls: c_int) -> bool;
    pub fn im_topic_build(
        tenant: *const c_char,
        device: *const c_char,
        cls: c_int,
        out: *mut c_char,
        cap: usize,
        out_len: *mut usize,
    ) -> im_err_t;
    pub fn im_topic_parse(topic: *const c_char, n: usize, out: *mut im_topic_t) -> im_err_t;
    pub fn im_topic_device_may_publish(topic: *const c_char, n: usize, device: *const c_char) -> bool;
    pub fn im_topic_device_may_subscribe(topic: *const c_char, n: usize, device: *const c_char) -> bool;
}

// ---- im_envelope.h ----------------------------------------------------------------------------

pub type ResolveFn =
    unsafe extern "C" fn(ctx: *mut c_void, kid: *const u8, kid_len: usize, kid_text: bool, out: *mut im_pubkey_t) -> im_err_t;
pub type CheckRecordFn = unsafe extern "C" fn(ctx: *mut c_void, kid: *const u8, kid_len: usize, dir: c_int, seq: u64) -> im_err_t;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_key_resolver_t {
    pub resolve: Option<ResolveFn>,
    pub ctx: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_replay_store_t {
    pub check_and_record: Option<CheckRecordFn>,
    pub ctx: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_env_decode_opts_t {
    pub resolver: *const im_key_resolver_t,
    pub replay: *const im_replay_store_t,
    pub now: u64,
    pub max_skew: u64,
    pub expected_direction: c_int,
    pub expected_tenant: *const c_char,
    pub expected_nonce: *const u8,
    pub limits: *const im_cbor_limits_t,
    pub work: *mut u8,
    pub work_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_env_msg_t {
    pub seq: u64,
    pub ts: u64,
    pub type_: u8,
    pub direction: c_int,
    pub kid: *const u8,
    pub kid_len: usize,
    pub kid_text: bool,
    pub nonce: *const u8,
    pub body: im_cbor_val_t,
    pub payload: *const u8,
    pub payload_len: usize,
}

impl Default for im_env_msg_t {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_telemetry_t {
    pub cpu_pct: f64,
    pub mem_pct: f64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub temp_c: f64,
    pub uptime_s: u64,
    pub auth_failures: u64,
    pub fw_hash: [u8; 32],
    pub fw_version: *const c_char,
    pub has_proc_count: bool,
    pub proc_count: u64,
    pub top_procs: *const *const c_char,
    pub n_top_procs: usize,
    pub has_rssi: bool,
    pub rssi: i64,
    pub has_free_heap: bool,
    pub free_heap: u64,
    pub has_lat: bool,
    pub lat: f64,
    pub has_lon: bool,
    pub lon: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_replay_entry_t {
    pub used: bool,
    pub dir: u8,
    pub kid_len: u8,
    pub kid: [u8; 52],
    pub last_seq: u64,
}

pub type PersistFn = unsafe extern "C" fn(ctx: *mut c_void, e: *const im_replay_entry_t) -> im_err_t;

#[repr(C)]
pub struct im_replay_mem_t {
    pub e: [im_replay_entry_t; 8],
    pub persist: Option<PersistFn>,
    pub persist_ctx: *mut c_void,
}

extern "C" {
    pub fn im_env_decode_opts_init(o: *mut im_env_decode_opts_t);
    pub fn im_env_decode(buf: *const u8, len: usize, o: *const im_env_decode_opts_t, msg: *mut im_env_msg_t) -> im_err_t;
    pub fn im_env_decode_payload(p: *const u8, n: usize, lim: *const im_cbor_limits_t, msg: *mut im_env_msg_t) -> im_err_t;
    pub fn im_env_payload_begin(e: *mut im_cbor_enc_t, seq: u64, ts: u64, type_: u8, has_nonce: bool);
    pub fn im_env_payload_end(e: *mut im_cbor_enc_t, nonce: *const u8, len: *mut usize) -> im_err_t;
    pub fn im_body_telemetry(e: *mut im_cbor_enc_t, t: *const im_telemetry_t);
    pub fn im_body_command(
        e: *mut im_cbor_enc_t,
        cmd_id: *const c_char,
        name: *const c_char,
        args: *const u8,
        args_len: usize,
        idem: *const c_char,
        expires_at: u64,
    );
    pub fn im_body_command_ack(
        e: *mut im_cbor_enc_t,
        cmd_id: *const c_char,
        status: u64,
        result: *const u8,
        result_len: usize,
        error: *const c_char,
    );
    pub fn im_body_ota_notify(
        e: *mut im_cbor_enc_t,
        campaign: *const c_char,
        manifest: *const u8,
        manifest_len: usize,
        url: *const c_char,
        delta_from: *const u8,
    );
    pub fn im_body_config(e: *mut im_cbor_enc_t, version: u64, settings: *const u8, settings_len: usize);
    pub fn im_body_shadow(e: *mut im_cbor_enc_t, state: *const u8, state_len: usize, version: u64);
    pub fn im_body_attestation(
        e: *mut im_cbor_enc_t,
        nonce: *const u8,
        csr_hash: *const u8,
        fw_hash: *const u8,
        fw_version: *const c_char,
        se_type: *const c_char,
    );
    pub fn im_env_sign_uplink(
        id: *const im_identity_t,
        kid: *const u8,
        kid_len: usize,
        payload: *const u8,
        payload_len: usize,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> im_err_t;
    pub fn im_replay_mem_init(s: *mut im_replay_mem_t);
    pub fn im_replay_mem_store(s: *mut im_replay_mem_t, out: *mut im_replay_store_t);
    pub fn im_replay_mem_last(s: *const im_replay_mem_t, kid: *const u8, kid_len: usize, dir: c_int, seq: *mut u64) -> bool;
}

// ---- im_manifest.h / im_delta.h / im_hpke.h / im_attest.h ------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_manifest_t {
    pub product: *const c_char,
    pub product_len: usize,
    pub version: *const c_char,
    pub version_len: usize,
    pub version_code: u64,
    pub image_sha256: *const u8,
    pub image_size: u64,
    pub created_at: u64,
    pub min_version_code: u64,
    pub has_delta: bool,
    pub delta_base_sha256: *const u8,
    pub delta_patch_sha256: *const u8,
    pub delta_patch_size: u64,
    pub signing_key_id: *const c_char,
    pub signing_key_id_len: usize,
}

impl Default for im_manifest_t {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_fw_keys_t {
    pub key: [*const u8; 4],
    pub len: [usize; 4],
    pub n: usize,
}

pub type ReadBaseFn = unsafe extern "C" fn(ctx: *mut c_void, off: u64, buf: *mut u8, len: usize) -> im_err_t;
pub type WriteFn = unsafe extern "C" fn(ctx: *mut c_void, off: u64, data: *const u8, len: usize) -> im_err_t;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_delta_io_t {
    pub read_base: Option<ReadBaseFn>,
    pub write: Option<WriteFn>,
    pub ctx: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct im_hpke_ctx_t {
    pub key: [u8; 16],
    pub base_nonce: [u8; 12],
    pub exporter_secret: [u8; 32],
    pub seq: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_attest_verify_opts_t {
    pub expected_nonce: *const u8,
    pub csr_der: *const u8,
    pub csr_len: usize,
    pub now: u64,
    pub max_skew: u64,
    pub expected_kid: *const u8,
    pub expected_kid_len: usize,
    pub allowed_se_types: c_uint,
    pub replay: *const im_replay_store_t,
}

extern "C" {
    pub fn im_manifest_decode(p: *const u8, n: usize, lim: *const im_cbor_limits_t, out: *mut im_manifest_t) -> im_err_t;
    pub fn im_manifest_verify(
        buf: *const u8,
        len: usize,
        trusted: *const im_fw_keys_t,
        require_pq: bool,
        lim: *const im_cbor_limits_t,
        work: *mut u8,
        work_len: usize,
        out: *mut im_manifest_t,
        pq_verified: *mut bool,
    ) -> im_err_t;
    pub fn im_manifest_encode(m: *const im_manifest_t, out: *mut u8, cap: usize, out_len: *mut usize) -> im_err_t;
    pub fn im_manifest_precheck(m: *const im_manifest_t, cur: u64, product: *const c_char) -> im_err_t;
    pub fn im_manifest_accept_image_bytes(
        m: *const im_manifest_t,
        image: *const u8,
        len: usize,
        cur: u64,
        product: *const c_char,
    ) -> im_err_t;
    pub fn im_manifest_accept_patch(m: *const im_manifest_t, patch_len: u64, patch_sha: *const u8, cur_hash: *const u8) -> im_err_t;

    pub fn im_delta_ctx_size() -> usize;
    pub fn im_delta_init(
        d: *mut c_void,
        io: *const im_delta_io_t,
        base_size: u64,
        max_target: u64,
        work: *mut u8,
        work_len: usize,
    ) -> im_err_t;
    pub fn im_delta_feed(d: *mut c_void, data: *const u8, len: usize) -> im_err_t;
    pub fn im_delta_finish(d: *mut c_void) -> im_err_t;
    pub fn im_delta_abort(d: *mut c_void);

    pub fn im_hpke_decap(id: *const im_identity_t, enc: *const u8, shared: *mut u8) -> im_err_t;
    pub fn im_hpke_key_schedule(shared: *const u8, info: *const u8, info_len: usize, ctx: *mut im_hpke_ctx_t) -> im_err_t;
    pub fn im_hpke_open(ctx: *mut im_hpke_ctx_t, aad: *const u8, aad_len: usize, ct: *const u8, ct_len: usize, pt: *mut u8) -> im_err_t;
    pub fn im_hpke_seal(ctx: *mut im_hpke_ctx_t, aad: *const u8, aad_len: usize, pt: *const u8, pt_len: usize, out: *mut u8) -> im_err_t;
    pub fn im_hpke_export(ctx: *const im_hpke_ctx_t, exp: *const u8, exp_len: usize, out: *mut u8, out_len: usize) -> im_err_t;
    pub fn im_hpke_derive_sk(ikm: *const u8, ikm_len: usize, sk: *mut u8) -> im_err_t;
    pub fn im_config_unwrap(buf: *const u8, len: usize, id: *const im_identity_t, pt: *mut u8, cap: usize, pt_len: *mut usize) -> im_err_t;

    pub fn im_attest_build(
        id: *const im_identity_t,
        kid: *const u8,
        kid_len: usize,
        seq: u64,
        ts: u64,
        nonce: *const u8,
        csr: *const u8,
        csr_len: usize,
        fw_hash: *const u8,
        fw_version: *const c_char,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> im_err_t;
    pub fn im_attest_verify(
        buf: *const u8,
        len: usize,
        key: *const im_pubkey_t,
        opts: *const im_attest_verify_opts_t,
        msg: *mut im_env_msg_t,
    ) -> im_err_t;
}
