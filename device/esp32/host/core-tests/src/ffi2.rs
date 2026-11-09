//! FFI declarations for the runtime modules: MQTT codec/session, ring buffer, OTA state machine,
//! utilities (JSON, base64, command cache), the device agent and the DUT dispatcher.
//! `tests/abi.rs` checks every mirrored struct size against `im_abi_size()`.
#![allow(non_camel_case_types, missing_docs)]

use crate::ffi::*;
use core::ffi::{c_char, c_int, c_void};

// ---- im_mqtt.h ------------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_mqtt_user_prop_t {
    pub key: *const c_char,
    pub key_len: u16,
    pub val: *const c_char,
    pub val_len: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_mqtt_props_t {
    pub has_payload_format: bool,
    pub payload_format: u8,
    pub has_message_expiry: bool,
    pub message_expiry: u32,
    pub content_type: *const c_char,
    pub content_type_len: u16,
    pub response_topic: *const c_char,
    pub response_topic_len: u16,
    pub correlation: *const u8,
    pub correlation_len: u16,
    pub sub_ids: [u32; 4],
    pub n_sub_ids: u8,
    pub has_session_expiry: bool,
    pub session_expiry: u32,
    pub assigned_client_id: *const c_char,
    pub assigned_client_id_len: u16,
    pub has_server_keep_alive: bool,
    pub server_keep_alive: u16,
    pub auth_method: *const c_char,
    pub auth_method_len: u16,
    pub auth_data: *const u8,
    pub auth_data_len: u16,
    pub has_request_problem_info: bool,
    pub request_problem_info: u8,
    pub has_will_delay: bool,
    pub will_delay: u32,
    pub has_request_response_info: bool,
    pub request_response_info: u8,
    pub response_info: *const c_char,
    pub response_info_len: u16,
    pub server_reference: *const c_char,
    pub server_reference_len: u16,
    pub reason_string: *const c_char,
    pub reason_string_len: u16,
    pub has_receive_maximum: bool,
    pub receive_maximum: u16,
    pub has_topic_alias_maximum: bool,
    pub topic_alias_maximum: u16,
    pub has_topic_alias: bool,
    pub topic_alias: u16,
    pub has_maximum_qos: bool,
    pub maximum_qos: u8,
    pub has_retain_available: bool,
    pub retain_available: u8,
    pub user: [im_mqtt_user_prop_t; 4],
    pub n_user: u8,
    pub n_user_all: u16,
    pub has_maximum_packet_size: bool,
    pub maximum_packet_size: u32,
    pub has_wildcard_available: bool,
    pub wildcard_available: u8,
    pub has_sub_id_available: bool,
    pub sub_id_available: u8,
    pub has_shared_available: bool,
    pub shared_available: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_mqtt_packet_t {
    pub type_: u8,
    pub flags: u8,
    pub session_present: bool,
    pub reason_code: u8,
    pub qos: u8,
    pub retain: bool,
    pub dup: bool,
    pub topic: *const c_char,
    pub topic_len: u16,
    pub payload: *const u8,
    pub payload_len: usize,
    pub packet_id: u16,
    pub reason_codes: *const u8,
    pub n_reason_codes: usize,
    pub filter: *const c_char,
    pub filter_len: u16,
    pub keep_alive: u16,
    pub clean_start: bool,
    pub client_id: *const c_char,
    pub client_id_len: u16,
    pub username: *const c_char,
    pub username_len: u16,
    pub has_password: bool,
    pub has_will: bool,
    pub props: im_mqtt_props_t,
}

impl Default for im_mqtt_packet_t {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_mqtt_connect_t {
    pub client_id: *const c_char,
    pub keep_alive: u16,
    pub clean_start: bool,
    pub session_expiry: u32,
    pub receive_maximum: u16,
    pub maximum_packet_size: u32,
    pub username: *const c_char,
    pub user: *const im_mqtt_user_prop_t,
    pub n_user: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_mqtt_session_cb_t {
    pub send: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> im_err_t>,
    pub on_connack: Option<unsafe extern "C" fn(*mut c_void, bool, u8)>,
    pub on_publish: Option<unsafe extern "C" fn(*mut c_void, *const im_mqtt_packet_t)>,
    pub on_puback: Option<unsafe extern "C" fn(*mut c_void, u16, u8)>,
    pub on_suback: Option<unsafe extern "C" fn(*mut c_void, u16, u8)>,
    pub on_disconnect: Option<unsafe extern "C" fn(*mut c_void, u8, bool)>,
    pub ctx: *mut c_void,
}

extern "C" {
    pub fn im_mqtt_frame(buf: *const u8, len: usize, max_packet: usize, frame_len: *mut usize) -> im_err_t;
    pub fn im_mqtt_decode(frame: *const u8, len: usize, out: *mut im_mqtt_packet_t) -> im_err_t;
    pub fn im_mqtt_enc_connect(c: *const im_mqtt_connect_t, out: *mut u8, cap: usize, len: *mut usize) -> im_err_t;
    pub fn im_mqtt_enc_publish(
        topic: *const c_char,
        topic_len: usize,
        qos: u8,
        retain: bool,
        dup: bool,
        pid: u16,
        user: *const im_mqtt_user_prop_t,
        n_user: usize,
        payload: *const u8,
        payload_len: usize,
        out: *mut u8,
        cap: usize,
        len: *mut usize,
    ) -> im_err_t;
    pub fn im_mqtt_enc_puback(pid: u16, reason: u8, out: *mut u8, cap: usize, len: *mut usize) -> im_err_t;
    pub fn im_mqtt_enc_subscribe(
        pid: u16,
        filter: *const c_char,
        filter_len: usize,
        options: u8,
        out: *mut u8,
        cap: usize,
        len: *mut usize,
    ) -> im_err_t;
    pub fn im_mqtt_enc_pingreq(out: *mut u8, cap: usize, len: *mut usize) -> im_err_t;
    pub fn im_mqtt_enc_pingresp(out: *mut u8, cap: usize, len: *mut usize) -> im_err_t;
    pub fn im_mqtt_enc_disconnect(reason: u8, out: *mut u8, cap: usize, len: *mut usize) -> im_err_t;
    pub fn im_mqtt_enc_connack(sp: bool, reason: u8, rm: u16, out: *mut u8, cap: usize, len: *mut usize) -> im_err_t;
    pub fn im_mqtt_enc_suback(pid: u16, codes: *const u8, n: usize, out: *mut u8, cap: usize, len: *mut usize) -> im_err_t;

    pub fn im_mqtt_session_init(s: *mut c_void, cb: *const im_mqtt_session_cb_t);
    pub fn im_mqtt_session_connect(s: *mut c_void, c: *const im_mqtt_connect_t, now_ms: u64) -> im_err_t;
    pub fn im_mqtt_session_input(s: *mut c_void, data: *const u8, len: usize, now_ms: u64) -> im_err_t;
    pub fn im_mqtt_session_publish(
        s: *mut c_void,
        topic: *const c_char,
        payload: *const u8,
        len: usize,
        qos: u8,
        retain: bool,
        user: *const im_mqtt_user_prop_t,
        n_user: usize,
        pid: *mut u16,
        now_ms: u64,
    ) -> im_err_t;
    pub fn im_mqtt_session_subscribe(s: *mut c_void, filter: *const c_char, qos: u8, pid: *mut u16, now_ms: u64) -> im_err_t;
    pub fn im_mqtt_session_disconnect(s: *mut c_void, reason: u8) -> im_err_t;
    pub fn im_mqtt_session_tick(s: *mut c_void, now_ms: u64) -> im_err_t;
    pub fn im_mqtt_session_reset(s: *mut c_void);
    pub fn im_mqtt_session_inflight(s: *const c_void) -> usize;
}

// ---- im_ringbuf.h -----------------------------------------------------------------------------

pub type StRead = unsafe extern "C" fn(*mut c_void, u32, *mut u8, usize) -> im_err_t;
pub type StWrite = unsafe extern "C" fn(*mut c_void, u32, *const u8, usize) -> im_err_t;
pub type StErase = unsafe extern "C" fn(*mut c_void, u32, usize) -> im_err_t;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_storage_t {
    pub read: Option<StRead>,
    pub write: Option<StWrite>,
    pub erase: Option<StErase>,
    pub ctx: *mut c_void,
    pub size: u32,
    pub sector_size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_ringbuf_t {
    pub st: im_storage_t,
    pub slot_size: u32,
    pub nslots: u32,
    pub head: u32,
    pub tail: u32,
    pub next_id: u32,
    pub count: u32,
    pub dropped: u32,
    pub tail_valid: bool,
}

extern "C" {
    pub fn im_rb_init(rb: *mut im_ringbuf_t, st: *const im_storage_t, slot_size: u32) -> im_err_t;
    pub fn im_rb_format(rb: *mut im_ringbuf_t) -> im_err_t;
    pub fn im_rb_max_payload(rb: *const im_ringbuf_t) -> u32;
    pub fn im_rb_push(rb: *mut im_ringbuf_t, data: *const u8, len: usize) -> im_err_t;
    pub fn im_rb_peek(rb: *mut im_ringbuf_t, buf: *mut u8, cap: usize, len: *mut usize, id: *mut u32) -> im_err_t;
    pub fn im_rb_pop(rb: *mut im_ringbuf_t) -> im_err_t;
    pub fn im_rb_count(rb: *const im_ringbuf_t) -> u32;
    pub fn im_crc32(crc: u32, p: *const u8, n: usize) -> u32;
}

// ---- im_ota.h ---------------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_kv_t {
    pub get: Option<unsafe extern "C" fn(*mut c_void, *const c_char, *mut u8, usize, *mut usize) -> im_err_t>,
    pub set: Option<unsafe extern "C" fn(*mut c_void, *const c_char, *const u8, usize) -> im_err_t>,
    pub erase: Option<unsafe extern "C" fn(*mut c_void, *const c_char) -> im_err_t>,
    pub ctx: *mut c_void,
}

pub type ReportFn = unsafe extern "C" fn(*mut c_void, *const c_char, c_int, u32, *const c_char, *const u8);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_ota_platform_t {
    pub slot_begin: Option<unsafe extern "C" fn(*mut c_void, u64) -> im_err_t>,
    pub slot_write: Option<unsafe extern "C" fn(*mut c_void, u64, *const u8, usize) -> im_err_t>,
    pub slot_finish: Option<unsafe extern "C" fn(*mut c_void) -> im_err_t>,
    pub slot_abort: Option<unsafe extern "C" fn(*mut c_void)>,
    pub set_boot: Option<unsafe extern "C" fn(*mut c_void, u64) -> im_err_t>,
    pub read_running: Option<unsafe extern "C" fn(*mut c_void, u64, *mut u8, usize) -> im_err_t>,
    pub mark_valid: Option<unsafe extern "C" fn(*mut c_void) -> im_err_t>,
    pub rollback: Option<unsafe extern "C" fn(*mut c_void) -> im_err_t>,
    pub report: Option<ReportFn>,
    pub ctx: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_ota_config_t {
    pub pf: im_ota_platform_t,
    pub kv: im_kv_t,
    pub product: *const c_char,
    pub current_version_code: u64,
    pub current_fw_hash: [u8; 32],
    pub running_size: u64,
    pub slot_size: u64,
    pub require_pq: bool,
    pub keys: im_fw_keys_t,
    pub work: *mut u8,
    pub work_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_ota_notify_t {
    pub campaign_id: *const c_char,
    pub manifest: *const u8,
    pub manifest_len: usize,
    pub url: *const c_char,
    pub url_len: usize,
    pub delta_from: *const u8,
}

extern "C" {
    pub fn im_ota_ctx_size() -> usize;
    pub fn im_ota_init(o: *mut c_void, cfg: *const im_ota_config_t) -> im_err_t;
    pub fn im_ota_boot(o: *mut c_void, now_ms: u64, reason: *mut c_int) -> im_err_t;
    pub fn im_ota_on_notify(o: *mut c_void, n: *const im_ota_notify_t) -> im_err_t;
    pub fn im_ota_on_data(o: *mut c_void, data: *const u8, len: usize) -> im_err_t;
    pub fn im_ota_on_complete(o: *mut c_void) -> im_err_t;
    pub fn im_ota_on_failure(o: *mut c_void, err: im_err_t);
    pub fn im_ota_health_ok(o: *mut c_void) -> im_err_t;
    pub fn im_ota_tick(o: *mut c_void, now_ms: u64) -> im_err_t;
    pub fn im_ota_busy(o: *const c_void) -> bool;
    pub fn im_ota_error_name(err: im_err_t) -> *const c_char;
    pub fn im_ota_state_name(state: c_int) -> *const c_char;
}

// ---- im_util.h --------------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_cmd_entry_t {
    pub used: bool,
    pub key_hash: [u8; 16],
    pub cmd_id: [c_char; 37],
    pub status: u8,
    pub keep_until: u64,
    pub lru: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_cmd_cache_t {
    pub e: [im_cmd_entry_t; 16],
    pub tick: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct im_json_tok_t {
    pub type_: u8,
    pub start: u32,
    pub end: u32,
    pub size: u32,
    pub span: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_json_t {
    pub js: *const c_char,
    pub len: usize,
    pub tok: *mut im_json_tok_t,
    pub ntok: usize,
}

#[repr(C)]
pub struct im_json_w_t {
    pub buf: *mut c_char,
    pub cap: usize,
    pub len: usize,
    pub err: bool,
    pub depth: u8,
    pub first: [bool; 9],
    pub after_key: bool,
}

extern "C" {
    pub fn im_abi_size(which: c_int) -> usize;
    pub fn im_cmd_cache_init(c: *mut im_cmd_cache_t);
    pub fn im_cmd_cache_lookup(
        c: *mut im_cmd_cache_t,
        key: *const c_char,
        n: usize,
        now: u64,
        status: *mut u8,
        cmd_id: *mut c_char,
    ) -> im_err_t;
    pub fn im_cmd_cache_store(
        c: *mut im_cmd_cache_t,
        key: *const c_char,
        n: usize,
        cmd_id: *const c_char,
        status: u8,
        expires_at: u64,
        now: u64,
    ) -> im_err_t;
    pub fn im_b64_encode(input: *const u8, n: usize, out: *mut c_char, cap: usize, out_len: *mut usize) -> im_err_t;
    pub fn im_b64_decode(input: *const c_char, n: usize, out: *mut u8, cap: usize, out_len: *mut usize) -> im_err_t;
    pub fn im_json_parse(j: *mut im_json_t, js: *const c_char, len: usize, toks: *mut im_json_tok_t, max: usize) -> im_err_t;
    pub fn im_json_get(j: *const im_json_t, obj: c_int, key: *const c_char) -> c_int;
    pub fn im_json_u64(j: *const im_json_t, tok: c_int, out: *mut u64) -> bool;
    pub fn im_json_bool(j: *const im_json_t, tok: c_int, out: *mut bool) -> bool;
    pub fn im_json_str(j: *const im_json_t, tok: c_int, out: *mut c_char, cap: usize, len: *mut usize) -> bool;
    pub fn im_jw_init(w: *mut im_json_w_t, buf: *mut c_char, cap: usize);
    pub fn im_jw_obj(w: *mut im_json_w_t);
    pub fn im_jw_obj_end(w: *mut im_json_w_t);
    pub fn im_jw_arr(w: *mut im_json_w_t);
    pub fn im_jw_arr_end(w: *mut im_json_w_t);
    pub fn im_jw_key(w: *mut im_json_w_t, k: *const c_char);
    pub fn im_jw_str(w: *mut im_json_w_t, s: *const c_char, n: usize);
    pub fn im_jw_cstr(w: *mut im_json_w_t, s: *const c_char);
    pub fn im_jw_hex(w: *mut im_json_w_t, p: *const u8, n: usize);
    pub fn im_jw_u64(w: *mut im_json_w_t, v: u64);
    pub fn im_jw_i64(w: *mut im_json_w_t, v: i64);
    pub fn im_jw_bool(w: *mut im_json_w_t, v: bool);
    pub fn im_jw_null(w: *mut im_json_w_t);
    pub fn im_jw_finish(w: *mut im_json_w_t, len: *mut usize) -> im_err_t;
}

// ---- im_agent.h -------------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_agent_config_t {
    pub device_id: *const c_char,
    pub tenant_id: *const c_char,
    pub product: *const c_char,
    pub fw_version: *const c_char,
    pub fw_version_code: u64,
    pub fw_hash: [u8; 32],
    pub fw_size: u64,
    pub slot_size: u64,
    pub bundle_pubkey: [u8; 32],
    pub require_pq: bool,
    pub telemetry_interval_s: u32,
    pub ringbuf_slot_size: u32,
    pub bootstrap_kid: *const u8,
    pub bootstrap_kid_len: usize,
    pub target: *const c_char,
    pub boot_reason: c_int,
    pub active_slot: *const c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_agent_platform_t {
    pub ctx: *mut c_void,
    pub identity: *const im_identity_t,
    pub now_unix: Option<unsafe extern "C" fn(*mut c_void) -> u64>,
    pub mono_ms: Option<unsafe extern "C" fn(*mut c_void) -> u64>,
    pub kv: im_kv_t,
    pub storage: im_storage_t,
    pub mqtt_connect: Option<unsafe extern "C" fn(*mut c_void, *const c_char, u16, *const c_char) -> im_err_t>,
    pub mqtt_disconnect: Option<unsafe extern "C" fn(*mut c_void) -> im_err_t>,
    pub mqtt_publish: Option<unsafe extern "C" fn(*mut c_void, *const c_char, *const u8, usize, c_int, bool, *mut u16) -> im_err_t>,
    pub mqtt_subscribe: Option<unsafe extern "C" fn(*mut c_void, *const c_char, *mut u16) -> im_err_t>,
    pub est_enroll: Option<unsafe extern "C" fn(*mut c_void, bool) -> im_err_t>,
    pub ota: im_ota_platform_t,
    pub ota_download: Option<unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> im_err_t>,
    pub sample: Option<unsafe extern "C" fn(*mut c_void, *mut im_telemetry_t)>,
    pub exec_command: Option<unsafe extern "C" fn(*mut c_void, *const c_char, usize, *const im_cbor_val_t, *mut u8) -> im_err_t>,
    pub apply_config: Option<unsafe extern "C" fn(*mut c_void, u64, *const im_cbor_val_t)>,
    pub emit: Option<unsafe extern "C" fn(*mut c_void, *const c_char, usize)>,
    pub reboot: Option<unsafe extern "C" fn(*mut c_void, c_int)>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_rejection_t {
    pub at_ms: u64,
    pub code: im_err_t,
    pub topic: [c_char; 96],
    pub detail: [c_char; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct im_dut_hooks_t {
    pub set_clock: Option<unsafe extern "C" fn(*mut c_void, u64) -> im_err_t>,
    pub slots: Option<unsafe extern "C" fn(*mut c_void, *mut im_json_w_t, *mut *const c_char, *mut *const c_char)>,
    pub ctx: *mut c_void,
}

pub const IM_REBOOT_REQUESTED: c_int = 0;
pub const IM_REBOOT_OTA_APPLY: c_int = 1;
pub const IM_REBOOT_ROLLBACK: c_int = 2;
pub const IM_REBOOT_WATCHDOG: c_int = 3;
pub const IM_REBOOT_POWER_ON: c_int = 4;

extern "C" {
    pub fn im_agent_ctx_size() -> usize;
    pub fn im_agent_init(a: *mut c_void, cfg: *const im_agent_config_t, pf: *const im_agent_platform_t) -> im_err_t;
    pub fn im_agent_start(a: *mut c_void) -> im_err_t;
    pub fn im_agent_tick(a: *mut c_void);
    pub fn im_agent_enroll(a: *mut c_void, renew: bool) -> im_err_t;
    pub fn im_agent_connect(a: *mut c_void) -> im_err_t;
    pub fn im_agent_send_telemetry(a: *mut c_void, count: u32, first: *mut u64, last: *mut u64) -> im_err_t;
    pub fn im_agent_attestation(
        a: *mut c_void,
        nonce: *const u8,
        csr: *const u8,
        csr_len: usize,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> im_err_t;
    pub fn im_agent_on_enrolled(
        a: *mut c_void,
        serial: *const u8,
        serial_len: usize,
        nb: u64,
        na: u64,
        bundle: *const u8,
        bundle_len: usize,
    ) -> im_err_t;
    pub fn im_agent_on_enroll_failed(a: *mut c_void, http_status: c_int, reason: *const c_char);
    pub fn im_agent_load_bundle(a: *mut c_void, bundle: *const u8, len: usize) -> im_err_t;
    pub fn im_agent_on_connected(a: *mut c_void, tls: *const c_char, alpn: *const c_char, sp: bool, resumed: bool);
    pub fn im_agent_on_connect_failed(a: *mut c_void, reason: *const c_char);
    pub fn im_agent_on_disconnected(a: *mut c_void, reason: *const c_char, code: c_int);
    pub fn im_agent_on_puback(a: *mut c_void, id: u16, reason: u8);
    pub fn im_agent_on_suback(a: *mut c_void, id: u16, reason: u8);
    pub fn im_agent_on_message(a: *mut c_void, topic: *const c_char, topic_len: usize, payload: *const u8, len: usize);
    pub fn im_agent_on_ota_data(a: *mut c_void, data: *const u8, len: usize);
    pub fn im_agent_on_ota_done(a: *mut c_void, err: im_err_t);
    pub fn im_agent_ota_version(a: *const c_void, out: *mut c_char, cap: usize) -> im_err_t;
    pub fn im_dut_handle(
        a: *mut c_void,
        hooks: *const im_dut_hooks_t,
        line: *const c_char,
        len: usize,
        out: *mut c_char,
        cap: usize,
        out_len: *mut usize,
    ) -> im_err_t;
}
