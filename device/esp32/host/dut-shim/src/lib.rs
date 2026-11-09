//! `esp32-host` DUT: the ESP32 protocol core (`components/im_core`, compiled for the host) behind
//! the DUT control protocol of `conformance/DUT_PROTOCOL.md`.
//!
//! **Every protocol decision runs in C** (`im_agent.c`, `im_dut.c`, envelope/replay/OTA/buffer/
//! command handling). This crate only supplies what the ESP32 platform layer supplies on the
//! device: crypto (via `im_host::crypto`), the identity key, TLS + MQTT transport bytes (the C
//! MQTT session runs over either the in-process simulated broker or a real rustls connection),
//! a simulated NOR flash / NVS / A/B slot pair, the clock, and the EST HTTP exchange.
//!
//! What this validates: the protocol core. What it does not: the ESP32 radio, esp-tls/mbedTLS,
//! esp-mqtt, the ATECC608 driver or the bootloader - those are covered by the HIL job.

pub mod der;
pub mod net;
pub mod sim_cloud;

use core::ffi::{c_char, c_int, c_void, CStr};
use im_host::err::*;
use im_host::ffi::*;
use im_host::ffi2::*;
use im_host::sim::{Kv, NorFlash, Slots};
use im_host::{testkit, Opaque, SoftIdentity};
use sim_cloud::SimCloud;
use std::collections::VecDeque;
use std::ffi::CString;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const TARGET: &str = "esp32-host";
const RINGBUF_BYTES: u32 = 256 * 1024;
const SLOT_SIZE: u64 = 2 * 1024 * 1024;

/// Static identity and firmware description of the simulated device.
#[derive(Clone)]
pub struct DeviceConfig {
    pub device_id: String,
    pub tenant_id: String,
    pub product: String,
    pub fw_version: String,
    pub fw_version_code: u64,
    pub firmware: Vec<u8>,
    pub bootstrap_serial: Vec<u8>,
    pub bundle_pubkey: [u8; 32],
    pub telemetry_interval_s: u32,
    pub real: Option<net::RealConfig>,
}

impl DeviceConfig {
    /// Defaults for the simulated cloud.
    pub fn sim() -> Self {
        let keys = sim_cloud::SimKeys::new();
        Self {
            device_id: "dev-8f3a1c2b9d4e5f60".into(),
            tenant_id: "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11".into(),
            product: "sensor-esp32".into(),
            fw_version: "1.0.0".into(),
            fw_version_code: 10000,
            firmware: (0..64 * 1024).map(|i| (i as u32).wrapping_mul(2_654_435_761) as u8).collect(),
            bootstrap_serial: vec![0x0b, 0x00, 0x7a, 0x11],
            bundle_pubkey: keys.bundle.public(),
            telemetry_interval_s: 0,
            real: None,
        }
    }
}

/// Mutable device state shared with the C callbacks (always accessed through a raw pointer).
pub struct Inner {
    cfg: DeviceConfig,
    c_device: CString,
    c_tenant: CString,
    c_product: CString,
    c_fw_version: CString,
    c_target: CString,
    c_slot_names: [CString; 2],
    agent: Opaque,
    identity: Box<SoftIdentity>,
    id_ffi: Box<im_identity_t>,
    pub flash: Box<NorFlash>,
    pub kv: Box<Kv>,
    pub slots: Slots,
    slot_versions: [String; 2],
    clock_offset: i64,
    mono_offset_ms: u64,
    start: Instant,
    pub events: VecDeque<String>,
    session: Opaque,
    link: Option<Box<dyn net::Link>>,
    connect_count: u32,
    pending_reboot: Option<c_int>,
    pending_enroll: Option<bool>,
    pending_download: Option<String>,
    pending_connect_fail: Option<&'static str>,
    pub sim: Option<SimCloud>,
    op_cert: Option<Vec<u8>>,
    staged: Vec<u8>,
    pub executed_commands: Vec<String>,
}

/// The device under test.
pub struct Device {
    p: *mut Inner,
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe { drop(Box::from_raw(self.p)) };
    }
}

unsafe fn inner<'a>(ctx: *mut c_void) -> &'a mut Inner {
    &mut *(ctx as *mut Inner)
}

fn now_unix(i: &Inner) -> u64 {
    let sys = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    (sys + i.clock_offset).max(0) as u64
}

// ---- platform callbacks ------------------------------------------------------------------------

unsafe extern "C" fn cb_now(ctx: *mut c_void) -> u64 {
    now_unix(inner(ctx))
}

unsafe extern "C" fn cb_mono(ctx: *mut c_void) -> u64 {
    let i = inner(ctx);
    i.start.elapsed().as_millis() as u64 + i.mono_offset_ms
}

unsafe extern "C" fn cb_emit(ctx: *mut c_void, line: *const c_char, len: usize) {
    let s = String::from_utf8_lossy(core::slice::from_raw_parts(line as *const u8, len)).into_owned();
    inner(ctx).events.push_back(s);
}

unsafe extern "C" fn cb_reboot(ctx: *mut c_void, reason: c_int) {
    inner(ctx).pending_reboot = Some(reason);
}

unsafe extern "C" fn cb_est(ctx: *mut c_void, renew: bool) -> i32 {
    inner(ctx).pending_enroll = Some(renew);
    IM_OK
}

unsafe extern "C" fn cb_sample(_ctx: *mut c_void, t: *mut im_telemetry_t) {
    let t = &mut *t;
    t.cpu_pct = 12.5;
    t.mem_pct = 40.25;
    t.temp_c = 36.5;
    t.has_rssi = true;
    t.rssi = -61;
    t.has_free_heap = true;
    t.free_heap = 182_272;
}

unsafe extern "C" fn cb_exec(ctx: *mut c_void, name: *const c_char, n: usize, _args: *const im_cbor_val_t, status: *mut u8) -> i32 {
    let name = String::from_utf8_lossy(core::slice::from_raw_parts(name as *const u8, n)).into_owned();
    let i = inner(ctx);
    if name == "blink" || name == "noop" {
        i.executed_commands.push(name);
        *status = 0;
        return IM_OK;
    }
    IM_ERR_NOT_FOUND
}

// MQTT: the C session produces/consumes the bytes, the link carries them.

unsafe extern "C" fn cb_mqtt_connect(ctx: *mut c_void, host: *const c_char, port: u16, client_id: *const c_char) -> i32 {
    let i = inner(ctx);
    let host = CStr::from_ptr(host).to_string_lossy().into_owned();
    let link: Result<Box<dyn net::Link>, String> = match (&i.cfg.real, &mut i.sim) {
        (Some(real), _) => {
            let pins = agent_pins(i);
            net::TlsLink::connect(real, &host, port, &pins, i.op_cert.clone(), &i.identity).map(|l| Box::new(l) as Box<dyn net::Link>)
        }
        (None, Some(sim)) => {
            sim.broker.reset_connection();
            Ok(Box::new(net::SimLink::default()))
        }
        _ => Err("network".into()),
    };
    match link {
        Ok(l) => {
            i.link = Some(l);
            let c = im_mqtt_connect_t {
                client_id,
                keep_alive: 60,
                clean_start: false,
                session_expiry: 7 * 24 * 3600,
                receive_maximum: 32,
                maximum_packet_size: 16384,
                username: std::ptr::null(),
                user: std::ptr::null(),
                n_user: 0,
            };
            let now = cb_mono(ctx);
            im_mqtt_session_connect(i.session.ptr(), &c, now)
        }
        Err(reason) => {
            i.events
                .push_back(format!("{{\"event\":\"_log\",\"data\":{{\"connect_error\":{:?}}}}}", reason));
            // async failure, reported from poll() like a real stack would
            i.pending_connect_fail = Some(net::classify(&reason));
            IM_OK
        }
    }
}

fn agent_pins(i: &Inner) -> Vec<[u8; 32]> {
    // pins live inside the C agent struct; the shim reads them through the bundle it stored
    let mut out = Vec::new();
    if let Some(b) = i.kv.map.get("bundle") {
        out = net::bundle_pins(b);
    }
    out
}

unsafe extern "C" fn cb_mqtt_disconnect(ctx: *mut c_void) -> i32 {
    let i = inner(ctx);
    let _ = im_mqtt_session_disconnect(i.session.ptr(), 0);
    if let Some(mut l) = i.link.take() {
        l.close();
    }
    IM_OK
}

unsafe extern "C" fn cb_mqtt_publish(
    ctx: *mut c_void,
    topic: *const c_char,
    p: *const u8,
    n: usize,
    qos: c_int,
    retain: bool,
    id: *mut u16,
) -> i32 {
    let i = inner(ctx);
    let now = cb_mono(ctx);
    im_mqtt_session_publish(i.session.ptr(), topic, p, n, qos as u8, retain, std::ptr::null(), 0, id, now)
}

unsafe extern "C" fn cb_mqtt_subscribe(ctx: *mut c_void, topic: *const c_char, id: *mut u16) -> i32 {
    let i = inner(ctx);
    let now = cb_mono(ctx);
    im_mqtt_session_subscribe(i.session.ptr(), topic, 1, id, now)
}

unsafe extern "C" fn cb_ota_download(ctx: *mut c_void, url: *const c_char, n: usize) -> i32 {
    let url = String::from_utf8_lossy(core::slice::from_raw_parts(url as *const u8, n)).into_owned();
    inner(ctx).pending_download = Some(url);
    IM_OK
}

// OTA slots

unsafe extern "C" fn ota_begin(ctx: *mut c_void, _size: u64) -> i32 {
    inner(ctx).staged.clear();
    IM_OK
}
unsafe extern "C" fn ota_write(ctx: *mut c_void, off: u64, d: *const u8, n: usize) -> i32 {
    let i = inner(ctx);
    if off as usize != i.staged.len() || i.staged.len() + n > SLOT_SIZE as usize {
        return IM_ERR_IO;
    }
    i.staged.extend_from_slice(core::slice::from_raw_parts(d, n));
    IM_OK
}
unsafe extern "C" fn ota_finish(_ctx: *mut c_void) -> i32 {
    IM_OK
}
unsafe extern "C" fn ota_abort(ctx: *mut c_void) {
    inner(ctx).staged.clear();
}
unsafe extern "C" fn ota_set_boot(ctx: *mut c_void, vc: u64) -> i32 {
    let i = inner(ctx);
    let t = i.slots.inactive();
    let mut ver = [0 as c_char; 80];
    let v = if im_agent_ota_version(i.agent.ptr(), ver.as_mut_ptr(), ver.len()) == IM_OK {
        CStr::from_ptr(ver.as_ptr()).to_string_lossy().into_owned()
    } else {
        "0.0.0".into()
    };
    i.slots.slots[t].image = std::mem::take(&mut i.staged);
    i.slots.slots[t].version_code = vc;
    i.slots.slots[t].version = v.clone();
    i.slots.slots[t].state = "new".into();
    i.slot_versions[t] = v;
    i.slots.boot_next = Some(t);
    IM_OK
}
unsafe extern "C" fn ota_read(ctx: *mut c_void, off: u64, b: *mut u8, n: usize) -> i32 {
    let img = &inner(ctx).slots.running().image;
    let off = off as usize;
    if off + n > img.len() {
        return IM_ERR_IO;
    }
    core::slice::from_raw_parts_mut(b, n).copy_from_slice(&img[off..off + n]);
    IM_OK
}
unsafe extern "C" fn ota_valid(ctx: *mut c_void) -> i32 {
    let i = inner(ctx);
    let a = i.slots.active;
    i.slots.slots[a].state = "valid".into();
    IM_OK
}
unsafe extern "C" fn ota_rollback(ctx: *mut c_void) -> i32 {
    let i = inner(ctx);
    let a = i.slots.active;
    i.slots.slots[a].state = "invalid".into();
    i.slots.active = 1 - a;
    i.slots.boot_next = None;
    i.pending_reboot = Some(IM_REBOOT_ROLLBACK);
    IM_OK
}

// MQTT session -> agent

unsafe extern "C" fn s_send(ctx: *mut c_void, d: *const u8, n: usize) -> i32 {
    let i = inner(ctx);
    let data = core::slice::from_raw_parts(d, n);
    match (&mut i.link, &mut i.sim) {
        (Some(l), sim) => {
            if l.is_sim() {
                if let Some(sim) = sim {
                    if !sim.broker.ingest(data) {
                        l.close();
                    }
                    return IM_OK;
                }
            }
            if l.send(data).is_ok() {
                IM_OK
            } else {
                IM_ERR_IO
            }
        }
        _ => IM_ERR_IO,
    }
}
unsafe extern "C" fn s_connack(ctx: *mut c_void, sp: bool, reason: u8) {
    let i = inner(ctx);
    if reason == 0 {
        i.connect_count += 1;
        let resumed = i.link.as_ref().is_some_and(|l| l.resumed()) || (i.sim.is_some() && i.connect_count > 1);
        let tls = i.link.as_ref().map(|l| l.tls_version()).unwrap_or("TLSv1.3");
        let tls = CString::new(tls).unwrap();
        im_agent_on_connected(i.agent.ptr(), tls.as_ptr(), c"mqtt".as_ptr(), sp, resumed);
    } else {
        i.link = None;
        im_agent_on_connect_failed(i.agent.ptr(), c"not_authorized".as_ptr());
    }
}
unsafe extern "C" fn s_publish(ctx: *mut c_void, p: *const im_mqtt_packet_t) {
    let i = inner(ctx);
    let p = &*p;
    im_agent_on_message(i.agent.ptr(), p.topic, p.topic_len as usize, p.payload, p.payload_len);
}
unsafe extern "C" fn s_puback(ctx: *mut c_void, id: u16, r: u8) {
    im_agent_on_puback(inner(ctx).agent.ptr(), id, r);
}
unsafe extern "C" fn s_suback(ctx: *mut c_void, id: u16, r: u8) {
    im_agent_on_suback(inner(ctx).agent.ptr(), id, r);
}
unsafe extern "C" fn s_disconnect(ctx: *mut c_void, r: u8, _peer: bool) {
    let i = inner(ctx);
    i.link = None;
    im_agent_on_disconnected(i.agent.ptr(), c"broker".as_ptr(), c_int::from(r));
}

// DUT hooks

unsafe extern "C" fn h_set_clock(ctx: *mut c_void, unix_s: u64) -> i32 {
    let i = inner(ctx);
    let sys = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    i.clock_offset = unix_s as i64 - sys;
    IM_OK
}

unsafe extern "C" fn h_slots(ctx: *mut c_void, w: *mut im_json_w_t, active: *mut *const c_char, pending: *mut *const c_char) {
    let i = inner(ctx);
    *active = i.c_slot_names[i.slots.active].as_ptr();
    *pending = i.slots.boot_next.map_or(std::ptr::null(), |n| i.c_slot_names[n].as_ptr());
    if w.is_null() {
        return;
    }
    for (k, s) in i.slots.slots.iter().enumerate() {
        im_jw_obj(w);
        im_jw_key(w, c"name".as_ptr());
        im_jw_cstr(w, i.c_slot_names[k].as_ptr());
        let v = CString::new(s.version.clone()).unwrap_or_default();
        im_jw_key(w, c"version".as_ptr());
        im_jw_cstr(w, v.as_ptr());
        im_jw_key(w, c"version_code".as_ptr());
        im_jw_u64(w, s.version_code);
        im_jw_key(w, c"sha256_hex".as_ptr());
        if s.image.is_empty() {
            im_jw_null(w);
        } else {
            let h = testkit::sha256(&s.image);
            im_jw_hex(w, h.as_ptr(), 32);
        }
        let st = CString::new(s.state.clone()).unwrap_or_default();
        im_jw_key(w, c"state".as_ptr());
        im_jw_cstr(w, st.as_ptr());
        im_jw_obj_end(w);
    }
}

impl Inner {
    fn platform(&mut self) -> im_agent_platform_t {
        let ctx: *mut c_void = (self as *mut Inner).cast();
        im_agent_platform_t {
            ctx,
            identity: &*self.id_ffi,
            now_unix: Some(cb_now),
            mono_ms: Some(cb_mono),
            kv: self.kv.ffi(),
            storage: self.flash.storage(),
            mqtt_connect: Some(cb_mqtt_connect),
            mqtt_disconnect: Some(cb_mqtt_disconnect),
            mqtt_publish: Some(cb_mqtt_publish),
            mqtt_subscribe: Some(cb_mqtt_subscribe),
            est_enroll: Some(cb_est),
            ota: im_ota_platform_t {
                slot_begin: Some(ota_begin),
                slot_write: Some(ota_write),
                slot_finish: Some(ota_finish),
                slot_abort: Some(ota_abort),
                set_boot: Some(ota_set_boot),
                read_running: Some(ota_read),
                mark_valid: Some(ota_valid),
                rollback: Some(ota_rollback),
                report: None,
                ctx,
            },
            ota_download: Some(cb_ota_download),
            sample: Some(cb_sample),
            exec_command: Some(cb_exec),
            apply_config: None,
            emit: Some(cb_emit),
            reboot: Some(cb_reboot),
        }
    }

    /// (Re)create the C agent for the currently running slot.
    unsafe fn boot(&mut self, reason: c_int) -> Result<(), String> {
        let ctx: *mut c_void = (self as *mut Inner).cast();
        let running = self.slots.running().clone();
        self.c_fw_version = CString::new(if running.version.is_empty() {
            self.cfg.fw_version.clone()
        } else {
            running.version.clone()
        })
        .unwrap();
        let cb = im_mqtt_session_cb_t {
            send: Some(s_send),
            on_connack: Some(s_connack),
            on_publish: Some(s_publish),
            on_puback: Some(s_puback),
            on_suback: Some(s_suback),
            on_disconnect: Some(s_disconnect),
            ctx,
        };
        im_mqtt_session_init(self.session.ptr(), &cb);
        let cfg = im_agent_config_t {
            device_id: self.c_device.as_ptr(),
            tenant_id: self.c_tenant.as_ptr(),
            product: self.c_product.as_ptr(),
            fw_version: self.c_fw_version.as_ptr(),
            fw_version_code: running.version_code,
            fw_hash: testkit::sha256(&running.image),
            fw_size: running.image.len() as u64,
            slot_size: SLOT_SIZE,
            bundle_pubkey: self.cfg.bundle_pubkey,
            require_pq: false,
            telemetry_interval_s: self.cfg.telemetry_interval_s,
            ringbuf_slot_size: 512,
            bootstrap_kid: self.cfg.bootstrap_serial.as_ptr(),
            bootstrap_kid_len: self.cfg.bootstrap_serial.len(),
            target: self.c_target.as_ptr(),
            boot_reason: reason,
            active_slot: self.c_slot_names[self.slots.active].as_ptr(),
        };
        let pf = self.platform();
        im_host::check(im_agent_init(self.agent.ptr(), &cfg, &pf)).map_err(String::from)?;
        im_host::check(im_agent_start(self.agent.ptr())).map_err(String::from)
    }
}

impl Device {
    pub fn new(cfg: DeviceConfig) -> Result<Self, String> {
        let bootstrap = SoftIdentity::random();
        let sim = if cfg.real.is_none() {
            Some(SimCloud::new(&cfg.device_id))
        } else {
            None
        };
        let identity = match &cfg.real {
            Some(r) => SoftIdentity::from_scalar(&r.bootstrap_key),
            None => bootstrap,
        };
        let id_ffi = Box::new(identity.ffi());
        let slots = Slots::new(cfg.firmware.clone(), &cfg.fw_version, cfg.fw_version_code);
        let inner = Box::new(Inner {
            c_device: CString::new(cfg.device_id.clone()).map_err(|e| e.to_string())?,
            c_tenant: CString::new(cfg.tenant_id.clone()).map_err(|e| e.to_string())?,
            c_product: CString::new(cfg.product.clone()).map_err(|e| e.to_string())?,
            c_fw_version: CString::new(cfg.fw_version.clone()).map_err(|e| e.to_string())?,
            c_target: CString::new(TARGET).unwrap(),
            c_slot_names: [CString::new("ota_0").unwrap(), CString::new("ota_1").unwrap()],
            agent: Opaque::new(unsafe { im_agent_ctx_size() }),
            identity,
            id_ffi,
            flash: NorFlash::new(RINGBUF_BYTES, 4096),
            kv: Box::default(),
            slots,
            slot_versions: [cfg.fw_version.clone(), String::new()],
            clock_offset: 0,
            mono_offset_ms: 0,
            start: Instant::now(),
            events: VecDeque::new(),
            session: Opaque::new(unsafe { im_abi_size(2) }),
            link: None,
            connect_count: 0,
            pending_reboot: None,
            pending_enroll: None,
            pending_download: None,
            pending_connect_fail: None,
            sim,
            op_cert: None,
            staged: Vec::new(),
            executed_commands: Vec::new(),
            cfg,
        });
        let p = Box::into_raw(inner);
        let d = Device { p };
        unsafe { (*p).boot(IM_REBOOT_POWER_ON)? };
        Ok(d)
    }

    fn i(&self) -> *mut Inner {
        self.p
    }

    /// Handle one DUT request line; returns the response line.
    pub fn handle_line(&mut self, line: &str) -> String {
        let mut out = vec![0 as c_char; 64 * 1024];
        let mut n = 0usize;
        let p = self.i();
        let hooks = im_dut_hooks_t {
            set_clock: Some(h_set_clock),
            slots: Some(h_slots),
            ctx: p.cast(),
        };
        let r = unsafe {
            im_dut_handle(
                (*p).agent.ptr(),
                &hooks,
                line.as_ptr().cast(),
                line.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut n,
            )
        };
        let resp = if r == IM_OK {
            String::from_utf8_lossy(unsafe { core::slice::from_raw_parts(out.as_ptr() as *const u8, n) }).into_owned()
        } else {
            format!(
                "{{\"id\":0,\"ok\":false,\"error\":{{\"code\":\"internal\",\"message\":\"{}\"}}}}",
                im_host::err_name(r)
            )
        };
        self.poll();
        resp
    }

    /// Run deferred work: transport I/O, keep-alive, agent timers, EST, OTA download, reboot.
    pub fn poll(&mut self) {
        let p = self.i();
        unsafe {
            for _ in 0..64 {
                let mut progressed = false;
                if let Some(reason) = (*p).pending_connect_fail.take() {
                    let r = CString::new(reason).unwrap();
                    im_agent_on_connect_failed((*p).agent.ptr(), r.as_ptr());
                    progressed = true;
                }
                if let Some(renew) = (*p).pending_enroll.take() {
                    enroll(p, renew);
                    progressed = true;
                }
                if pump(p) {
                    progressed = true;
                }
                if let Some(url) = (*p).pending_download.take() {
                    download(p, &url);
                    progressed = true;
                }
                let now = cb_mono(p.cast());
                let _ = im_mqtt_session_tick((*p).session.ptr(), now);
                im_agent_tick((*p).agent.ptr());
                if let Some(reason) = (*p).pending_reboot.take() {
                    do_reboot(p, reason);
                    progressed = true;
                }
                let deferred = (*p).pending_enroll.is_some()
                    || (*p).pending_download.is_some()
                    || (*p).pending_reboot.is_some()
                    || (*p).pending_connect_fail.is_some()
                    || ((*p).link.is_some() && (*p).sim.as_ref().is_some_and(|s| !s.broker.to_device.is_empty()));
                if !progressed && !deferred {
                    break;
                }
            }
        }
    }

    /// Drain emitted DUT events (JSON lines).
    pub fn take_events(&mut self) -> Vec<String> {
        unsafe { (*self.p).events.drain(..).collect() }
    }

    pub fn sim(&mut self) -> &mut SimCloud {
        unsafe { (*self.p).sim.as_mut().expect("simulated cloud") }
    }

    pub fn state(&mut self) -> &mut Inner {
        unsafe { &mut *self.p }
    }

    /// Current identity public key (to verify uplink messages in tests).
    pub fn identity_public(&self) -> [u8; 65] {
        unsafe { (*self.p).identity.public_raw() }
    }

    /// Cloud-side injection of a downlink message (sim mode).
    pub fn inject(&mut self, suffix: &str, payload: &[u8], retain: bool) {
        let topic = unsafe { format!("im/v1/{}/{}/{}", (*self.p).cfg.tenant_id, (*self.p).cfg.device_id, suffix) };
        self.sim().broker.inject(&topic, payload, retain);
        self.poll();
    }

    pub fn tenant_id(&self) -> String {
        unsafe { (*self.p).cfg.tenant_id.clone() }
    }

    pub fn device_id(&self) -> String {
        unsafe { (*self.p).cfg.device_id.clone() }
    }

    /// Advance the monotonic and wall clocks (health-check timeout, renewal and backoff tests).
    pub fn advance(&mut self, ms: u64) {
        unsafe {
            (*self.p).mono_offset_ms += ms;
            (*self.p).clock_offset += (ms / 1000) as i64;
        }
        self.poll();
    }

    pub fn now(&self) -> u64 {
        unsafe { now_unix(&*self.p) }
    }
}

unsafe fn pump(p: *mut Inner) -> bool {
    let mut progressed = false;
    // simulated broker -> device
    if let (Some(link), Some(sim)) = ((*p).link.as_ref(), (*p).sim.as_mut()) {
        if link.is_sim() {
            let frames: Vec<Vec<u8>> = sim.broker.to_device.drain(..).collect();
            for f in frames {
                progressed = true;
                let now = cb_mono(p.cast());
                let _ = im_mqtt_session_input((*p).session.ptr(), f.as_ptr(), f.len(), now);
            }
            if (*p).link.as_ref().is_some_and(|l| l.closed()) {
                (*p).link = None;
                im_mqtt_session_reset((*p).session.ptr());
                im_agent_on_disconnected((*p).agent.ptr(), c"broker".as_ptr(), 0);
                progressed = true;
            }
            return progressed;
        }
    }
    // real transport
    if let Some(link) = (*p).link.as_mut() {
        match link.recv() {
            Ok(Some(bytes)) => {
                let now = cb_mono(p.cast());
                let _ = im_mqtt_session_input((*p).session.ptr(), bytes.as_ptr(), bytes.len(), now);
                progressed = true;
            }
            Ok(None) => {}
            Err(_) => {
                (*p).link = None;
                im_mqtt_session_reset((*p).session.ptr());
                im_agent_on_disconnected((*p).agent.ptr(), c"network".as_ptr(), 0);
                progressed = true;
            }
        }
    }
    progressed
}

unsafe fn download(p: *mut Inner, url: &str) {
    let data = match (&(*p).cfg.real, &(*p).sim) {
        (None, Some(sim)) => sim.artifacts.get(url).cloned().ok_or_else(|| "404".to_string()),
        (Some(real), _) => net::https_get(real, url),
        _ => Err("no transport".into()),
    };
    match data {
        Ok(bytes) => {
            for c in bytes.chunks(1400) {
                im_agent_on_ota_data((*p).agent.ptr(), c.as_ptr(), c.len());
            }
            im_agent_on_ota_done((*p).agent.ptr(), IM_OK);
        }
        Err(_) => im_agent_on_ota_done((*p).agent.ptr(), IM_ERR_IO),
    }
}

unsafe fn do_reboot(p: *mut Inner, reason: c_int) {
    if let Some(mut l) = (*p).link.take() {
        l.close();
    }
    if let Some(sim) = (*p).sim.as_mut() {
        sim.broker.reset_connection();
    }
    let boot_reason = if reason == IM_REBOOT_ROLLBACK {
        IM_REBOOT_ROLLBACK
    } else {
        (*p).slots.reset()
    };
    let reason = if reason == IM_REBOOT_ROLLBACK || boot_reason != IM_REBOOT_REQUESTED {
        boot_reason
    } else {
        reason
    };
    (*p).staged.clear();
    if let Err(e) = (*p).boot(reason) {
        (*p).events
            .push_back(format!("{{\"event\":\"_log\",\"data\":{{\"boot_error\":{e:?}}}}}"));
        return;
    }
    let _ = im_agent_connect((*p).agent.ptr()); // NOT_PROVISIONED/STATE when not enrolled: ignored
}

/// EST enrollment: new key in the "secure element", CSR, attestation (C), certificate.
unsafe fn enroll(p: *mut Inner, renew: bool) {
    let new_key = SoftIdentity::random();
    let csr = match net::build_csr(&new_key, &(*p).cfg.device_id, &(*p).cfg.tenant_id) {
        Ok(c) => c,
        Err(e) => {
            fail_enroll(p, 0, &e);
            return;
        }
    };
    if (*p).cfg.real.is_some() {
        let real = (*p).cfg.real.clone().unwrap();
        let agent = (*p).agent.ptr();
        let attest = |nonce: &[u8; 32]| -> Result<Vec<u8>, String> {
            let mut out = vec![0u8; 2048];
            let mut n = 0usize;
            im_host::check(im_agent_attestation(
                agent,
                nonce.as_ptr(),
                csr.as_ptr(),
                csr.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut n,
            ))
            .map_err(String::from)?;
            out.truncate(n);
            Ok(out)
        };
        match net::est_enroll(&real, renew, (*p).op_cert.as_deref(), &(*p).identity, &csr, attest) {
            Ok(res) => finish_enroll(p, new_key, res.cert, res.bundle),
            Err((status, reason)) => fail_enroll(p, status, &reason),
        }
        return;
    }
    // simulated EST server
    let now = now_unix(&*p);
    let mut nonce = [0u8; 32];
    im_host::crypto::im_crypto_random(nonce.as_mut_ptr(), 32);
    let mut att = vec![0u8; 2048];
    let mut n = 0usize;
    if im_agent_attestation(
        (*p).agent.ptr(),
        nonce.as_ptr(),
        csr.as_ptr(),
        csr.len(),
        att.as_mut_ptr(),
        att.len(),
        &mut n,
    ) != IM_OK
    {
        fail_enroll(p, 0, "attestation");
        return;
    }
    att.truncate(n);
    let tls_key = (*p).identity.public_raw();
    let kid = current_kid(p);
    let sim = (*p).sim.as_mut().unwrap();
    if sim.pki.quarantined {
        fail_enroll(p, 403, "device quarantined");
        return;
    }
    if let Err(e) = sim.pki.verify_attestation(&att, &tls_key, &nonce, &csr, &kid, now) {
        fail_enroll(p, 400, e);
        return;
    }
    let serial = sim.pki.issue_serial();
    let ttl = sim.pki.cert_ttl;
    let bundle = sim.pki.bundle();
    let cert = der::CertInfo {
        der: vec![],
        serial,
        not_before: now,
        not_after: now + ttl,
        spki: vec![],
        subject_cn: Some((*p).cfg.device_id.clone()),
        is_ca: false,
    };
    finish_enroll(p, new_key, cert, Some(bundle));
}

unsafe fn current_kid(p: *mut Inner) -> Vec<u8> {
    match (*p).kv.map.get("prov") {
        Some(b) if b.len() == 37 && b[0] >= 1 && b[0] <= 20 => b[1..1 + b[0] as usize].to_vec(),
        _ => (*p).cfg.bootstrap_serial.clone(),
    }
}

unsafe fn finish_enroll(p: *mut Inner, new_key: Box<SoftIdentity>, cert: der::CertInfo, bundle: Option<Vec<u8>>) {
    // rotate: from now on the identity is the freshly generated key
    let old = std::mem::replace(&mut (*p).identity, new_key);
    *(*p).id_ffi = (*p).identity.ffi();
    let b = bundle.unwrap_or_default();
    let r = im_agent_on_enrolled(
        (*p).agent.ptr(),
        cert.serial.as_ptr(),
        cert.serial.len(),
        cert.not_before,
        cert.not_after,
        if b.is_empty() { std::ptr::null() } else { b.as_ptr() },
        b.len(),
    );
    if r != IM_OK {
        (*p).identity = old;
        *(*p).id_ffi = (*p).identity.ffi();
        fail_enroll(p, 0, im_host::err_name(r));
        return;
    }
    if !cert.der.is_empty() {
        (*p).op_cert = Some(cert.der);
    }
}

unsafe fn fail_enroll(p: *mut Inner, status: i32, reason: &str) {
    let r = CString::new(reason.replace('\0', "")).unwrap();
    im_agent_on_enroll_failed((*p).agent.ptr(), status, r.as_ptr());
}
