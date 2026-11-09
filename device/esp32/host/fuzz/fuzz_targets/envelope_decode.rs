//! Full §3.6 envelope verification with a resolver that knows the test tenant and device keys,
//! plus the payload/body validator on raw bytes and the Config (HPKE) unwrap.
#![no_main]
use im_host::ffi::*;
use im_host::{SoftIdentity, StaticResolver};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

struct Keys {
    res: StaticResolver,
    id: Box<SoftIdentity>,
}
// SAFETY: built once, then only read (the C callbacks never mutate it).
unsafe impl Send for Keys {}
unsafe impl Sync for Keys {}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    K.get_or_init(|| {
        // public test material from device/common/vectors
        let mut res = StaticResolver::default();
        let dev = hex("043b2d8f7da23928e408e5ee2b814e7a49e9c521370c05dea4d796b1de20bb43e282fb0cda24bd1a6f248db21551202543aecb83e95b71ba514efea6664f4c77c5");
        res.add_p256(&hex("3fa1b2c3d4e5f60718293a4b5c6d7e8f"), &dev);
        res.add_ed25519(
            "tenant-cmd-7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11",
            &hex("4e67c0305f773ee78ec1c21ff9b60b5e4b4eebf52d42717988e55b834ec62ec1"),
        );
        let id = SoftIdentity::from_scalar(&hex("e0243710df7363a7a990622d33188c3b6ba69a8be86051d4397bcb8561b653e3"));
        Keys { res, id }
    })
}

fuzz_target!(|data: &[u8]| {
    let k = keys();
    unsafe {
        let mut store: Box<im_replay_mem_t> = Box::new(core::mem::zeroed());
        im_replay_mem_init(&mut *store);
        let mut st: im_replay_store_t = core::mem::zeroed();
        im_replay_mem_store(&mut *store, &mut st);
        let res = k.res.ffi();
        let mut o: im_env_decode_opts_t = core::mem::zeroed();
        im_env_decode_opts_init(&mut o);
        let mut work = vec![0u8; data.len() + 128];
        o.resolver = &res;
        o.replay = &st;
        o.now = 1_767_225_600;
        o.expected_tenant = c"7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11".as_ptr();
        o.work = work.as_mut_ptr();
        o.work_len = work.len();
        let mut m = im_env_msg_t::default();
        let _ = im_env_decode(data.as_ptr(), data.len(), &o, &mut m);
        let _ = im_env_decode_payload(data.as_ptr(), data.len(), core::ptr::null(), &mut m);
        let idf = k.id.ffi();
        let mut pt = vec![0u8; data.len()];
        let mut n = 0usize;
        let _ = im_config_unwrap(data.as_ptr(), data.len(), &idf, pt.as_mut_ptr(), pt.len(), &mut n);
    }
});
