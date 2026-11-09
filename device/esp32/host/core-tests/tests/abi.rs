//! The Rust mirrors of the C structs must have exactly the C layout sizes.

use im_host::ffi::*;
use im_host::ffi2::*;
use std::mem::size_of;

#[test]
fn struct_sizes_match_c() {
    let check = |which: i32, rust: usize, what: &str| {
        let c = unsafe { im_abi_size(which) };
        assert_eq!(c, rust, "{what}: C {c} vs Rust {rust}");
    };
    check(0, size_of::<im_mqtt_packet_t>(), "im_mqtt_packet_t");
    check(1, size_of::<im_mqtt_props_t>(), "im_mqtt_props_t");
    check(3, size_of::<im_ringbuf_t>(), "im_ringbuf_t");
    check(4, size_of::<im_ota_config_t>(), "im_ota_config_t");
    check(5, size_of::<im_agent_config_t>(), "im_agent_config_t");
    check(6, size_of::<im_agent_platform_t>(), "im_agent_platform_t");
    check(7, size_of::<im_cmd_cache_t>(), "im_cmd_cache_t");
    check(8, size_of::<im_json_tok_t>(), "im_json_tok_t");
    check(9, size_of::<im_env_msg_t>(), "im_env_msg_t");
    check(10, size_of::<im_manifest_t>(), "im_manifest_t");
    check(11, size_of::<im_telemetry_t>(), "im_telemetry_t");
    check(12, size_of::<im_ota_notify_t>(), "im_ota_notify_t");
    check(13, size_of::<im_rejection_t>(), "im_rejection_t");
    assert!(unsafe { im_abi_size(2) } > 32 * 1024, "session buffers");
}
