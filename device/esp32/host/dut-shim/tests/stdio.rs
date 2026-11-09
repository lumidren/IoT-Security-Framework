//! The binary speaks the line protocol on stdin/stdout.

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn line_protocol_over_stdio() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_im-dut-shim"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        for l in [
            r#"{"id":1,"op":"hello"}"#,
            "garbage",
            r#"{"id":2,"op":"enroll"}"#,
            r#"{"id":3,"op":"connect"}"#,
            r#"{"id":4,"op":"send_telemetry","args":{"count":2}}"#,
            r#"{"id":5,"op":"status"}"#,
        ] {
            writeln!(stdin, "{l}").unwrap();
        }
    }
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let lines: Vec<serde_json::Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let resp = |id: u64| lines.iter().find(|v| v["id"] == id && v.get("ok").is_some()).cloned().unwrap();
    assert_eq!(resp(1)["result"]["target"], "esp32-host");
    assert!(lines.iter().any(|v| v["id"] == 0 && v["ok"] == false), "malformed line answered");
    assert!(lines.iter().any(|v| v["event"] == "enrolled"));
    assert!(lines.iter().any(|v| v["event"] == "connected"));
    assert_eq!(
        resp(4)["result"]["last_seq"].as_u64().unwrap() - resp(4)["result"]["first_seq"].as_u64().unwrap(),
        1
    );
    assert_eq!(resp(5)["result"]["state"], "connected");
    assert!(
        lines.iter().all(|v| v.get("id").is_some() || v["at_ms"].is_u64()),
        "events carry at_ms"
    );
}
