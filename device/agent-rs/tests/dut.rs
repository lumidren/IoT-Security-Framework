//! DUT control protocol (`conformance/DUT_PROTOCOL.md`) over an in-memory pipe.
#![cfg(feature = "dut-control")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use ironmesh_agent::dut::{serve, OptionsFactory};
use serde_json::{json, Value};
use support::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

struct Client {
    w: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    r: BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    next: u64,
    events: Vec<Value>,
}

impl Client {
    async fn line(&mut self) -> Value {
        let mut l = String::new();
        tokio::time::timeout(Duration::from_secs(20), self.r.read_line(&mut l)).await.unwrap().unwrap();
        serde_json::from_str(&l).unwrap()
    }

    async fn call(&mut self, op: &str, args: Value) -> Value {
        self.next += 1;
        let id = self.next;
        let req = json!({"id": id, "op": op, "args": args}).to_string() + "\n";
        self.w.write_all(req.as_bytes()).await.unwrap();
        loop {
            let v = self.line().await;
            if v.get("event").is_some() {
                self.events.push(v);
            } else {
                assert_eq!(v["id"], id);
                return v;
            }
        }
    }

    async fn event(&mut self, name: &str) -> Value {
        if let Some(i) = self.events.iter().position(|e| e["event"] == name) {
            return self.events.remove(i);
        }
        loop {
            let v = self.line().await;
            if v["event"] == name {
                assert!(v["at_ms"].is_u64());
                return v;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dut_protocol_session() {
    let env = Arc::new(Env::new(3600).await);
    let e2 = env.clone();
    let factory: OptionsFactory = Arc::new(move |events, reason, want, net| {
        let mut o = e2.options(reason, want, net);
        o.events = events;
        Ok(o)
    });
    let (a, b) = tokio::io::duplex(1 << 20);
    let (dut_r, dut_w) = tokio::io::split(b);
    let server = tokio::spawn(serve(factory, dut_r, dut_w));
    let (r, w) = tokio::io::split(a);
    let mut c = Client { w, r: BufReader::new(r), next: 0, events: Vec::new() };

    let hello = c.call("hello", json!({})).await;
    assert_eq!(hello["ok"], true);
    assert_eq!(hello["result"]["protocol_version"], 1);
    assert_eq!(hello["result"]["target"], "agent-rs");
    let st = c.call("status", json!({})).await;
    assert_eq!(st["result"]["state"], "offline");
    assert_eq!(c.call("send_telemetry", json!({"count": 1})).await["error"]["code"], "not_provisioned");
    assert_eq!(c.call("enroll", json!({})).await["ok"], true);
    let e = c.event("enrolled").await;
    assert_eq!(e["data"]["se_type"], "software");
    assert_eq!(c.call("connect", json!({})).await["ok"], true);
    let e = c.event("connected").await;
    assert_eq!(e["data"]["tls_version"], "TLSv1.3");
    let t = c.call("send_telemetry", json!({"count": 3})).await;
    let (first, last) = (t["result"]["first_seq"].as_u64().unwrap(), t["result"]["last_seq"].as_u64().unwrap());
    assert_eq!(last, first + 2);
    let st = c.call("status", json!({})).await["result"].clone();
    assert_eq!(st["state"], "connected");
    assert!(st["seq_out"].as_u64().unwrap() > last);
    assert_eq!(st["active_slot"], "a");
    // Raw ACL probes.
    let other = format!("im/v1/{TENANT}/dev-0000000000000001/telemetry");
    c.call("publish_raw", json!({"topic": other, "payload_b64": "AQI=", "qos": 1, "retain": false})).await;
    assert_eq!(c.event("publish_result").await["data"]["ok"], false);
    c.call("subscribe_raw", json!({"topic": "im/v1/#"})).await;
    assert_eq!(c.event("subscribe_result").await["data"]["granted"], false);
    // Offline + resync.
    c.call("net_down", json!({})).await;
    c.event("disconnected").await;
    c.call("send_telemetry", json!({"count": 2})).await;
    assert_eq!(c.call("status", json!({})).await["result"]["buffered"], 2);
    c.call("net_up", json!({})).await;
    assert_eq!(c.event("buffer_flushed").await["data"]["count"], 2);
    // Rejections and clock.
    let topic = env.topic(ironmesh_agent::wire::ids::TopicClass::CmdReq);
    env.broker.inject(DEVICE, &topic, vec![0xd2, 0x80], false);
    let mr = c.event("message_rejected").await;
    assert_eq!(mr["data"]["code"], "COSE_STRUCTURE");
    let rej = c.call("rejections", json!({"since_ms": 0})).await;
    assert_eq!(rej["result"]["items"][0]["code"], "COSE_STRUCTURE");
    assert_eq!(c.call("set_clock", json!({"unix_s": 2_000_000_000u64})).await["ok"], true);
    assert_eq!(c.call("set_clock", json!({})).await["error"]["code"], "invalid_args");
    let slots = c.call("ota_slots", json!({})).await;
    assert_eq!(slots["result"]["slots"].as_array().unwrap().len(), 2);
    // Errors.
    assert_eq!(c.call("format_disk", json!({})).await["error"]["code"], "unsupported");
    assert_eq!(c.call("send_telemetry", json!({"count": 0})).await["error"]["code"], "invalid_args");
    assert_eq!(c.call("publish_raw", json!({"topic": "x"})).await["error"]["code"], "invalid_args");
    assert_eq!(c.call("subscribe_raw", json!({})).await["error"]["code"], "invalid_args");
    c.w.write_all(b"not json\n").await.unwrap();
    assert_eq!(c.line().await["error"]["code"], "invalid_args");
    c.w.write_all(b"{\"op\": \"hello\"}\n").await.unwrap();
    assert_eq!(c.line().await["error"]["code"], "invalid_args");
    // Reboot: in-process restart; seq continues, reconnects.
    let real_now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    c.call("set_clock", json!({"unix_s": real_now})).await;
    let before = c.call("status", json!({})).await["result"]["seq_out"].as_u64().unwrap();
    c.call("reboot", json!({})).await;
    let rb = c.event("rebooted").await;
    assert_eq!(rb["data"]["reason"], "requested");
    c.event("connected").await;
    assert!(c.call("status", json!({})).await["result"]["seq_out"].as_u64().unwrap() >= before);
    assert_eq!(c.call("renew", json!({})).await["ok"], true);
    c.event("cert_renewed").await;
    c.call("disconnect", json!({})).await;
    c.event("disconnected").await;
    drop(c);
    tokio::time::timeout(Duration::from_secs(10), server).await.unwrap().unwrap().unwrap();
}
