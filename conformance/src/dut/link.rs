//! The DUT control protocol transport (`conformance/DUT_PROTOCOL.md` "Framing"): one JSON object
//! per line, requests `{id, op, args}`, responses `{id, ok, result|error}`, asynchronous events
//! `{event, at_ms, data}`; on serial every protocol line carries the `@@IM ` prefix and anything
//! else is device log output. Transport-agnostic: any `AsyncRead`/`AsyncWrite` pair.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot, Notify};

/// Maximum protocol line (64 KiB).
pub const MAX_LINE: usize = 64 * 1024;
/// Serial line prefix.
pub const SERIAL_PREFIX: &str = "@@IM ";
/// The protocol's response deadline.
pub const RESPONSE_DEADLINE: Duration = Duration::from_secs(5);

/// One asynchronous event.
#[derive(Debug, Clone)]
pub struct Event {
    /// Event name.
    pub name: String,
    /// DUT monotonic time (ms).
    pub at_ms: u64,
    /// Payload.
    pub data: Value,
    /// When the harness received it.
    pub seen: Instant,
}

/// A failed request.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DutError {
    /// `ok: false` with a protocol error code.
    #[error("{op}: DUT error {code}: {message}")]
    Op {
        /// Operation.
        op: String,
        /// Error code (`unsupported`, `busy`, `invalid_args`, `not_provisioned`, `internal`).
        code: String,
        /// Message.
        message: String,
    },
    /// No response in time.
    #[error("{0}: no response within the deadline")]
    Timeout(String),
    /// The transport closed.
    #[error("DUT link closed")]
    Closed,
}

impl DutError {
    /// The protocol error code, if any.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            DutError::Op { code, .. } => Some(code),
            _ => None,
        }
    }
}

/// A protocol violation seen on the link (reported as evidence; some fail cases).
#[derive(Debug, Clone)]
pub struct Violation {
    /// When.
    pub at: Instant,
    /// What.
    pub what: String,
}

/// An outstanding request: op, send time, response slot.
type Pending = (String, Instant, oneshot::Sender<Value>);

struct Shared {
    pending: Mutex<HashMap<u64, Pending>>,
    events: Mutex<Vec<Event>>,
    notify: Notify,
    violations: Mutex<Vec<Violation>>,
    transcript: Mutex<Vec<String>>,
    closed: AtomicBool,
    slow: Mutex<Vec<(String, Duration)>>,
}

/// A line-protocol client.
#[derive(Clone)]
pub struct DutLink {
    tx: mpsc::UnboundedSender<String>,
    shared: Arc<Shared>,
    next: Arc<AtomicU64>,
    prefix: Option<&'static str>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn stamp() -> String {
    time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}

impl DutLink {
    /// Start reader/writer tasks. `prefix` is `Some("@@IM ")` on serial links.
    pub fn spawn<R, W>(reader: R, writer: W, prefix: Option<&'static str>) -> Self
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let shared = Arc::new(Shared {
            pending: Mutex::new(HashMap::new()),
            events: Mutex::new(Vec::new()),
            notify: Notify::new(),
            violations: Mutex::new(Vec::new()),
            transcript: Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
            slow: Mutex::new(Vec::new()),
        });
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let w_shared = shared.clone();
        tokio::spawn(async move {
            let mut writer = writer;
            while let Some(line) = rx.recv().await {
                lock(&w_shared.transcript).push(format!("{} >> {}", stamp(), line.trim_end()));
                if writer.write_all(line.as_bytes()).await.is_err() || writer.flush().await.is_err() {
                    break;
                }
            }
        });
        let r_shared = shared.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::with_capacity(MAX_LINE + 1024, reader);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                match reader.read_until(b'\n', &mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                let line = String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']).to_string();
                handle_line(&r_shared, &line, prefix);
            }
            r_shared.closed.store(true, Ordering::SeqCst);
            lock(&r_shared.pending).clear();
            r_shared.notify.notify_waiters();
        });
        Self { tx, shared, next: Arc::new(AtomicU64::new(0)), prefix }
    }

    /// Send a request and wait for its response (`timeout` > protocol deadline so that a late
    /// answer is recorded as a violation instead of a hard failure).
    ///
    /// # Errors
    /// [`DutError`].
    pub async fn call(&self, op: &str, args: Value, timeout: Duration) -> Result<Value, DutError> {
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err(DutError::Closed);
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let (otx, orx) = oneshot::channel();
        lock(&self.shared.pending).insert(id, (op.to_owned(), Instant::now(), otx));
        let line = json!({"id": id, "op": op, "args": args}).to_string();
        let framed = match self.prefix {
            Some(p) => format!("{p}{line}\n"),
            None => format!("{line}\n"),
        };
        if self.tx.send(framed).is_err() {
            return Err(DutError::Closed);
        }
        let resp = match tokio::time::timeout(timeout, orx).await {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => return Err(DutError::Closed),
            Err(_) => {
                lock(&self.shared.pending).remove(&id);
                return Err(DutError::Timeout(op.to_owned()));
            }
        };
        if resp["ok"] == true {
            Ok(resp.get("result").cloned().unwrap_or(Value::Null))
        } else {
            Err(DutError::Op {
                op: op.to_owned(),
                code: resp["error"]["code"].as_str().unwrap_or("internal").to_owned(),
                message: resp["error"]["message"].as_str().unwrap_or("").to_owned(),
            })
        }
    }

    /// Send a raw line (protocol robustness probes).
    pub fn send_raw(&self, line: &str) {
        let framed = match self.prefix {
            Some(p) => format!("{p}{line}\n"),
            None => format!("{line}\n"),
        };
        let _ = self.tx.send(framed);
    }

    /// Number of events received so far (a position for [`DutLink::wait_event`]).
    #[must_use]
    pub fn mark(&self) -> usize {
        lock(&self.shared.events).len()
    }

    /// Events from position `from`.
    #[must_use]
    pub fn events_since(&self, from: usize) -> Vec<Event> {
        lock(&self.shared.events).iter().skip(from).cloned().collect()
    }

    /// Events named `name` from position `from`.
    #[must_use]
    pub fn named_since(&self, from: usize, name: &str) -> Vec<Event> {
        lock(&self.shared.events).iter().skip(from).filter(|e| e.name == name).cloned().collect()
    }

    /// Wait for the first event at or after `from` named `name` and matching `pred`.
    pub async fn wait_event(&self, from: usize, name: &str, timeout: Duration, pred: impl Fn(&Value) -> bool) -> Option<Event> {
        self.wait_any(from, &[name], timeout, pred).await
    }

    /// Wait for the first event at or after `from` whose name is in `names` and matches `pred`.
    pub async fn wait_any(&self, from: usize, names: &[&str], timeout: Duration, pred: impl Fn(&Value) -> bool) -> Option<Event> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.shared.notify.notified();
            if let Some(e) = lock(&self.shared.events).iter().skip(from).find(|e| names.contains(&e.name.as_str()) && pred(&e.data)) {
                return Some(e.clone());
            }
            if self.shared.closed.load(Ordering::SeqCst) {
                return None;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return None;
            }
        }
    }

    /// Protocol violations.
    #[must_use]
    pub fn violations(&self) -> Vec<Violation> {
        lock(&self.shared.violations).clone()
    }

    /// Responses slower than the 5 s deadline.
    #[must_use]
    pub fn slow_responses(&self) -> Vec<(String, Duration)> {
        lock(&self.shared.slow).clone()
    }

    /// Whether the transport closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }

    /// Write the transcript to `path`.
    pub fn save_transcript(&self, path: &PathBuf) {
        let t = lock(&self.shared.transcript).join("\n");
        let _ = std::fs::write(path, t + "\n");
    }
}

fn handle_line(s: &Shared, line: &str, prefix: Option<&'static str>) {
    let payload = match prefix {
        Some(p) => match line.find(p) {
            Some(i) => &line[i + p.len()..],
            None => {
                lock(&s.transcript).push(format!("{} .. {line}", stamp()));
                return; // device log output
            }
        },
        None => line,
    };
    lock(&s.transcript).push(format!("{} << {payload}", stamp()));
    if payload.trim().is_empty() {
        return;
    }
    if payload.len() > MAX_LINE {
        lock(&s.violations).push(Violation { at: Instant::now(), what: format!("line of {} bytes exceeds 64 KiB", payload.len()) });
    }
    let Ok(v) = serde_json::from_str::<Value>(payload) else {
        if prefix.is_some() || payload.starts_with('{') {
            lock(&s.violations)
                .push(Violation { at: Instant::now(), what: format!("not JSON: {}", payload.chars().take(200).collect::<String>()) });
        }
        return; // log output on stdout of a host target
    };
    if let Some(name) = v.get("event").and_then(Value::as_str) {
        if name.starts_with('_') {
            return; // target-private diagnostics (e.g. the shim's _log), kept in the transcript
        }
        if !v["at_ms"].is_u64() {
            lock(&s.violations).push(Violation { at: Instant::now(), what: format!("event {name} without a u64 at_ms") });
        }
        lock(&s.events).push(Event {
            name: name.to_owned(),
            at_ms: v["at_ms"].as_u64().unwrap_or(0),
            data: v["data"].clone(),
            seen: Instant::now(),
        });
        s.notify.notify_waiters();
        return;
    }
    if let Some(id) = v.get("id").and_then(Value::as_u64) {
        let entry = lock(&s.pending).remove(&id);
        if let Some((op, sent, tx)) = entry {
            let took = sent.elapsed();
            if took > RESPONSE_DEADLINE {
                lock(&s.slow).push((op, took));
            }
            let _ = tx.send(v);
        } else if !v["ok"].is_boolean() {
            lock(&s.violations).push(Violation { at: Instant::now(), what: format!("unexpected line: {payload}") });
        }
        return;
    }
    if v.get("ok").is_some() {
        // A response without a usable id (e.g. invalid_args for a malformed request).
        return;
    }
    lock(&s.violations).push(Violation { at: Instant::now(), what: format!("neither response nor event: {payload}") });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake DUT on the other end of a duplex pipe, speaking `prefix`-framed lines.
    async fn fake_dut(stream: tokio::io::DuplexStream, prefix: &'static str) {
        let (r, mut w) = tokio::io::split(stream);
        let mut lines = BufReader::new(r).lines();
        w.write_all(b"boot: rom v1 (log noise)\n").await.unwrap();
        while let Ok(Some(l)) = lines.next_line().await {
            let body = l.strip_prefix(prefix).unwrap_or(&l);
            let v: Value = serde_json::from_str(body).unwrap();
            let id = v["id"].as_u64().unwrap();
            let out = match v["op"].as_str().unwrap() {
                "hello" => json!({"id": id, "ok": true, "result": {"target": "fake", "protocol_version": 1}}),
                "enroll" => {
                    let ev = json!({"event": "enrolled", "at_ms": 5, "data": {"cert_serial_hex": "0a"}});
                    w.write_all(format!("{prefix}{ev}\n").as_bytes()).await.unwrap();
                    json!({"id": id, "ok": true, "result": {}})
                }
                _ => json!({"id": id, "ok": false, "error": {"code": "unsupported", "message": "nope"}}),
            };
            w.write_all(format!("log line between\n{prefix}{out}\n").as_bytes()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn serial_framing_with_prefix_and_log_noise() {
        let (a, b) = tokio::io::duplex(1 << 16);
        tokio::spawn(fake_dut(b, SERIAL_PREFIX));
        let (r, w) = tokio::io::split(a);
        let link = DutLink::spawn(r, w, Some(SERIAL_PREFIX));
        let h = link.call("hello", json!({}), Duration::from_secs(2)).await.unwrap();
        assert_eq!(h["target"], "fake");
        let m = link.mark();
        link.call("enroll", json!({}), Duration::from_secs(2)).await.unwrap();
        let e = link.wait_event(m, "enrolled", Duration::from_secs(2), |_| true).await.unwrap();
        assert_eq!(e.data["cert_serial_hex"], "0a");
        assert_eq!(e.at_ms, 5);
        let err = link.call("format", json!({}), Duration::from_secs(2)).await.unwrap_err();
        assert_eq!(err.code(), Some("unsupported"));
        assert!(link.violations().is_empty(), "{:?}", link.violations());
    }

    #[tokio::test]
    async fn stdio_framing_tolerates_log_lines_and_detects_garbage() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (r, w) = tokio::io::split(a);
        let link = DutLink::spawn(r, w, None);
        let (_br, mut bw) = tokio::io::split(b);
        bw.write_all(b"plain log line\n{\"event\":\"connected\",\"at_ms\":1,\"data\":{}}\n{\"event\":\"x\"}\n{broken\n").await.unwrap();
        let e = link.wait_event(0, "connected", Duration::from_secs(2), |_| true).await;
        assert!(e.is_some());
        tokio::time::sleep(Duration::from_millis(50)).await;
        let v = link.violations();
        assert_eq!(v.len(), 2, "{v:?}");
        drop(bw);
        drop(_br);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(link.is_closed());
        assert!(matches!(link.call("hello", json!({}), Duration::from_millis(200)).await, Err(DutError::Closed)));
    }

    #[tokio::test]
    async fn timeouts() {
        let (a, _b) = tokio::io::duplex(1 << 16);
        let (r, w) = tokio::io::split(a);
        let link = DutLink::spawn(r, w, None);
        assert!(matches!(link.call("hello", json!({}), Duration::from_millis(100)).await, Err(DutError::Timeout(_))));
        assert!(link.wait_event(0, "never", Duration::from_millis(50), |_| true).await.is_none());
    }
}
