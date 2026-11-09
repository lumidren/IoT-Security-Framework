//! Device-under-test control channel (`conformance/DUT_PROTOCOL.md`) over stdin/stdout.
//!
//! Compiled only with the `dut-control` cargo feature; release builds exclude it and
//! `ironmesh-agent --dut` exits with status 2 (C-HOOK-1). One JSON object per line (max 64 KiB),
//! requests `{id, op, args}`, responses `{id, ok, result|error}`, events `{event, at_ms, data}`.
//! Every request is answered immediately; long operations report completion through events.
//! `reboot` (and OTA apply / rollback) restarts the agent in-process from its persisted state.

use std::future::Future;
use std::sync::Arc;

use base64::Engine;
use serde_json::{json, Value as Json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, RwLock};

use crate::agent::{Agent, AgentError, AgentEvent, AgentOptions, RebootReason};

/// Maximum request line.
pub const MAX_LINE: usize = 64 * 1024;

/// Builds fresh [`AgentOptions`] for every (re)start.
pub type OptionsFactory =
    Arc<dyn Fn(broadcast::Sender<AgentEvent>, Option<RebootReason>, bool, bool) -> Result<AgentOptions, String> + Send + Sync>;

fn ok(id: &Json, result: Json) -> Json {
    json!({"id": id, "ok": true, "result": result})
}

fn fail(id: &Json, code: &str, message: impl Into<String>) -> Json {
    json!({"id": id, "ok": false, "error": {"code": code, "message": message.into()}})
}

fn agent_err(id: &Json, e: &AgentError) -> Json {
    match e {
        AgentError::State("not provisioned") => fail(id, "not_provisioned", e.to_string()),
        AgentError::State(_) => fail(id, "busy", e.to_string()),
        _ => fail(id, "internal", e.to_string()),
    }
}

struct Dut {
    current: RwLock<Agent>,
    factory: OptionsFactory,
    events: broadcast::Sender<AgentEvent>,
}

impl Dut {
    async fn agent(&self) -> Agent {
        self.current.read().await.clone()
    }

    async fn reboot(&self, reason: RebootReason) -> Result<mpsc::UnboundedReceiver<RebootReason>, String> {
        let mut guard = self.current.write().await;
        let old = guard.clone();
        let (net, want) = (old.net_is_up(), old.wants_connection());
        old.shutdown().await;
        let opts = (self.factory)(self.events.clone(), Some(reason), want, net)?;
        let (agent, rx) = Agent::start(opts).await.map_err(|e| e.to_string())?;
        *guard = agent;
        Ok(rx)
    }

    async fn handle(self: &Arc<Self>, req: Json) -> Json {
        let id = req.get("id").cloned().unwrap_or(Json::Null);
        if !id.is_u64() {
            return fail(&id, "invalid_args", "id must be a u64");
        }
        let Some(op) = req.get("op").and_then(Json::as_str) else {
            return fail(&id, "invalid_args", "op must be a string");
        };
        let args = req.get("args").cloned().unwrap_or_else(|| json!({}));
        let agent = self.agent().await;
        match op {
            "hello" => ok(&id, agent.hello()),
            "status" => ok(&id, agent.status().await),
            "enroll" => {
                tokio::spawn(async move {
                    let _ = agent.enroll().await;
                });
                ok(&id, json!({}))
            }
            "renew" => {
                tokio::spawn(async move {
                    let _ = agent.renew().await;
                });
                ok(&id, json!({}))
            }
            "connect" => {
                agent.set_connected(true);
                ok(&id, json!({}))
            }
            "disconnect" => {
                agent.set_connected(false);
                ok(&id, json!({}))
            }
            "net_down" => {
                agent.set_net(false);
                ok(&id, json!({}))
            }
            "net_up" => {
                agent.set_net(true);
                ok(&id, json!({}))
            }
            "send_telemetry" => {
                let Some(count) = args.get("count").and_then(Json::as_u64).filter(|c| (1..=10_000).contains(c)) else {
                    return fail(&id, "invalid_args", "count must be 1..10000");
                };
                match tokio::time::timeout(std::time::Duration::from_secs(4), agent.send_telemetry(count as u32)).await {
                    Ok(Ok((first, last))) => ok(&id, json!({"first_seq": first, "last_seq": last})),
                    Ok(Err(e)) => agent_err(&id, &e),
                    Err(_) => fail(&id, "busy", "telemetry did not complete within 4 s"),
                }
            }
            "publish_raw" => {
                let topic = args.get("topic").and_then(Json::as_str).map(str::to_owned);
                let payload = args.get("payload_b64").and_then(Json::as_str).map(|p| base64::engine::general_purpose::STANDARD.decode(p));
                let qos = args.get("qos").and_then(Json::as_u64).unwrap_or(1);
                let retain = args.get("retain").and_then(Json::as_bool).unwrap_or(false);
                match (topic, payload) {
                    (Some(t), Some(Ok(p))) if qos <= 1 => {
                        tokio::spawn(async move {
                            let _ = agent.publish_raw(&t, p, qos as u8, retain).await;
                        });
                        ok(&id, json!({}))
                    }
                    _ => fail(&id, "invalid_args", "topic, payload_b64 (base64) and qos 0..1 required"),
                }
            }
            "subscribe_raw" => match args.get("topic").and_then(Json::as_str).map(str::to_owned) {
                Some(t) => {
                    tokio::spawn(async move {
                        let _ = agent.subscribe_raw(&t).await;
                    });
                    ok(&id, json!({}))
                }
                None => fail(&id, "invalid_args", "topic required"),
            },
            "ota_slots" => ok(&id, agent.ota_slots()),
            "reboot" => {
                agent.request_reboot(RebootReason::Requested);
                ok(&id, json!({}))
            }
            "rejections" => {
                let since = args.get("since_ms").and_then(Json::as_u64).unwrap_or(0);
                let items: Vec<Json> = agent
                    .rejections(since)
                    .into_iter()
                    .map(|r| json!({"at_ms": r.at_ms, "code": r.code, "topic": r.topic, "detail": r.detail}))
                    .collect();
                ok(&id, json!({"items": items}))
            }
            "set_clock" => match args.get("unix_s").and_then(Json::as_u64) {
                Some(t) => {
                    agent.set_clock(t);
                    ok(&id, json!({}))
                }
                None => fail(&id, "invalid_args", "unix_s required"),
            },
            _ => fail(&id, "unsupported", format!("unknown op {op}")),
        }
    }
}

/// Read one line of at most [`MAX_LINE`] bytes; `Ok(None)` at EOF. Oversized lines are consumed
/// and reported as `Err`.
async fn read_line<R: AsyncBufReadExt + Unpin>(r: &mut R, buf: &mut Vec<u8>) -> std::io::Result<Option<Result<String, ()>>> {
    buf.clear();
    let mut too_long = false;
    let finish = |buf: &Vec<u8>, too_long: bool| if too_long { Err(()) } else { Ok(String::from_utf8_lossy(buf).into_owned()) };
    loop {
        let available = r.fill_buf().await?;
        if available.is_empty() {
            return Ok((!buf.is_empty() || too_long).then(|| finish(buf, too_long)));
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let chunk = &available[..newline.unwrap_or(available.len())];
        if buf.len() + chunk.len() > MAX_LINE {
            too_long = true;
        } else {
            buf.extend_from_slice(chunk);
        }
        let consumed = newline.map_or(available.len(), |i| i + 1);
        r.consume(consumed);
        if newline.is_some() {
            return Ok(Some(finish(buf, too_long)));
        }
    }
}

/// Serve the DUT protocol on arbitrary streams (stdin/stdout in production, duplex in tests).
///
/// # Errors
/// If the initial agent cannot be started.
pub async fn serve<R, W>(factory: OptionsFactory, input: R, output: W) -> Result<(), String>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (events, _) = broadcast::channel(1024);
    let opts = factory(events.clone(), None, false, true)?;
    let (agent, mut reboot_rx) = Agent::start(opts).await.map_err(|e| e.to_string())?;
    let dut = Arc::new(Dut { current: RwLock::new(agent), factory, events: events.clone() });
    let (out_tx, mut out_rx) = mpsc::channel::<String>(1024);
    let writer = tokio::spawn(async move {
        let mut output = output;
        while let Some(line) = out_rx.recv().await {
            if output.write_all(line.as_bytes()).await.is_err() || output.write_all(b"\n").await.is_err() || output.flush().await.is_err() {
                break;
            }
        }
    });
    // Events.
    let mut ev_rx = events.subscribe();
    let ev_tx = out_tx.clone();
    let ev_task = tokio::spawn(async move {
        loop {
            match ev_rx.recv().await {
                Ok(e) => {
                    let line = json!({"event": e.name, "at_ms": e.at_ms, "data": e.data}).to_string();
                    if ev_tx.send(line).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    // Reboots.
    let dut_r = dut.clone();
    let reboot_task = tokio::spawn(async move {
        while let Some(reason) = reboot_rx.recv().await {
            match dut_r.reboot(reason).await {
                Ok(rx) => reboot_rx = rx,
                Err(e) => {
                    tracing::error!(error = %e, "in-process restart failed");
                    break;
                }
            }
        }
    });
    let mut reader = tokio::io::BufReader::new(input);
    let mut buf = Vec::new();
    loop {
        let line = match read_line(&mut reader, &mut buf).await {
            Ok(Some(l)) => l,
            Ok(None) | Err(_) => break,
        };
        let resp = match line {
            Err(()) => fail(&Json::Null, "invalid_args", "line exceeds 64 KiB"),
            Ok(l) if l.trim().is_empty() => continue,
            Ok(l) => match serde_json::from_str::<Json>(&l) {
                Ok(req) => dut.handle(req).await,
                Err(e) => fail(&Json::Null, "invalid_args", format!("invalid JSON: {e}")),
            },
        };
        if out_tx.send(resp.to_string()).await.is_err() {
            break;
        }
    }
    reboot_task.abort();
    dut.agent().await.shutdown().await;
    ev_task.abort();
    drop(out_tx);
    let _ = writer.await;
    Ok(())
}

/// Serve on the process's stdin/stdout.
///
/// # Errors
/// See [`serve`].
pub fn run_stdio(factory: OptionsFactory) -> impl Future<Output = Result<(), String>> {
    serve(factory, tokio::io::stdin(), tokio::io::stdout())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn line_reader_limits() {
        let data = format!("{}\n{}\nshort", "a".repeat(10), "b".repeat(MAX_LINE + 5));
        let mut r = tokio::io::BufReader::with_capacity(16, data.as_bytes());
        let mut buf = Vec::new();
        assert_eq!(read_line(&mut r, &mut buf).await.unwrap(), Some(Ok("a".repeat(10))));
        assert_eq!(read_line(&mut r, &mut buf).await.unwrap(), Some(Err(())));
        assert_eq!(read_line(&mut r, &mut buf).await.unwrap(), Some(Ok("short".into())));
        assert_eq!(read_line(&mut r, &mut buf).await.unwrap(), None);
    }
}
