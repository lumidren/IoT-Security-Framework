# IronMesh load test

`ironmesh-conformance load` drives N simulated devices (default 10 000) through the part of the
IronMesh protocol path that runs on one machine without Docker. It reuses the hermetic cloud of
the conformance suite (`conformance/src/harness/`) and the agent-rs device stack as a library, and
measures everything it reports during the run. The results of the runs on the development machine
are in [`REPORT.md`](REPORT.md); every run writes its raw data to `results/<timestamp>[-label]/`.

## What runs

| Component | Real or double | Process |
|---|---|---|
| Device stack: software identity, EST enrollment with attestation, pinned TLS 1.3 + mTLS, MQTT 5 client, COSE_Sign1 telemetry, downlink verification, command execution | **real** (`device/agent-rs` as a library, `fleet::Model` telemetry) | fleet (`load-fleet`, spawned by `load`) |
| Policy service: EMQX authn/authz hooks, Rego, decision cache, registry lookups | **real** (`go build ./services/policy/cmd/policy`) | policy |
| MQTT broker | double (`conformance/src/harness/broker.rs`): TLS 1.3 + mTLS + ALPN `mqtt`, every CONNECT / PUBLISH / SUBSCRIBE decided by the real policy service | harness (`load`) |
| EST / CA | double (`conformance/src/harness/est.rs`): the checks of `services/pki/internal/est` | harness |
| Registry | double (lifecycle endpoint, CRL distribution point) | harness |
| Uplink verification (bridge stand-in) | harness code using the agent-rs wire library: COSE_Sign1 ES256 with the presented certificate key, timestamp, per-device replay stream | harness |

Not exercised here: EMQX, the bridge, Kafka, the registry service and its database. Those run in
the nightly `load-smoke` job (below).

## Run it locally

Requirements: Rust stable, Go (on Windows `C:\Program Files\Go\bin\go.exe` is used when `go` is not
on `PATH`). The policy binary is built into `conformance/target/bin/` on first use.

```sh
cd conformance
cargo build --release

# 1 000-device smoke, 2 minutes of sustained load
./target/release/ironmesh-conformance load --devices 1000 --sustain-s 120 --label smoke-1000

# the full run: 10 000 devices, 200 starts/s in 4 stages, telemetry every 10 s, 10 minutes sustained
./target/release/ironmesh-conformance load --devices 10000 --label full-10000
```

Exit status: 0 when the ramp and the sustained window completed and every device's last
acknowledged `seq` was accepted by the verifier with no replay rejection, 1 otherwise, 2 on a
start-up error.

### Options

| Option | Default | Meaning |
|---|---|---|
| `--devices` | 10000 | simulated devices |
| `--rate` | 200 | device starts per second during the ramp (each start = EST enrollment + MQTT connect + SUBSCRIBE) |
| `--stages`, `--stage-hold-s` | `25,50,75,100`, 15 | cumulative % of the fleet per stage, pause after each stage |
| `--interval-s` | 10 | telemetry period per device |
| `--sustain-s` | 600 | sustained window after the ramp |
| `--ramp-grace-s` | 60 | longest wait for stragglers after the ramp schedule |
| `--cmd-fraction` | 0.05 | share of devices that receive one tenant-signed `ping` command during the sustained window |
| `--sample-s` | 5 | sampling period (CPU/RSS via `sysinfo`, fleet status, broker counters) |
| `--rss-cap-mb` | 70 % of RAM | abort when fleet + harness + policy RSS exceeds this |
| `--min-available-mb` | 768 | abort when the host's available memory drops below this (keeps the machine usable) |
| `--hook-pool` | 64 | persistent broker -> policy hook connections |
| `--publish-timeout-s` | 30 | publish -> PUBACK timeout |
| `--backoff-scale` | 1.0 | reconnect / re-enroll backoff scale (1.0 = contract: 1 s base, 300 s cap, full jitter) |
| `--fleet-threads` | 0 | tokio workers in the fleet process (0 = one per logical CPU) |
| `--label`, `--out`, `--keep-fleet` | | results directory suffix, results root, keep the device directories |

### Outputs

`loadtest/results/<UTC timestamp>[-label]/`:

* `summary.json`: environment, configuration, outcome, device counts, rates, latency summaries
  (exact nearest-rank percentiles over every sample), commands, policy `/metrics` deltas, errors from
  every vantage point, verification, resource statistics;
* `timeseries.csv`: one row per sample: phase, devices started/enrolled/connected, broker sessions,
  connect rate, accepted telemetry/s, publish and hook latency of the interval, CPU % and RSS of the
  three processes, host available memory, verifier backlog;
* `report.md`: the same as tables and ASCII charts.

Run-time scratch data (device directories, `fleet.log`, `policy.log`, raw `/metrics` before and
after) is in `conformance/target/load/<run>/`; the device directories are deleted at the end unless
`--keep-fleet` is given.

## How it measures

* **Device side** (fleet process): enroll, connect (TCP + TLS 1.3 + CONNACK) and telemetry
  publish -> PUBACK durations per message; error classes (`enroll: EST HTTP 403`,
  `connect: timeout`, `publish: PUBACK timeout`, ...); the last acknowledged `seq` per device.
  Statistics are taken per sampling interval and per phase (ramp, sustain).
* **Broker side** (harness): accepted / denied CONNECT, PUBLISH, SUBSCRIBE, TLS handshake failures by
  reason, session ends by cause, and the HTTP round trip of every authn/authz hook call (the policy
  service exports decision counters but no latency histogram).
* **Policy service**: `/metrics` scraped before the ramp and after the stop; every changed
  `ironmesh_*`, `process_*` and Go runtime series is reported as a delta.
* **Commands**: signed with the tenant key, injected as `svc-registry` (authorized by the policy
  service like any publish), verified and executed on the device, acked; the round trip ends when
  the broker accepts the CommandAck and the verifier has checked its signature, cmd_id and nonce
  echo.
* **Verification**: every accepted Telemetry and CommandAck is verified; at the end, each device's
  last PUBACKed `seq` must equal the last `seq` the verifier accepted, with zero `ENV_REPLAY`.
* **Resources**: `sysinfo` CPU % (of one logical CPU) and RSS of the fleet, harness and policy
  processes every `--sample-s`; the run aborts gracefully (devices disconnect, results are still
  written) when the RSS cap or the available-memory floor is crossed.

The broker double runs in *load mode* during this test: its per-message observation log (which the
conformance cases assert on) is off, wildcard-free subscriptions are indexed by topic and the policy
hooks use a persistent connection pool, as EMQX does. Without the pool every hook call would open a
TCP connection and the ephemeral port range would run out in TIME_WAIT within a minute at these
rates.

## In CI

* **Nightly, stack**: `.github/workflows/nightly.yml`, job `load-smoke` ("load smoke (1000 devices,
  5 min)"): the docker-compose stack (EMQX, PKI, policy, registry, bridge, Kafka, ...) plus 1 000
  `ironmesh-fleet` devices for 5 minutes; asserts no container restarts and no bridge forward
  errors. That is where EMQX, the bridge, Kafka and registry ingest are exercised.
* **This test in CI**: any Linux or Windows runner with Rust and Go can run it; no services needed.
  A step such as

  ```yaml
  - name: hermetic load test (1 000 devices, 2 min)
    working-directory: conformance
    run: cargo run --release -- load --devices 1000 --sustain-s 120 --label ci --out "${RUNNER_TEMP}/load"
  - uses: actions/upload-artifact@6f51ac03b9356f520e9adb1b1b7802705f340c2b # v4.5.0
    if: always()
    with:
      name: hermetic-load
      path: ${{ runner.temp }}/load
  ```

  fits a standard runner (the 1 000-device runs peaked at 226 MiB combined RSS; see `REPORT.md`). On Linux, raise `ulimit -n` above twice the device count for the 10 000-device
  run (each device holds one socket in the fleet process and one in the harness).
