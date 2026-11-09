# IronMesh load test `20261109-214027-ramp-fleet-threads-64`: NOT PASSED

**Aborted:** host available memory 643 MiB fell below the floor of 768 MiB (combined RSS 656 MiB: fleet 347, harness 252, policy 57)

5000 of 10000 devices enrolled and connected through the real agent-rs device stack and the real policy service; 0 telemetry messages/s accepted during 0 s of sustained load; publish -> PUBACK p50 / p95 / p99 / max - ms; every device's last `seq` accepted: yes.

## Environment

| | |
|---|---|
| CPU | 12th Gen Intel(R) Core(TM) i7-12700H (14 cores, 20 logical) |
| RAM | 16088 MiB (3884 MiB available at start) |
| OS | Windows 11 Home |
| Rust | rustc 1.99.1 (58cf8f9c3 2026-10-13) |
| Go | go version go1.27.3 windows/amd64 |
| Git commit | 23b7dfd49f21eb8ef2617c034609b7a6965cf7e2 (working tree modified) |
| TCP ephemeral ports | start 1024, 64511 ports |
| Started | 2026-11-09T21:40:27.7650766Z |

```sh
ironmesh-conformance load --devices 10000 --sustain-s 60 --fleet-threads 64 --label ramp-fleet-threads-64
```

Configuration: 10000 devices, start rate 200/s in stages [25, 50, 75, 100] % with 15 s holds, telemetry every 10 s, sustain 60 s, 5.0 % of the devices get one command, policy hook pool 64, publish timeout 30 s, backoff scale 1.

## Devices and rates

| Metric | Value |
|---|---|
| Provisioned (identity, bootstrap cert, manufacture record) | 10000 |
| Factory provisioning time | 54.6 s |
| Device tasks started | 5000 |
| Enrolled (EST + attestation) | 5000 |
| Connected at least once (CONNACK + SUBACK) | 5000 |
| Never connected | 5000 |
| Broker sessions at the end of the sustained window | 5000 |
| Peak broker sessions | 5000 |
| Ramp duration (incl. stage holds) | 0 s |
| Target start rate | 200 devices/s |
| Achieved first-connect rate (holds excluded) | 0.0 devices/s |
| Sustained window | 0 s |
| Telemetry accepted by the broker, sustained | 0 (0.0/s) |
| Offered rate at the end (sessions / interval) | 500.0/s |
| Telemetry accepted by the broker, whole run | 11063 |
| Telemetry PUBACKs received by devices, whole run | 11063 |

## Latency (ms)

| Path | n | p50 | p95 | p99 | max | mean |
|---|---|---|---|---|---|---|
| Telemetry publish -> PUBACK, sustained (device) | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| Telemetry publish -> PUBACK, ramp (device) | 11049 | 24.6 | 3014.0 | 3465.6 | 3877.7 | 770.3 |
| Connect: TCP + TLS 1.3 mTLS + CONNACK (device) | 5000 | 1097.3 | 3545.9 | 3780.0 | 4139.8 | 1402.2 |
| EST enrollment with attestation (device) | 5000 | 297.3 | 1835.4 | 2382.5 | 3264.1 | 587.8 |
| Command round trip (inject -> verified CommandAck) | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| Policy authn hook round trip (broker) | 5000 | 1022.6 | 3272.7 | 3550.0 | 3882.6 | 1260.1 |
| Policy authz hook round trip (broker) | 16063 | 315.2 | 2842.8 | 3308.6 | 3790.0 | 776.1 |
| ... of which waiting for a hook pool connection | 21063 | 451.5 | 2859.2 | 3269.3 | 3420.6 | 815.0 |

services/policy exports decision counters but no authn/authz latency histogram; hook latency is the broker-side HTTP round trip (what EMQX would observe)

## Downlink commands

0 tenant-signed `ping` commands injected as `svc-registry` (policy-authorized), 0 acked with a verified CommandAck (cmd_id + nonce echo), 0 not delivered (device not subscribed at that moment), 0 injection errors, 0 unacked at the end, 0 mismatching acks. Device side: 0 executed, 0 rejected. Ack status codes: {}.

## Policy service (`/metrics` before -> after)

| Counter | Delta |
|---|---|
| authn allow | 5000 |
| authn deny | 0 |
| authz allow | 16063 |
| authz deny | 0 |
| authz cache hit | 3303 |
| authz cache miss | 12760 |
| registry lookups | 5000 |
| process CPU seconds | 20.1 |

Every changed series is in `summary.json` (`policy.deltas`).

## End-to-end verification

* Uplinks verified (COSE_Sign1 ES256 with the presented certificate key, profile, timestamp, per-device replay stream): 11063 (11063 telemetry, 0 CommandAck)
* Replay rejections: 0
* Devices with at least one PUBACKed uplink: 4025; last PUBACKed `seq` equal to the verifier's last accepted `seq`: 4025; different: 0
* Peak verifier backlog: 99 messages
* Result: **passed**


## Errors

* Device side (class: count, first example): none
* Broker TLS handshake failures: none
* Broker -> policy hook transport errors: none
* Broker session ends by cause:
  * `client_disconnect`: 5000
* CONNECTs refused: 0; PUBLISHes denied: 0; SUBSCRIBE filters denied: 0
* EST attempts by HTTP status:
  * `200`: 5000
* Uplink verification failures: none

## Resources (sysinfo, every sample; CPU in % of one logical CPU)

| Process | CPU mean | CPU max | RSS mean (MiB) | RSS max (MiB) |
|---|---|---|---|---|
| fleet, sustained | 0 | 0 | 0 | 0 |
| harness (broker + EST doubles, verifier), sustained | 0 | 0 | 0 | 0 |
| policy service, sustained | 0 | 0 | 0 | 0 |
| fleet, whole run | 397 | 734 | 219 | 347 |
| harness, whole run | 135 | 218 | 172 | 252 |
| policy service, whole run | 45 | 77 | 72 | 111 |

Peak combined RSS 667 MiB (abort cap 11262 MiB); lowest host available memory 643 MiB (abort floor 768 MiB). Fleet RSS per connected device 71.1 KiB; harness RSS per broker session 51.6 KiB (end of the sustained window). Broker -> policy hook pool: 64 connections max, 64 opened.

## Time series

**Connected devices** (full scale = 5000 devices)

```text
     5 s ramp    |#####...................................|     662.0
    10 s ramp    |#############...........................|    1578.0
    15 s ramp    |####################....................|    2500.0
    20 s ramp    |####################....................|    2500.0
    25 s ramp    |####################....................|    2500.0
    30 s ramp    |#####################...................|    2674.0
    35 s ramp    |########################................|    2972.0
    40 s ramp    |################################........|    3969.0
    45 s ramp    |########################################|    5000.0
```

**Telemetry accepted by the broker** (full scale = 624 msg/s)

```text
     5 s ramp    |#.......................................|      22.7
    10 s ramp    |######..................................|      95.6
    15 s ramp    |################........................|     251.5
    20 s ramp    |################........................|     250.0
    25 s ramp    |################........................|     250.8
    30 s ramp    |##############..........................|     218.5
    35 s ramp    |############............................|     184.0
    40 s ramp    |#####################...................|     328.3
    45 s ramp    |########################################|     623.8
```

**Publish -> PUBACK p99 per interval** (full scale = 3643 ms)

```text
     5 s ramp    |#########...............................|     776.7
    10 s ramp    |##########################..............|    2402.4
    15 s ramp    |#############...........................|    1213.7
    20 s ramp    |........................................|      10.7
    25 s ramp    |........................................|       1.7
    30 s ramp    |#########...............................|     803.5
    35 s ramp    |#################################.......|    3007.2
    40 s ramp    |########################################|    3642.5
    45 s ramp    |############################............|    2555.6
```

**Combined RSS (fleet + harness + policy)** (full scale = 667 MiB)

```text
     5 s ramp    |###############.........................|     246.6
    10 s ramp    |########################................|     394.1
    15 s ramp    |########################................|     392.9
    20 s ramp    |#######################.................|     388.7
    25 s ramp    |#######################.................|     389.5
    30 s ramp    |############################............|     470.5
    35 s ramp    |##################################......|     567.7
    40 s ramp    |########################################|     666.9
    45 s ramp    |#######################################.|     656.3
```

**Combined CPU (fleet + harness + policy)** (full scale = 969 % of one CPU)

```text
     5 s ramp    |##################################......|     815.9
    10 s ramp    |######################################..|     910.7
    15 s ramp    |######################..................|     537.7
    20 s ramp    |##......................................|      56.9
    25 s ramp    |##......................................|      40.9
    30 s ramp    |#####################...................|     499.7
    35 s ramp    |########################################|     969.3
    40 s ramp    |########################################|     962.7
    45 s ramp    |################........................|     391.3
```

| t (s) | phase | connected | tele/s | pub p50 | pub p99 | authz p99 | fleet CPU % | fleet MiB | harness CPU % | harness MiB | policy CPU % | policy MiB | avail MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 5 | ramp | 662 | 23 | 262.3 | 776.7 | 795.7 | 579 | 90 | 190 | 91 | 47 | 66 | 2935 |
| 10 | ramp | 1578 | 96 | 1018.7 | 2402.4 | 2713.8 | 653 | 153 | 208 | 130 | 49 | 111 | 2801 |
| 15 | ramp | 2500 | 251 | 155.8 | 1213.7 | 1129.3 | 354 | 188 | 122 | 151 | 62 | 53 | 2712 |
| 20 | ramp | 2500 | 250 | 0.9 | 10.7 | 9.8 | 16 | 188 | 24 | 153 | 17 | 47 | 2787 |
| 25 | ramp | 2500 | 251 | 0.5 | 1.7 | 1.1 | 13 | 188 | 15 | 154 | 12 | 47 | 2767 |
| 30 | ramp | 2674 | 219 | 0.8 | 803.5 | 876.5 | 359 | 216 | 115 | 171 | 26 | 83 | 2460 |
| 35 | ramp | 2972 | 184 | 1203.0 | 3007.2 | 2971.9 | 734 | 270 | 193 | 208 | 41 | 90 | 2237 |
| 40 | ramp | 3969 | 328 | 2652.1 | 3642.5 | 3500.9 | 668 | 331 | 218 | 240 | 77 | 96 | 2131 |
| 45 | ramp | 5000 | 624 | 3.4 | 2555.6 | 2522.0 | 195 | 347 | 127 | 252 | 70 | 57 | 643 |

Full resolution: `timeseries.csv`. Machine-readable results: `summary.json`.
