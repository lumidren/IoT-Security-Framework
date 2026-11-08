#!/usr/bin/env python3
"""Generate the IronMesh Grafana dashboards (dashboards-as-code).

    python observability/grafana/generate_dashboards.py

Writes observability/grafana/dashboards/*.json (Grafana 10/11 schema, schemaVersion 39,
datasource uid "prometheus", no __inputs). Metric names follow docs/DESIGN_CONTRACT.md §9,
the services' metrics packages and observability/README.md (extended metrics). The JSON files
are committed; re-run after editing this file and commit both.
"""
from __future__ import annotations

import json
import pathlib

OUT_DIR = pathlib.Path(__file__).resolve().parent / "dashboards"
DS = {"type": "prometheus", "uid": "prometheus"}
GREEN, YELLOW, ORANGE, RED, BLUE = "green", "yellow", "orange", "red", "blue"


class Layout:
    """Places panels left to right, wrapping at 24 columns."""

    def __init__(self) -> None:
        self.x = 0
        self.y = 0
        self.row_h = 0
        self.next_id = 1

    def place(self, w: int, h: int) -> dict:
        if self.x + w > 24:
            self.x = 0
            self.y += self.row_h
            self.row_h = 0
        pos = {"h": h, "w": w, "x": self.x, "y": self.y}
        self.x += w
        self.row_h = max(self.row_h, h)
        return pos

    def newline(self) -> None:
        if self.x:
            self.x = 0
            self.y += self.row_h
            self.row_h = 0

    def pid(self) -> int:
        i = self.next_id
        self.next_id += 1
        return i


def target(expr: str, legend: str = "__auto", ref: str = "A", instant: bool = False) -> dict:
    return {
        "datasource": DS,
        "editorMode": "code",
        "expr": expr,
        "legendFormat": legend,
        "range": not instant,
        "instant": instant,
        "refId": ref,
    }


def targets(*exprs) -> list:
    out = []
    for i, item in enumerate(exprs):
        expr, legend = item if isinstance(item, tuple) else (item, "__auto")
        out.append(target(expr, legend, chr(ord("A") + i)))
    return out


def thresholds(*steps) -> dict:
    """steps: (color, value) with value None for the base."""
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for c, v in steps]}


def timeseries(lay: Layout, title: str, tgts: list, *, w=12, h=8, unit="short", desc="", stack=False,
               min_=0, max_=None, thresh=None, thresh_style="off", fill=10, legend_calcs=None,
               overrides=None, decimals=None) -> dict:
    defaults = {
        "color": {"mode": "palette-classic"},
        "custom": {
            "axisBorderShow": False,
            "axisCenteredZero": False,
            "axisColorMode": "text",
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": fill,
            "gradientMode": "none",
            "hideFrom": {"legend": False, "tooltip": False, "viz": False},
            "insertNulls": False,
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 4,
            "scaleDistribution": {"type": "linear"},
            "showPoints": "never",
            "spanNulls": True,
            "stacking": {"group": "A", "mode": "normal" if stack else "none"},
            "thresholdsStyle": {"mode": thresh_style},
        },
        "mappings": [],
        "thresholds": thresh or thresholds((GREEN, None)),
        "unit": unit,
    }
    if min_ is not None:
        defaults["min"] = min_
    if max_ is not None:
        defaults["max"] = max_
    if decimals is not None:
        defaults["decimals"] = decimals
    return {
        "id": lay.pid(),
        "type": "timeseries",
        "title": title,
        "description": desc,
        "datasource": DS,
        "gridPos": lay.place(w, h),
        "fieldConfig": {"defaults": defaults, "overrides": overrides or []},
        "options": {
            "legend": {"calcs": legend_calcs or [], "displayMode": "list", "placement": "bottom", "showLegend": True},
            "tooltip": {"mode": "multi", "sort": "desc"},
        },
        "targets": tgts,
    }


def stat(lay: Layout, title: str, expr: str, *, w=4, h=4, unit="short", desc="", thresh=None,
         decimals=None, color_mode="value", graph="area", mappings=None, legend="__auto",
         instant=False, text_mode="auto", reducer="lastNotNull") -> dict:
    defaults = {
        "color": {"mode": "thresholds"},
        "mappings": mappings or [],
        "thresholds": thresh or thresholds((GREEN, None)),
        "unit": unit,
    }
    if decimals is not None:
        defaults["decimals"] = decimals
    return {
        "id": lay.pid(),
        "type": "stat",
        "title": title,
        "description": desc,
        "datasource": DS,
        "gridPos": lay.place(w, h),
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {
            "colorMode": color_mode,
            "graphMode": graph,
            "justifyMode": "auto",
            "orientation": "auto",
            "percentChangeColorMode": "standard",
            "reduceOptions": {"calcs": [reducer], "fields": "", "values": False},
            "showPercentChange": False,
            "textMode": text_mode,
            "wideLayout": True,
        },
        "targets": [target(expr, legend, "A", instant=instant)],
    }


def gauge(lay: Layout, title: str, expr: str, *, w=6, h=6, unit="percentunit", desc="", thresh=None,
          min_=0, max_=1, legend="__auto", decimals=None) -> dict:
    defaults = {
        "color": {"mode": "thresholds"},
        "mappings": [],
        "min": min_,
        "max": max_,
        "thresholds": thresh or thresholds((GREEN, None)),
        "unit": unit,
    }
    if decimals is not None:
        defaults["decimals"] = decimals
    return {
        "id": lay.pid(),
        "type": "gauge",
        "title": title,
        "description": desc,
        "datasource": DS,
        "gridPos": lay.place(w, h),
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {
            "minVizHeight": 75,
            "minVizWidth": 75,
            "orientation": "auto",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "showThresholdLabels": False,
            "showThresholdMarkers": True,
            "sizing": "auto",
        },
        "targets": [target(expr, legend, "A")],
    }


def bargauge(lay: Layout, title: str, expr: str, *, w=12, h=8, unit="percentunit", desc="", thresh=None,
             min_=0, max_=1, legend="__auto") -> dict:
    return {
        "id": lay.pid(),
        "type": "bargauge",
        "title": title,
        "description": desc,
        "datasource": DS,
        "gridPos": lay.place(w, h),
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "thresholds"},
                "mappings": [],
                "min": min_,
                "max": max_,
                "thresholds": thresh or thresholds((GREEN, None)),
                "unit": unit,
            },
            "overrides": [],
        },
        "options": {
            "displayMode": "gradient",
            "maxVizHeight": 300,
            "minVizHeight": 16,
            "minVizWidth": 8,
            "namePlacement": "auto",
            "orientation": "horizontal",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "showUnfilled": True,
            "sizing": "auto",
            "valueMode": "color",
        },
        "targets": [target(expr, legend, "A", instant=True)],
    }


def piechart(lay: Layout, title: str, expr: str, *, w=8, h=8, unit="short", desc="", legend="__auto") -> dict:
    return {
        "id": lay.pid(),
        "type": "piechart",
        "title": title,
        "description": desc,
        "datasource": DS,
        "gridPos": lay.place(w, h),
        "fieldConfig": {
            "defaults": {"color": {"mode": "palette-classic"}, "mappings": [], "unit": unit},
            "overrides": [],
        },
        "options": {
            "displayLabels": ["percent"],
            "legend": {"displayMode": "list", "placement": "right", "showLegend": True, "values": ["value"]},
            "pieType": "donut",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "tooltip": {"mode": "single", "sort": "none"},
        },
        "targets": [target(expr, legend, "A", instant=True)],
    }


def heatmap(lay: Layout, title: str, expr: str, *, w=12, h=9, unit="s", desc="", scheme="Oranges") -> dict:
    return {
        "id": lay.pid(),
        "type": "heatmap",
        "title": title,
        "description": desc,
        "datasource": DS,
        "gridPos": lay.place(w, h),
        "fieldConfig": {"defaults": {"custom": {"hideFrom": {"legend": False, "tooltip": False, "viz": False}, "scaleDistribution": {"type": "linear"}}}, "overrides": []},
        "options": {
            "calculate": False,
            "cellGap": 1,
            "color": {"exponent": 0.5, "fill": "dark-orange", "mode": "scheme", "reverse": False, "scale": "exponential", "scheme": scheme, "steps": 64},
            "exemplars": {"color": "rgba(255,0,255,0.7)"},
            "filterValues": {"le": 1e-9},
            "legend": {"show": True},
            "rowsFrame": {"layout": "auto"},
            "showValue": "never",
            "tooltip": {"mode": "single", "showColorScale": False, "yHistogram": True},
            "yAxis": {"axisPlacement": "left", "reverse": False, "unit": unit},
        },
        "targets": [{**target(expr, "{{le}}", "A"), "format": "heatmap"}],
    }


def table(lay: Layout, title: str, expr: str, *, w=24, h=8, desc="", unit="short", organize=None, thresh=None) -> dict:
    transformations = [{"id": "labelsToFields", "options": {"mode": "columns", "valueLabel": ""}}]
    if organize:
        transformations.append({"id": "organize", "options": organize})
    return {
        "id": lay.pid(),
        "type": "table",
        "title": title,
        "description": desc,
        "datasource": DS,
        "gridPos": lay.place(w, h),
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "thresholds"},
                "custom": {"align": "auto", "cellOptions": {"type": "auto"}, "inspect": False},
                "mappings": [],
                "thresholds": thresh or thresholds((GREEN, None)),
                "unit": unit,
            },
            "overrides": [],
        },
        "options": {
            "cellHeight": "sm",
            "footer": {"countRows": False, "fields": "", "reducer": ["sum"], "show": False},
            "showHeader": True,
        },
        "targets": [{**target(expr, "", "A", instant=True), "format": "table"}],
        "transformations": transformations,
    }


def row(lay: Layout, title: str) -> dict:
    lay.newline()
    return {"id": lay.pid(), "type": "row", "title": title, "collapsed": False, "gridPos": lay.place(24, 1), "panels": []}


def dashboard(uid: str, title: str, tags: list[str], panels: list, description: str, time_from="now-6h", refresh="30s") -> dict:
    return {
        "annotations": {
            "list": [
                {
                    "builtIn": 1,
                    "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                    "enable": True,
                    "hide": True,
                    "iconColor": "rgba(0, 211, 255, 1)",
                    "name": "Annotations & Alerts",
                    "type": "dashboard",
                },
                {
                    "datasource": DS,
                    "enable": True,
                    "expr": "ALERTS{alertstate=\"firing\",alertname=~\"IronMesh.*|AuthFailureBurst|RevocationLatencyHigh|CertExpiryBacklog|OtaFailureRateHigh|AnomalyRateSpike|ConnectedDevicesDrop|BridgeForwardErrors|ReplayRejectedSpike|ServiceDown\"}",
                    "iconColor": "red",
                    "name": "Firing alerts",
                    "step": "60s",
                    "titleFormat": "{{alertname}}",
                    "textFormat": "{{job}} {{instance}}",
                },
            ]
        },
        "description": description,
        "editable": True,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 1,
        "id": None,
        "links": [
            {
                "asDropdown": True,
                "icon": "external link",
                "includeVars": False,
                "keepTime": True,
                "tags": ["ironmesh"],
                "targetBlank": False,
                "title": "IronMesh dashboards",
                "tooltip": "",
                "type": "dashboards",
                "url": "",
            }
        ],
        "panels": panels,
        "refresh": refresh,
        "schemaVersion": 39,
        "tags": ["ironmesh", *tags],
        "templating": {
            "list": [
                {
                    "current": {"selected": False, "text": "Prometheus", "value": "prometheus"},
                    "hide": 2,
                    "includeAll": False,
                    "multi": False,
                    "name": "datasource",
                    "options": [],
                    "query": "prometheus",
                    "refresh": 1,
                    "regex": "/^prometheus$/",
                    "skipUrlSync": False,
                    "type": "datasource",
                }
            ]
        },
        "time": {"from": time_from, "to": "now"},
        "timepicker": {"refresh_intervals": ["10s", "30s", "1m", "5m", "15m", "1h"]},
        "timezone": "utc",
        "title": title,
        "uid": uid,
        "version": 1,
        "weekStart": "",
    }


# --------------------------------------------------------------------------------------------
# Dashboards
# --------------------------------------------------------------------------------------------

def fleet_overview() -> dict:
    lay = Layout()
    p = [
        stat(lay, "Connected devices", "sum(ironmesh_connected_devices)", desc="Live MQTT sessions reported by the broker/bridge (ironmesh_connected_devices).", thresh=thresholds((GREEN, None))),
        stat(lay, "Devices (registry)", "sum(ironmesh_devices_total)", desc="All devices known to the registry, any lifecycle state."),
        stat(lay, "Quarantined", "sum(ironmesh_devices_total{state=\"quarantined\"})", thresh=thresholds((GREEN, None), (ORANGE, 1), (RED, 10)), desc="Devices in the quarantined lifecycle state."),
        stat(lay, "Auth failures /s (5m)", "sum(rate(ironmesh_auth_failures_total[5m]))", unit="reqps", decimals=2, thresh=thresholds((GREEN, None), (ORANGE, 1), (RED, 5)), desc="AuthFailureBurst fires above 5/s for 2 minutes."),
        stat(lay, "Replay rejected /s (5m)", "sum(rate(ironmesh_replay_rejected_total[5m]))", unit="reqps", decimals=2, thresh=thresholds((GREEN, None), (ORANGE, 0.2), (RED, 1)), desc="Messages dropped for stale seq (ironmesh_replay_rejected_total)."),
        stat(lay, "Certs expiring < 24h", "sum(ironmesh_cert_expiring_total{window=\"24h\"})", thresh=thresholds((GREEN, None), (RED, 1)), desc="Operational certificates expiring within 24 h without renewal (CertExpiryBacklog)."),
        timeseries(lay, "Connected devices", targets(("sum(ironmesh_connected_devices)", "connected"), ("sum(emqx_live_connections_count)", "emqx live connections")), desc="ConnectedDevicesDrop fires on a >20% drop in 5 minutes.", legend_calcs=["last", "min", "max"]),
        piechart(lay, "Device state breakdown", "sum by (state) (ironmesh_devices_total)", legend="{{state}}", desc="Lifecycle states: manufactured, provisioned, active, quarantined, decommissioned."),
        stat(lay, "Hardware-backed share", "sum(ironmesh_devices_total{assurance=\"hardware\"}) / clamp_min(sum(ironmesh_devices_total{assurance=~\"hardware|software\"}), 1)", unit="percentunit", decimals=1, graph="none", thresh=thresholds((RED, None), (ORANGE, 0.9), (GREEN, 0.99)), desc="Devices with hardware assurance (ATECC608 / TPM 2.0 / OP-TEE) among enrolled devices."),
        timeseries(lay, "Message rate", targets(("sum(rate(emqx_messages_received[5m]))", "broker received"), ("sum(rate(emqx_messages_sent[5m]))", "broker sent"), ("sum(rate(ironmesh_bridge_messages_forwarded_total[5m]))", "bridged to kafka")), unit="mps", desc="Broker ingress/egress and bridge forwarding; received and bridged should track each other."),
        timeseries(lay, "Auth failures by reason", targets(("sum by (reason) (rate(ironmesh_auth_failures_total[5m]))", "{{reason}}")), unit="reqps", stack=True, thresh=thresholds((GREEN, None), (RED, 5)), thresh_style="dashed", desc="Policy authn denials by reason, plus PKI EST/management auth failures."),
        timeseries(lay, "Certificates expiring by window", targets(("sum by (window) (ironmesh_cert_expiring_total)", "{{window}}")), desc="Non-revoked certificates expiring within 24h / 72h / 7d. Renewal happens at 50% lifetime, so the 24h series should stay at zero."),
        timeseries(lay, "Device state over time", targets(("sum by (state) (ironmesh_devices_total)", "{{state}}")), stack=True, fill=30),
        timeseries(lay, "Anomaly alerts by rule", targets(("sum by (rule) (rate(ironmesh_anomaly_alerts_total[5m]) * 60)", "{{rule}}")), unit="cpm", stack=True, desc="Alerts per minute by detection rule (ironmesh_anomaly_alerts_total)."),
        timeseries(lay, "OTA results", targets(("sum by (result) (rate(ironmesh_ota_result_total[10m]) * 60)", "{{result}}")), unit="cpm", stack=True, desc="OTA outcomes per minute (ironmesh_ota_result_total)."),
        table(lay, "Firing IronMesh alerts", "ALERTS{alertstate=\"firing\"}", desc="Alerts currently firing in Prometheus (observability/prometheus/rules/ironmesh.rules.yml).",
              organize={"excludeByName": {"Time": True, "Value": True, "__name__": True, "alertstate": True}, "indexByName": {"alertname": 0, "severity": 1, "service": 2, "job": 3, "instance": 4}, "renameByName": {}}),
    ]
    return dashboard("ironmesh-fleet", "IronMesh / Fleet overview", ["fleet"], p, "Fleet health at a glance: connectivity, authentication, certificate lifecycle, device states, anomaly and OTA activity.")


def pki() -> dict:
    lay = Layout()
    p = [
        stat(lay, "Issuance rate (certs/min)", "sum(rate(ironmesh_certs_issued_total[5m])) * 60", unit="cpm", decimals=1, desc="Certificates issued per minute, all kinds (bootstrap, operational, service)."),
        stat(lay, "Revocations /h", "sum(rate(ironmesh_revocations_total{job=\"ironmesh-pki\"}[1h])) * 3600", decimals=1, desc="Certificates revoked per hour (PKI)."),
        stat(lay, "p99 revocation → kick", "histogram_quantile(0.99, sum by (le) (rate(ironmesh_revocation_latency_seconds_bucket{job=\"ironmesh-policy\"}[5m])))", unit="s", decimals=2, thresh=thresholds((GREEN, None), (ORANGE, 5), (RED, 8)), desc="End-to-end budget is 10 s (RevocationLatencyHigh at 8 s)."),
        stat(lay, "Expiring < 24h", "sum(ironmesh_cert_expiring_total{window=\"24h\"})", thresh=thresholds((GREEN, None), (RED, 1))),
        stat(lay, "Expiring < 7d", "sum(ironmesh_cert_expiring_total{window=\"7d\"})", desc="Expected to be non-zero: renewal starts 7 days before expiry."),
        stat(lay, "CRL age (policy)", "time() - max(ironmesh_crl_last_success_timestamp_seconds)", unit="s", decimals=0, thresh=thresholds((GREEN, None), (ORANGE, 120), (RED, 600)), desc="Seconds since the policy service last fetched the CRL (poll every 5 s; CrlStale at 10 min)."),
        timeseries(lay, "Certificates issued by kind", targets(("sum by (kind) (rate(ironmesh_certs_issued_total[5m]) * 60)", "{{kind}}")), unit="cpm", stack=True),
        timeseries(lay, "EST requests by operation and status", targets(("sum by (op, code) (rate(ironmesh_est_requests_total[5m]))", "{{op}} {{code}}")), unit="reqps", desc="cacerts, csrattrs, simpleenroll, simplereenroll and the attestation nonce endpoint."),
        heatmap(lay, "Revocation latency distribution (revoked_at → broker kick)", "sum by (le) (rate(ironmesh_revocation_latency_seconds_bucket{job=\"ironmesh-policy\"}[2m]))", desc="Policy service histogram; buckets 50 ms ... 60 s."),
        timeseries(lay, "Revocation latency percentiles", targets(
            ("histogram_quantile(0.50, sum by (le) (rate(ironmesh_revocation_latency_seconds_bucket{job=\"ironmesh-policy\"}[5m])))", "policy p50"),
            ("histogram_quantile(0.95, sum by (le) (rate(ironmesh_revocation_latency_seconds_bucket{job=\"ironmesh-policy\"}[5m])))", "policy p95"),
            ("histogram_quantile(0.99, sum by (le) (rate(ironmesh_revocation_latency_seconds_bucket{job=\"ironmesh-policy\"}[5m])))", "policy p99"),
            ("histogram_quantile(0.99, sum by (le) (rate(ironmesh_revocation_latency_seconds_bucket{job=\"ironmesh-pki\"}[5m])))", "pki publish p99"),
        ), unit="s", thresh=thresholds((GREEN, None), (RED, 10)), thresh_style="dashed", desc="Dashed line: 10 s contract budget. pki series = revoke request → policy acknowledgement."),
        timeseries(lay, "OCSP requests by status", targets(("sum by (status) (rate(ironmesh_ocsp_requests_total[5m]))", "{{status}}")), unit="reqps", stack=True),
        timeseries(lay, "CRL regenerations and policy CRL polls", targets(("sum(rate(ironmesh_crl_generations_total[5m]) * 60)", "CRL regenerations /min"), ("sum by (result) (rate(ironmesh_crl_poll_total[5m]) * 60)", "policy poll {{result}} /min")), unit="cpm"),
        timeseries(lay, "Expiring certificates by window", targets(("sum by (window) (ironmesh_cert_expiring_total)", "{{window}}"))),
        timeseries(lay, "Attestation failures by reason", targets(("sum by (reason) (rate(ironmesh_attestation_failures_total[5m]) * 60)", "{{reason}}")), unit="cpm", stack=True, desc="Rejected attestations: nonce, CSR binding, signature, PCR policy, lifecycle state."),
        timeseries(lay, "Revocation pipeline health", targets(
            ("sum(rate(ironmesh_revocation_publish_failures_total[5m]))", "publish failures /s"),
            ("sum by (result) (rate(ironmesh_kick_total[5m]))", "kick {{result}} /s"),
            ("sum by (source) (rate(ironmesh_revocations_total{job=\"ironmesh-policy\"}[5m]))", "applied via {{source}} /s"),
        ), unit="reqps", desc="PKI → policy event delivery, EMQX session kicks and how revocations reached the cache (event, crl, snapshot)."),
        timeseries(lay, "Revocation cache and CRL size", targets(("max(ironmesh_revocation_cache_entries)", "cache entries"), ("max(ironmesh_crl_revoked_serials)", "serials in CRL")), fill=0),
    ]
    return dashboard("ironmesh-pki", "IronMesh / PKI", ["pki"], p, "Certificate issuance, EST/OCSP/CRL traffic, revocation latency (10 s end-to-end budget) and attestation outcomes.")


def ota() -> dict:
    lay = Layout()
    ratio_thresh = thresholds((RED, None), (ORANGE, 0.9), (GREEN, 0.95))
    p = [
        gauge(lay, "Success ratio (10m)", "ironmesh:ota_success_ratio:10m", desc="Share of OTA results that are successes; stage gates halt a campaign above 5% failures.", thresh=ratio_thresh, decimals=2, w=6, h=6),
        gauge(lay, "Success ratio (1h)", "ironmesh:ota_success_ratio:1h", thresh=ratio_thresh, decimals=2, w=6, h=6),
        stat(lay, "Campaigns running", "sum(ironmesh_ota_campaigns{state=\"running\"})", w=4, h=3, graph="none"),
        stat(lay, "Campaigns halted", "sum(ironmesh_ota_campaigns{state=\"halted\"})", w=4, h=3, graph="none", thresh=thresholds((GREEN, None), (RED, 1))),
        stat(lay, "Rollbacks (24h)", "sum(increase(ironmesh_ota_result_total{result=\"rolled_back\"}[24h]))", w=4, h=3, graph="none", decimals=0, thresh=thresholds((GREEN, None), (ORANGE, 1), (RED, 10))),
        stat(lay, "Rejected (24h)", "sum(increase(ironmesh_ota_result_total{result=\"rejected\"}[24h]))", w=4, h=3, graph="none", decimals=0, thresh=thresholds((GREEN, None), (ORANGE, 1), (RED, 10)), desc="Images rejected by devices: bad signature, hash mismatch, anti-rollback or product mismatch."),
        stat(lay, "Failure ratio (10m)", "ironmesh:ota_failure_ratio:10m", w=4, h=3, unit="percentunit", decimals=2, graph="none", thresh=thresholds((GREEN, None), (ORANGE, 0.02), (RED, 0.05)), desc="OtaFailureRateHigh fires above 5% for 10 minutes."),
        stat(lay, "Results /min", "sum(rate(ironmesh_ota_result_total[10m])) * 60", w=4, h=3, unit="cpm", decimals=1, graph="none", desc="Volume of OtaStatus terminal results."),
        bargauge(lay, "Campaign progress", "ironmesh_ota_campaign_progress_ratio", legend="{{campaign}} ({{campaign_id}})", desc="Fraction of targeted devices in a terminal state per campaign.", thresh=thresholds((BLUE, None), (GREEN, 0.999))),
        bargauge(lay, "Campaign stage (% of fleet targeted)", "ironmesh_ota_campaign_stage_percent", legend="{{campaign}} ({{campaign_id}})", unit="percent", max_=100, desc="Current stage of the staged rollout (1% → 10% → 100% by default).", thresh=thresholds((BLUE, None), (GREEN, 100))),
        timeseries(lay, "OTA results by result", targets(("sum by (result) (rate(ironmesh_ota_result_total[5m]) * 60)", "{{result}}")), unit="cpm", stack=True, desc="success, failed, rolled_back, rejected (ironmesh_ota_result_total)."),
        timeseries(lay, "Devices by OTA state (active campaigns)", targets(("sum by (state) (ironmesh_ota_campaign_devices)", "{{state}}")), stack=True, fill=30, desc="OtaStatus states: received, downloading, verifying, applying, rebooting, success, rolled_back, rejected."),
        timeseries(lay, "Rollbacks and rejections", targets(("sum by (result) (rate(ironmesh_ota_result_total{result=~\"rolled_back|rejected|failed\"}[15m]) * 60)", "{{result}}")), unit="cpm", thresh=thresholds((GREEN, None), (RED, 1)), thresh_style="dashed"),
        timeseries(lay, "Firmware uploads and signings", targets(("sum(rate(ironmesh_ota_firmware_uploads_total[15m]) * 60)", "uploads /min"), ("sum by (algorithm) (rate(ironmesh_ota_signatures_total[15m]) * 60)", "signed {{algorithm}} /min")), unit="cpm", desc="Artifacts ingested and signed (Ed25519 always, ML-DSA-65 when enabled)."),
        table(lay, "Campaigns", "ironmesh_ota_campaign_progress_ratio", unit="percentunit", desc="Progress per campaign (instant).",
              organize={"excludeByName": {"Time": True, "__name__": True, "job": True, "instance": True}, "indexByName": {"campaign": 0, "campaign_id": 1, "Value": 2}, "renameByName": {"Value": "progress"}},
              thresh=thresholds((BLUE, None), (GREEN, 0.999))),
    ]
    return dashboard("ironmesh-ota", "IronMesh / OTA", ["ota"], p, "Campaign progress, staged rollout gates, success/failure ratios, rollbacks and rejections.")


def anomaly() -> dict:
    lay = Layout()
    p = [
        stat(lay, "Alerts /min (5m)", "sum(rate(ironmesh_anomaly_alerts_total[5m])) * 60", unit="cpm", decimals=1, desc="AnomalyRateSpike fires when this exceeds 3x the previous hour."),
        stat(lay, "Open alerts", "sum(ironmesh_anomaly_open_alerts)", thresh=thresholds((GREEN, None), (ORANGE, 10), (RED, 50))),
        stat(lay, "Critical open", "sum(ironmesh_anomaly_open_alerts{severity=\"critical\"})", thresh=thresholds((GREEN, None), (RED, 1))),
        stat(lay, "Quarantines (24h)", "sum(increase(ironmesh_anomaly_quarantines_total[24h]))", decimals=0, thresh=thresholds((GREEN, None), (ORANGE, 1), (RED, 20))),
        stat(lay, "Auto-quarantine", "max(ironmesh_anomaly_auto_quarantine_enabled)", graph="none", color_mode="background", text_mode="value",
             mappings=[{"type": "value", "options": {"0": {"text": "dry-run", "color": ORANGE, "index": 0}, "1": {"text": "ENABLED", "color": RED, "index": 1}}}],
             thresh=thresholds((ORANGE, None), (RED, 1)), desc="SECURITY.md: enable only after tuning rules in dry-run mode."),
        stat(lay, "Consumer lag (msgs)", "max(ironmesh_anomaly_consumer_lag_messages)", decimals=0, thresh=thresholds((GREEN, None), (ORANGE, 1000), (RED, 10000)), desc="Kafka lag of the anomaly consumer group on im.ingest / im.auth."),
        timeseries(lay, "Alerts by rule", targets(("sum by (rule) (rate(ironmesh_anomaly_alerts_total[5m]) * 60)", "{{rule}}")), unit="cpm", stack=True, desc="impossible_travel, auth_burst, topic_violation, fw_hash_mismatch, beaconing, isolation_forest."),
        piechart(lay, "Alert share by rule (24h)", "sum by (rule) (increase(ironmesh_anomaly_alerts_total[24h]))", legend="{{rule}}"),
        stat(lay, "Model score threshold", "max(ironmesh_anomaly_model_score_threshold)", decimals=3, graph="none", desc="Isolation Forest decision threshold (per device class, max shown)."),
        timeseries(lay, "Quarantines by rule", targets(("sum by (rule) (rate(ironmesh_anomaly_quarantines_total[5m]) * 60)", "{{rule}}")), unit="cpm", stack=True),
        heatmap(lay, "Isolation Forest score distribution", "sum by (le) (rate(ironmesh_anomaly_model_score_bucket[5m]))", unit="none", scheme="Purples", desc="Histogram of model scores (higher = more anomalous)."),
        timeseries(lay, "Model score percentiles", targets(
            ("histogram_quantile(0.50, sum by (le) (rate(ironmesh_anomaly_model_score_bucket[5m])))", "p50"),
            ("histogram_quantile(0.95, sum by (le) (rate(ironmesh_anomaly_model_score_bucket[5m])))", "p95"),
            ("histogram_quantile(0.99, sum by (le) (rate(ironmesh_anomaly_model_score_bucket[5m])))", "p99"),
            ("max(ironmesh_anomaly_model_score_threshold)", "threshold"),
        ), unit="none", decimals=3, min_=None, fill=0),
        timeseries(lay, "Open alerts by severity", targets(("sum by (severity) (ironmesh_anomaly_open_alerts)", "{{severity}}")), stack=True, fill=30),
        timeseries(lay, "Ingest processing", targets(("sum(rate(ironmesh_anomaly_messages_processed_total[5m]))", "processed /s"), ("max(ironmesh_anomaly_consumer_lag_messages)", "consumer lag")), unit="short", desc="Messages scored per second and consumer lag."),
    ]
    return dashboard("ironmesh-anomaly", "IronMesh / Anomaly", ["anomaly"], p, "Detection rules, quarantine actions, Isolation Forest scores and ingest health of the anomaly engine.")


def broker() -> dict:
    lay = Layout()
    p = [
        stat(lay, "Connections", "sum(emqx_connections_count)"),
        stat(lay, "Live connections", "sum(emqx_live_connections_count)"),
        stat(lay, "Sessions", "sum(emqx_sessions_count)"),
        stat(lay, "Subscriptions", "sum(emqx_subscriptions_count)"),
        stat(lay, "Retained messages", "sum(emqx_retained_count)", desc="Retained only on shadow/desired, ota/notify and config (ciphertext)."),
        stat(lay, "Cluster nodes running", "sum(emqx_cluster_nodes_running)", thresh=thresholds((RED, None), (ORANGE, 2), (GREEN, 3)), desc="Expected 3 in staging/prod."),
        timeseries(lay, "Connections per broker node", targets(("emqx_connections_count", "{{instance}}"))),
        timeseries(lay, "Connect / disconnect rate", targets(("sum(rate(emqx_client_connected[5m]))", "connected /s"), ("sum(rate(emqx_client_disconnected[5m]))", "disconnected /s"), ("sum(rate(emqx_packets_connack_auth_error[5m]))", "connack auth error /s")), unit="reqps"),
        timeseries(lay, "Messages", targets(("sum(rate(emqx_messages_received[5m]))", "received"), ("sum(rate(emqx_messages_sent[5m]))", "sent"), ("sum(rate(emqx_messages_dropped[5m]))", "dropped"), ("sum(rate(emqx_delivery_dropped[5m]))", "delivery dropped")), unit="mps", desc="BrokerMessagesDropped fires above 10 dropped/s for 10 minutes."),
        timeseries(lay, "Dropped by reason", targets(
            ("sum(rate(emqx_messages_dropped_expired[5m]))", "expired"),
            ("sum(rate(emqx_messages_dropped_no_subscribers[5m]))", "no subscribers"),
            ("sum(rate(emqx_messages_dropped_quota_exceeded[5m]))", "quota exceeded"),
            ("sum(rate(emqx_messages_dropped_receive_maximum[5m]))", "receive maximum"),
            ("sum(rate(emqx_delivery_dropped_queue_full[5m]))", "queue full"),
        ), unit="mps", stack=True),
        timeseries(lay, "Broker authn / authz", targets(
            ("sum(rate(emqx_authentication_success[5m]))", "authn success"),
            ("sum(rate(emqx_authentication_failure[5m]))", "authn failure"),
            ("sum(rate(emqx_authorization_allow[5m]))", "authz allow"),
            ("sum(rate(emqx_authorization_deny[5m]))", "authz deny"),
            ("sum(rate(emqx_authorization_cache_hit[5m]))", "authz cache hit"),
        ), unit="reqps", desc="EMQX-side counters; the HTTP authorizer is the policy service."),
        timeseries(lay, "Policy decisions", targets(
            ("sum by (result, kind) (rate(ironmesh_authn_decisions_total[5m]))", "authn {{result}} {{kind}}"),
            ("sum by (result, action) (rate(ironmesh_authz_decisions_total[5m]))", "authz {{result}} {{action}}"),
        ), unit="reqps", desc="Decisions returned by the policy service hooks (ironmesh_authn_decisions_total / ironmesh_authz_decisions_total)."),
        timeseries(lay, "Bridge throughput", targets(("sum(rate(ironmesh_bridge_messages_forwarded_total[5m]))", "forwarded /s"), ("sum by (topic) (rate(ironmesh_bridge_messages_forwarded_total[5m]))", "{{topic}}")), unit="mps", desc="MQTT → Kafka messages (ironmesh_bridge_messages_forwarded_total)."),
        timeseries(lay, "Bridge errors", targets(("sum by (reason) (rate(ironmesh_bridge_forward_errors_total[5m]))", "{{reason}}")), unit="reqps", stack=True, thresh=thresholds((GREEN, None), (RED, 0.1)), thresh_style="dashed", desc="BridgeForwardErrors fires above 0.1/s or 1% of forwarded."),
        timeseries(lay, "Bridge produce latency", targets(
            ("histogram_quantile(0.50, sum by (le) (rate(ironmesh_bridge_kafka_produce_latency_seconds_bucket[5m])))", "p50"),
            ("histogram_quantile(0.99, sum by (le) (rate(ironmesh_bridge_kafka_produce_latency_seconds_bucket[5m])))", "p99"),
        ), unit="s"),
        timeseries(lay, "Bytes in / out", targets(("sum(rate(emqx_bytes_received[5m]))", "in"), ("sum(rate(emqx_bytes_sent[5m]))", "out")), unit="Bps"),
        timeseries(lay, "Broker VM", targets(("avg(emqx_vm_cpu_use)", "cpu %"), ("sum(emqx_vm_used_memory)", "memory bytes")), unit="short", fill=0,
                   overrides=[{"matcher": {"id": "byName", "options": "memory bytes"}, "properties": [{"id": "unit", "value": "bytes"}, {"id": "custom.axisPlacement", "value": "right"}]}]),
        timeseries(lay, "Certificate expiry (broker listener)", targets(("min(emqx_cert_expiry_at) - time()", "seconds until expiry")), unit="s", thresh=thresholds((RED, None), (ORANGE, 604800), (GREEN, 2592000)), thresh_style="area", fill=0, desc="Services CA listener certificate (90 d); renewed by cert-manager 30 d before expiry."),
    ]
    return dashboard("ironmesh-broker", "IronMesh / Broker", ["broker", "emqx", "bridge"], p, "EMQX connections, sessions, message flow and drops, authn/authz decisions, and the MQTT → Kafka bridge.")


def slo() -> dict:
    lay = Layout()
    budget_thresh = thresholds((RED, None), (ORANGE, 0.2), (GREEN, 0.5))
    p = [
        row(lay, "30-day SLO attainment"),
        gauge(lay, "Broker availability (SLO 99.9%)", "avg_over_time(up{job=\"ironmesh-emqx\"}[30d])", thresh=thresholds((RED, None), (ORANGE, 0.995), (GREEN, 0.999)), min_=0.99, max_=1, decimals=4, desc="Scrape-based availability of the EMQX nodes."),
        gauge(lay, "Revocation ≤ 10 s (SLO 99%)", "sum(increase(ironmesh_revocation_latency_seconds_bucket{job=\"ironmesh-policy\",le=\"10\"}[30d])) / clamp_min(sum(increase(ironmesh_revocation_latency_seconds_count{job=\"ironmesh-policy\"}[30d])), 1e-9)", thresh=thresholds((RED, None), (ORANGE, 0.98), (GREEN, 0.99)), min_=0.9, max_=1, decimals=4, desc="Share of revocations applied to the broker within the 10 s contract budget."),
        gauge(lay, "OTA success (SLO 95%)", "sum(increase(ironmesh_ota_result_total{result=\"success\"}[30d])) / clamp_min(sum(increase(ironmesh_ota_result_total[30d])), 1e-9)", thresh=thresholds((RED, None), (ORANGE, 0.93), (GREEN, 0.95)), min_=0.8, max_=1, decimals=4),
        gauge(lay, "API availability (SLO 99.9%, worst job)", "min(1 - (sum by (job) (increase(ironmesh_http_requests_total{code=~\"5..\"}[30d])) / clamp_min(sum by (job) (increase(ironmesh_http_requests_total[30d])), 1e-9)))", thresh=thresholds((RED, None), (ORANGE, 0.995), (GREEN, 0.999)), min_=0.99, max_=1, decimals=4, desc="1 - 5xx ratio over 30 days, minimum across registry/ota/anomaly/policy/pki."),
        row(lay, "Error budget remaining (30 d)"),
        stat(lay, "Broker", "1 - ((1 - avg_over_time(up{job=\"ironmesh-emqx\"}[30d])) / (1 - 0.999))", unit="percentunit", decimals=1, thresh=budget_thresh, graph="none", w=6),
        stat(lay, "Revocation latency", "1 - ((1 - sum(increase(ironmesh_revocation_latency_seconds_bucket{job=\"ironmesh-policy\",le=\"10\"}[30d])) / clamp_min(sum(increase(ironmesh_revocation_latency_seconds_count{job=\"ironmesh-policy\"}[30d])), 1e-9)) / 0.01)", unit="percentunit", decimals=1, thresh=budget_thresh, graph="none", w=6),
        stat(lay, "OTA success", "1 - ((1 - sum(increase(ironmesh_ota_result_total{result=\"success\"}[30d])) / clamp_min(sum(increase(ironmesh_ota_result_total[30d])), 1e-9)) / 0.05)", unit="percentunit", decimals=1, thresh=budget_thresh, graph="none", w=6),
        stat(lay, "API (worst job)", "min(1 - ((sum by (job) (increase(ironmesh_http_requests_total{code=~\"5..\"}[30d])) / clamp_min(sum by (job) (increase(ironmesh_http_requests_total[30d])), 1e-9)) / 0.001))", unit="percentunit", decimals=1, thresh=budget_thresh, graph="none", w=6),
        row(lay, "Burn rates (multi-window, SLO 99.9% unless noted)"),
        timeseries(lay, "API burn rate – fast (1h / 5m)", targets(("ironmesh:http_error_ratio:1h / 0.001", "{{job}} 1h"), ("ironmesh:http_error_ratio:5m / 0.001", "{{job}} 5m")), unit="short", thresh=thresholds((GREEN, None), (RED, 14.4)), thresh_style="dashed", desc="ApiErrorBudgetBurnFast pages when both windows exceed 14.4x."),
        timeseries(lay, "API burn rate – slow (6h / 30m)", targets(("ironmesh:http_error_ratio:6h / 0.001", "{{job}} 6h"), ("ironmesh:http_error_ratio:30m / 0.001", "{{job}} 30m")), unit="short", thresh=thresholds((GREEN, None), (ORANGE, 6)), thresh_style="dashed", desc="ApiErrorBudgetBurnSlow tickets when both windows exceed 6x."),
        timeseries(lay, "Revocation latency burn rate (SLO 99% ≤ 10 s)", targets(("(1 - ironmesh:revocation_within_budget_ratio:30m) / 0.01", "30m window")), unit="short", thresh=thresholds((GREEN, None), (ORANGE, 6), (RED, 14.4)), thresh_style="dashed"),
        timeseries(lay, "OTA burn rate (SLO 95%)", targets(("ironmesh:ota_failure_ratio:10m / 0.05", "10m window")), unit="short", thresh=thresholds((GREEN, None), (ORANGE, 2), (RED, 10)), thresh_style="dashed"),
        row(lay, "SLIs"),
        timeseries(lay, "API 5xx ratio (5m)", targets(("ironmesh:http_error_ratio:5m", "{{job}}")), unit="percentunit", thresh=thresholds((GREEN, None), (RED, 0.001)), thresh_style="dashed", decimals=4),
        timeseries(lay, "API p99 latency (5m)", targets(("ironmesh:http_request_duration_seconds:p99_5m", "{{job}}")), unit="s", thresh=thresholds((GREEN, None), (ORANGE, 0.5), (RED, 1)), thresh_style="dashed"),
        timeseries(lay, "Broker up ratio (5m)", targets(("ironmesh:broker_up_ratio:5m", "up ratio")), unit="percentunit", min_=0, max_=1, fill=20),
        timeseries(lay, "Revocations within budget (30m)", targets(("ironmesh:revocation_within_budget_ratio:30m", "≤ 10 s")), unit="percentunit", min_=0.9, max_=1, fill=20, thresh=thresholds((RED, None), (GREEN, 0.99)), thresh_style="dashed"),
    ]
    return dashboard("ironmesh-slo", "IronMesh / SLOs", ["slo"], p, "Availability and latency SLOs with error budgets and multi-window burn rates (broker, API, revocation latency, OTA).", time_from="now-24h", refresh="1m")


DASHBOARDS = {
    "fleet-overview.json": fleet_overview,
    "pki.json": pki,
    "ota.json": ota,
    "anomaly.json": anomaly,
    "broker.json": broker,
    "slo.json": slo,
}


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, build in DASHBOARDS.items():
        doc = build()
        ids = [p["id"] for p in doc["panels"]]
        assert len(ids) == len(set(ids)), f"{name}: duplicate panel ids"
        path = OUT_DIR / name
        path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(OUT_DIR.parent.parent.parent)} ({len(doc['panels'])} panels)")


if __name__ == "__main__":
    main()
