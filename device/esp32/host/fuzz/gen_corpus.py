"""Regenerate the committed seed corpora in host/fuzz/corpus/<target>/ from device/common/vectors.

Usage (from device/esp32/host/fuzz):  python gen_corpus.py
Only reads the JSON vectors; file names are the SHA-1 of the content (libFuzzer convention).
"""

import hashlib
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
VEC = HERE.parents[2] / "common" / "vectors"
OUT = HERE / "corpus"


def load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))


def put(target, data):
    d = OUT / target
    d.mkdir(parents=True, exist_ok=True)
    # Content-addressed file name, as libFuzzer names corpus entries; not a security use.
    (d / hashlib.sha1(data, usedforsecurity=False).hexdigest()).write_bytes(data)


def hx(s):
    return bytes.fromhex(s)


def walk_hex(obj):
    """Every *_hex string in a JSON document."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and (k.endswith("_hex") or k == "hex") and len(v) % 2 == 0:
                try:
                    yield bytes.fromhex(v)
                except ValueError:
                    pass
            else:
                yield from walk_hex(v)
    elif isinstance(obj, list):
        for x in obj:
            yield from walk_hex(x)


def main():
    cbor = load("cbor_canonical.json")
    for c in cbor["valid"] + cbor["invalid"]:
        if len(c["hex"]) < 4096:
            put("cbor_decode", hx(c["hex"]))
    for f in ["cose_sign1_es256.json", "cose_sign1_eddsa.json", "envelope_telemetry.json",
              "envelope_command_ack.json", "manifest_signed.json", "attestation_software.json",
              "replay_cases.json", "hpke_rfc9180_a3.json"]:
        doc = load(f)
        for b in walk_hex(doc):
            if 0 < len(b) <= 16384 and b[0] in (0xD0, 0xD2, 0xD8, 0xA1, 0xA4, 0xA5, 0xA9):
                put("cbor_decode", b)
                put("cose_decode", b)
                put("envelope_decode", b)
                if f == "manifest_signed.json":
                    put("manifest_decode", b)
    m = load("manifest_signed.json")
    put("manifest_decode", hx(m["manifest_hex"]))
    for f in sorted(VEC.glob("delta_*.json")):
        doc = json.loads(f.read_text(encoding="utf-8"))
        patches = [doc["patch_hex"]] if "patch_hex" in doc else []
        patches += [c["patch_hex"] for c in doc.get("cases", [])]
        if "valid_patch_hex" in doc:
            patches.append(doc["valid_patch_hex"])
        for p in patches:
            b = hx(p)
            if len(b) <= 20000:
                put("delta_apply", bytes([0x80]) + b)
                put("delta_apply", bytes([0x05]) + b)
    mqtt = [
        "20030100000",  # placeholder replaced below
    ]
    mqtt = [
        "2003000000", "200801000005210020", "40020001", "4003000187", "900400010001",
        "c000", "d000", "e00100", "e0028e00",
        "3011000b696d2f76312f612f622f6300016869",
        "321300076369642f726571000700" + "6869",
        "3218000b696d2f76312f612f622f63000005260001610001626869",
        "820e00010000096161612f6262622f6301",
    ]
    for p in mqtt:
        try:
            put("mqtt_decode", hx(p))
        except ValueError:
            pass
    for line in [
        '{"id":1,"op":"hello"}',
        '{"id":2,"op":"status","args":{}}',
        '{"id":3,"op":"send_telemetry","args":{"count":5}}',
        '{"id":4,"op":"publish_raw","args":{"topic":"im/v1/x/dev-0/telemetry","payload_b64":"aGVsbG8=","qos":1,"retain":false}}',
        '{"id":5,"op":"rejections","args":{"since_ms":0}}',
        '{"id":6,"op":"set_clock","args":{"unix_s":1767225600}}',
        '{"id":7,"op":"subscribe_raw","args":{"topic":"im/v1/+/#"}}',
        '{"s":"\\u00e9\\ud83d\\ude00\\n","a":[1,-2.5e3,true,null,{"b":[]}]}',
    ]:
        put("dut_json", line.encode())


if __name__ == "__main__":
    main()
