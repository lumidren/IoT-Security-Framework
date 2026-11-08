"""Vector generator and command-line interface."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from ironmesh_wire import __version__, cli, delta, vectors
from tests.helpers import KEYS_DIR

EXPECTED_FILES = {
    "cbor_canonical",
    "cose_sign1_es256",
    "cose_sign1_eddsa",
    "envelope_telemetry",
    "envelope_command_ack",
    "manifest_signed",
    "hpke_rfc9180_a3",
    "attestation_software",
    "replay_cases",
    "ids_topics",
    "delta_identical",
    "delta_small_change",
    "delta_insert_shift",
    "delta_partial_tail",
    "delta_empty_base",
    "delta_empty_target",
    "delta_both_empty",
    "delta_invalid",
}


def test_generate_all(tmp_path: Path, keys: vectors.TestKeys) -> None:
    written = vectors.generate_all(tmp_path / "out", keys)
    assert {p.stem for p in written} == EXPECTED_FILES
    for path in written:
        document = json.loads(path.read_text(encoding="utf-8"))
        assert document["schema_version"] == 1
        assert isinstance(document["description"], str)
        assert document["description"]
        assert document["generator"] == f"ironmesh_wire {__version__}"
    # deterministic files are byte-identical across runs
    again = vectors.generate_all(tmp_path / "out2", keys)
    for first, second in zip(written, again, strict=True):
        if first.stem in {
            "cbor_canonical",
            "cose_sign1_eddsa",
            "ids_topics",
            "hpke_rfc9180_a3",
        } or first.stem.startswith("delta_"):
            assert first.read_bytes() == second.read_bytes(), first.stem


def test_default_keys_dir() -> None:
    assert vectors.default_keys_dir() == KEYS_DIR.resolve()
    assert vectors.default_keys_dir().is_dir()


def test_cli_vectors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "vec"
    assert cli.main(["vectors", "--out", str(out), "--keys", str(KEYS_DIR)]) == 0
    captured = capsys.readouterr()
    assert "wrote 18 vector files" in captured.out
    assert len(list(out.glob("*.json"))) == 18
    assert cli.main(["vectors", "--out", str(tmp_path / "vec2")]) == 0  # default keys dir
    assert cli.main(["vectors", "--out", str(out), "--keys", str(tmp_path / "missing")]) == 2
    assert "not found" in capsys.readouterr().err


def test_cli_delta(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    old = tmp_path / "old.bin"
    new = tmp_path / "new.bin"
    patch = tmp_path / "patch.imdelta"
    out = tmp_path / "out.bin"
    old.write_bytes(bytes(range(256)) * 20)
    new.write_bytes(bytes(range(256)) * 16 + b"changed" + bytes(range(256)) * 4)
    assert cli.main(["delta", "make", str(old), str(new), str(patch)]) == 0
    assert "COPY ops" in capsys.readouterr().out
    assert patch.read_bytes() == delta.make_delta(old.read_bytes(), new.read_bytes())
    assert cli.main(["delta", "apply", str(old), str(patch), str(out)]) == 0
    assert out.read_bytes() == new.read_bytes()
    assert cli.main(["delta", "info", str(patch)]) == 0
    info = capsys.readouterr().out
    assert "block_size:    4096" in info
    assert f"target_size:   {new.stat().st_size}" in info
    # corrupted patch -> WireError -> exit 1
    bad = tmp_path / "bad.imdelta"
    bad.write_bytes(b"IMDELTA2" + patch.read_bytes()[8:])
    assert cli.main(["delta", "apply", str(old), str(bad), str(out)]) == 1
    assert "DELTA_MAGIC" in capsys.readouterr().err
    # missing input -> OSError -> exit 1
    assert cli.main(["delta", "make", str(tmp_path / "nope"), str(new), str(patch)]) == 1
    assert "error" in capsys.readouterr().err


def test_cli_argparse_behaviour() -> None:
    with pytest.raises(SystemExit) as info:
        cli.main(["--version"])
    assert info.value.code == 0
    with pytest.raises(SystemExit) as info:
        cli.main([])
    assert info.value.code == 2


def test_module_entry_point() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "ironmesh_wire", "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0
    assert __version__ in result.stdout


def test_expect_error_helper_is_strict() -> None:
    from ironmesh_wire.errors import WireError

    def raise_a() -> None:
        raise WireError("A")

    assert vectors._expect_error(raise_a, "A") == "A"
    with pytest.raises(AssertionError, match="expected B, got A"):
        vectors._expect_error(raise_a, "B")
    with pytest.raises(AssertionError, match="succeeded"):
        vectors._expect_error(lambda: None, "A")
