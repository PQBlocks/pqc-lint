"""Regression tests for review defects (verdict must follow content, not names)."""

import json

from pqblocks_lint.cli import main
from pqblocks_lint.classifier import PRIMITIVE_MAP
from pqblocks_lint.serialize import build_cbom_dict

RSA_1024 = "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"


def _run(target, tmp_path):
    out = tmp_path / "o.json"
    return main(["--target", str(target), "--output", str(out), "--seed", "0"]), out


def test_production_file_named_mock_is_not_benign(tmp_path):
    f = tmp_path / "mock_payments.py"
    f.write_text(RSA_1024)
    code, out = _run(f, tmp_path)
    assert code == 1
    assert json.loads(out.read_text())["verdict"] == "NON_COMPLIANT_VULNERABLE"


def test_function_named_encap_is_not_ml_kem(tmp_path):
    f = tmp_path / "billing.py"
    f.write_text("def encapsulate_header(h):\n    return h\nhdr = encapsulate_header(b'x')\n" + RSA_1024)
    code, out = _run(f, tmp_path)
    assert code == 1
    assert "ML-KEM-768" not in [c["name"] for c in json.loads(out.read_text())["components"]]


def test_real_oqs_ml_kem_plus_classical_is_hybrid(hybrid_path, tmp_path):
    code, _ = _run(hybrid_path, tmp_path)
    assert code == 0


def test_unparsable_file_in_directory_scan_fails_with_exit_6(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n")
    code, _ = _run(tmp_path, tmp_path)
    assert code == 6


def test_cbom_oid_and_lines_are_not_constants():
    aes = PRIMITIVE_MAP["aes"]
    rsa = PRIMITIVE_MAP["rsa"]
    props = build_cbom_dict([aes, rsa])["components"]
    by = {c["name"].split("-")[0]: c["cryptoProperties"] for c in props}
    assert by["AES"]["oid"] == "2.16.840.1.101.3.4.1.46"
    assert by["RSA"]["detectionContext"]["sourceLine"] == 0  # not measured
