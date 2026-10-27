"""Tests for pqblocks-lint CBOM and SARIF serializer.

Contract: output_files = emit_outputs(assets, format) -> CycloneDX 1.6 JSON or SARIF 2.1.0
with sorted keys, normalized timestamps.

Covers: format selection, CBOM validity, SARIF validity, determinism, edge cases.
"""
import json
import hashlib
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from pqblocks_lint.classifier import FIPSParams
from pqblocks_lint.serialize import emit_cbom, emit_sarif, emit_outputs, build_cbom_dict, build_sarif_dict


def _sample_rsa_params():
    return FIPSParams(algorithm="RSA", fips_id="FIPS 186-5", nist_level=0, key_size_bits=2048, quantum_safe=False, compliance="Non-compliant (CNSA 2.0 / OMB M-23-02)", family="asymmetric")

def _sample_mlkem_params():
    return FIPSParams(algorithm="ML-KEM", fips_id="FIPS 203", nist_level=3, key_size_bits=768, quantum_safe=True, compliance="Compliant (CNSA 2.0 / OMB M-23-02)", family="asymmetric")

def _sample_aes_params():
    return FIPSParams(algorithm="AES", fips_id="FIPS 197", nist_level=3, key_size_bits=256, quantum_safe=True, compliance="Compliant", family="symmetric")


class TestCBOMSerializer:
    def test_cbom_has_required_top_level_fields(self):
        d = build_cbom_dict([_sample_rsa_params()], target="instance_01_classical_rsa.py", seed=42)
        assert d["bomFormat"] == "CycloneDX"
        assert d["specVersion"] == "1.6"
        assert "serialNumber" in d
        assert "metadata" in d
        assert "components" in d
        assert d["metadata"]["timestamp"]
        assert d["metadata"]["tools"][0]["name"] == "pqblocks_lint"

    def test_cbom_component_contains_crypto_asset_fields(self):
        d = build_cbom_dict([_sample_rsa_params()], target="instance_01_classical_rsa.py", seed=1)
        comp = d["components"][0]
        assert comp["type"] == "cryptographic-asset"
        assert "cryptoProperties" in comp
        cp = comp["cryptoProperties"]
        assert "algorithmProperties" in cp
        ap = cp["algorithmProperties"]
        assert "parameterSetIdentifier" in ap
        assert "nistQuantumSecurityLevel" in ap
        assert ap["nistQuantumSecurityLevel"] == 0
        assert "detectionContext" in cp
        assert "shorVulnerable" in cp["detectionContext"]
        assert cp["detectionContext"]["shorVulnerable"] is True
        assert "cnsa20Compliant" in cp["detectionContext"]

    def test_cbom_shor_vulnerable_and_cnsa_flags(self):
        d_rsa = build_cbom_dict([_sample_rsa_params()], seed=0)
        assert d_rsa["components"][0]["cryptoProperties"]["detectionContext"]["shorVulnerable"] is True
        assert d_rsa["components"][0]["cryptoProperties"]["detectionContext"]["cnsa20Compliant"] is False
        d_pqc = build_cbom_dict([_sample_mlkem_params()], seed=0)
        assert d_pqc["components"][0]["cryptoProperties"]["detectionContext"]["shorVulnerable"] is False
        assert d_pqc["components"][0]["cryptoProperties"]["detectionContext"]["cnsa20Compliant"] is True

    def test_cbom_sorted_keys_and_normalized_timestamp(self, tmp_path):
        p = tmp_path / "cbom.json"
        emit_cbom([_sample_rsa_params()], str(p), target="x.py", seed=7)
        raw = p.read_text(encoding="utf-8")
        data = json.loads(raw)
        # sorted keys: raw should equal json.dumps(data, sort_keys=True, indent=2)
        expected = json.dumps(data, sort_keys=True, indent=2)
        assert raw.strip() == expected.strip()
        # timestamp is ISO-8601 and ends with Z
        ts = data["metadata"]["timestamp"]
        assert ts.endswith("Z")
        assert "T" in ts

    def test_cbom_determinism_same_seed_same_sha(self, tmp_path):
        p1 = tmp_path / "a.json"
        p2 = tmp_path / "b.json"
        assets = [_sample_rsa_params(), _sample_mlkem_params()]
        emit_cbom(assets, str(p1), target="x.py", seed=123)
        emit_cbom(assets, str(p2), target="x.py", seed=123)
        assert hashlib.sha256(p1.read_bytes()).hexdigest() == hashlib.sha256(p2.read_bytes()).hexdigest()

    def test_cbom_different_seed_different_serial(self):
        d1 = build_cbom_dict([_sample_rsa_params()], seed=1)
        d2 = build_cbom_dict([_sample_rsa_params()], seed=2)
        assert d1["serialNumber"] != d2["serialNumber"]

    def test_cbom_empty_assets_no_crypto(self):
        d = build_cbom_dict([], target="empty.py", seed=0)
        assert d["components"] == []
        # still valid CycloneDX structure
        assert d["bomFormat"] == "CycloneDX"

    def test_cbom_hybrid_emits_multiple_assets(self):
        d = build_cbom_dict([_sample_rsa_params(), _sample_mlkem_params(), _sample_aes_params()], seed=0)
        assert len(d["components"]) == 3
        names = {c["name"] for c in d["components"]}
        assert any("RSA" in n for n in names)
        assert any("ML-KEM" in n for n in names)


class TestSARIFSerializer:
    def test_sarif_has_required_fields(self):
        d = build_sarif_dict([_sample_rsa_params()], target="x.py", seed=0)
        assert d["version"] == "2.1.0"
        assert "$schema" in d
        assert "runs" in d
        assert len(d["runs"]) == 1
        run = d["runs"][0]
        assert "tool" in run and "results" in run
        assert run["tool"]["driver"]["name"] == "pqblocks_lint"

    def test_sarif_ruleId_and_level(self):
        d = build_sarif_dict([_sample_rsa_params()], seed=0)
        run = d["runs"][0]
        # rules contain entry per asset
        rules = run["tool"]["driver"]["rules"]
        assert any("RSA" in r["id"] for r in rules)
        # level for level 0 should be error
        result = run["results"][0]
        assert "ruleId" in result
        assert "level" in result
        assert result["level"] == "error"
        # PQC level 3 => note or none
        d2 = build_sarif_dict([_sample_mlkem_params()], seed=0)
        lvl = d2["runs"][0]["results"][0]["level"]
        assert lvl in ("note", "none")

    def test_sarif_sorted_keys(self, tmp_path):
        p = tmp_path / "out.sarif"
        emit_sarif([_sample_rsa_params()], str(p), target="x.py", seed=5)
        raw = p.read_text(encoding="utf-8")
        data = json.loads(raw)
        expected = json.dumps(data, sort_keys=True, indent=2)
        assert raw.strip() == expected.strip()

    def test_sarif_determinism(self, tmp_path):
        p1 = tmp_path / "a.sarif"
        p2 = tmp_path / "b.sarif"
        emit_sarif([_sample_rsa_params()], str(p1), seed=99)
        emit_sarif([_sample_rsa_params()], str(p2), seed=99)
        assert hashlib.sha256(p1.read_bytes()).hexdigest() == hashlib.sha256(p2.read_bytes()).hexdigest()

    def test_sarif_empty_assets(self):
        d = build_sarif_dict([], seed=0)
        assert d["runs"][0]["results"] == []
        assert d["runs"][0]["tool"]["driver"]["rules"] == []


class TestEmitOutputsDispatch:
    def test_emit_outputs_cbom(self, tmp_path):
        p = tmp_path / "out.json"
        ret = emit_outputs([_sample_rsa_params()], fmt="cbom", output_path=str(p), target="x.py", seed=42)
        assert Path(ret).exists()
        data = json.loads(Path(ret).read_text())
        assert data["bomFormat"] == "CycloneDX"

    def test_emit_outputs_sarif(self, tmp_path):
        p = tmp_path / "out.sarif"
        ret = emit_outputs([_sample_rsa_params()], fmt="sarif", output_path=str(p), target="x.py", seed=42)
        assert Path(ret).exists()
        data = json.loads(Path(ret).read_text())
        assert data["version"] == "2.1.0"

    def test_emit_outputs_invalid_format_raises(self, tmp_path):
        p = tmp_path / "out.json"
        with pytest.raises(ValueError):
            emit_outputs([], fmt="xml", output_path=str(p))

    def test_emit_outputs_creates_parent_dirs(self, tmp_path):
        p = tmp_path / "a" / "b" / "out.json"
        emit_outputs([], fmt="cbom", output_path=str(p), seed=0)
        assert p.exists()

    def test_format_case_insensitive(self, tmp_path):
        p = tmp_path / "out.json"
        emit_outputs([], fmt="CBOM", output_path=str(p), seed=0)
        assert p.exists()


class TestEdgeCasesSerializer:
    def test_non_fips_params_dict_input(self, tmp_path):
        # allow dict assets for flexibility
        d = build_cbom_dict([{"algorithm": "Custom", "nist_level": 0, "key_size_bits": 1024, "quantum_safe": False}], seed=0)
        assert len(d["components"]) == 1

    def test_large_asset_list(self):
        assets = [_sample_rsa_params() for _ in range(100)]
        d = build_cbom_dict(assets, seed=0)
        # deduplication? classifier dedupes; serializer should emit per input (but test ensures no crash and at least 1)
        assert len(d["components"]) >= 1

    def test_timestamp_iso8601_parseable(self):
        import datetime
        d = build_cbom_dict([_sample_rsa_params()], seed=0)
        ts = d["metadata"]["timestamp"]
        # should be parseable as ISO8601
        dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert dt.tzinfo is not None
