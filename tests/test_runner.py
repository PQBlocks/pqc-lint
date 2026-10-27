"""Tests for pqblocks-lint test-suite runner and verifier.

Contract: results = run_all_instances(suite_path) -> runs each instance
through graph+taint+classify+serialize, records pass/fail vs ground truth,
verifies same-seed determinism.
"""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

from pqblocks_lint.runner import run_all_instances, run_instance

SUITE_DIR = Path(__file__).parent / "test-instances"


class TestRunInstance:
    def test_run_instance_rsa_returns_result_structure(self):
        r = run_instance(str(SUITE_DIR / "instance_01_classical_rsa.py"), seed=42)
        for key in ("id", "path", "verdict", "primitives", "num_assets",
                    "cbom_sha256", "deterministic", "error"):
            assert key in r, f"missing key {key}"
        assert r["error"] is None
        assert r["num_assets"] >= 1

    def test_run_instance_empty_file_no_crypto(self, tmp_path):
        p = tmp_path / "empty.py"
        p.write_text("", encoding="utf-8")
        r = run_instance(str(p), seed=0)
        assert r["verdict"] == "NO_CRYPTO_DETECTED"
        assert r["num_assets"] == 0
        assert r["error"] is None

    def test_run_instance_mock_fixture_runs_without_crash(self):
        r = run_instance(str(SUITE_DIR / "instance_05_mock_test_vector.py"), seed=0)
        assert r["error"] is None
        assert "verdict" in r

    def test_run_instance_missing_file_records_error(self, tmp_path):
        r = run_instance(str(tmp_path / "nope.py"), seed=0)
        assert r["error"] is not None
        assert r["verdict"] == "ERROR"

    def test_run_instance_deterministic_same_seed(self):
        a = run_instance(str(SUITE_DIR / "instance_01_classical_rsa.py"), seed=7)
        b = run_instance(str(SUITE_DIR / "instance_01_classical_rsa.py"), seed=7)
        assert a["deterministic"] is True
        assert a["cbom_sha256"] == b["cbom_sha256"]


class TestRunAllInstances:
    def test_runs_all_five_instances(self):
        results = run_all_instances(str(SUITE_DIR), seed=42)
        assert results["total"] == 5
        assert len(results["instances"]) == 5
        assert results["passed"] + results["failed"] == 5

    def test_suite_result_structure(self):
        results = run_all_instances(str(SUITE_DIR), seed=42)
        for key in ("seed", "suite", "timestamp", "instances",
                    "passed", "failed", "total", "deterministic_all"):
            assert key in results, f"missing key {key}"
        assert results["seed"] == 42
        assert results["timestamp"].endswith("Z")

    def test_each_instance_has_expected_verdict(self):
        results = run_all_instances(str(SUITE_DIR), seed=42)
        for inst in results["instances"]:
            assert "expected_verdict" in inst
            assert "match" in inst
            assert isinstance(inst["match"], bool)

    def test_suite_determinism_same_seed(self):
        a = run_all_instances(str(SUITE_DIR), seed=99)
        b = run_all_instances(str(SUITE_DIR), seed=99)
        assert a["deterministic_all"] is True
        sha_a = [i["cbom_sha256"] for i in a["instances"]]
        sha_b = [i["cbom_sha256"] for i in b["instances"]]
        assert sha_a == sha_b

    def test_writes_output_file_sorted_keys(self, tmp_path):
        p = tmp_path / "instance-results.json"
        ret = run_all_instances(str(SUITE_DIR), seed=1, output_path=str(p))
        assert Path(ret["output_path"]).exists()
        raw = p.read_text(encoding="utf-8")
        data = json.loads(raw)
        assert raw.strip() == json.dumps(data, sort_keys=True, indent=2).strip()

    def test_invalid_suite_path_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            run_all_instances(str(tmp_path / "no-such-dir"), seed=0)

    def test_suite_without_instances_json_raises(self, tmp_path):
        (tmp_path / "lonely.py").write_text("x = 1\n", encoding="utf-8")
        with pytest.raises(FileNotFoundError):
            run_all_instances(str(tmp_path), seed=0)


class TestBenignVerdictRegression:
    def test_mock_fixture_verdict_is_benign(self):
        r = run_instance(str(SUITE_DIR / "instance_05_mock_test_vector.py"), seed=42)
        assert r["error"] is None
        assert r["verdict"] == "BENIGN_TEST_CODE"
