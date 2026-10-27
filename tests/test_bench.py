"""Tests for pqblocks-lint benchmark-harness."""

import json
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pqblocks_lint.bench import run_benchmarks, BenchmarkResult

SUITE_DIR = Path(__file__).parent / "test-instances"

class TestBenchmarkHarness:
    def test_run_benchmarks_returns_structure(self):
        card = run_benchmarks(str(SUITE_DIR), seed=42)
        assert isinstance(card, dict)
        assert "baselines" in card
        assert "instances" in card
        assert "summary" in card
        assert "ks_tests" in card
        assert card["summary"]["total_instances"] == 5
        assert card["summary"]["seed"] == 42

    def test_benchmark_result_dataclass(self):
        fields = getattr(BenchmarkResult, "__dataclass_fields__", {})
        for f in ("algorithm", "instance_id", "wall_time_ns", "solution_quality", "optimal_energy", "tts_target", "tts_wall_ns"):
            assert f in fields, f"missing field {f}"

    def test_run_benchmarks_on_small_suite(self):
        card = run_benchmarks(str(SUITE_DIR), seed=123, timeout_per_instance=10)
        assert isinstance(card, dict)
        assert len(card["baselines"]) >= 3
        # at least dwave-neal and cp-sat present
        assert "dwave-neal" in card["baselines"]
        assert "cp-sat" in card["baselines"]

    def test_benchmark_result_contains_tto_and_gap(self):
        card = run_benchmarks(str(SUITE_DIR), seed=42, timeout_per_instance=5)
        for baseline, agg in card["baselines"].items():
            if agg.get("unavailable"):
                continue
            assert "tto_ns" in agg or "wall_time_ns" in agg
            assert "optimality_gap" in agg

    def test_benchmark_respects_timeout(self):
        card = run_benchmarks(str(SUITE_DIR), seed=1, timeout_per_instance=1)
        assert isinstance(card, dict)
        assert card["summary"]["total_instances"] == 5

    def test_benchmark_output_file_written(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "bench.json"
            card = run_benchmarks(str(SUITE_DIR), seed=42, output_path=str(out_path), timeout_per_instance=5)
            assert out_path.exists()
            data = json.loads(out_path.read_text())
            assert isinstance(data, dict)
            assert "baselines" in data
