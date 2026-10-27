"""Test-suite runner and verifier for pqblocks-lint."""

import datetime
import hashlib
import json
from pathlib import Path
from typing import Any


def _ts(seed: int) -> str:
    base = datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
    dt = base + datetime.timedelta(seconds=int(seed) % 86400)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_sha(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def run_instance(instance_path: str | Path, seed: int = 0) -> dict[str, Any]:
    from pqblocks_lint.classifier import classify
    from pqblocks_lint.graph import build_cfg_cg, get_source_nodes
    from pqblocks_lint.serialize import build_cbom_dict
    from pqblocks_lint.taint import propagate_taint

    path = str(instance_path)
    try:
        graph = build_cfg_cg(path)
        tainted = propagate_taint(graph, set(get_source_nodes(graph)))
        assets = classify(graph, tainted)
        first = build_cbom_dict(assets, target=Path(path).name, seed=seed, test_code=graph.graph["test_code"])
        second = build_cbom_dict(assets, target=Path(path).name, seed=seed, test_code=graph.graph["test_code"])
        sha = _canonical_sha(first)
        return {
            "id": Path(path).stem,
            "path": path,
            "verdict": first.get("verdict", "UNKNOWN"),
            "primitives": sorted({a.algorithm for a in assets}),
            "num_assets": len(assets),
            "cbom_sha256": sha,
            "deterministic": sha == _canonical_sha(second),
            "error": None,
        }
    except (FileNotFoundError, SyntaxError, ValueError) as exc:
        return {
            "id": Path(path).stem,
            "path": path,
            "verdict": "ERROR",
            "primitives": [],
            "num_assets": 0,
            "cbom_sha256": "",
            "deterministic": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def run_all_instances(
    suite_path: str | Path,
    seed: int = 0,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    suite = Path(suite_path)
    manifest = suite / "instances.json" if suite.is_dir() else suite
    if not manifest.is_file():
        raise FileNotFoundError(f"suite manifest not found: {manifest}")
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    entries = spec.get("instances", [])

    instances: list[dict[str, Any]] = []
    for entry in entries:
        result = run_instance(str(manifest.parent / entry["path"]), seed=seed)
        result["id"] = entry.get("id", result["id"])
        result["expected_verdict"] = entry.get("ground_truth_verdict", "UNKNOWN")
        result["match"] = result["error"] is None and result["verdict"] == result["expected_verdict"]
        instances.append(result)

    passed = sum(1 for i in instances if i["match"])
    payload: dict[str, Any] = {
        "seed": seed,
        "suite": str(manifest.parent),
        "timestamp": _ts(seed),
        "total": len(instances),
        "passed": passed,
        "failed": len(instances) - passed,
        "deterministic_all": all(i["deterministic"] for i in instances) if instances else True,
        "instances": sorted(instances, key=lambda i: i["id"]),
    }
    if output_path is not None:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(payload, sort_keys=True, indent=2)
        out.write_text(text + "\n", encoding="utf-8")
        payload["output_path"] = str(out)
    return payload
