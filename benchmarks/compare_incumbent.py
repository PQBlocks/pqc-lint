"""Head-to-head detection check: pqblocks-lint against a third-party incumbent scanner.

Each corpus file is scanned on its own. "Flagged" means:
- pqblocks-lint: the CLI exits with 1 (NON_COMPLIANT_VULNERABLE);
- incumbent: at least one finding with quantum_risk == "VULNERABLE" in its JSON output.

Usage:
    python compare.py --corpus benchmarks/corpus --python <python with pqblocks-lint installed> \
        --incumbent-venv <venv with the incumbent installed> --output benchmarks/incumbent-comparison.json
"""
import argparse
import json
import os
import shutil
import subprocess
import tempfile


def ours(python, path):
    out = os.path.join(tempfile.mkdtemp(), "cbom.json")
    rc = subprocess.run([python, "-m", "pqblocks_lint.cli", "--target", path, "--format", "cbom",
                         "--output", out, "--seed", "0"], capture_output=True).returncode
    cbom = json.load(open(out)) if os.path.exists(out) else {}
    return {"exit_code": rc, "verdict": cbom.get("verdict"), "flagged": rc == 1,
            "assets": sorted(c["name"] for c in cbom.get("components", []))}


def incumbent(venv, path):
    exe = os.path.join(venv, "bin", "qproof")  # qproof 0.4.0 CLI
    d = tempfile.mkdtemp()
    shutil.copy(path, d)
    report = json.loads(subprocess.run([exe, "scan", "--format", "json", d], capture_output=True, text=True).stdout)
    vuln = sorted({f["algorithm_id"] for f in report["findings"] if f["quantum_risk"] == "VULNERABLE"})
    return {"flagged": bool(vuln), "vulnerable_algorithms": vuln, "findings": len(report["findings"])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--python", required=True)
    ap.add_argument("--incumbent-venv", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    labels = json.load(open(os.path.join(a.corpus, "labels.json")))
    rows = []
    for rel, lab in sorted(labels["files"].items()):
        path = os.path.join(a.corpus, rel)
        o, i = ours(a.python, path), incumbent(a.incumbent_venv, path)
        rows.append({"file": rel, "expected_flagged": lab["flagged"], "note": lab["note"],
                     "pqblocks_lint": o, "incumbent": i,
                     "pqblocks_lint_correct": o["flagged"] == lab["flagged"],
                     "incumbent_correct": i["flagged"] == lab["flagged"]})
    summary = {"files": len(rows),
               "pqblocks_lint_correct": sum(r["pqblocks_lint_correct"] for r in rows),
               "incumbent_correct": sum(r["incumbent_correct"] for r in rows)}
    json.dump({"incumbent": labels["incumbent"], "summary": summary, "rows": rows},
              open(a.output, "w"), indent=1, sort_keys=True)
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
