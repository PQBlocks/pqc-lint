# Testing: pqblocks-lint

This document details test structure, coverage, execution procedures, and reproduction instructions for `pqblocks-lint`.

## Test environment

- **Runner:** `pytest` 9.1.1 with `pytest-cov` 7.1.0 and `hypothesis` 6.168.0
- **Supported Python runtimes:** 3.11, 3.12, 3.13, 3.14
- **Dependencies under test:** `networkx`, `numpy`, `scipy`, `ortools`, `dwave-neal`, `openjij`

---

## Running the test suite

### Standard execution

```bash
cd packages/pqblocks-lint
PYTHONPATH=src pytest -q
```

### With coverage report

```bash
cd packages/pqblocks-lint
PYTHONPATH=src pytest --cov=pqblocks_lint
```

---

## Test suite architecture

The test suite consists of **188 automated tests** across 9 active test modules and 1 placeholder module:

| Module | Test Count | Scope |
|---|---|---|
| `tests/test_bench.py` | 6 | QUBO solver benchmark harness (`pqblocks_lint.bench`), execution limits, result structure |
| `tests/test_classifier.py` | 34 | Primitive classification (`classify`), compliance mapping (`classify_compliance`), FIPS parameter mappings, immutability, edge cases |
| `tests/test_cli.py` | 40 | CLI argument parsing, valid/invalid inputs, exit codes (0, 1, 2, 3, 4, 5), format selection (CBOM / SARIF), directory walk |
| `tests/test_graph.py` | 30 | AST parsing via `ast.parse`, CFG/CG node and edge generation, taint source/sink tagging, circular reference handling |
| `tests/test_regressions.py` | 5 | Review defects: name-independent verdicts, ML-KEM only from real APIs, scan errors (exit 6), CBOM OIDs and lines |
| `tests/test_runner.py` | 13 | End-to-end execution of golden test suites, determinism verification across identical seeds, ground truth comparison |
| `tests/test_serialize.py` | 21 | CycloneDX 1.6 CBOM and SARIF 2.1.0 serialization, deterministic output, sorted keys, ISO-8601 timestamps |
| `tests/test_taint.py` | 38 | Forward taint propagation, interprocedural taint propagation, call graphs, diamond topologies, tainted source extraction |
| `tests/test_placeholder.py` | 1 | Suite sanity check |
| **Total** | **188** | **All passing** |

---

## Statement coverage breakdown

Measured on Python 3.14.8 with `pytest-cov`:

| Module | Statements | Missed | Coverage |
|---|---|---|---|
| `src/pqblocks_lint/__init__.py` | 2 | 0 | 100% |
| `src/pqblocks_lint/bench/__init__.py` | 157 | 14 | 91% |
| `src/pqblocks_lint/classifier.py` | 112 | 8 | 93% |
| `src/pqblocks_lint/cli.py` | 142 | 3 | 98% |
| `src/pqblocks_lint/graph.py` | 244 | 34 | 86% |
| `src/pqblocks_lint/runner.py` | 50 | 0 | 100% |
| `src/pqblocks_lint/serialize.py` | 128 | 3 | 98% |
| `src/pqblocks_lint/taint.py` | 72 | 10 | 86% |
| **Total** | **907** | **72** | **92%** |

---

## Example programs execution

Three standalone example scripts in `examples/` demonstrate standard workflows and run cleanly against installed wheels or `PYTHONPATH=src`:

```bash
# 1. Single file scan and exit-code inspection
PYTHONPATH=src python3 examples/scan_file.py

# 2. SARIF 2.1.0 generation and rule ID verification
PYTHONPATH=src python3 examples/sarif_report.py

# 3. Direct library API usage (graph, taint, classify)
PYTHONPATH=src python3 examples/library_pipeline.py
```
