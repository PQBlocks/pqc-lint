# Verification report: pqblocks-lint 0.1.0

This is an internal self-verification report detailing testing, build packaging, benchmark results, and security review disclosures for `pqblocks-lint` 0.1.0. This is not an external audit or third-party validation.

## Summary

| Area | Result |
|---|---|
| Correctness | 188 / 188 automated tests pass across Python 3.11, 3.12, 3.13, 3.14 |
| Coverage | 92% statement coverage (907 statements, 72 missed) |
| Installation | Clean wheel installation with dependencies on Python 3.11, 3.12, 3.13, 3.14 |
| Examples | All 3 standalone example scripts pass cleanly across Python 3.11, 3.12, 3.13, 3.14 |
| Packaging | Source distribution and wheel build cleanly; `twine check --strict` passes |
| Output formats | CycloneDX 1.6 CBOM and OASIS SARIF 2.1.0 |
| Accuracy | 15 / 16 correct on test corpus after the fixes (was 12 / 16); the miss is documented in [BENCHMARKS.md](BENCHMARKS.md) |
| Review disclosures | Two HIGH findings and the silent-skip finding are fixed (test-first); remaining MEDIUM/LOW findings disclosed in [SECURITY_NOTES.md](SECURITY_NOTES.md) |

---

## Review checks completed

| Check | Purpose | Result |
|---|---|---|
| Check 1 (design review) | Scope, sources, and regulatory mandates identified | Pass |
| Check 2 (spec review) | Data models, CFG/CG node structures, and serialization formats defined | Pass |
| Check 3 (correctness) | Test suite (188 tests), golden test fixtures, 92% coverage | Pass |
| Check 4 (benchmark review) | Single-file latency, LOC scaling from 38 to 608 lines, 16-file accuracy corpus | Pass |
| Check 5 (adversarial review) | Hostile inputs, circular graphs, AST depth limits, determinism verification | Pass |
| Release check | Wheel build, clean venv installation, 4 Python versions, 0 leak hits | Pass |

---

## Verification test evidence

```
build sdist+wheel                  PASS  Successfully built dist/pqblocks_lint-0.1.0-py3-none-any.whl
twine check --strict               PASS  Checking dist/*: PASSED
python 3.11: tests                 PASS  188 passed
python 3.12: tests                 PASS  188 passed
python 3.13: tests                 PASS  188 passed
python 3.14: tests                 PASS  188 passed
examples (scan_file, sarif_report, library_pipeline) PASS on all four versions
leak gate (folder + wheel + sdist) PASS  0 leak hits
```

---

## Defects found and review disclosures

During preparation of this release, early drafts containing misleading claims ("Ising/QUBO dynamics in static analysis", "verified against NIST FIPS") were removed. The tool is a purely classical static AST analyzer and heuristic detector.

The read-only security review identified the following findings, documented in [SECURITY_NOTES.md](SECURITY_NOTES.md). Items 1, 2 and 3 and the OID/line part of item 5 are **fixed** (tests in `tests/test_regressions.py`); the rest remain open. The final gate was re-run after the fixes (rebuilt wheel and sdist, 188 tests on 3.11 to 3.14, examples, leak gate):

1. **Test-file substring false negatives:** The classifier treats any file whose basename contains `"test"`, `"mock"`, or `"fixture"` as `BENIGN_TEST_CODE` (exit code 2). This causes production files such as `attestation.py` or `latest_keys.py` to be silenced if they contain vulnerable cryptography.
2. **Unanchored `encap` false positives:** Any function or call containing `"encap"` in its name (such as `encapsulate_header`) is treated as ML-KEM-768. Combined with classical algorithms, this produces a false `COMPLIANT_QUANTUM_SAFE` hybrid verdict.
3. **Silent file skips on syntax errors:** In directory scanning mode, files raising `SyntaxError` or `ValueError` are skipped without emitting a warning or failing the overall scan.
4. **Limited primitive coverage:** The scanner uses fixed name patterns. Ed25519, Ed448, DSA, and finite-field DH are not recognized. ECDH over P-256 is reported as RSA-3072 + X25519.
5. **Fixed CBOM fields:** `sourceLine` and `sinkLine` default to fixed values (12/20 for RSA, 0 otherwise). OIDs for non-RSA/non-ML-KEM algorithms use a fixed curve OID (`1.3.132.0.10`).

---

## Known limitations

- **Python AST only:** Does not analyze C extensions, compiled shared objects, or non-Python configuration files.
- **Runtime execution not traced:** Does not execute scanned code; dynamic runtime imports or dynamically computed algorithm names are not resolved.
- **Toy QUBO harness:** The package includes an internal benchmark subpackage (`pqblocks_lint.bench`) timing external optimization solvers; this is separate from source code analysis.
