# Benchmarks: pqblocks-lint

This document records measured execution latency, lines-of-code (LOC) scaling, and detection accuracy across a 16-file test corpus. All figures come from direct measurements in `benchmarks/analysis-latency.json` or reproduction runs executed on the release candidate.

## Test environment

- **CPU:** Intel(R) Core(TM) i5-10300H CPU @ 2.50 GHz (4 cores / 8 threads)
- **OS:** Linux x86_64 (glibc 2.44)
- **Python version:** 3.14.7
- **Dependencies:** `networkx` 3.6.1, `numpy` 2.5.3, `scipy` 1.18.1, `ortools` 9.15.6755, `dwave-neal` 0.6.0, `openjij`

---

## 1. Golden test instances latency

Measured in-process via `pqblocks_lint.runner.run_instance` using `time.perf_counter_ns` across 10 runs per file with median latency recorded:

| Target File | LOC | Median Latency | Exit Code | Verdict |
|---|---|---|---|---|
| `golden/instance_01_classical_rsa.py` | 38 | 0.87 ms (871,319 ns) | 1 | `NON_COMPLIANT_VULNERABLE` |
| `golden/instance_02_aliased_import.py` | 42 | 1.10 ms (1,103,022 ns) | 1 | `NON_COMPLIANT_VULNERABLE` |
| `golden/instance_03_interprocedural_flow.py` | 74 | 1.77 ms (1,772,247 ns) | 1 | `NON_COMPLIANT_VULNERABLE` |
| `golden/instance_04_pqc_mlkem_hybrid.py` | 68 | 1.48 ms (1,476,522 ns) | 1 | `NON_COMPLIANT_VULNERABLE` (latency not re-measured; verdict re-run) |
| `golden/instance_05_mock_test_vector.py` | 31 | 0.45 ms (452,547 ns) | 2 | `BENIGN_TEST_CODE` |

Analysis per single module finishes in under 2 milliseconds.

---

## 2. LOC scaling

Scaling was benchmarked by concatenating `instance_01` repeatedly from 1x to 16x LOC across 20 runs per size (seeds 100–119):

| Multiplier | Lines of Code (LOC) | Median Latency | Scaling Factor | Verdict Deterministic |
|---|---|---|---|---|
| 1x | 38 | 0.83 ms (827,712 ns) | 1.00x | Yes |
| 2x | 76 | 1.31 ms (1,310,113 ns) | 1.58x | Yes |
| 4x | 152 | 2.28 ms (2,280,407 ns) | 2.75x | Yes |
| 8x | 304 | 4.33 ms (4,328,643 ns) | 5.23x | Yes |
| 16x | 608 | 8.52 ms (8,524,009 ns) | 10.30x | Yes |

Graph building and taint reachability scale roughly linearly (~14 µs per source line) up to 600 lines. Files with extreme AST nesting depths will see higher graph traversal times.

---

## 3. Detection accuracy on 16-file corpus

We evaluated `pqblocks-lint` on the 16 corpus files in `benchmarks/corpus/` against ground truth labels (`labels.json`) and compared with the third-party scanner `qproof 0.4.0`.

A file is considered **flagged** when:
- `pqblocks-lint`: the CLI exits with code 1 (`NON_COMPLIANT_VULNERABLE`).
- `qproof 0.4.0`: at least one finding has `quantum_risk == "VULNERABLE"`.

### Results table

Re-measured after the verdict fixes (CLI, `--seed 0`, one run per file).

| Corpus File | Expected Flagged | pqblocks-lint Exit | pqblocks-lint Verdict | Detected Assets | Correct? |
|---|---|---|---|---|---|
| `golden/instance_01_classical_rsa.py` | True | 1 | `NON_COMPLIANT_VULNERABLE` | `RSA-2048-OAEP-SHA256` | **Yes** |
| `golden/instance_02_aliased_import.py` | True | 1 | `NON_COMPLIANT_VULNERABLE` | `RSA-3072` | **Yes** |
| `golden/instance_03_interprocedural_flow.py` | True | 1 | `NON_COMPLIANT_VULNERABLE` | `ECDSA-256`, `RSA-3072` | **Yes** |
| `golden/instance_04_pqc_mlkem_hybrid.py` | True | 1 | `NON_COMPLIANT_VULNERABLE` | `AES-256`, `HKDF`, `X25519-253` | **Yes** |
| `golden/instance_05_mock_test_vector.py` | False | 2 | `BENIGN_TEST_CODE` | `[]` | **Yes** |
| `probes/aesgcm_only.py` | False | 0 | `NO_CRYPTO_DETECTED` | `[]` | **Yes** |
| `probes/hash_only.py` | False | 0 | `NO_CRYPTO_DETECTED` | `[]` | **Yes** |
| `probes/rsa_sign.py` | True | 1 | `NON_COMPLIANT_VULNERABLE` | `RSA-3072` | **Yes** |
| `probes/nested_rsa.py` | True | 1 | `NON_COMPLIANT_VULNERABLE` | `RSA-3072` | **Yes** |
| `probes/ecdh_p256.py` | True | 1 | `NON_COMPLIANT_VULNERABLE` | `RSA-3072`, `X25519-253` | **Yes** |
| `probes/pycryptodome_rsa.py` | True | 1 | `NON_COMPLIANT_VULNERABLE` | `AES-256`, `RSA-3072` | **Yes** |
| `probes/rsa_plus_encap_name.py` | True | 1 | `NON_COMPLIANT_VULNERABLE` | `RSA-3072` | **Yes** |
| `probes/billing.py` | True | 1 | `NON_COMPLIANT_VULNERABLE` | `RSA-3072` | **Yes** |
| `probes/attestation.py` | True | 1 | `NON_COMPLIANT_VULNERABLE` | `RSA-3072` | **Yes** |
| `probes/latest_keys.py` | True | 1 | `NON_COMPLIANT_VULNERABLE` | `RSA-2048-OAEP-SHA256` | **Yes** |
| `probes/ed25519_sign.py` | True | 0 | `NO_CRYPTO_DETECTED` | `[]` | **No (Miss)** |

### Summary and breakdown of misses

- **Total corpus files:** 16
- **`pqblocks-lint` correct verdicts:** 15 / 16 (93.8%), up from 12 / 16 before the fixes
- **Remaining miss:** `probes/ed25519_sign.py`. Ed25519, Ed448, DSA and finite-field Diffie-Hellman are absent from the primitive pattern map, yielding `NO_CRYPTO_DETECTED` (exit 0).
- Fixed: `attestation.py` and `latest_keys.py` (file name no longer decides the verdict), `billing.py` (a helper named `encapsulate_header` is no longer ML-KEM).
- `golden/instance_04_pqc_mlkem_hybrid.py` now exits 1: it fakes a KEM with `os.urandom` and calls no ML-KEM API, so only X25519 remains. Its label in `labels.json` is changed to flagged.
- Other assets in the table keep their known mis-detections (for example ECDH over P-256 reported as `RSA-3072` + `X25519-253`); the verdict is right, the asset list is not.

---

## 4. QUBO benchmarking harness (`pqblocks_lint.bench`)

The package includes an internal subpackage `pqblocks_lint.bench`. It executes small 4-variable Ising optimization problems against third-party solvers:
- D-Wave Neal simulated annealing (`dwave-neal`)
- OpenJij simulated annealing (`openjij`)
- OR-Tools CP-SAT (`ortools`)

> [!NOTE]
> This harness tests third-party mathematical optimization solvers on toy QUBO matrices. It has **no connection** to cryptographic analysis, data-flow taint analysis, or CBOM generation. Do not interpret its timing figures as AST scanner performance metrics.
