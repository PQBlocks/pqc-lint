# AGENTS.md: pqblocks-lint

Guidance for AI coding agents integrating or invoking `pqblocks-lint`.

## Purpose & Scope

- **What it does:** Performs static analysis on Python source files via `ast.parse`, constructs control-flow and call graphs, propagates taint from key-generation calls, and emits CycloneDX 1.6 CBOM or SARIF 2.1.0 documents.
- **What it is NOT:** It is not a cryptographic engine. It performs no encryption, decryption, key exchange, or signature operations, and handles no secrets.
- **Install:** `pip install pqblocks-lint`

---

## Canonical Imports & APIs

```python
from pqblocks_lint import cli, graph, taint, classifier, serialize, runner

# 1. Parse AST into CFG / call graph
cfg = graph.build_cfg_cg("path/to/source.py")

# 2. Extract source nodes and trace taint reachability
sources = graph.get_source_nodes(cfg)
tainted_nodes = taint.propagate_taint_interprocedural(cfg, set(sources))

# 3. Classify primitives
primitives = classifier.classify(cfg, tainted_nodes)
compliance = classifier.classify_compliance(cfg, tainted_nodes)

# 4. Serialize to standardized outputs
cbom_doc = serialize.build_cbom_dict(primitives, target="path/to/source.py", seed=0)
sarif_doc = serialize.build_sarif_dict(primitives, target="path/to/source.py", seed=0)
```

CLI entrypoint:
```bash
pqblocks-lint analyze --target <path> --format {cbom|sarif} --output <out_path> --seed 0
```

### Exit code contract

- `0`: `COMPLIANT_QUANTUM_SAFE` (all matched algorithms are quantum-safe or hybrid) or `NO_CRYPTO_DETECTED`.
- `1`: `NON_COMPLIANT_VULNERABLE` (one or more classical quantum-vulnerable primitives detected, e.g. RSA, ECDSA).
- `2`: `BENIGN_TEST_CODE` (file detected as test code or mock fixture).
- `3`: Error parsing single target (e.g. `SyntaxError`, `UnicodeDecodeError`).
- `4`: CLI argument validation failure (missing required argument, negative seed, nonexistent path).
- `5`: Execution exceeded `--timeout`.

---

## Agent Pitfalls & Traps

1. **Do not rely on exit code 0 without checking reported assets:**
   - Any function or variable with `"encap"` in its identifier (e.g. `encapsulate_header`) triggers an `ML-KEM-768` detection. If paired with RSA/ECDSA, this yields a false `COMPLIANT_QUANTUM_SAFE` exit code 0.
   - Files containing Ed25519, Ed448, DSA, or finite-field DH are not recognized and report exit code 0 (`NO_CRYPTO_DETECTED`).
2. **Watch out for exit code 2 on production files:**
   - Any file whose basename contains `"test"` (e.g. `attestation.py`, `latest_keys.py`, `contest.py`) returns exit code 2 (`BENIGN_TEST_CODE`) regardless of vulnerable algorithms.
3. **Directory scans skip syntax errors:**
   - Unparsable or non-UTF-8 files in directory mode are swallowed without failing the command. Validate python syntax before scanning trees.
4. **CBOM line numbers and non-standard OIDs:**
   - `sourceLine` / `sinkLine` are static defaults. Do not assume line numbers pinpoint exact AST tokens.
5. **No QUBO optimization connection:**
   - Ignore `pqblocks_lint.bench`. It is a small internal benchmark for third-party optimization solvers (dwave-neal, OpenJij, OR-Tools) on toy problems; it has nothing to do with code linting.
