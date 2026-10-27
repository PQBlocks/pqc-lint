# Use cases: pqblocks-lint

Each runnable example below is located in `examples/` and verifies its own execution output.

---

## 1. Fast Python file cryptographic audit (CBOM output)

You need to audit a Python script for quantum-vulnerable cryptography and generate a machine-readable CycloneDX 1.6 CBOM document.

```bash
python examples/scan_file.py
```

Output:
```
RSA file exit code: 1 verdict: NON_COMPLIANT_VULNERABLE
AES file exit code: 0
CBOM format: CycloneDX 1.6 ['RSA-2048-OAEP-SHA256']
check passed: True
```

In the shell:
```bash
pqblocks-lint analyze --target path/to/script.py --format cbom --output cbom.json --seed 0
```
- Exit code `1`: Cryptography vulnerable to Shor's algorithm detected (e.g. RSA, ECDSA).
- Exit code `0`: No vulnerable cryptography detected or quantum-safe/hybrid implementation found.

---

## 2. GitHub CodeQL / Security SARIF 2.1.0 reporting

You want to integrate post-quantum cryptographic linting into CI/CD pipelines (e.g., GitHub Security tab) using standard SARIF 2.1.0 output:

```bash
python examples/sarif_report.py
```

Output:
```
exit code: 1
SARIF version: 2.1.0 tool: pqblocks_lint
results: [('PQBLOCKS-LINT/ECDSA-256', 'error'), ('PQBLOCKS-LINT/RSA-3072', 'error')]
check passed: True
```

In GitHub Actions:
```bash
pqblocks-lint analyze --target src/ --format sarif --output pqc-audit.sarif --seed 0
```
Then upload using `github/codeql-action/upload-sarif@v3`.

---

## 3. Direct AST & taint graph library analysis

You want to embed cryptographic data-flow and taint tracking directly into your custom developer tooling or security analyzers:

```bash
python examples/library_pipeline.py
```

Output:
```
RSA 3072 quantum_safe = False
verdict: NON_COMPLIANT_VULNERABLE
check passed: True
```

Code excerpt:
```python
from pqblocks_lint import classifier, graph, taint

# 1. Parse into control flow & call graph
g = graph.build_cfg_cg("path/to/module.py")

# 2. Extract key generation sources
sources = graph.get_source_nodes(g)

# 3. Propagate taint across interprocedural flows
tainted = taint.propagate_taint_interprocedural(g, set(sources))

# 4. Classify tainted primitives into canonical FIPS representations
fips_params = classifier.classify(g, tainted)
compliance = classifier.classify_compliance(g, tainted)
```
