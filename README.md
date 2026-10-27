# pqblocks-lint

Static analysis for Python source that finds cryptographic primitives and says which ones a quantum computer would break (RSA, ECDSA/ECC, X25519) and which it would not (ML-KEM, AES-256, HKDF).
Use it to build a first inventory of the cryptography in a Python codebase as a **CycloneDX 1.6 CBOM** or a **SARIF 2.1.0** log, as one input to a post-quantum migration plan.
How it works: it parses the code with Python's `ast` module (the code is never executed), builds a data-flow graph, follows values from key-generation calls to encrypt, sign, exchange and derive calls, and matches the result against a fixed table of name patterns. It is a static-analysis heuristic, **not** a cryptographic module.

> **Read [Limitations](#limitations) before using the verdict as a CI gate.** Ed25519, DSA and finite-field DH are not detected, so a file using only those gets `NO_CRYPTO_DETECTED`.

```bash
pip install pqblocks-lint
```

```python
import pathlib, tempfile
from pqblocks_lint import cli

src = pathlib.Path(tempfile.mkdtemp(), "keys.py")
src.write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n"
               "def make_key():\n"
               "    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
               "    return key\n")
code = cli.main(["--target", str(src), "--format", "cbom", "--output", str(src.with_suffix(".cbom.json")), "--seed", "0"])
print(code)   # 1: quantum-vulnerable cryptography found (RSA-2048)
```

The same from a shell:

```bash
pqblocks-lint analyze --target src/ --format sarif --output crypto.sarif --seed 0; echo $?
```

## Why PQBlocks

- **Tested:** 188 tests: CLI exit codes, graph construction, taint propagation, classification, CBOM/SARIF output, determinism, and five labelled sample programs.
- **Honest about accuracy:** [BENCHMARKS.md](BENCHMARKS.md) compares the tool, file by file, with a third-party scanner on a 16-file labelled corpus, and lists every miss.
- **Licence:** Apache-2.0. Pure Python. Analysis needs only `networkx` and the standard library.

## Usage

### Command line

```
pqblocks-lint [analyze] --target PATH --format {cbom,sarif} --output FILE --seed N [--timeout S] [--threads N]
```

- `--target` is a `.py` file or a directory (every `*.py` below it is scanned).
- `--seed` (required, ≥ 0) does not change the analysis. It only sets the synthetic CBOM timestamp (2026-01-01T00:00:00Z plus `seed` seconds) and the `serialNumber`, so the same input and seed always give byte-identical output.
- You can also run `python -m pqblocks_lint.cli`.

| Exit code | Verdict | Meaning |
|---|---|---|
| 0 | `COMPLIANT_QUANTUM_SAFE` or `NO_CRYPTO_DETECTED` | No quantum-vulnerable primitive matched |
| 1 | `NON_COMPLIANT_VULNERABLE` | A quantum-vulnerable primitive was found |
| 2 | `BENIGN_TEST_CODE` | Nothing was detected and the file looks like test code (imports `pytest`/`unittest` and defines `test*`/`Test*`) |
| 3 | n/a | Internal error, e.g. a single target file with a syntax error |
| 4 | n/a | Invalid arguments (missing option, negative seed, path does not exist) |
| 5 | n/a | The analysis took longer than `--timeout` (checked after it finishes) |
| 6 | n/a | Directory scan only: at least one `.py` file could not be analysed (syntax error, undecodable, unreadable). Each is printed to stderr as `scan error: ...`; the output file holds the results for the other files. Takes precedence over 0, 1 and 2 |

In a directory scan, the verdict is `NON_COMPLIANT_VULNERABLE` if any file is vulnerable.
Files that fail to parse are reported on stderr and make the run exit 6; they are never counted as clean.

### Output

- **CBOM** (`--format cbom`): a CycloneDX `specVersion` 1.6 JSON document. Each detected algorithm is a `cryptographic-asset` component with `cryptoProperties`.
  - It adds two fields of its own: a top-level `verdict`, and `cryptoProperties.detectionContext`, which carries `shorVulnerable`, `cnsa20Compliant` and `fips1403Status`.
  - Keys are sorted.
- **SARIF** (`--format sarif`): a SARIF version 2.1.0 log (OASIS Standard, 27 March 2020, with Errata 01 of 28 August 2023). `$schema` is `https://json.schemastore.org/sarif-2.1.0.json`.
  - One rule per algorithm, with IDs of the form `PQBLOCKS-LINT/RSA-2048`.
  - Results have level `error` for quantum-vulnerable algorithms and `note` for quantum-safe ones. Every result points at line 1.

## API reference

All signatures are from the code.

| Module | Function | Purpose |
|---|---|---|
| `pqblocks_lint.cli` | `main(argv: list[str] \| None = None) -> int` | Run the CLI and return the exit code |
| | `parse_cli_arguments(argv=None) -> LintArgs` | Parse and validate arguments (raises `SystemExit(4)`) |
| | `validate_args(args) -> str \| None` | Error message, or `None` |
| | `LintArgs(target, format="cbom", output, seed=0, timeout=30, threads=1)` | Frozen dataclass with `.is_valid` |
| `pqblocks_lint.graph` | `build_cfg_cg(source_path: str) -> networkx.DiGraph` | Parse one file into a data-flow graph. Raises `FileNotFoundError` or `SyntaxError` |
| | `get_source_nodes(graph)`, `get_sink_nodes(graph)` | Node IDs |
| | `get_taint_closure(graph, sources)`, `find_tainted_paths(graph, sources, sinks)` | Reachability helpers |
| `pqblocks_lint.taint` | `propagate_taint(graph, sources: set[str], taint_filter=None) -> set[str]` | Nodes reachable from the sources |
| | `propagate_taint_interprocedural(graph, sources, call_graph=None)` | Also follows call edges |
| | `get_tainted_sources(graph, tainted_nodes)`, `classify_taint(graph, tainted_nodes)` | Source / intermediate / sink roles |
| `pqblocks_lint.classifier` | `classify(graph, tainted_nodes=None) -> list[FIPSParams]` | One entry per detected algorithm family |
| | `classify_compliance(graph, tainted_nodes=None) -> dict` | Summary: `is_quantum_safe`, `nist_level`, `families`, `compliance` |
| | `FIPSParams` | Frozen dataclass: `algorithm`, `fips_id`, `nist_level`, `key_size_bits`, `quantum_safe`, `compliance`, `family` |
| `pqblocks_lint.serialize` | `build_cbom_dict(assets, target="unknown", seed=0, verdict=None) -> dict` | CBOM, with the verdict computed when `None` |
| | `build_sarif_dict(assets, target="unknown", seed=0) -> dict` | SARIF log |
| | `emit_outputs(assets, fmt, output_path, target="unknown", seed=0, verdict=None) -> str` | Write `cbom` or `sarif`. Raises `ValueError` for any other format |
| `pqblocks_lint.runner` | `run_instance(instance_path, seed=0) -> dict` | Analyse one file and check that the output is deterministic |
| | `run_all_instances(suite_path, seed=0, output_path=None) -> dict` | Run a labelled suite (`instances.json`) |

The package also contains `pqblocks_lint.bench`. It is a small harness that times third-party QUBO solvers (dwave-neal, OpenJij, OR-Tools CP-SAT) on a fixed 4-variable problem. It plays no part in the analysis, which is why those solvers appear as dependencies. Its numbers say nothing about this tool.

## Limitations

**False "safe" verdicts.** These are the most important limitations:
- File names no longer affect the verdict. `BENIGN_TEST_CODE` is given only when nothing was detected; a finding is never downgraded because of a test-like name or path (a `tests/` directory is not treated specially, so RSA in test code fails the gate).
- ML-KEM is reported only from a real API: an import of `kyber_py`, `mlkem`, `ml_kem` or `pqcrypto.kem.ml_kem*`/`kyber*`, or a call `KeyEncapsulation("ML-KEM-...")`/`KeyEncapsulation("Kyber...")` (liboqs-python). Aliased imports of `KeyEncapsulation` and other PQC libraries are not recognised. A file is called hybrid only if it has both such a call/import and a classical primitive.
- A golden sample that fakes a KEM with `os.urandom` is now reported as vulnerable (X25519 only).

**Detection.**
- Detection uses name patterns (`generate_private_key`, `encrypt`, `sign`, `exchange`, `derive`, and names such as `rsa`, `ecdsa`, `x25519`, `aes`, `hkdf`, `ml_kem`). Imports are not resolved.
- Ed25519, Ed448, X448, DSA and finite-field DH are **not detected**.
- ECDH over P-256 is reported as `RSA-3072` + `X25519-253`, because `ec.generate_private_key` matches the RSA key-generation pattern.
- RSA key size is read only from a literal `key_size=` keyword inside a function body. Otherwise RSA is reported as 3072 bits.

**CBOM fields.**
- `sourceLine`/`sinkLine` are always 0 (line numbers are not measured).
- `oid` is emitted only for RSA (RSAES-OAEP), ML-KEM-768, ML-DSA-65, X25519 and AES-256-GCM; other algorithms omit it. It is a per-algorithm value, not derived from the detected parameters.
- 2048-bit RSA is always named `RSA-2048-OAEP-SHA256`.
- The CBOM timestamp is synthetic.

**Compliance labels.**
- CNSA 2.0 requires ML-KEM-1024, ML-DSA-87 and AES-256. The tool labels ML-KEM-768 and ML-DSA as "Compliant (CNSA 2.0 / OMB M-23-02)".
- OMB M-23-02 is an inventory memo, not an algorithm list.
- Treat these labels as hints, not as an assessment.

**Scope.**
- Python source only.
- Measured accuracy covers the 16-file corpus in [BENCHMARKS.md](BENCHMARKS.md). The false-positive and false-negative rates on real repositories are **not measured**.
- Analysis time was measured only up to 608 lines per file.

**Options that do nothing.** `--timeout` is checked only after the scan ends, and `--threads` is accepted but ignored.

## Security notes

The package reads source files and writes one output file. It never imports or executes the code it scans, and it handles no keys. Its main risk is a wrong verdict; see [SECURITY_NOTES.md](SECURITY_NOTES.md).

## Verification

[TESTING.md](TESTING.md) · [BENCHMARKS.md](BENCHMARKS.md) · [EVIDENCE.md](EVIDENCE.md) · [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) · [USE_CASES.md](USE_CASES.md)

## Part of PQBlocks

[PQBlocks](https://github.com/PQBlocks) builds open, tested building blocks for the post-quantum transition. This package is its Python cryptography-inventory scanner.
