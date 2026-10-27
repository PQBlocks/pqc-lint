# Security notes: pqblocks-lint

## What this package is

`pqblocks-lint` is a **static analysis scanner**, not a cryptographic implementation.
- It parses Python source code using the standard library `ast` module.
- It never executes, imports, or runs the target source code.
- It holds no cryptographic keys, performs no encryption or decryption, generates no nonces, and handles no sensitive credentials.
- Its verdicts and generated CBOM/SARIF artifacts are decision-support heuristics for post-quantum migration planning, not formal compliance certifications.

---

## Known limitations & verdict accuracy risks

The primary security risk of `pqblocks-lint` is an **incorrect security verdict** (reporting vulnerable production cryptography as quantum-safe or benign). Callers using this tool in continuous integration (CI) gates must take note of the following behavior:

### 1. Basename substring false negatives (fixed)
Files whose basename contains `"test"`, `"mock"`, or `"fixture"` anywhere receive exit code 2 (`BENIGN_TEST_CODE`).
- **Impact:** Production files like `attestation.py`, `latest_keys.py`, or `contest.py` will be classified as benign test fixtures even if they contain vulnerable classical keys (e.g. RSA-2048).
- **Mitigation:** Inspect findings in files with these substrings manually or configure directory filters in CI.

### 2. Spurious ML-KEM classification from `encap` (fixed)
Any call or function identifier containing the substring `"encap"` (e.g., `encapsulate_header`) triggers detection of NIST FIPS 203 `ML-KEM-768`.
- **Impact:** If a codebase pairs classical RSA or ECDSA with an unrelated helper containing `"encap"`, the scanner treats the file as a hybrid post-quantum implementation, emitting exit code 0 (`COMPLIANT_QUANTUM_SAFE`).
- **Mitigation:** Verify reported `ML-KEM-768` assets against actual post-quantum library imports.

### 3. Silent failure on syntax errors in directory mode (fixed)
When scanning a directory tree, files that raise `SyntaxError`, `ValueError`, or `FileNotFoundError` are caught and skipped silently.
- **Impact:** A codebase containing broken syntax or unparsable encoding in critical security files will not fail the directory scan and may yield a clean exit code 0 (`NO_CRYPTO_DETECTED`).
- **Mitigation:** Ensure code passes syntax linting (`pyflakes` / `flake8` / `ruff`) prior to running `pqblocks-lint`.

### 4. Limited algorithm coverage & pattern matching
The tool identifies primitives through a fixed lexical pattern table rather than resolved type definitions:
- **Missing primitives:** Ed25519, Ed448, X448, DSA, and finite-field Diffie-Hellman are not in the pattern dictionary and will result in `NO_CRYPTO_DETECTED`.
- **Misclassifications:** ECDH key agreement over curve P-256 (`ec.generate_private_key`) is classified as RSA-3072 paired with X25519-253.
- **Key size detection:** RSA key size is inferred only if passed via a literal `key_size=` keyword argument. Otherwise, it defaults to 3072 bits.

### 5. CBOM fields (partly fixed)
In the generated CycloneDX 1.6 CBOM:
- `sourceLine` and `sinkLine` are always 0 (not measured; real line numbers are open).
- OIDs exist only for RSA, ML-KEM, ML-DSA, X25519 and AES; other algorithms omit the field.
- Timestamps are synthetic, derived from the `--seed` argument.

---

### Status of items 1 to 3
- Item 1: the verdict no longer depends on the file name. `BENIGN_TEST_CODE` is given only when nothing is detected and the file imports `pytest`/`unittest` and defines `test*`/`Test*`. Findings are never downgraded, not even under a `tests/` directory (so RSA in test code fails the gate; a deliberate choice, opt-out is open).
- Item 2: ML-KEM comes only from known imports or a `KeyEncapsulation("ML-KEM-*"/"Kyber*")` call. Aliased imports (`from oqs import KeyEncapsulation as KE`) and other PQC libraries are not recognised, which can only produce a false "vulnerable", not a false "safe". "Hybrid" is declared when both a real ML-KEM use and a classical primitive are present; the tool does not check that both feed one KDF (open).
- Item 3: unparsable or unreadable files in a directory scan are printed to stderr as `scan error: ...` and the run exits 6 (also when other files are vulnerable). They are not written into the CBOM/SARIF file (open). `RecursionError` is still uncaught (exit 3).

## Input handling & denial of service

- **Memory and recursion:** Deeply nested ASTs (hundreds of nested blocks) will raise `RecursionError` in Python's standard `ast` walker. In single-file mode, this exits with code 3; in directory mode it is not caught and the run exits 3.
- **Graph reachability:** Taint analysis evaluates all reachable paths in a directed graph. Pathologically large single files with dense interprocedural call graphs may experience slow analysis times.
- **Non-UTF-8 source files:** Non-UTF-8 files raise `UnicodeDecodeError` and are reported as scan errors (exit 6) in directory mode.

---

## Cryptographic RNG & zeroization

- **RNG:** No cryptographic random numbers are used. Deterministic document UUIDs are generated from target names and seeds via Python's standard `uuid` module.
- **Zeroization:** Not applicable. The process handles no secret keys, private keys, or plaintext data.
