# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- A file name containing `test`, `mock` or `fixture` no longer yields `BENIGN_TEST_CODE`. The verdict now follows content: `BENIGN_TEST_CODE` only when nothing was detected and the file looks like test code.
- ML-KEM is detected only from real APIs (`kyber_py`, `mlkem`, `ml_kem`, `pqcrypto.kem`, liboqs `KeyEncapsulation("ML-KEM-*")`), not from names such as `encap`. RSA plus a helper named `encapsulate_header` is now `NON_COMPLIANT_VULNERABLE`.
- Directory scans report files that cannot be analysed on stderr and exit with the new code 6 instead of skipping them.
- CBOM `oid` is per algorithm (omitted when unknown) instead of the secp256k1 OID; `sourceLine`/`sinkLine` are 0 (not measured) instead of 12/20.

### Changed
- Tests: 188 (was 183), including `tests/test_regressions.py`. The golden `instance_04` sample (a mock KEM) is now reported as vulnerable.

## [0.1.0] - 2026-10-25

### Added
- Static AST parser and control flow graph (CFG) builder for Python source files using `ast.parse`.
- Source-to-sink forward and interprocedural taint propagation tracking cryptographic key lifecycle.
- Cryptographic primitive classifier supporting RSA, ECDSA, ML-KEM-768, AES, and HKDF.
- CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) serialization with `cryptoProperties`.
- OASIS SARIF 2.1.0 static analysis report serialization.
- `pqblocks-lint` CLI supporting `--target`, `--format` (`cbom` or `sarif`), `--output`, and `--seed`.
- Deterministic analysis mode guaranteeing byte-identical output across runs with identical seeds.
- Standalone runnable examples: single-file audit, SARIF reporting, and library pipeline.
- 183 automated tests covering AST graph creation, taint propagation, classification, and serialization.
