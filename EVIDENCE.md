# Evidence: pqblocks-lint

This file lists the primary standards, regulatory guidelines, and specifications implemented by `pqblocks-lint`, along with exact mappings from specification elements to the codebase.

## Primary sources

### Output formats

1. **CycloneDX Bill of Materials Standard, version 1.6.** OWASP Foundation, released 9 April 2024.
   - Schema: `http://cyclonedx.org/schema/bom-1.6.schema.json`
   - Specification: https://cyclonedx.org/docs/1.6/json/
   - The package emits `"specVersion": "1.6"`, using `cryptographic-asset` components with `cryptoProperties`.
   - Extensions: top-level `"verdict"` and `"detectionContext"` within `cryptoProperties`.

2. **Static Analysis Results Interchange Format (SARIF) Version 2.1.0.** OASIS Standard, 27 March 2020 (with Errata 01, 28 August 2023).
   - Schema: `https://json.schemastore.org/sarif-2.1.0.json`
   - Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
   - Emits rules categorized under `PQBLOCKS-LINT/<ALGORITHM>` with URI `https://github.com/PQBlocks/pqc-lint`.

### Cryptographic standards & regulatory mandates

3. **NIST FIPS 203**, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, August 2024. doi:[10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203)
   - Defines ML-KEM parameter sets (ML-KEM-512, ML-KEM-768, ML-KEM-1024).
4. **NIST FIPS 204**, *Module-Lattice-Based Digital Signature Standard*, August 2024. doi:[10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204)
   - Defines ML-DSA parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87).
5. **NIST FIPS 205**, *Stateless Hash-Based Digital Signature Standard*, August 2024. doi:[10.6028/NIST.FIPS.205](https://doi.org/10.6028/NIST.FIPS.205)
   - Defines SLH-DSA parameter sets.
6. **OMB Memorandum M-23-02**, *Migrating to Post-Quantum Cryptography*, November 2022.
   - Federal requirement for agencies to establish a Cryptographic Bill of Materials (CBOM) inventory.
7. **NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)**.
   - Migration mandates for national security systems specifying ML-KEM-1024, ML-DSA-87, and AES-256.

---

## Method to code

| Specification / Requirement | Implementation in `pqblocks-lint` |
|---|---|
| AST Parsing without execution | `pqblocks_lint.graph.build_cfg_cg`: parses Python source with `ast.parse`, constructs a `networkx.DiGraph` representing control flow and call relationships. |
| Source & Sink Identification | `graph.py` and `taint.py`: tags call nodes originating from key generation (`generate_private_key`, `ec.generate_private_key`) as sources, and operations like `encrypt`, `sign`, `exchange` as sinks. |
| Taint Reachability | `pqblocks_lint.taint.propagate_taint` & `propagate_taint_interprocedural`: performs forward graph reachability over tainted data edges. |
| Primitive Classification | `pqblocks_lint.classifier.classify`: matches AST node names and call metadata against `PRIMITIVE_PATTERNS` to identify algorithm families and construct `FIPSParams`. |
| CycloneDX 1.6 Serialization | `pqblocks_lint.serialize.build_cbom_dict`: formats classified primitives as CycloneDX 1.6 `cryptographic-asset` components with synthetic timestamps and UUIDs. |
| SARIF 2.1.0 Logging | `pqblocks_lint.serialize.build_sarif_dict`: formats findings as SARIF results with rule IDs, error/note levels, and source locations. |
| Deterministic Outputs | `serialize.py`: serializes dictionaries with sorted keys, deterministic UUIDs derived via `uuid.UUID(bytes=...)`, and fixed base timestamps offset by `--seed`. |
