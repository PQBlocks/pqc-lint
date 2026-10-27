"""pqblocks-lint — Cryptographic Bill of Materials & PQC Readiness Prover.

Static analysis tool for detecting, classifying, and cataloging cryptographic
primitives in Python source code with CycloneDX 1.6 CBOM and SARIF 2.1.0 output.
"""

__version__ = "0.1.0"
__all__ = ["cli", "taint", "classify", "serialize", "runner", "bench"]