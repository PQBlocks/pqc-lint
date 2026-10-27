"""Instance 05: Mock Test Fixture / Known Answer Test Data (False-Positive Suppression).

Ground Truth:
- Scope: Unit Test / Fixture code (Non-production)
- Expected Handling: Scoped as "test" or suppressed from production CI failure
- Prevents False Positives: Naive linters fail builds on test files containing legacy vectors
"""

import pytest

# Known Answer Test vector for legacy RSA-1024 (RFC 3447 test vector)
KAT_RSA_1024_MODULUS_HEX = (
    "bbf82f090682ce9c2338ac2b9da871f7368d07eed41043a440d6b6fdec97ba93"
    "cb3090098df2410a54457e0ad5ae560408d3e20084323e0c0343a419266e7ea8"
    "4be66e4a2d48386121fe39b2323a6ea237f37452d3a39e76318c48a735399587"
    "40a7cf14e7a828e8d89e5fc8b4618e47b2c01995efb4081048f8c2ca83b7ffb"
)


class TestLegacyCryptographicDecoder:
    """Fixture class testing backwards compatibility parsers."""

    def test_legacy_vector_parsing(self):
        # Benign test code: verifying that an import of a legacy format parser works
        assert len(KAT_RSA_1024_MODULUS_HEX) == 255 or len(KAT_RSA_1024_MODULUS_HEX) == 256
        raw_bytes = bytes.fromhex(KAT_RSA_1024_MODULUS_HEX)
        assert len(raw_bytes) == 128
