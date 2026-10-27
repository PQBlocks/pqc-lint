"""Instance 04: Quantum-Safe Hybrid Key Establishment & Envelope (NIST SP 800-56C Rev 2).

Ground Truth:
- Algorithms: Classical X25519 + PQC ML-KEM-768 (FIPS 203)
- Key Derivation: HKDF-SHA256 (NIST SP 800-56C Rev 2 Eq. 1: Z_prime = Z_classical || Z_pqc)
- Symmetric Cipher: AES-256-GCM
- Vulnerability: Quantum-Safe (Lattice assumption: Module-LWE remains hard against CRQC)
- Compliance: Compliant with CNSA 2.0 and OMB M-23-02
- NIST Quantum Security Level: 3
"""

import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MockMLKEM768Engine:
    """Mock baseline simulating NIST FIPS 203 ML-KEM-768 encapsulation."""
    ALGORITHM = "ML-KEM-768"
    OID = "2.16.840.1.101.3.4.4.2"
    NIST_LEVEL = 3

    @staticmethod
    def encap(peer_pk: bytes) -> tuple[bytes, bytes]:
        # Emulates FIPS 203 ML-KEM.Encaps_internal
        # Returns (shared_secret, ciphertext)
        ss_pqc = os.urandom(32)
        ct_pqc = os.urandom(1088)  # ML-KEM-768 ct size
        return ss_pqc, ct_pqc


def establish_hybrid_channel(peer_x25519_pk: x25519.X25519PublicKey, peer_pqc_pk: bytes):
    # Classical X25519 key exchange
    eph_x25519 = x25519.X25519PrivateKey.generate()
    ss_classical = eph_x25519.exchange(peer_x25519_pk)

    # Post-Quantum ML-KEM-768 encapsulation
    ss_pqc, ct_pqc = MockMLKEM768Engine.encap(peer_pqc_pk)

    # NIST SP 800-56C Rev 2 concatenation: Z' = Z_classical || Z_pqc
    z_prime = ss_classical + ss_pqc

    # Key derivation using HKDF-SHA256
    derived_aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"PQBlocks-Hybrid-X25519-MLKEM768-v1",
    ).derive(z_prime)

    return AESGCM(derived_aes_key), ct_pqc, eph_x25519.public_key()


if __name__ == "__main__":
    peer_priv = x25519.X25519PrivateKey.generate()
    cipher, ct, eph_pub = establish_hybrid_channel(peer_priv.public_key(), os.urandom(1184))
    nonce = os.urandom(12)
    payload = cipher.encrypt(nonce, b"Quantum-Safe Hybrid Enterprise Data", None)
    print(f"Hybrid ciphertext produced: {len(payload)} bytes, PQC CT: {len(ct)} bytes")
