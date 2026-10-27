"""Instance 01: Direct Classical RSA Cryptographic Usage.

Ground Truth:
- Algorithm: RSA-2048
- Vulnerability: Quantum-vulnerable (Shor's algorithm factoring)
- Compliance: Non-compliant with CNSA 2.0 and OMB M-23-02
- NIST Quantum Security Level: 0
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def generate_and_encrypt_payload(plaintext: bytes) -> bytes:
    # Source: Direct instantiation of RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Sink: Encryption using OAEP padding with SHA-256
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


if __name__ == "__main__":
    msg = b"Confidential federal enterprise data"
    ct = generate_and_encrypt_payload(msg)
    print(f"Ciphertext length: {len(ct)}")
