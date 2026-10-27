"""Instance 02: Aliased & Dynamically Assigned Cryptographic Usage.

Ground Truth:
- Algorithm: RSA-3072
- Vulnerability: Quantum-vulnerable (Shor's algorithm factoring)
- Compliance: Non-compliant with CNSA 2.0 (Evasion test for naive AST/regex linters)
- NIST Quantum Security Level: 0
"""

from cryptography.hazmat.primitives.asymmetric import rsa as secret_asym_engine
from cryptography.hazmat.primitives.asymmetric import padding as secret_pad
from cryptography.hazmat.primitives import hashes as secret_hashes


class CipherWrapper:
    def __init__(self, key_engine):
        self.engine = key_engine

    def build_key(self, bits: int):
        # Tainted flow: alias resolution through class property
        return self.engine.generate_private_key(public_exponent=65537, key_size=bits)


def encrypt_with_aliased_engine(data: bytes) -> bytes:
    # Obfuscated / aliased wrapper
    wrapper = CipherWrapper(secret_asym_engine)
    active_key = wrapper.build_key(3072)
    pub = active_key.public_key()

    # Encryption sink using aliased padding symbols
    pad_strategy = secret_pad.OAEP(
        mgf=secret_pad.MGF1(algorithm=secret_hashes.SHA384()),
        algorithm=secret_hashes.SHA384(),
        label=None,
    )
    return pub.encrypt(data, pad_strategy)


if __name__ == "__main__":
    ct = encrypt_with_aliased_engine(b"Aliased sensitive token")
    print(f"Encrypted token length: {len(ct)}")
