"""Instance 03: Interprocedural Cryptographic Data Flow Across Call Boundaries.

Ground Truth:
- Algorithm: ECDSA with NIST P-256 (secp256r1) and SHA-256
- Vulnerability: Quantum-vulnerable (Shor's algorithm discrete logarithm)
- Compliance: Non-compliant with CNSA 2.0 and OMB M-23-02
- NIST Quantum Security Level: 0
- Flow: Source in KeyVaultManager -> Intermediate in SessionContext -> Sink in NetworkTokenSigner
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


class KeyVaultManager:
    """Module A: Source of cryptographic keys."""
    @staticmethod
    def provision_signing_key():
        # Source: Generation of classical elliptic curve key
        return ec.generate_private_key(ec.SECP256R1())


class SessionChannelContext:
    """Module B: Intermediate propagation context."""
    def __init__(self, key_provider):
        self.signing_handle = key_provider.provision_signing_key()

    def get_authorized_handle(self):
        return self.signing_handle


class NetworkTokenSigner:
    """Module C: Cryptographic sink."""
    def __init__(self, context: SessionChannelContext):
        self.context = context

    def sign_dispatch_packet(self, packet: bytes) -> bytes:
        key = self.context.get_authorized_handle()
        # Sink: Digital signature generation using ECDSA
        signature = key.sign(packet, ec.ECDSA(hashes.SHA256()))
        return signature


def execute_network_handshake(data: bytes) -> bytes:
    vault = KeyVaultManager()
    session = SessionChannelContext(vault)
    signer = NetworkTokenSigner(session)
    return signer.sign_dispatch_packet(data)


if __name__ == "__main__":
    sig = execute_network_handshake(b"Authorization-Header: Bearer token-12345")
    print(f"Signature generated: {len(sig)} bytes")
