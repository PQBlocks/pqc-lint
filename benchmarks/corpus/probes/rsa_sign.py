from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
sig = key.sign(b"msg", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
