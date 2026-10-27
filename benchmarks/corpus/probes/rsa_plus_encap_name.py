from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
def encapsulate_header(h):
    return b"hdr" + h
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ct = key.public_key().encrypt(b"x", padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
