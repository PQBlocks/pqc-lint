import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=256)
aead = AESGCM(key)
ct = aead.encrypt(os.urandom(12), b"data", None)
