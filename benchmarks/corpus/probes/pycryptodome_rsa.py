from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
key = RSA.generate(2048)
cipher = PKCS1_OAEP.new(key.publickey())
ct = cipher.encrypt(b"secret")
