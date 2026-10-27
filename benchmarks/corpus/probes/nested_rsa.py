from cryptography.hazmat.primitives.asymmetric import rsa
class Vault:
    def make(self):
        if True:
            k = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            return k
