from cryptography.hazmat.primitives.asymmetric import ec
priv = ec.generate_private_key(ec.SECP256R1())
peer = ec.generate_private_key(ec.SECP256R1()).public_key()
shared = priv.exchange(ec.ECDH(), peer)
