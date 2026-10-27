"""Use the library API directly: graph -> taint -> classify -> CBOM dict.

Checks that an interprocedural RSA flow (key made in one function, used for encryption in another) is
classified as RSA, marked not quantum-safe, and gives the NON_COMPLIANT_VULNERABLE verdict.
"""
import pathlib
import tempfile

from pqblocks_lint.classifier import classify
from pqblocks_lint.graph import build_cfg_cg, get_source_nodes
from pqblocks_lint.serialize import build_cbom_dict
from pqblocks_lint.taint import propagate_taint

src = pathlib.Path(tempfile.mkdtemp(), "envelope.py")
src.write_text(
    "from cryptography.hazmat.primitives.asymmetric import rsa, padding\n"
    "from cryptography.hazmat.primitives import hashes\n"
    "def make_key():\n"
    "    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
    "    return private_key\n"
    "def wrap(key, data):\n"
    "    ciphertext = key.public_key().encrypt(data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))\n"
    "    return ciphertext\n"
)

graph = build_cfg_cg(str(src))
tainted = propagate_taint(graph, set(get_source_nodes(graph)))
assets = classify(graph, tainted)
cbom = build_cbom_dict(assets, target=src.name, seed=0)

for a in assets:
    print(a.algorithm, a.key_size_bits, "quantum_safe =", a.quantum_safe)
print("verdict:", cbom["verdict"])
ok = any(a.algorithm == "RSA" and not a.quantum_safe for a in assets) and cbom["verdict"] == "NON_COMPLIANT_VULNERABLE"
print("check passed:", ok)
assert ok
