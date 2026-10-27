"""Scan two small Python files and check the CLI verdicts.

The first file generates an RSA-2048 key (quantum-vulnerable, exit code 1). The second only uses
AES-256-GCM (no quantum-vulnerable primitive, exit code 0). The CBOM written for the first file must be
a CycloneDX 1.6 document that lists an RSA asset. (A 2048-bit RSA asset is always named
RSA-2048-OAEP-SHA256 in this release, even when no OAEP call is present.)
"""
import json
import pathlib
import tempfile

from pqblocks_lint import cli

work = pathlib.Path(tempfile.mkdtemp())
rsa_file = work / "keys.py"
rsa_file.write_text(
    "from cryptography.hazmat.primitives.asymmetric import rsa\n"
    "def make_key():\n"
    "    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    "    return key\n"
)
aes_file = work / "storage.py"
aes_file.write_text(
    "import os\n"
    "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
    "key = AESGCM.generate_key(bit_length=256)\n"
    "ct = AESGCM(key).encrypt(os.urandom(12), b'data', None)\n"
)

rsa_code = cli.main(["--target", str(rsa_file), "--format", "cbom", "--output", str(work / "rsa.cbom.json"), "--seed", "0"])
aes_code = cli.main(["--target", str(aes_file), "--format", "cbom", "--output", str(work / "aes.cbom.json"), "--seed", "0"])
cbom = json.loads((work / "rsa.cbom.json").read_text())

print("RSA file exit code:", rsa_code, "verdict:", cbom["verdict"])
print("AES file exit code:", aes_code)
print("CBOM format:", cbom["bomFormat"], cbom["specVersion"], [c["name"] for c in cbom["components"]])
ok = (rsa_code == 1 and aes_code == 0 and cbom["bomFormat"] == "CycloneDX" and cbom["specVersion"] == "1.6"
      and any(c["name"].startswith("RSA") for c in cbom["components"]))
print("check passed:", ok)
assert ok
