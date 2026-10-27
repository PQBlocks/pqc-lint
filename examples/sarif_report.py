"""Write a SARIF 2.1.0 log for an ECDSA signing module and check its structure.

The log must declare version 2.1.0, name the tool, and report the ECDSA finding at level "error"
(quantum-vulnerable). Known limitations visible in this output: every result's region is startLine 1
(line numbers are not tracked), and `ec.generate_private_key` also yields a spurious RSA-3072 result because
the key-generation pattern is shared with RSA.
"""
import json
import pathlib
import tempfile

from pqblocks_lint import cli

work = pathlib.Path(tempfile.mkdtemp())
src = work / "signer.py"
src.write_text(
    "from cryptography.hazmat.primitives.asymmetric import ec\n"
    "from cryptography.hazmat.primitives import hashes\n"
    "def sign(message):\n"
    "    signing_key = ec.generate_private_key(ec.SECP256R1())\n"
    "    signature = signing_key.sign(message, ec.ECDSA(hashes.SHA256()))\n"
    "    return signature\n"
)
out = work / "signer.sarif"
code = cli.main(["--target", str(src), "--format", "sarif", "--output", str(out), "--seed", "0"])
log = json.loads(out.read_text())
run = log["runs"][0]
results = [(r["ruleId"], r["level"]) for r in run["results"]]

print("exit code:", code)
print("SARIF version:", log["version"], "tool:", run["tool"]["driver"]["name"])
print("results:", results)
ok = code == 1 and log["version"] == "2.1.0" and any(rid.endswith("ECDSA-256") and lvl == "error" for rid, lvl in results)
print("check passed:", ok)
assert ok
