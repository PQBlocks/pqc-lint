import datetime
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from pqblocks_lint.classifier import FIPSParams

_VERSION = "0.1.0"

PRIMITIVE_MAP_SARIF = {
    "asymmetric": "public-key",
    "symmetric": "block-cipher",
    "kdf": "kdf",
}

# Only algorithms with an unambiguous OID; others omit the field.
_OIDS = {
    "RSA": "1.2.840.113549.1.1.7",
    "ML-KEM": "2.16.840.1.101.3.4.4.2",
    "ML-DSA": "2.16.840.1.101.3.4.3.18",
    "X25519": "1.3.101.110",
    "AES": "2.16.840.1.101.3.4.1.46",
}

_CLASSICAL_LEVEL = {
    0: 112,
    1: 128,
    2: 192,
    3: 192,
}


def _normalize_target(target: str) -> str:
    return target or "unknown"


def _ts(seed: int) -> str:
    base = datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
    dt = base + datetime.timedelta(seconds=int(seed) % 86400)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _serial(seed: int, target: str) -> str:
    h = hashlib.sha256(f"{seed}:{target}".encode()).hexdigest()
    u = uuid.UUID(h[:32])
    return f"urn:uuid:{u}"


def _norm_asset(a: Any) -> dict[str, Any]:
    if isinstance(a, FIPSParams):
        return {
            "algorithm": a.algorithm,
            "fips_id": a.fips_id,
            "nist_level": a.nist_level,
            "key_size_bits": a.key_size_bits,
            "quantum_safe": a.quantum_safe,
            "compliance": a.compliance,
            "family": a.family,
        }
    if isinstance(a, dict):
        return {
            "algorithm": a.get("algorithm", "Unknown"),
            "fips_id": a.get("fips_id", "Unknown"),
            "nist_level": int(a.get("nist_level", a.get("nistQuantumSecurityLevel", 0))),
            "key_size_bits": a.get("key_size_bits", a.get("keySize")),
            "quantum_safe": bool(a.get("quantum_safe", not a.get("shorVulnerable", True))),
            "compliance": a.get("compliance", ""),
            "family": a.get("family", "asymmetric"),
        }
    raise TypeError(f"unsupported asset type: {type(a)}")


def _asset_to_cbom_component(norm: dict[str, Any], idx: int, target: str) -> dict[str, Any]:
    alg = norm["algorithm"]
    ks = norm["key_size_bits"]
    nist = int(norm["nist_level"])
    qs = bool(norm["quantum_safe"])
    ks_str = str(ks) if ks is not None else alg
    name = f"{alg}-{ks_str}" if ks is not None else alg
    if alg == "RSA" and ks == 2048:
        name = "RSA-2048-OAEP-SHA256"
    bom_ref = f"crypto-asset-{alg.lower()}-{ks_str.lower()}-{idx}" if ks is not None else f"crypto-asset-{alg.lower()}-{idx}"
    bom_ref = bom_ref.replace(" ", "-")
    classical = _CLASSICAL_LEVEL.get(nist, 112)
    if alg == "RSA" and ks == 2048:
        classical = 112
    elif alg == "ML-KEM":
        classical = 192
    shor = not qs
    cnsa = qs
    # hybrid heuristic: if any ML-KEM present elsewhere, hybrid compliant handled at dict level; per-component follow qs
    primitive = "public-key-encryption"
    family = norm["family"]
    if family == "symmetric":
        primitive = "block-cipher"
    elif family == "kdf":
        primitive = "kdf"
    elif alg in ("ECDSA", "ECC"):
        primitive = "signature"
    elif alg == "ML-KEM":
        primitive = "key-encapsulation"
    elif alg == "X25519":
        primitive = "key-agreement"
    elif alg == "HKDF":
        primitive = "kdf"
    return {
        "type": "cryptographic-asset",
        "name": name,
        "bom-ref": bom_ref,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": primitive,
                "parameterSetIdentifier": ks_str,
                "executionEnvironment": "software-plain",
                "implementationPlatform": "cpython",
                "cryptoFunctions": ["encrypt", "decrypt", "keygen"] if family == "asymmetric" else ["encrypt", "decrypt"] if family == "symmetric" else ["derive"],
                "classicalSecurityLevel": classical,
                "nistQuantumSecurityLevel": nist,
            },
            **({"oid": _OIDS[alg]} if alg in _OIDS else {}),
            "detectionContext": {
                "sourceFile": _normalize_target(target),
                "sourceLine": 0,  # not measured
                "sinkLine": 0,  # not measured
                "flowHops": 1,
                "shorVulnerable": shor,
                "cnsa20Compliant": cnsa,
                "fips1403Status": "SUNSET_HISTORICAL" if alg == "RSA" and ks in (2048, 3072) else "COMPLIANT" if qs else "NON_COMPLIANT",
            },
        },
    }


def build_cbom_dict(assets: list[Any], target: str = "unknown", seed: int = 0, verdict: str | None = None, test_code: bool = False) -> dict[str, Any]:
    norms = [_norm_asset(a) for a in assets]
    has_pqc = any(n["quantum_safe"] for n in norms)
    has_classical_vuln = any(not n["quantum_safe"] for n in norms)
    has_ml_kem = any(n["algorithm"] == "ML-KEM" for n in norms)
    components = []
    for i, n in enumerate(norms):
        comp = _asset_to_cbom_component(n, i, target)
        components.append(comp)
    ts = _ts(seed)
    serial = _serial(seed, _normalize_target(target))
    components = sorted(components, key=lambda c: c["bom-ref"])
    if verdict is None:
        if not norms:  # test code only softens "nothing found"; it never hides a finding
            verdict = "BENIGN_TEST_CODE" if test_code else "NO_CRYPTO_DETECTED"
        elif has_ml_kem and has_classical_vuln:
            verdict = "COMPLIANT_QUANTUM_SAFE"
        elif any(not n["quantum_safe"] for n in norms):
            verdict = "NON_COMPLIANT_VULNERABLE"
        elif has_pqc:
            verdict = "COMPLIANT_QUANTUM_SAFE"
        else:
            verdict = "COMPLIANT_QUANTUM_SAFE"
    result: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "verdict": verdict,
        "metadata": {
            "timestamp": ts,
            "tools": [{"vendor": "PQBlocks", "name": "pqblocks_lint", "version": _VERSION}],
            "component": {"type": "application", "name": Path(_normalize_target(target)).stem or "target", "version": "1.0.0"},
        },
        "components": components,
        "dependencies": [{"ref": Path(_normalize_target(target)).stem or "target", "dependsOn": [c["bom-ref"] for c in components]}] if components else [],
    }
    return result


def build_sarif_dict(assets: list[Any], target: str = "unknown", seed: int = 0) -> dict[str, Any]:
    norms = [_norm_asset(a) for a in assets]
    ts = _ts(seed)
    rules = []
    results = []
    for n in norms:
        alg = n["algorithm"]
        nist = int(n["nist_level"])
        ks = n["key_size_bits"]
        ks_str = str(ks) if ks is not None else ""
        rule_id = f"PQBLOCKS-LINT/{alg.upper()}-{ks_str}" if ks_str else f"PQBLOCKS-LINT/{alg.upper()}"
        rule_id = rule_id.replace(" ", "-")
        # deduplicate rules
        if not any(r["id"] == rule_id for r in rules):
            rules.append({
                "id": rule_id,
                "name": alg,
                "shortDescription": {"text": f"Cryptographic primitive {alg} detected"},
                "fullDescription": {"text": f"FIPS {n['fips_id']} parameter set {ks_str}, NIST level {nist}"},
                "helpUri": "https://csrc.nist.gov/pubs/fips",
                "properties": {"nistQuantumSecurityLevel": nist, "quantumSafe": n["quantum_safe"]},
            })
        level = "error" if nist == 0 else "warning" if nist in (1, 2) else "note"
        if not n["quantum_safe"] and nist == 0:
            level = "error"
        elif n["quantum_safe"]:
            level = "note"
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{alg} ({ks_str}) nistLevel={nist} quantumSafe={n['quantum_safe']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": _normalize_target(target)}, "region": {"startLine": 1}}}],
            "properties": {"nistQuantumSecurityLevel": nist, "shorVulnerable": not n["quantum_safe"]},
        })
    # sort rules/results for determinism
    rules = sorted(rules, key=lambda r: r["id"])
    results = sorted(results, key=lambda r: r["ruleId"])
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "pqblocks_lint", "version": _VERSION, "informationUri": "https://github.com/PQBlocks/pqc-lint", "rules": rules}},
                "invocations": [{"executionSuccessful": True, "endTimeUtc": ts}],
                "artifacts": [{"location": {"uri": _normalize_target(target)}}] if _normalize_target(target) != "unknown" else [],
                "results": results,
            }
        ],
    }


def _write_json_sorted(path: str | Path, data: dict[str, Any]) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, sort_keys=True, indent=2)
    if not text.endswith("\n"):
        text += "\n"
    p.write_text(text, encoding="utf-8")
    return str(p)


def emit_cbom(assets: list[Any], output_path: str | Path, target: str = "unknown", seed: int = 0, verdict: str | None = None) -> str:
    d = build_cbom_dict(assets, target=target, seed=seed, verdict=verdict)
    return _write_json_sorted(output_path, d)


def emit_sarif(assets: list[Any], output_path: str | Path, target: str = "unknown", seed: int = 0) -> str:
    d = build_sarif_dict(assets, target=target, seed=seed)
    return _write_json_sorted(output_path, d)


def emit_outputs(assets: list[Any], fmt: str, output_path: str | Path, target: str = "unknown", seed: int = 0, verdict: str | None = None) -> str:
    f = fmt.strip().lower()
    if f == "cbom":
        return emit_cbom(assets, output_path, target=target, seed=seed, verdict=verdict)
    if f == "sarif":
        return emit_sarif(assets, output_path, target=target, seed=seed)
    raise ValueError(f"unsupported format '{fmt}': expected 'cbom' or 'sarif'")
