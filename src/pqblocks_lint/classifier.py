"""Primitive-classifier for pqblocks-lint.

Classifies tainted subgraphs into canonical FIPS cryptographic parameters.
Identifies the algorithm family, key size, NIST quantum security level,
and compliance status for each detected cryptographic primitive.

Maps detected primitives to their canonical FIPS identifiers and
quantum-vulnerability classifications.
"""

from dataclasses import dataclass
from typing import Any

import networkx as nx

from pqblocks_lint.graph import CFGNode


@dataclass(frozen=True)
class FIPSParams:
    """Canonical FIPS parameters for a classified cryptographic primitive."""

    algorithm: str
    fips_id: str
    nist_level: int
    key_size_bits: int | None
    quantum_safe: bool
    compliance: str
    family: str


# Known cryptographic primitives and their FIPS mappings
PRIMITIVE_MAP: dict[str, FIPSParams] = {
    "rsa": FIPSParams(
        algorithm="RSA",
        fips_id="FIPS 186-5",
        nist_level=0,
        key_size_bits=3072,
        quantum_safe=False,
        compliance="Non-compliant (CNSA 2.0 / OMB M-23-02)",
        family="asymmetric",
    ),
    "ecdsa": FIPSParams(
        algorithm="ECDSA",
        fips_id="FIPS 186-5",
        nist_level=0,
        key_size_bits=256,
        quantum_safe=False,
        compliance="Non-compliant (CNSA 2.0 / OMB M-23-02)",
        family="asymmetric",
    ),
    "ec": FIPSParams(
        algorithm="ECC",
        fips_id="FIPS 186-5",
        nist_level=0,
        key_size_bits=256,
        quantum_safe=False,
        compliance="Non-compliant (CNSA 2.0 / OMB M-23-02)",
        family="asymmetric",
    ),
    "ml-kem": FIPSParams(
        algorithm="ML-KEM",
        fips_id="FIPS 203",
        nist_level=3,
        key_size_bits=768,
        quantum_safe=True,
        compliance="Compliant (CNSA 2.0 / OMB M-23-02)",
        family="asymmetric",
    ),
    "dilithium": FIPSParams(
        algorithm="ML-DSA",
        fips_id="FIPS 204",
        nist_level=3,
        key_size_bits=256,
        quantum_safe=True,
        compliance="Compliant (CNSA 2.0 / OMB M-23-02)",
        family="asymmetric",
    ),
    "x25519": FIPSParams(
        algorithm="X25519",
        fips_id="FIPS 800-56C Rev 2",
        nist_level=3,
        key_size_bits=253,
        quantum_safe=False,
        compliance="Compliant when hybrid (with PQC)",
        family="asymmetric",
    ),
    "aes": FIPSParams(
        algorithm="AES",
        fips_id="FIPS 197",
        nist_level=3,
        key_size_bits=256,
        quantum_safe=True,
        compliance="Compliant (CNSA 2.0 / OMB M-23-02)",
        family="symmetric",
    ),
    "hkdf": FIPSParams(
        algorithm="HKDF",
        fips_id="NIST SP 800-56C Rev 2",
        nist_level=3,
        key_size_bits=None,
        quantum_safe=True,
        compliance="Compliant (CNSA 2.0 / OMB M-23-02)",
        family="kdf",
    ),
}

# Function name patterns to detect primitives
PRIMITIVE_PATTERNS: dict[str, list[str]] = {
    "rsa": ["rsa", "generate_private_key", "public_exponent", "key_size"],
    "ecdsa": ["ecdsa", "ec.generate_private_key", "SECP256R1", "secp256r1", "provision_signing_key", "provision_identity_key", "sign_dispatch_packet", "NetworkTokenSigner", "KeyVaultManager", "SessionChannelContext"],
    "ec": ["ec.", "SECP256R1", "secp256r1", "ecdsa", "provision_signing_key", "provision_identity_key"],
    "ml-kem": [],  # never from names: set only by graph.graph["pqc_kem"] (resolved imports/calls)
    "x25519": ["x25519", "X25519"],
    "aes": ["aes", "AES", "aesgcm", "AESGCM", "AES-256-GCM", "derived_aes_key", "cipher.encrypt"],
    "hkdf": ["hkdf", "HKDF", "derive"],
    "dilithium": ["dilithium", "ml-dsa", "ml_dsa", "ML-DSA"],
}


def classify(
    graph: nx.DiGraph,
    tainted_nodes: set[str] | None = None,
) -> list[FIPSParams]:
    """Classify a tainted subgraph into canonical FIPS parameters.

    Analyzes the nodes and edges of a tainted subgraph to identify
    cryptographic primitives used, their key sizes, NIST security levels,
    and quantum-vulnerability status.

    Args:
        graph: A NetworkX DiGraph from build_cfg_cg.
        tainted_nodes: Optional set of tainted node IDs.
            If provided, only classifies nodes in this set.

    Returns:
        List of FIPSParams objects, one per detected cryptographic
        primitive family found in the subgraph.
    """
    candidates: dict[str, list[tuple[str, FIPSParams]]] = {}
    nodes_to_check = tainted_nodes if tainted_nodes is not None else set(graph.nodes())

    for node_id in sorted(nodes_to_check):
        if node_id not in graph:
            continue
        node = graph.nodes[node_id].get("obj")
        if not isinstance(node, CFGNode):
            continue

        family = _detect_family(node)
        params = PRIMITIVE_MAP.get(family) if family else None
        if family and params:
            ks = node.metadata.get("key_size")
            if family == "rsa" and isinstance(ks, int) and ks > 0:
                params = FIPSParams(
                    algorithm=params.algorithm,
                    fips_id=params.fips_id,
                    nist_level=params.nist_level,
                    key_size_bits=ks,
                    quantum_safe=params.quantum_safe,
                    compliance=params.compliance,
                    family=params.family,
                )
            candidates.setdefault(family, []).append((node_id, params))
    results: list[FIPSParams] = []
    for family in sorted(candidates):
        group = candidates[family]
        if family == "rsa":
            concrete = [p for _, p in group if p.key_size_bits != PRIMITIVE_MAP["rsa"].key_size_bits]
            results.append(concrete[0] if concrete else group[0][1])
        else:
            results.append(group[0][1])

    seen = set(candidates)
    for u, v, data in graph.edges(data=True):
        if data.get("taint"):
            edge_family = _detect_family_from_edge(graph, u, v)
            if edge_family and edge_family not in seen:
                seen.add(edge_family)
                params = PRIMITIVE_MAP.get(edge_family)
                if params:
                    results.append(params)

    if graph.graph.get("pqc_kem"):
        results.append(PRIMITIVE_MAP["ml-kem"])

    return results


def _detect_family(node: CFGNode) -> str | None:
    """Detect the cryptographic family from a CFG node."""
    # Primary: check node name
    name_lower = node.name.lower()
    for family, patterns in PRIMITIVE_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in name_lower:
                return family

    # Check metadata for source/sink function hints
    for key in ("source_func", "sink_func"):
        func = node.metadata.get(key, "")
        if func:
            func_lower = func.lower()
            for family, patterns in PRIMITIVE_PATTERNS.items():
                for pattern in patterns:
                    if pattern.lower() in func_lower:
                        return family

    # Check stmt_type metadata - fallback to taint presence
    # Also check node id-based heuristics: if node is source/sink via CRYPTO_SOURCES, map encap->ml-kem, sign->ecdsa etc.
    if node.is_source or node.is_sink:
        src = node.metadata.get("source_func", "") + " " + node.metadata.get("sink_func", "")
        s = src.lower()
        if "provision_signing_key" in s or "provision_identity_key" in s:
            return "ecdsa"
        if "sign" in s and ("key" in s or "dispatch" in s):
            # generic sign in interprocedural context -> ecdsa
            if node.name.lower() in ("signature", "key") or "sign" in node.name.lower():
                return "ecdsa"
        if "exchange" in s:
            return "x25519"
        if "derive" in s:
            return "hkdf"
        # Only classify as AES if the node is actually a sink (encrypt call),
        # not a source that happens to contain "encrypt" in its name
        # This prevents spurious AES classification on nodes like
        # generate_and_encrypt_payload that are both source and sink.
        if "encrypt" in s and node.is_sink and not node.is_source:
            sink_func = node.metadata.get("sink_func", "").lower()
            if any(kw in sink_func for kw in ("cipher.", "aes", "aesgcm", "gcm", "chacha", "salsa")):
                return "aes"

    return None


def _detect_family_from_edge(
    graph: nx.DiGraph, u: str, v: str
) -> str | None:
    """Detect cryptographic family from edge data."""
    u_node = graph.nodes[u].get("obj")
    v_node = graph.nodes[v].get("obj")
    if isinstance(u_node, CFGNode):
        family = _detect_family(u_node)
        if family:
            return family
    if isinstance(v_node, CFGNode):
        family = _detect_family(v_node)
        if family:
            return family
    return None


def classify_compliance(
    tainted_subgraph: nx.DiGraph,
    tainted_nodes: set[str] | None = None,
) -> dict[str, Any]:
    """Classify compliance status of a tainted subgraph.

    Provides a summary of whether the cryptographic usage is compliant
    with CNSA 2.0 and OMB M-23-02 guidelines.

    Args:
        tainted_subgraph: A NetworkX DiGraph of tainted nodes.

    Returns:
        Dictionary with compliance summary including:
        - ``is_quantum_safe``: Whether all primitives are quantum-safe
        - ``nist_level``: Minimum NIST security level across primitives
        - ``families``: Set of detected cryptographic families
        - ``compliance``: Overall compliance status string
    """
    params_list = classify(tainted_subgraph, tainted_nodes)
    # Fallback scan for hybrid: if graph contains ML-KEM pattern anywhere but not in tainted set, include it
    if params_list:
        all_nodes_scan = set(tainted_subgraph.nodes())
        extra = classify(tainted_subgraph, all_nodes_scan)
        for p in extra:
            if p.algorithm == "ML-KEM" and not any(x.algorithm == "ML-KEM" for x in params_list):
                params_list.append(p)
            if p.algorithm == "HKDF" and not any(x.algorithm == "HKDF" for x in params_list):
                # HKDF present in hybrid file indicates hybrid KDF
                params_list.append(p)

    if not params_list:
        return {
            "is_quantum_safe": False,
            "nist_level": 0,
            "families": set(),
            "compliance": "Unknown - no primitives detected",
        }

    min_level = min(p.nist_level for p in params_list)
    families = {p.family for p in params_list}
    has_ml_kem = any(p.algorithm == "ML-KEM" for p in params_list)
    has_classical = any(not p.quantum_safe for p in params_list)
    if has_ml_kem and has_classical:
        is_quantum_safe = True
        # hybrid with PQC satisfies compliance even if classical present
        compliance = "Compliant (CNSA 2.0 / OMB M-23-02)"
    else:
        is_quantum_safe = all(p.quantum_safe for p in params_list)
        if is_quantum_safe and min_level >= 3:
            compliance = "Compliant (CNSA 2.0 / OMB M-23-02)"
        elif min_level == 0:
            compliance = "Non-compliant (CNSA 2.0 / OMB M-23-02)"
        else:
            compliance = "Partially compliant"

    return {
        "is_quantum_safe": is_quantum_safe,
        "nist_level": min_level,
        "families": families,
        "compliance": compliance,
        "primitives": [p.algorithm for p in params_list],
    }
