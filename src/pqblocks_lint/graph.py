"""Control-flow graph (CFG) and call graph (CG) construction for pqblocks-lint.

Builds a directed graph representing data dependencies and call relationships
in analyzed Python source code. Uses networkx for graph operations and
ast for AST parsing.

The graph is used by the taint-propagation engine to trace cryptographic
data flows from sources through transitive call chains to sinks.
"""

import ast
import re
from typing import Any

import networkx as nx

# Known cryptographic source function patterns (taint origins)
CRYPTO_SOURCES = frozenset({
    "generate_private_key",
    "generate",
    "encaps",
    "sign",
    "provision_signing_key",
    "provision_identity_key",
})

# Known cryptographic sink function patterns (taint destinations)
CRYPTO_SINKS = frozenset({
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "exchange",
    "derive",
})


# Modules whose import alone means a real ML-KEM implementation (liboqs-python's
# oqs needs a KeyEncapsulation("ML-KEM-*"/"Kyber*") call, see _facts).
_ML_KEM_MODULE = re.compile(r"^(kyber_py|mlkem|ml_kem)(\.|$)|^pqcrypto\.kem\.(ml_kem|kyber)")


def _facts(tree: ast.AST) -> tuple[bool, bool]:
    """Return (uses a real ML-KEM API, looks like test code) from imports/calls only."""
    kem = tests = False
    test_imports = names = False
    for n in ast.walk(tree):
        mods = [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module or ""] if isinstance(n, ast.ImportFrom) else []
        kem |= any(_ML_KEM_MODULE.match(m) for m in mods)
        test_imports |= any(m.split(".")[0] in ("pytest", "unittest") for m in mods)
        if isinstance(n, ast.Call) and isinstance(n.func, (ast.Name, ast.Attribute)) and getattr(n.func, "id", getattr(n.func, "attr", "")) == "KeyEncapsulation":
            a = n.args[0] if n.args else None
            kem |= isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value.lower().startswith(("ml-kem", "kyber"))
        names |= isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name.startswith(("test", "Test"))
    return kem, test_imports and names


class CFGNode:
    """Represents a node in the control-flow graph."""

    def __init__(
        self,
        node_id: str,
        stmt_type: str,
        name: str = "",
        is_source: bool = False,
        is_sink: bool = False,
    ):
        self.id = node_id
        self.stmt_type = stmt_type
        self.name = name
        self.is_source = is_source
        self.is_sink = is_sink
        self.metadata: dict[str, Any] = {}

    def __repr__(self) -> str:
        return f"CFGNode({self.id}, {self.stmt_type}, {self.name})"


def build_cfg_cg(source_path: str) -> nx.DiGraph:
    """Build a combined CFG+CG graph from a Python source file.

    Parses the AST, constructs nodes for each statement and function,
    and adds directed edges for control flow and data dependencies.
    Analyzes function bodies recursively to find cryptographic calls.

    Args:
        source_path: Path to the Python file to analyze.

    Returns:
        NetworkX DiGraph where nodes are CFGNode objects and edges
        represent data-flow dependencies. Nodes may have
        ``is_source`` and ``is_sink`` attributes set.

    Raises:
        FileNotFoundError: If source_path does not exist.
        SyntaxError: If the file contains invalid Python syntax.
    """
    with open(source_path) as f:
        source_code = f.read()

    tree = ast.parse(source_code, filename=source_path)
    graph: nx.DiGraph = nx.DiGraph()
    graph.graph["pqc_kem"], graph.graph["test_code"] = _facts(tree)

    # Track function definitions and their bodies for CG edges
    func_defs: dict[str, ast.FunctionDef] = {}
    # Track variable assignments for data-flow edges
    assignments: dict[str, ast.AST] = {}
    # Node counter for unique IDs
    node_counter = 0

    def make_node(stmt_type: str, name: str = "") -> str:
        nonlocal node_counter
        node_id = f"n{node_counter}"
        node_counter += 1
        graph.add_node(node_id, obj=CFGNode(node_id, stmt_type, name))
        return node_id

    def get_function_name(node: ast.AST) -> str:
        """Extract the function name from various node types."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{get_name(node.value)}.{node.attr}"
        return ""

    def _extract_key_size(call_node: ast.Call) -> int | None:
        """Extract key_size from rsa.generate_private_key or similar calls."""
        for kw in call_node.keywords:
            if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                return int(kw.value.value)
        return None

    def get_name(node: ast.AST) -> str:
        """Get the name from an AST name/attribute node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{get_name(node.value)}.{node.attr}"
        return ""

    def _is_crypto_source_call(func_name: str) -> bool:
        """Check if a function name matches a known crypto source.
        Only checks exact suffix match on the leaf name, not substring."""
        leaf = func_name.split(".")[-1]
        return leaf in CRYPTO_SOURCES

    def _is_crypto_sink_call(func_name: str) -> bool:
        """Check if a function name matches a known crypto sink.
        Only checks exact suffix match on the leaf name, not substring."""
        leaf = func_name.split(".")[-1]
        return leaf in CRYPTO_SINKS

    def _is_symmetric_cipher_call(func_name: str) -> bool:
        """Check if a function name looks like a symmetric cipher operation."""
        leaf = func_name.split(".")[-1].lower()
        return leaf in ("encrypt", "decrypt")

    def _add_receiver_edge(call_node: ast.Call) -> None:
        if isinstance(call_node.func, ast.Attribute):
            receiver = call_node.func.value
            if isinstance(receiver, ast.Name) and receiver.id in assignments:
                receiver_tid = assignments[receiver.id]
                for nid, data in graph.nodes(data=True):
                    obj = data.get("obj")
                    if isinstance(obj, CFGNode) and obj.stmt_type == "call" and obj.name == get_function_name(call_node.func):
                        graph.add_edge(receiver_tid, nid)
                        break

    def _analyze_function_body(
        body, graph, assignments, func_defs, make_node, get_name, node_counter
    ):
        """Analyze a function or class body for crypto calls and data flow."""
        for stmt in body:
            if isinstance(stmt, ast.Assign):
                raw_targets = []
                for t in stmt.targets:
                    if isinstance(t, ast.Tuple):
                        for elt in t.elts:
                            raw_targets.append(elt)
                    else:
                        raw_targets.append(t)
                created_targets = []
                for raw in raw_targets:
                    tname = get_name(raw)
                    tid = make_node("assignment", tname)
                    created_targets.append((tid, tname, raw))
                for tid, tname, raw in created_targets:
                    if isinstance(stmt.value, ast.Call):
                        func_name = get_function_name(stmt.value.func)
                        if _is_crypto_source_call(func_name):
                            graph.nodes[tid]["obj"].is_source = True
                            graph.nodes[tid]["obj"].metadata["source_func"] = func_name
                            # Extract key_size from the call if present
                            key_size = _extract_key_size(stmt.value)
                            if key_size is not None:
                                graph.nodes[tid]["obj"].metadata["key_size"] = key_size
                        if _is_crypto_sink_call(func_name) or _is_symmetric_cipher_call(func_name):
                            graph.nodes[tid]["obj"].is_sink = True
                            graph.nodes[tid]["obj"].metadata["sink_func"] = func_name
                        value_node = make_node("call", get_function_name(stmt.value.func))
                        graph.add_edge(value_node, tid)
                        _add_receiver_edge(stmt.value)
                    elif isinstance(stmt.value, ast.Name):
                        if stmt.value.id in assignments:
                            graph.add_edge(assignments[stmt.value.id], tid)
                        else:
                            value_node = make_node("name", stmt.value.id)
                            graph.add_edge(value_node, tid)
                    elif isinstance(stmt.value, ast.Attribute):
                        value_node = make_node("attribute", get_name(stmt.value))
                        graph.add_edge(value_node, tid)
                    assignments[tname] = tid

            elif isinstance(stmt, ast.Return):
                if isinstance(stmt.value, ast.Call):
                    func_name = get_function_name(stmt.value.func)
                    call_node = make_node("call", func_name)
                    if _is_crypto_source_call(func_name):
                        graph.nodes[call_node]["obj"].is_source = True
                        graph.nodes[call_node]["obj"].metadata["source_func"] = func_name
                    if _is_crypto_sink_call(func_name) or _is_symmetric_cipher_call(func_name):
                        graph.nodes[call_node]["obj"].is_sink = True
                        graph.nodes[call_node]["obj"].metadata["sink_func"] = func_name
                    _add_receiver_edge(stmt.value)

            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                func_name = get_function_name(stmt.value.func)
                call_node = make_node("call", func_name)
                if _is_crypto_source_call(func_name):
                    graph.nodes[call_node]["obj"].is_source = True
                    graph.nodes[call_node]["obj"].metadata["source_func"] = func_name
                if _is_crypto_sink_call(func_name) or _is_symmetric_cipher_call(func_name):
                    graph.nodes[call_node]["obj"].is_sink = True
                    graph.nodes[call_node]["obj"].metadata["sink_func"] = func_name
                _add_receiver_edge(stmt.value)

            elif isinstance(stmt, ast.FunctionDef):
                func_defs[stmt.name] = stmt
                func_node = make_node("function", stmt.name)
                _analyze_function_body(
                    stmt.body, graph, assignments, func_defs, make_node, get_name, node_counter
                )

            elif isinstance(stmt, ast.ClassDef):
                class_node = make_node("class", stmt.name)
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.Assign)):
                        body_node = make_node("statement", get_name(item) or stmt.name)
                        graph.add_edge(class_node, body_node)
                        _analyze_function_body(
                            [item], graph, assignments, func_defs, make_node, get_name, node_counter
                        )

    # First pass: collect function definitions
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            func_defs[node.name] = node

    # Second pass: build nodes and edges
    for node in ast.walk(tree):
        # Function definitions at module level
        if isinstance(node, ast.FunctionDef):
            _analyze_function_body(
                node.body, graph, assignments, func_defs, make_node, get_name, node_counter
            )

        # Class definitions at module level
        elif isinstance(node, ast.ClassDef):
            class_node = make_node("class", node.name)
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.Assign)):
                    body_node = make_node("statement", get_name(item) or node.name)
                    graph.add_edge(class_node, body_node)
                    _analyze_function_body(
                        [item], graph, assignments, func_defs, make_node, get_name, node_counter
                    )

        # Module-level assignments with call targets (includes aliased imports)
        elif isinstance(node, ast.Assign):
            raw_targets = []
            for t in node.targets:
                if isinstance(t, ast.Tuple):
                    for elt in t.elts:
                        raw_targets.append(elt)
                else:
                    raw_targets.append(t)
            created_targets = []
            for raw in raw_targets:
                tname = get_name(raw)
                tid = make_node("assignment", tname)
                created_targets.append((tid, tname, raw))
            for tid, tname, raw in created_targets:
                if isinstance(node.value, ast.Call):
                    func_name = get_function_name(node.value.func)
                    if _is_crypto_source_call(func_name):
                        graph.nodes[tid]["obj"].is_source = True
                        graph.nodes[tid]["obj"].metadata["source_func"] = func_name
                    if _is_crypto_sink_call(func_name) or _is_symmetric_cipher_call(func_name):
                        graph.nodes[tid]["obj"].is_sink = True
                        graph.nodes[tid]["obj"].metadata["sink_func"] = func_name
                    value_node = make_node("call", func_name)
                    graph.add_edge(value_node, tid)
                    _add_receiver_edge(node.value)
                elif isinstance(node.value, ast.Name):
                    if node.value.id in assignments:
                        graph.add_edge(assignments[node.value.id], tid)
                    else:
                        value_node = make_node("name", node.value.id)
                        graph.add_edge(value_node, tid)
                elif isinstance(node.value, ast.Attribute):
                    value_node = make_node("attribute", get_name(node.value))
                    # Check if the attribute call is a crypto operation
                    attr_func = get_function_name(node.value)
                    if _is_crypto_source_call(attr_func):
                        graph.nodes[tid]["obj"].is_source = True
                        graph.nodes[tid]["obj"].metadata["source_func"] = attr_func
                    if _is_crypto_sink_call(attr_func) or _is_symmetric_cipher_call(attr_func):
                        graph.nodes[tid]["obj"].is_sink = True
                        graph.nodes[tid]["obj"].metadata["sink_func"] = attr_func
                    graph.add_edge(value_node, tid)
                assignments[tname] = tid

        # Module-level expression statements (standalone calls)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            func_name = get_function_name(node.value.func)
            call_node = make_node("call", func_name)
            if _is_crypto_source_call(func_name):
                graph.nodes[call_node]["obj"].is_source = True
                graph.nodes[call_node]["obj"].metadata["source_func"] = func_name
            if _is_crypto_sink_call(func_name) or _is_symmetric_cipher_call(func_name):
                graph.nodes[call_node]["obj"].is_sink = True
                graph.nodes[call_node]["obj"].metadata["sink_func"] = func_name
            _add_receiver_edge(node.value)

    # Add taint edges: connect sources to sinks through call chains
    for u, v, data in list(graph.edges(data=True)):
        src_node = graph.nodes[u].get("obj")
        dst_node = graph.nodes[v].get("obj")
        if src_node and dst_node:
            if src_node.is_source and not dst_node.is_sink:
                graph.add_edge(u, v, taint=True)
            if dst_node.is_sink:
                graph.add_edge(u, v, taint=True)

    return graph


def get_source_nodes(graph: nx.DiGraph) -> list[str]:
    """Get all source (taint-origin) nodes in the graph."""
    return [
        n for n, d in graph.nodes(data=True)
        if d.get("obj") and d["obj"].is_source
    ]


def get_sink_nodes(graph: nx.DiGraph) -> list[str]:
    """Get all sink (taint-destination) nodes in the graph."""
    return [
        n for n, d in graph.nodes(data=True)
        if d.get("obj") and d["obj"].is_sink
    ]


def get_taint_closure(graph: nx.DiGraph, sources: list[str]) -> set[str]:
    """Compute the taint closure from source nodes.

    Returns all nodes reachable from any source node via directed edges.
    """
    closure: set[str] = set()
    for src in sources:
        if src in graph:
            reachable = nx.descendants(graph, src)
            closure.update(reachable)
            closure.add(src)
    return closure


def find_tainted_paths(graph: nx.DiGraph, sources: list[str], sinks: list[str]) -> list[list[str]]:
    """Find all paths from source nodes to sink nodes in the graph."""
    paths: list[list[str]] = []
    for src in sources:
        for snk in sinks:
            if src in graph and snk in graph:
                try:
                    all_paths = list(nx.all_simple_paths(graph, src, snk))
                    paths.extend(all_paths)
                except nx.NetworkXNoPath:
                    continue
    return paths
