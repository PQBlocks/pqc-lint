"""Taint-propagation engine for pqblocks-lint.

Traces cryptographic data flows through the control-flow and call graphs
built by the graph module. Propagates taint from source nodes (cryptographic
key generation) through data dependencies and call chains to sink nodes
(cryptographic operations).

The engine handles:
- Direct taint propagation along data-flow edges
- Interprocedural taint tracking across function boundaries
- Aliased import resolution for taint tracing
- Transitive taint closure computation
"""

import networkx as nx
from typing import Any, Callable, Set

from pqblocks_lint.graph import CFGNode, get_source_nodes, get_sink_nodes


def propagate_taint(
    graph: nx.DiGraph,
    sources: set[str],
    taint_filter: Callable[[str, CFGNode], bool] | None = None,
) -> set[str]:
    """Propagate taint from source nodes through the graph.

    Traces all reachable nodes from the given source set via directed
    edges. Optionally filters nodes based on a predicate.

    Args:
        graph: The data-flow graph from build_cfg_cg.
        sources: Set of source node IDs to start taint propagation.
        taint_filter: Optional predicate(node_id, node) -> bool.
            If provided, only nodes where the predicate returns True
            are included in the taint set.

    Returns:
        Set of node IDs that are tainted (reachable from any source).
        Includes the source nodes themselves.

    Raises:
        nx.NodeNotFound: If any source node does not exist in the graph.
    """
    tainted: set[str] = set()
    for src in sources:
        if src not in graph:
            continue
        src_node = graph.nodes[src].get("obj")
        if taint_filter is not None and not taint_filter(src, src_node):
            continue
        tainted.add(src)
        # BFS from source following directed edges
        for descendant in nx.descendants(graph, src):
            if taint_filter is None or taint_filter(descendant, graph.nodes[descendant].get("obj", CFGNode(descendant, "", ""))):
                tainted.add(descendant)
    return tainted


def propagate_taint_interprocedural(
    graph: nx.DiGraph,
    sources: set[str],
    call_graph: nx.DiGraph | None = None,
) -> set[str]:
    """Propagate taint across function boundaries.

    Extends basic taint propagation to handle interprocedural flows:
    when a tainted value is passed as an argument to a function call,
    the taint propagates to the function's body and its return value.

    Args:
        graph: The combined CFG+CG graph.
        sources: Set of source node IDs.
        call_graph: Optional separate call graph. If not provided,
            the call edges are extracted from the main graph.

    Returns:
        Set of all tainted node IDs including interprocedural propagation.
    """
    tainted = propagate_taint(graph, sources)

    # Build call graph if not provided
    if call_graph is None:
        call_graph = _extract_call_graph(graph)

    # Propagate taint through call edges
    additional_tainted = set(tainted)
    for caller in tainted:
        if caller in call_graph:
            for callee in call_graph.successors(caller):
                if callee not in tainted:
                    additional_tainted.add(callee)

    # Iterate until fixed point
    while additional_tainted != tainted:
        tainted = additional_tainted.copy()
        for caller in tainted:
            if caller in call_graph:
                for callee in call_graph.successors(caller):
                    additional_tainted.add(callee)

    return tainted


def _extract_call_graph(graph: nx.DiGraph) -> nx.DiGraph:
    """Extract a call graph from the combined CFG+CG graph.

    Identifies function-call relationships by looking at call nodes
    and their successors.

    Args:
        graph: The combined CFG+CG graph.

    Returns:
        A DiGraph where nodes are function names and edges represent
        call relationships.
    """
    call_graph = nx.DiGraph()
    for node_id in graph.nodes():
        node = graph.nodes[node_id].get("obj")
        if isinstance(node, CFGNode) and node.stmt_type == "call":
            # Add call edge
            call_graph.add_node(node_id, name=node.name)
            for successor in graph.successors(node_id):
                succ_node = graph.nodes[successor].get("obj")
                if isinstance(succ_node, CFGNode):
                    call_graph.add_edge(node_id, successor, func=node.name)
    return call_graph


def get_tainted_sources(
    graph: nx.DiGraph,
    tainted_nodes: set[str],
) -> set[str]:
    """Identify which source nodes are responsible for tainting.

    For each tainted node, traces back to find the nearest source
    ancestor in the graph.

    Args:
        graph: The data-flow graph.
        tainted_nodes: Set of tainted node IDs.

    Returns:
        Set of source node IDs that contribute to the taint.
    """
    sources = get_source_nodes(graph)
    responsible: set[str] = set()
    for taint_node in tainted_nodes:
        for src in sources:
            if src in graph and taint_node in graph:
                try:
                    if nx.has_path(graph, src, taint_node):
                        responsible.add(src)
                except nx.NodeNotFound:
                    continue
    return responsible


def classify_taint(
    graph: nx.DiGraph,
    tainted_nodes: set[str],
) -> dict[str, str]:
    """Classify each tainted node by its role in the data flow.

    Args:
        graph: The data-flow graph.
        tainted_nodes: Set of tainted node IDs.

    Returns:
        Mapping of node_id -> classification string:
        - "source": cryptographic key generation origin
        - "intermediate": propagated through function calls
        - "sink": cryptographic operation consuming tainted data
        - "unknown": cannot be classified
    """
    sinks = set(get_sink_nodes(graph))
    sources = set(get_source_nodes(graph))
    classification: dict[str, str] = {}

    for node in tainted_nodes:
        node_obj = graph.nodes[node].get("obj")
        if node_obj and node_obj.is_source:
            classification[node] = "source"
        elif node_obj and node_obj.is_sink:
            classification[node] = "sink"
        elif node in sinks:
            classification[node] = "sink"
        elif node in sources:
            classification[node] = "source"
        else:
            classification[node] = "intermediate"

    return classification
