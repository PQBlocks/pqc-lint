"""Tests for pqblocks-lint taint-propagation engine.

Validates:
- Direct taint propagation through data-flow edges
- Interprocedural taint tracking across call boundaries
- Source identification and taint classification
- Edge-case handling for empty graphs and disconnected nodes
"""

import pytest
import networkx as nx

from pqblocks_lint.graph import CFGNode, build_cfg_cg, get_source_nodes
from pqblocks_lint.taint import (
    classify_taint,
    get_tainted_sources,
    propagate_taint,
    propagate_taint_interprocedural,
)

INSTANCE_DIR = __import__("pathlib").Path(__file__).parent / "test-instances"


class TestPropagateTaint:
    """Tests for propagate_taint function."""

    def test_propagate_from_source(self):
        """Taint propagates from source to all reachable nodes."""
        graph = nx.DiGraph()
        graph.add_edge("src1", "mid1")
        graph.add_edge("mid1", "sink1")
        tainted = propagate_taint(graph, {"src1"})
        assert "src1" in tainted
        assert "mid1" in tainted
        assert "sink1" in tainted

    def test_propagate_multiple_sources(self):
        """Taint from multiple sources combines correctly."""
        graph = nx.DiGraph()
        graph.add_edge("src1", "mid1")
        graph.add_edge("src2", "mid2")
        graph.add_edge("mid1", "sink1")
        graph.add_edge("mid2", "sink2")
        tainted = propagate_taint(graph, {"src1", "src2"})
        assert "src1" in tainted and "mid1" in tainted
        assert "src2" in tainted and "mid2" in tainted

    def test_propagate_empty_sources(self):
        """Empty source set produces empty tainted set."""
        graph = nx.DiGraph()
        graph.add_edge("a", "b")
        tainted = propagate_taint(graph, set())
        assert tainted == set()

    def test_propagate_with_filter(self):
        """Taint filter restricts which nodes appear in the tainted set."""
        graph = nx.DiGraph()
        graph.add_edge("src1", "mid1")
        graph.add_edge("mid1", "sink1")
        graph.nodes["src1"]["obj"] = CFGNode("src1", "assignment", "key", is_source=True)
        graph.nodes["mid1"]["obj"] = CFGNode("mid1", "assignment", "temp")
        graph.nodes["sink1"]["obj"] = CFGNode("sink1", "assignment", "encrypted", is_sink=True)

        def allow_only_sources_and_sinks(node_id, node):
            return (hasattr(node, "is_source") and node.is_source) or \
                   (hasattr(node, "is_sink") and node.is_sink)

        tainted = propagate_taint(graph, {"src1"}, taint_filter=allow_only_sources_and_sinks)
        assert "src1" in tainted
        assert "mid1" not in tainted
        assert "sink1" in tainted

    def test_propagate_nonexistent_source(self):
        """Non-existent source node is silently skipped."""
        graph = nx.DiGraph()
        graph.add_edge("a", "b")
        tainted = propagate_taint(graph, {"nonexistent"})
        assert tainted == set()

    def test_propagate_disconnected_graph(self):
        """Taint does not cross disconnected components."""
        graph = nx.DiGraph()
        graph.add_edge("src1", "sink1")
        graph.add_node("disconnected")
        tainted = propagate_taint(graph, {"src1"})
        assert "disconnected" not in tainted

    def test_propagate_from_instance_01(self):
        """Propagate taint from actual RSA instance."""
        path = INSTANCE_DIR / "instance_01_classical_rsa.py"
        graph = build_cfg_cg(str(path))
        sources = set(get_source_nodes(graph))
        tainted = propagate_taint(graph, sources)
        assert len(tainted) > 0
        assert sources.issubset(tainted)

    def test_propagate_from_instance_03(self):
        """Propagate taint from interprocedural instance."""
        path = INSTANCE_DIR / "instance_03_interprocedural_flow.py"
        graph = build_cfg_cg(str(path))
        sources = set(get_source_nodes(graph))
        tainted = propagate_taint(graph, sources)
        assert len(tainted) > 0
        assert sources.issubset(tainted)


class TestPropagateTaintInterprocedural:
    """Tests for interprocedural taint propagation."""

    def test_interpropagate_simple(self):
        """Taint propagates through simple call chain."""
        graph = nx.DiGraph()
        graph.add_edge("caller", "callee")
        graph.add_edge("callee", "sink")
        tainted = propagate_taint_interprocedural(graph, {"caller"})
        assert "caller" in tainted
        assert "callee" in tainted
        assert "sink" in tainted

    def test_interpropagate_disconnected(self):
        """Taint does not propagate to disconnected functions."""
        graph = nx.DiGraph()
        graph.add_edge("caller", "callee")
        graph.add_node("orphan")
        tainted = propagate_taint_interprocedural(graph, {"caller"})
        assert "orphan" not in tainted

    def test_interpropagate_from_instance_03(self):
        """Interprocedural taint in instance_03."""
        path = INSTANCE_DIR / "instance_03_interprocedural_flow.py"
        graph = build_cfg_cg(str(path))
        sources = set(get_source_nodes(graph))
        tainted = propagate_taint_interprocedural(graph, sources)
        assert len(tainted) > 0
        assert sources.issubset(tainted)

    def test_interpropagate_empty_graph(self):
        """Empty graph produces empty taint set."""
        graph = nx.DiGraph()
        tainted = propagate_taint_interprocedural(graph, set())
        assert tainted == set()


class TestGetTaintedSources:
    """Tests for get_tainted_sources function."""

    def test_identify_sources(self):
        """Identify which sources contribute to taint."""
        graph = nx.DiGraph()
        graph.add_edge("src1", "mid1")
        graph.add_edge("mid1", "sink1")
        graph.add_edge("src2", "sink1")
        graph.nodes["src1"]["obj"] = CFGNode("src1", "assignment", "key", is_source=True)
        graph.nodes["src2"]["obj"] = CFGNode("src2", "assignment", "key", is_source=True)
        tainted = {"mid1", "sink1"}
        sources = get_tainted_sources(graph, tainted)
        assert "src1" in sources
        assert "src2" in sources

    def test_no_sources(self):
        """No sources in graph returns empty set."""
        graph = nx.DiGraph()
        graph.add_node("a")
        sources = get_tainted_sources(graph, {"a"})
        assert sources == set()

    def test_from_instance_01(self):
        """Identify taint sources in RSA instance."""
        path = INSTANCE_DIR / "instance_01_classical_rsa.py"
        graph = build_cfg_cg(str(path))
        sources = set(get_source_nodes(graph))
        tainted = propagate_taint(graph, sources)
        responsible = get_tainted_sources(graph, tainted)
        assert responsible == sources


class TestClassifyTaint:
    """Tests for classify_taint function."""

    def test_classify_basic(self):
        """Classify nodes into source/intermediate/sink."""
        graph = nx.DiGraph()
        graph.add_edge("src1", "mid1")
        graph.add_edge("mid1", "sink1")
        graph.nodes["src1"]["obj"] = CFGNode("src1", "assignment", "key", is_source=True)
        graph.nodes["sink1"]["obj"] = CFGNode("sink1", "assignment", "encrypted", is_sink=True)
        tainted = {"src1", "mid1", "sink1"}
        classification = classify_taint(graph, tainted)
        assert classification["src1"] == "source"
        assert classification["sink1"] == "sink"
        assert classification["mid1"] == "intermediate"

    def test_classify_empty(self):
        """Empty tainted set produces empty classification."""
        graph = nx.DiGraph()
        classification = classify_taint(graph, set())
        assert classification == {}

    def test_classify_from_instance(self):
        """Classify taint in a real instance."""
        path = INSTANCE_DIR / "instance_01_classical_rsa.py"
        graph = build_cfg_cg(str(path))
        sources = set(get_source_nodes(graph))
        tainted = propagate_taint(graph, sources)
        classification = classify_taint(graph, tainted)
        # Should have at least some classification
        assert len(classification) > 0
        assert "source" in classification.values()


class TestEdgeCases:
    """Edge case tests for taint propagation."""

    def test_circular_dependency(self):
        """Taint propagation handles circular dependencies."""
        graph = nx.DiGraph()
        graph.add_edge("a", "b")
        graph.add_edge("b", "c")
        graph.add_edge("c", "a")  # cycle
        graph.add_edge("c", "sink")
        tainted = propagate_taint(graph, {"a"})
        assert "a" in tainted and "b" in tainted and "c" in tainted and "sink" in tainted

    def test_large_graph_performance(self):
        """Propagation works on larger graphs."""
        graph = nx.DiGraph()
        for i in range(100):
            graph.add_edge(f"n{i}", f"n{i+1}")
        tainted = propagate_taint(graph, {"n0"})
        assert len(tainted) == 101  # n0 through n100

    def test_diamond_pattern(self):
        """Taint propagates correctly through diamond pattern."""
        graph = nx.DiGraph()
        graph.add_edge("src", "a")
        graph.add_edge("src", "b")
        graph.add_edge("a", "c")
        graph.add_edge("b", "c")
        graph.add_edge("c", "sink")
        tainted = propagate_taint(graph, {"src"})
        assert tainted == {"src", "a", "b", "c", "sink"}

    def test_filter_none_node_obj(self):
        """Taint filter handles nodes without obj attribute."""
        graph = nx.DiGraph()
        graph.add_edge("a", "b")
        # Node 'b' has no obj attribute
        def safe_filter(node_id, node):
            return True  # allow all
        tainted = propagate_taint(graph, {"a"}, taint_filter=safe_filter)
        assert tainted == {"a", "b"}

    def test_propagate_taint_with_taint_filter(self):
        graph = nx.DiGraph()
        graph.add_edge("src1", "mid1")
        graph.add_edge("mid1", "sink1")
        def block_sink(node_id, node):
            return "sink" not in node_id
        tainted = propagate_taint(graph, {"src1"}, taint_filter=block_sink)
        assert "src1" in tainted
        assert "mid1" in tainted
        assert "sink1" not in tainted

    def test_propagate_taint_interprocedural_with_call_graph(self):
        graph = nx.DiGraph()
        graph.add_edge("main", "func1")
        graph.add_edge("func1", "sink")
        call_graph = nx.DiGraph()
        call_graph.add_edge("main", "func1")
        tainted = propagate_taint_interprocedural(graph, {"main"}, call_graph=call_graph)
        assert "main" in tainted
        assert "func1" in tainted

    def test_propagate_taint_interprocedural_without_call_graph(self):
        graph = nx.DiGraph()
        graph.add_edge("src1", "sink1")
        tainted = propagate_taint_interprocedural(graph, {"src1"}, call_graph=None)
        assert "src1" in tainted
        assert "sink1" in tainted

    def test_classify_taint_returns_set(self):
        from pqblocks_lint.taint import classify_taint
        graph = nx.DiGraph()
        graph.add_edge("src1", "sink1")
        tainted = {"src1", "sink1"}
        result = classify_taint(graph, tainted)
        assert isinstance(result, dict)
        assert "src1" in result
        assert "sink1" in result

    def test_get_tainted_sources_with_missing_node(self):
        graph = nx.DiGraph()
        graph.add_edge("src1", "sink1")
        graph.nodes["src1"]["obj"] = CFGNode("src1", "assignment", "key", is_source=True)
        sources = {"src1", "nonexistent"}
        tainted = get_tainted_sources(graph, sources)
        assert "src1" in tainted
        assert "nonexistent" not in tainted

    def test_classify_taint_empty_graph(self):
        from pqblocks_lint.taint import classify_taint
        graph = nx.DiGraph()
        result = classify_taint(graph, set())
        assert result == {}

    def test_get_tainted_sources_node_not_found(self):
        graph = nx.DiGraph()
        graph.add_node("src1")
        graph.nodes["src1"]["obj"] = CFGNode("src1", "assignment", "key", is_source=True)
        sources = {"src1", "missing"}
        tainted = get_tainted_sources(graph, sources)
        assert "src1" in tainted


class TestTaintEdgeCasesExtended:
    """Extended edge case tests for uncovered taint branches."""

    def test_get_tainted_sources_with_node_in_graph(self):
        """Test get_tainted_sources with node that exists in graph."""
        graph = nx.DiGraph()
        graph.add_node("src1")
        graph.add_node("taint_node")
        graph.nodes["src1"]["obj"] = CFGNode("src1", "assignment", "key", is_source=True)
        graph.add_edge("src1", "taint_node")
        tainted = {"taint_node"}
        sources = get_tainted_sources(graph, tainted)
        assert "src1" in sources

    def test_get_tainted_sources_with_missing_source_node(self):
        """Test get_tainted_sources with source node not in graph."""
        graph = nx.DiGraph()
        graph.add_node("taint_node")
        # src1 doesn't exist in graph
        sources = get_tainted_sources(graph, {"taint_node"})
        assert len(sources) == 0

    def test_propagate_taint_with_filter_returns_false(self):
        """Test propagate_taint with filter that always returns False."""
        graph = nx.DiGraph()
        graph.add_edge("src1", "sink1")
        graph.nodes["src1"]["obj"] = CFGNode("src1", "assignment", "key", is_source=True)
        
        def block_all(node_id, node):
            return False
        
        tainted = propagate_taint(graph, {"src1"}, taint_filter=block_all)
        assert len(tainted) == 0

    def test_propagate_taint_with_filter_returns_true(self):
        """Test propagate_taint with filter that returns True."""
        graph = nx.DiGraph()
        graph.add_edge("src1", "sink1")
        graph.nodes["src1"]["obj"] = CFGNode("src1", "assignment", "key", is_source=True)
        
        def allow_all(node_id, node):
            return True
        
        tainted = propagate_taint(graph, {"src1"}, taint_filter=allow_all)
        assert "src1" in tainted
        assert "sink1" in tainted

    def test_extract_call_graph(self):
        """Test _extract_call_graph function."""
        from pqblocks_lint.taint import _extract_call_graph
        graph = nx.DiGraph()
        graph.add_node("n0")
        node0 = CFGNode("n0", "call", "call_function")
        graph.nodes["n0"]["obj"] = node0
        graph.add_node("n1", obj=CFGNode("n1", "call", "callee"))
        graph.add_edge("n0", "n1", func="test")
        call_graph = _extract_call_graph(graph)
        assert len(call_graph.nodes()) == 2

    def test_classify_taint_with_unknown_node(self):
        """Test classify_taint with node that has no obj attribute."""
        from pqblocks_lint.taint import classify_taint
        graph = nx.DiGraph()
        graph.add_node("unknown_node")
        # No obj attribute
        result = classify_taint(graph, {"unknown_node"})
        assert result["unknown_node"] == "intermediate"

    def test_classify_taint_with_non_obj_node(self):
        """Test classify_taint with node that has a CFGNode without is_sink attrs."""
        from pqblocks_lint.taint import classify_taint
        graph = nx.DiGraph()
        graph.add_node("n_src", obj=CFGNode("n_src", "assignment", "k", is_source=True))
        graph.add_node("regular_node")
        graph.nodes["regular_node"]["obj"] = CFGNode("regular_node", "", "")
        result = classify_taint(graph, {"regular_node"})
        assert result["regular_node"] == "intermediate"

    def test_propagate_taint_with_circular_graph(self):
        """Test propagate_taint on graph with circular dependencies."""
        graph = nx.DiGraph()
        graph.add_edge("a", "b")
        graph.add_edge("b", "c")
        graph.add_edge("c", "a")  # cycle
        graph.add_edge("c", "sink")
        graph.nodes["a"]["obj"] = CFGNode("a", "assignment", "start", is_source=True)
        tainted = propagate_taint(graph, {"a"})
        assert len(tainted) == 4  # a, b, c, sink

    def test_propagate_taint_interprocedural_with_none_graph(self):
        """Test propagate_taint_interprocedural with graph that has no calls."""
        graph = nx.DiGraph()
        graph.add_node("standalone")
        tainted = propagate_taint_interprocedural(graph, {"standalone"})
        assert "standalone" in tainted
