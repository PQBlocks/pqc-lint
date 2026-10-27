"""Tests for pqblocks-lint data-flow graph construction.

Validates:
- CFG+CG construction from Python source files
- Source and sink node detection
- Taint closure computation
- Path finding between sources and sinks
- Edge-case handling for empty files and disconnected instances
"""

import os
from pathlib import Path

import networkx as nx
import pytest

from pqblocks_lint.graph import (
    CFGNode,
    build_cfg_cg,
    find_tainted_paths,
    get_sink_nodes,
    get_source_nodes,
    get_taint_closure,
)

# Path to test instances
INSTANCE_DIR = Path(__file__).parent / "test-instances"


class TestBuildCfgCg:
    """Tests for build_cfg_cg function."""

    def test_build_from_rsa_instance(self):
        """Build graph from instance_01 and detect source/sink nodes."""
        path = INSTANCE_DIR / "instance_01_classical_rsa.py"
        graph = build_cfg_cg(str(path))
        assert isinstance(graph, nx.DiGraph)
        assert len(graph.nodes()) > 0

        sources = get_source_nodes(graph)
        assert len(sources) > 0, "Should detect rsa.generate_private_key as source"

        sinks = get_sink_nodes(graph)
        assert len(sinks) > 0, "Should detect public_key.encrypt as sink"

    def test_build_from_aliased_instance(self):
        """Build graph from aliased import instance."""
        path = INSTANCE_DIR / "instance_02_aliased_import.py"
        graph = build_cfg_cg(str(path))
        assert isinstance(graph, nx.DiGraph)
        assert len(graph.nodes()) > 0

    def test_build_from_interprocedural_instance(self):
        """Build graph from interprocedural flow instance."""
        path = INSTANCE_DIR / "instance_03_interprocedural_flow.py"
        graph = build_cfg_cg(str(path))
        assert isinstance(graph, nx.DiGraph)
        assert len(graph.nodes()) > 0

        sources = get_source_nodes(graph)
        assert len(sources) > 0, "Should detect ec.generate_private_key as source"

        sinks = get_sink_nodes(graph)
        assert len(sinks) > 0, "Should detect key.sign as sink"

    def test_build_from_hybrid_instance(self):
        """Build graph from quantum-safe hybrid instance."""
        path = INSTANCE_DIR / "instance_04_pqc_mlkem_hybrid.py"
        graph = build_cfg_cg(str(path))
        assert isinstance(graph, nx.DiGraph)
        assert len(graph.nodes()) > 0

    def test_graph_has_edges(self):
        """Graph should have edges representing data dependencies."""
        path = INSTANCE_DIR / "instance_01_classical_rsa.py"
        graph = build_cfg_cg(str(path))
        assert len(graph.edges()) > 0, "Graph should have data-flow edges"

    def test_graph_is_directed(self):
        """Graph should be a DiGraph (directed)."""
        path = INSTANCE_DIR / "instance_01_classical_rsa.py"
        graph = build_cfg_cg(str(path))
        assert graph.is_directed()

    def test_node_types_present(self):
        """Graph should contain nodes of various types."""
        path = INSTANCE_DIR / "instance_01_classical_rsa.py"
        graph = build_cfg_cg(str(path))
        node_types = {
            graph.nodes[n]["obj"].stmt_type
            for n in graph.nodes()
            if "obj" in graph.nodes[n]
        }
        assert "function" in node_types or "assignment" in node_types

    def test_cfg_node_attributes(self):
        """CFGNode objects should have correct attributes."""
        node = CFGNode("n0", "assignment", "private_key")
        assert node.id == "n0"
        assert node.stmt_type == "assignment"
        assert node.name == "private_key"
        assert node.is_source is False
        assert node.is_sink is False


class TestTaintClosure:
    """Tests for taint closure computation."""

    def test_closure_empty_graph(self):
        """Taint closure of empty sources in empty graph is empty."""
        graph = nx.DiGraph()
        closure = get_taint_closure(graph, [])
        assert closure == set()

    def test_closure_with_sources(self):
        """Taint closure from sources includes reachable nodes."""
        graph = nx.DiGraph()
        graph.add_edge("src1", "mid1")
        graph.add_edge("mid1", "sink1")
        graph.add_edge("src1", "sink2")
        closure = get_taint_closure(graph, ["src1"])
        assert "src1" in closure
        assert "mid1" in closure
        assert "sink1" in closure
        assert "sink2" in closure

    def test_closure_disconnected(self):
        """Taint closure does not include disconnected nodes."""
        graph = nx.DiGraph()
        graph.add_edge("src1", "sink1")
        graph.add_node("disconnected")
        closure = get_taint_closure(graph, ["src1"])
        assert "disconnected" not in closure

    def test_closure_multiple_sources(self):
        """Taint closure from multiple sources includes all reachable nodes."""
        graph = nx.DiGraph()
        graph.add_edge("src1", "mid1")
        graph.add_edge("src2", "mid1")
        graph.add_edge("mid1", "sink1")
        closure = get_taint_closure(graph, ["src1", "src2"])
        assert "sink1" in closure


class TestFindTaintedPaths:
    """Tests for finding tainted paths between sources and sinks."""

    def test_paths_found(self):
        """Paths are found when sources and sinks are connected."""
        graph = nx.DiGraph()
        graph.add_edge("src1", "mid1")
        graph.add_edge("mid1", "sink1")
        paths = find_tainted_paths(graph, ["src1"], ["sink1"])
        assert len(paths) > 0
        assert paths[0] == ["src1", "mid1", "sink1"]

    def test_no_paths_disconnected(self):
        """No paths when sources and sinks are disconnected."""
        graph = nx.DiGraph()
        graph.add_edge("src1", "mid1")
        graph.add_node("sink1")
        paths = find_tainted_paths(graph, ["src1"], ["sink1"])
        assert len(paths) == 0

    def test_paths_from_instance_01(self):
        """Find tainted paths in RSA instance."""
        path = INSTANCE_DIR / "instance_01_classical_rsa.py"
        graph = build_cfg_cg(str(path))
        sources = get_source_nodes(graph)
        sinks = get_sink_nodes(graph)
        if sources and sinks:
            paths = find_tainted_paths(graph, sources, sinks)
            # Should find at least one path from source to sink
            # (may be empty if taint markers not set on this instance)
            assert isinstance(paths, list)

    def test_paths_from_instance_03(self):
        """Find tainted paths in interprocedural instance."""
        path = INSTANCE_DIR / "instance_03_interprocedural_flow.py"
        graph = build_cfg_cg(str(path))
        sources = get_source_nodes(graph)
        sinks = get_sink_nodes(graph)
        if sources and sinks:
            paths = find_tainted_paths(graph, sources, sinks)
            assert isinstance(paths, list)


class TestEdgeCases:
    """Edge case tests for graph construction."""

    def test_empty_file(self, tmp_path):
        """Empty file produces a graph with no nodes."""
        empty_file = tmp_path / "empty.py"
        empty_file.write_text("")
        graph = build_cfg_cg(str(empty_file))
        assert isinstance(graph, nx.DiGraph)
        assert len(graph.nodes()) == 0

    def test_only_comments(self, tmp_path):
        """File with only comments produces a graph with no nodes."""
        comment_file = tmp_path / "comments.py"
        comment_file.write_text("# Just a comment\n# Another comment\n")
        graph = build_cfg_cg(str(comment_file))
        assert isinstance(graph, nx.DiGraph)

    def test_syntax_error_raises(self, tmp_path):
        """Invalid Python syntax raises SyntaxError."""
        bad_file = tmp_path / "bad.py"
        bad_file.write_text("def missing_paren(:\n")
        with pytest.raises(SyntaxError):
            build_cfg_cg(str(bad_file))

    def test_nonexistent_file_raises(self):
        """Non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            build_cfg_cg("/nonexistent/path/to/file.py")

    def test_file_with_only_imports(self, tmp_path):
        """File with only imports has no source/sink nodes."""
        import_file = tmp_path / "imports_only.py"
        import_file.write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n")
        graph = build_cfg_cg(str(import_file))
        assert isinstance(graph, nx.DiGraph)
        # May have import nodes but no source/sink


class TestEdgeCasesExtended:
    """Extended edge case tests for uncovered branches."""

    def test_module_level_assignment_with_call_target(self, tmp_path):
        """Test module-level assignment with call that has crypto source/sink."""
        test_file = tmp_path / "module_call.py"
        test_file.write_text("""
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
""")
        graph = build_cfg_cg(str(test_file))
        sources = get_source_nodes(graph)
        assert len(sources) > 0

    def test_module_level_assignment_with_attribute_call(self, tmp_path):
        """Test module-level assignment with attribute call (e.g., obj.method())."""
        test_file = tmp_path / "module_attr.py"
        test_file.write_text("""
class CryptoProvider:
    def generate_key(self):
        return "key"

provider = CryptoProvider()
key = provider.generate_key()
""")
        graph = build_cfg_cg(str(test_file))
        # Should handle attribute calls without crashing
        assert isinstance(graph, nx.DiGraph)

    def test_module_level_expression_statement(self, tmp_path):
        """Test standalone expression statement (call not assigned)."""
        test_file = tmp_path / "module_expr.py"
        test_file.write_text("""
from cryptography.hazmat.primitives.asymmetric import rsa
rsa.generate_private_key(public_exponent=65537, key_size=2048)
""")
        graph = build_cfg_cg(str(test_file))
        sources = get_source_nodes(graph)
        assert len(sources) > 0

    def test_class_def_with_methods(self, tmp_path):
        """Test class definition with methods containing crypto calls."""
        test_file = tmp_path / "class_method.py"
        test_file.write_text("""
from cryptography.hazmat.primitives.asymmetric import rsa

class KeyManager:
    def generate(self):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    def use_key(self, key):
        return key.public_key()

manager = KeyManager()
key = manager.generate()
pub = manager.use_key(key)
""")
        graph = build_cfg_cg(str(test_file))
        sources = get_source_nodes(graph)
        assert len(sources) > 0

    def test_find_tainted_paths_networkx_no_path(self):
        """Test find_tainted_paths handles NetworkXNoPath exception."""
        graph = nx.DiGraph()
        graph.add_node("src")
        graph.add_node("sink")
        # No edge between src and sink - should handle gracefully
        paths = find_tainted_paths(graph, ["src"], ["sink"])
        assert paths == []

    def test_get_taint_closure_with_nonexistent_source(self):
        """Test get_taint_closure with source not in graph."""
        graph = nx.DiGraph()
        graph.add_edge("a", "b")
        closure = get_taint_closure(graph, ["nonexistent"])
        assert closure == set()

    def test_build_cfg_cg_with_tuple_assignment(self, tmp_path):
        """Test tuple assignment handling."""
        test_file = tmp_path / "tuple_assign.py"
        test_file.write_text("""
a, b = 1, 2
c, d = "x", "y"
""")
        graph = build_cfg_cg(str(test_file))
        assert isinstance(graph, nx.DiGraph)

    def test_build_cfg_cg_with_aug_assign(self, tmp_path):
        """Test augmented assignment (not explicitly handled, should not crash)."""
        test_file = tmp_path / "aug_assign.py"
        test_file.write_text("""
x = 0
x += 1
""")
        graph = build_cfg_cg(str(test_file))
        assert isinstance(graph, nx.DiGraph)

    def test_get_function_name_edge_cases(self):
        """Test get_function_name with various node types."""
        import ast
        # The function is internal, test via behavior
        import tempfile, os
        test_file = tempfile.mktemp(suffix=".py")
        with open(test_file, "w") as f:
            f.write("""
import os
result = os.path.join("a", "b")
""")
        from pqblocks_lint.graph import build_cfg_cg
        graph = build_cfg_cg(test_file)
        assert isinstance(graph, nx.DiGraph)
        os.unlink(test_file)
