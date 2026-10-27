"""Tests for pqblocks-lint CLI."""

import subprocess
import sys
import os
import tempfile
import json
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

def _run_cli(*cli_args: str, timeout: int = 10):
    """Run pqblocks-lint CLI with proper PYTHONPATH."""
    env = dict(os.environ)
    src_dir = str(Path(__file__).parent.parent / "src")
    prior = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = src_dir + (os.pathsep + prior if prior else "")
    return subprocess.run(
        [sys.executable, "-m", "pqblocks_lint.cli", *cli_args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )

def test_cli_help():
    """Test that CLI help text works."""
    result = _run_cli("--help")
    assert result.returncode == 0, f"Help failed: {result.stderr}"
    assert "pqblocks-lint" in result.stdout, "Help should mention pqblocks-lint"
    assert "--target" in result.stdout, "Help should show --target option"
    assert "--format" in result.stdout, "Help should show --format option"
    assert "--seed" in result.stdout, "Help should show --seed option"

def test_cli_missing_required_args():
    """Test CLI with missing required arguments."""
    result = _run_cli()
    assert result.returncode == 4, f"Expected exit code 4, got {result.returncode}"

def test_cli_invalid_target():
    """Test CLI with non-existent target."""
    result = _run_cli(
        "--target", "/nonexistent/path",
        "--format", "cbom",
        "--output", "/tmp/out.json",
        "--seed", "42",
    )
    assert result.returncode == 4, f"Expected exit code 4 for invalid target, got {result.returncode}"
    assert "does not exist" in result.stderr.lower() or "does not exist" in result.stdout, \
        f"Should report non-existent path: {result.stdout}"

def test_cli_invalid_seed():
    """Test CLI with invalid seed value."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("# test file with no crypto")
        temp_file = f.name
    
    try:
        result = _run_cli(
            "--target", temp_file,
            "--format", "cbom",
            "--output", "/tmp/out.json",
            "--seed", "-1",
        )
        assert result.returncode == 4, f"Expected exit code 4 for invalid seed, got {result.returncode}"
    finally:
        os.unlink(temp_file)

def test_cli_valid_args():
    """Test CLI with valid arguments (stub implementation)."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = 1\n')
        temp_file = f.name
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        output_file = f.name
    
    try:
        result = _run_cli(
            "--target", temp_file,
            "--format", "cbom",
            "--output", output_file,
            "--seed", "42",
        )
        assert result.returncode == 0, f"Expected exit code 0, got {result.returncode}. stderr: {result.stderr}"
        assert os.path.exists(output_file), "CLI should write the output file"
        with open(output_file, encoding="utf-8") as fh:
            payload = json.load(fh)
        assert payload["verdict"] == "NO_CRYPTO_DETECTED"
    finally:
        os.unlink(temp_file)
        if os.path.exists(output_file):
            os.unlink(output_file)

def test_cli_format_sarif():
    """Test CLI with sarif format selection."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('# Test file\n')
        temp_file = f.name
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
        output_file = f.name
    
    try:
        result = _run_cli(
            "analyze",
            "--target", temp_file,
            "--format", "sarif",
            "--output", output_file,
            "--seed", "123",
        )
        assert result.returncode == 0, f"Expected exit code 0, got {result.returncode}"
    finally:
        os.unlink(temp_file)
        if os.path.exists(output_file):
            os.unlink(output_file)

def test_cli_invalid_format():
    """Test CLI with invalid format value."""
    result = _run_cli(
        "--target", "/tmp",
        "--format", "invalid",
        "--output", "/tmp/out.json",
        "--seed", "42",
    )
    assert result.returncode != 0

def test_cli_assert_imports():
    """Test that CLI module can be imported and has required functions."""
    from pqblocks_lint import cli
    
    assert hasattr(cli, 'create_parser'), "cli module should have create_parser function"
    assert hasattr(cli, 'parse_cli_arguments'), "cli module should have parse_cli_arguments function"
    assert hasattr(cli, 'validate_args'), "cli module should have validate_args function"
    assert hasattr(cli, 'main'), "cli module should have main function"
    
    parser = cli.create_parser()
    assert parser is not None, "create_parser should return an ArgumentParser"
    
    args = cli.parse_cli_arguments([
        '--target', '/tmp',
        '--output', '/tmp/out.json',
        '--seed', '42',
    ])
    assert cli.validate_args(args) is None
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = 1\n')
        temp_file = f.name
    try:
        parsed = cli.parse_cli_arguments([
            'analyze',
            '--target', temp_file,
            '--output', '/tmp/out.json',
            '--seed', '42',
        ])
        assert parsed.target == temp_file
        assert cli.validate_args(parsed) is None
    finally:
        os.unlink(temp_file)

def test_cli_args_structure():
    """Test that CLI arguments have the correct structure."""
    from pqblocks_lint.cli import create_parser
    
    parser = create_parser()
    
    # Check all required arguments are present
    actions = {action.dest for action in parser._actions}
    
    required_args = ['target', 'format', 'output', 'seed', 'timeout', 'threads']
    for arg in required_args:
        assert arg in actions, f"Missing required argument: --{arg}"

if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])


def test_main_returns_zero_for_valid_args():
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = 1\n')
        temp_file = f.name
    try:
        from pqblocks_lint.cli import main
        code = main(['--target', temp_file, '--output', '/tmp/out.json', '--seed', '42'])
        assert code == 0, f"Expected exit code 0, got {code}"
    finally:
        os.unlink(temp_file)


def test_main_returns_four_for_missing_target():
    from pqblocks_lint.cli import main
    code = main(['--output', '/tmp/out.json', '--seed', '42'])
    assert code == 4, f"Expected exit code 4, got {code}"


def test_main_returns_four_for_invalid_seed():
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = 1\n')
        temp_file = f.name
    try:
        from pqblocks_lint.cli import main
        code = main(['--target', temp_file, '--output', '/tmp/out.json', '--seed', '-1'])
        assert code == 4, f"Expected exit code 4, got {code}"
    finally:
        os.unlink(temp_file)


def test_validate_args_returns_error_for_missing_fields():
    from pqblocks_lint.cli import LintArgs, validate_args
    args = LintArgs(target="", output="", seed=0)
    err = validate_args(args)
    assert err is not None


def test_validate_args_returns_none_for_valid_args():
    import tempfile, os
    from pqblocks_lint.cli import LintArgs, validate_args
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = 1\n')
        temp_file = f.name
    try:
        args = LintArgs(target=temp_file, output="/tmp/out.json", seed=42)
        err = validate_args(args)
        assert err is None
    finally:
        os.unlink(temp_file)


def test_lint_args_is_valid_property():
    from pqblocks_lint.cli import LintArgs
    args = LintArgs(target="/tmp", output="/tmp/out.json", seed=42)
    assert args.is_valid is True
    args2 = LintArgs(target="", output="/tmp/out.json", seed=42)
    assert args2.is_valid is False


def test_parser_error_raises_system_exit_with_code_4():
    import sys
    from pqblocks_lint.cli import create_parser
    parser = create_parser()
    try:
        parser.error("test error")
    except SystemExit as e:
        assert e.code == 4
    else:
        assert False, "parser.error should raise SystemExit"


def test_parse_cli_arguments_missing_seed():
    """Test parse_cli_arguments with missing --seed argument."""
    import tempfile, os
    from pqblocks_lint.cli import parse_cli_arguments
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = 1\n')
        temp_file = f.name
    try:
        try:
            parse_cli_arguments(['--target', temp_file, '--output', '/tmp/out.json'])
            assert False, "Should have raised SystemExit"
        except SystemExit as e:
            assert e.code == 4
    finally:
        os.unlink(temp_file)


def test_parse_cli_arguments_invalid_target_path():
    """Test parse_cli_arguments with non-existent target path."""
    from pqblocks_lint.cli import parse_cli_arguments
    try:
        parse_cli_arguments(['--target', '/nonexistent/path', '--output', '/tmp/out.json', '--seed', '42'])
        assert False, "Should have raised SystemExit"
    except SystemExit as e:
        assert e.code == 4


def test_parse_cli_arguments_invalid_format():
    """Test parse_cli_arguments with invalid format."""
    import tempfile, os
    from pqblocks_lint.cli import parse_cli_arguments
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = 1\n')
        temp_file = f.name
    try:
        try:
            parse_cli_arguments(['--target', temp_file, '--output', '/tmp/out.json', '--seed', '42', '--format', 'invalid'])
            assert False, "Should have raised SystemExit"
        except SystemExit as e:
            assert e.code == 4
    finally:
        os.unlink(temp_file)


def test_parse_cli_arguments_invalid_timeout():
    """Test parse_cli_arguments with invalid timeout (< 1)."""
    import tempfile, os
    from pqblocks_lint.cli import parse_cli_arguments
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = 1\n')
        temp_file = f.name
    try:
        try:
            parse_cli_arguments(['--target', temp_file, '--output', '/tmp/out.json', '--seed', '42', '--timeout', '0'])
            assert False, "Should have raised SystemExit"
        except SystemExit as e:
            assert e.code == 4
    finally:
        os.unlink(temp_file)


def test_parse_cli_arguments_invalid_threads():
    """Test parse_cli_arguments with invalid threads (< 1)."""
    import tempfile, os
    from pqblocks_lint.cli import parse_cli_arguments
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = 1\n')
        temp_file = f.name
    try:
        try:
            parse_cli_arguments(['--target', temp_file, '--output', '/tmp/out.json', '--seed', '42', '--threads', '0'])
            assert False, "Should have raised SystemExit"
        except SystemExit as e:
            assert e.code == 4
    finally:
        os.unlink(temp_file)


def test_parse_cli_arguments_negative_seed():
    """Test parse_cli_arguments with negative seed."""
    import tempfile, os
    from pqblocks_lint.cli import parse_cli_arguments
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = 1\n')
        temp_file = f.name
    try:
        try:
            parse_cli_arguments(['--target', temp_file, '--output', '/tmp/out.json', '--seed', '-1'])
            assert False, "Should have raised SystemExit"
        except SystemExit as e:
            assert e.code == 4
    finally:
        os.unlink(temp_file)


def test_validate_args_with_non_lintargs():
    """Test validate_args with non-LintArgs object."""
    from pqblocks_lint.cli import validate_args
    class FakeArgs:
        target = "/tmp/test.py"
        output = "/tmp/out.json"
        seed = "42"
    # Create a temporary file for target to exist
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = 1\n')
        temp_file = f.name
    try:
        FakeArgs.target = temp_file
        err = validate_args(FakeArgs())
        assert err is None
    finally:
        os.unlink(temp_file)


def test_validate_args_with_invalid_seed_type():
    """Test validate_args with invalid seed type."""
    from pqblocks_lint.cli import validate_args
    class FakeArgs:
        target = "/tmp/test.py"
        output = "/tmp/out.json"
        seed = "not-an-int"
    err = validate_args(FakeArgs())
    assert err is not None
    assert "seed must be a non-negative integer" in err


def test_validate_args_with_negative_seed():
    """Test validate_args with negative seed on non-LintArgs."""
    from pqblocks_lint.cli import validate_args
    class FakeArgs:
        target = "/tmp/test.py"
        output = "/tmp/out.json"
        seed = -1
    err = validate_args(FakeArgs())
    assert err is not None
    assert "seed must be a non-negative integer" in err


def test_validate_args_with_nonexistent_target():
    """Test validate_args with nonexistent target on non-LintArgs."""
    from pqblocks_lint.cli import validate_args
    class FakeArgs:
        target = "/nonexistent/path.py"
        output = "/tmp/out.json"
        seed = 42
    err = validate_args(FakeArgs())
    assert err is not None
    assert "does not exist" in err


def test_main_returns_three_on_exception():
    """Test main returns 3 on unexpected exception."""
    from pqblocks_lint.cli import main
    # Trigger an exception by passing invalid args that cause an error in the stub
    code = main(['--target', '/nonexistent.py', '--output', '/tmp/out.json', '--seed', '42'])
    assert code == 4  # This goes through parse_cli_arguments which exits with 4
    
    # Test the generic exception handler in main
    import pqblocks_lint.cli as cli_module
    original_parse = cli_module.parse_cli_arguments
    def raising_parse(*args, **kwargs):
        raise RuntimeError("simulated error")
    cli_module.parse_cli_arguments = raising_parse
    try:
        code = main(['--target', '/tmp/test.py', '--output', '/tmp/out.json', '--seed', '42'])
        assert code == 3, f"Expected 3 for generic exception, got {code}"
    finally:
        cli_module.parse_cli_arguments = original_parse


def test_main_exit_1_for_vulnerable_instance():
    """GAP-2: CLI maps NON_COMPLIANT_VULNERABLE to exit code 1 (RED)."""
    import tempfile, os
    from pathlib import Path
    from pqblocks_lint.cli import main
    target = Path(__file__).parent / "test-instances" / "instance_01_classical_rsa.py"
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        out = f.name
    try:
        code = main(['--target', str(target), '--output', out, '--seed', '42'])
        assert code == 1, f"Expected exit 1 for vulnerable RSA, got {code}"
        import json
        payload = json.loads(Path(out).read_text(encoding="utf-8"))
        assert payload["verdict"] == "NON_COMPLIANT_VULNERABLE"
    finally:
        if os.path.exists(out):
            os.unlink(out)


def test_main_exit_2_for_benign_fixture():
    """GAP-2: CLI maps BENIGN_TEST_CODE to exit code 2 (RED)."""
    import tempfile, os
    from pathlib import Path
    from pqblocks_lint.cli import main
    target = Path(__file__).parent / "test-instances" / "instance_05_mock_test_vector.py"
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        out = f.name
    try:
        code = main(['--target', str(target), '--output', out, '--seed', '42'])
        assert code == 2, f"Expected exit 2 for benign fixture, got {code}"
    finally:
        if os.path.exists(out):
            os.unlink(out)


def test_main_exit_0_for_compliant_hybrid(hybrid_path):
    import tempfile, os, json
    from pathlib import Path
    from pqblocks_lint.cli import main
    target = hybrid_path
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        out = f.name
    try:
        code = main(['analyze', '--target', str(target), '--format', 'cbom', '--output', out, '--seed', '7'])
        assert code == 0, f"Expected exit 0 for compliant hybrid, got {code}"
        assert json.loads(Path(out).read_text(encoding="utf-8"))["verdict"] == "COMPLIANT_QUANTUM_SAFE"
    finally:
        if os.path.exists(out):
            os.unlink(out)


def test_main_sarif_output_valid():
    import tempfile, os, json
    from pathlib import Path
    from pqblocks_lint.cli import main
    target = Path(__file__).parent / "test-instances" / "instance_01_classical_rsa.py"
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
        out = f.name
    try:
        code = main(['--target', str(target), '--format', 'sarif', '--output', out, '--seed', '42'])
        assert code == 1, f"Expected exit 1 for vulnerable RSA+sarif, got {code}"
        doc = json.loads(Path(out).read_text(encoding="utf-8"))
        assert doc["version"] == "2.1.0"
        results = doc["runs"][0]["results"]
        assert results and all("ruleId" in r and "level" in r for r in results)
    finally:
        if os.path.exists(out):
            os.unlink(out)


def test_main_directory_target_vuln_wins():
    import tempfile, os, shutil
    from pathlib import Path
    from pqblocks_lint.cli import main
    src = Path(__file__).parent / "test-instances"
    tmpd = tempfile.mkdtemp()
    try:
        shutil.copy(src / "instance_01_classical_rsa.py", Path(tmpd) / "a_vuln.py")
        shutil.copy(src / "instance_05_mock_test_vector.py", Path(tmpd) / "b_mock_test_vector.py")
        out = str(Path(tmpd) / "out.json")
        code = main(['--target', tmpd, '--output', out, '--seed', '42'])
        assert code == 1, f"Expected exit 1 for dir containing vuln, got {code}"
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


def test_parse_argv_none_uses_sys_argv():
    from pqblocks_lint.cli import parse_cli_arguments
    try:
        parse_cli_arguments(None)
        assert False, "Should have raised SystemExit"
    except SystemExit as e:
        assert e.code == 4


def test_parse_missing_output():
    import tempfile, os
    from pqblocks_lint.cli import parse_cli_arguments
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = 1\n')
        tf = f.name
    try:
        try:
            parse_cli_arguments(['--target', tf, '--seed', '42'])
            assert False, "Should have raised SystemExit"
        except SystemExit as e:
            assert e.code == 4
    finally:
        os.unlink(tf)


def test_validate_lintargs_bad_seed_and_target():
    import tempfile, os
    from pqblocks_lint.cli import LintArgs, validate_args
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = 1\n')
        tf = f.name
    try:
        assert validate_args(LintArgs(target=tf, output="/tmp/o.json", seed=-3)) is not None
        assert validate_args(LintArgs(target="/nonexistent-xyz.py", output="/tmp/o.json", seed=1)) is not None
    finally:
        os.unlink(tf)


def test_validate_non_lintargs_missing_fields():
    from pqblocks_lint.cli import validate_args
    class Empty:
        pass
    assert validate_args(Empty()) is not None


def test_main_invalid_args_object_returns_4():
    from pqblocks_lint.cli import LintArgs, main
    import pqblocks_lint.cli as cli_module
    orig = cli_module.parse_cli_arguments
    cli_module.parse_cli_arguments = lambda argv=None: LintArgs(target="", output="", seed=0)
    try:
        assert main(['--target', '/tmp', '--output', '/tmp/o.json', '--seed', '1']) == 4
    finally:
        cli_module.parse_cli_arguments = orig


def test_main_emit_failure_returns_3():
    import tempfile, os
    from pathlib import Path
    import pqblocks_lint.cli as cli_module
    from pqblocks_lint.cli import main
    target = Path(__file__).parent / "test-instances" / "instance_01_classical_rsa.py"
    orig = cli_module.emit_outputs if hasattr(cli_module, 'emit_outputs') else None
    import pqblocks_lint.serialize as _ser
    orig_ser = _ser.emit_outputs
    def boom(*a, **k):
        raise OSError("disk full")
    _ser.emit_outputs = boom
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            out = f.name
        try:
            assert main(['--target', str(target), '--output', out, '--seed', '42']) == 3
        finally:
            if os.path.exists(out):
                os.unlink(out)
    finally:
        _ser.emit_outputs = orig_ser


def test_main_dir_benign_only_compliant_only_empty():
    import tempfile, shutil, json
    from pathlib import Path
    from pqblocks_lint.cli import main
    src = Path(__file__).parent / "test-instances"
    for files, expect in [
        (["instance_05_mock_test_vector.py"], 2),
        (["instance_04_pqc_mlkem_hybrid.py"], 1),  # mock KEM is not ML-KEM
        ([], 0),
    ]:
        tmpd = tempfile.mkdtemp()
        try:
            for fn in files:
                shutil.copy(src / fn, Path(tmpd) / fn)
            Path(tmpd, "notes.txt").write_text("not python", encoding="utf-8")
            out = str(Path(tmpd) / "out.json")
            code = main(['--target', tmpd, '--output', out, '--seed', '42'])
            assert code == expect, f"{files}: expected {expect}, got {code}"
            assert Path(out).is_file()
        finally:
            shutil.rmtree(tmpd, ignore_errors=True)


def test_main_timeout_exceeded_returns_5():
    import tempfile, os, time
    from pathlib import Path
    import pqblocks_lint.cli as cli_module
    from pqblocks_lint.cli import main
    target = Path(__file__).parent / "test-instances" / "instance_01_classical_rsa.py"
    orig = cli_module._analyze_file
    def slow(path: str):
        time.sleep(1.2)
        return orig(path)
    cli_module._analyze_file = slow
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        out = f.name
    try:
        code = main(['--target', str(target), '--output', out, '--seed', '42', '--timeout', '1'])
        assert code == 5, f"Expected exit 5 on timeout, got {code}"
    finally:
        cli_module._analyze_file = orig
        if os.path.exists(out):
            os.unlink(out)