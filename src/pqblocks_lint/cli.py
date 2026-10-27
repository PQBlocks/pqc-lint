"""CLI argument parser for pqblocks-lint.

Implements the standardized command-line interface with exit code conventions
per spec/spec.md Section 8.

Exit codes:
    0 - No quantum-vulnerable cryptography detected
    1 - Quantum-vulnerable cryptography detected
    2 - Only benign test cryptography detected
    3 - Internal error during analysis
    4 - Invalid command-line arguments
    5 - Analysis timeout exceeded
    6 - One or more files in a directory scan could not be analysed
"""

import argparse
import sys
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class LintArgs:
    """Validated CLI arguments for pqblocks-lint analysis."""

    target: str = ""
    format: str = "cbom"
    output: str = ""
    seed: int = 0
    timeout: int = 30
    threads: int = 1

    @property
    def is_valid(self) -> bool:
        return bool(self.target) and bool(self.output) and self.seed >= 0


class LintArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that maps all errors to exit code 4 per spec Section 8.2."""

    def error(self, message: str) -> None:
        """Override to emit exit code 4 instead of default 2."""
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        sys.exit(4)


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser.

    The parser accepts both ``pqblocks-lint --target ...`` and
    ``pqblocks-lint analyze --target ...`` (spec Section 8.1 shows the
    ``analyze`` subcommand form). The leading ``analyze`` token is
    stripped in :func:`parse_cli_arguments` before parsing, so the
    top-level ``--help`` lists all options directly.

    Returns:
        ArgumentParser configured with pqblocks-lint CLI options.
    """
    parser = LintArgumentParser(
        prog="pqblocks-lint",
        description=(
            "pqblocks-lint: Cryptographic Bill of Materials and PQC readiness scanner. "
            "Static analysis tool that detects, classifies, and catalogs "
            "cryptographic primitives in Python source code.\n\n"
            "Usage: pqblocks-lint analyze --target <path> --format <cbom|sarif> "
            "--output <path> --seed <int> [--timeout <s>] [--threads <n>]"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--target",
        required=False,
        default=None,
        help="File or directory to analyze (required)",
    )
    parser.add_argument(
        "--format",
        choices=["cbom", "sarif"],
        default="cbom",
        help="Output format: cbom for CycloneDX 1.6 JSON or sarif for SARIF 2.1.0 log (default: cbom)",
    )
    parser.add_argument(
        "--output",
        required=False,
        default=None,
        help="Path for output file (required)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        required=False,
        default=None,
        help="SplitMix64 seed for reproducible analysis (required, non-negative integer)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Analysis timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=1,
        help="Number of threads for parallel analysis (default: 1)",
    )

    return parser


def parse_cli_arguments(argv: Optional[list[str]] = None) -> LintArgs:
    """Parse and validate command-line arguments for pqblocks-lint.
    
    Args:
        argv: Optional list of arguments (defaults to sys.argv[1:]).
    
    Returns:
        Validated LintArgs dataclass.
    
    Raises:
        SystemExit with code 4: On invalid arguments or missing required fields.
    """
    if argv is None:
        argv = sys.argv[1:]
    else:
        argv = list(argv)
    if argv and argv[0] == "analyze":
        argv = argv[1:]

    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.target:
        parser.error("--target is required")
    if not args.output:
        parser.error("--output is required")
    if args.seed is None:
        parser.error("--seed is required and must be a non-negative integer")
    if args.seed is not None and args.seed < 0:
        parser.error("--seed must be a non-negative integer")

    import os as _os

    if not _os.path.exists(args.target):
        parser.error(f"--target path does not exist: {args.target}")

    if args.format not in ("cbom", "sarif"):
        parser.error("--format must be 'cbom' or 'sarif'")

    if args.timeout < 1:
        parser.error("--timeout must be a positive integer")

    if args.threads < 1:
        parser.error("--threads must be a positive integer")
    
    return LintArgs(
        target=args.target,
        format=args.format,
        output=args.output,
        seed=args.seed,
        timeout=args.timeout,
        threads=args.threads,
    )


def validate_args(args: object) -> Optional[str]:
    import os as _os

    if isinstance(args, LintArgs):
        if not args.target or not args.output:
            return "Invalid arguments: target and output are required"
        if args.seed < 0:
            return "Invalid arguments: seed must be a non-negative integer"
        if not _os.path.exists(args.target):
            return f"Invalid arguments: target does not exist: {args.target}"
        return None
    target = getattr(args, "target", None)
    output = getattr(args, "output", None)
    seed = getattr(args, "seed", None)
    if not target or not output or seed is None:
        return "Invalid arguments: target, output, and seed are required"
    try:
        seed_int = int(seed)
    except (TypeError, ValueError):
        return "Invalid arguments: seed must be a non-negative integer"
    if seed_int < 0:
        return "Invalid arguments: seed must be a non-negative integer"
    if not _os.path.exists(str(target)):
        return f"Invalid arguments: target does not exist: {target}"
    return None


EXIT_FOR_VERDICT = {
    "COMPLIANT_QUANTUM_SAFE": 0,
    "NO_CRYPTO_DETECTED": 0,
    "NON_COMPLIANT_VULNERABLE": 1,
    "BENIGN_TEST_CODE": 2,
}


def _analyze_file(path: str) -> tuple[list, str]:
    from pqblocks_lint.classifier import classify
    from pqblocks_lint.graph import build_cfg_cg, get_source_nodes
    from pqblocks_lint.serialize import build_cbom_dict
    from pqblocks_lint.taint import propagate_taint

    graph = build_cfg_cg(path)
    tainted = propagate_taint(graph, set(get_source_nodes(graph)))
    assets = classify(graph, tainted)
    verdict = build_cbom_dict(assets, target=path, seed=0, test_code=graph.graph["test_code"])["verdict"]
    return assets, verdict


def main(argv: Optional[list[str]] = None) -> int:
    import time as _time

    try:
        args = parse_cli_arguments(argv)
    except SystemExit as e:
        code = e.code
        return code if isinstance(code, int) else 4
    except Exception:
        return 3

    if not args.is_valid:
        return 4
    started = _time.monotonic()
    try:
        import os as _os

        from pqblocks_lint.serialize import emit_outputs

        assets: list = []
        verdict = "NO_CRYPTO_DETECTED"
        scan_errors: list[str] = []
        if _os.path.isdir(args.target):
            per_verdicts: list[str] = []
            for root, _dirs, files in _os.walk(args.target):
                for fn in sorted(files):
                    if not fn.endswith(".py"):
                        continue
                    fp = _os.path.join(root, fn)
                    try:
                        fa, fv = _analyze_file(fp)
                    except (FileNotFoundError, SyntaxError, ValueError) as exc:
                        scan_errors.append(f"{fp}: {type(exc).__name__}: {exc}")
                        continue
                    assets.extend(fa)
                    per_verdicts.append(fv)
            if any(v == "NON_COMPLIANT_VULNERABLE" for v in per_verdicts):
                verdict = "NON_COMPLIANT_VULNERABLE"
            elif per_verdicts and all(v in ("BENIGN_TEST_CODE", "NO_CRYPTO_DETECTED") for v in per_verdicts) and any(
                v == "BENIGN_TEST_CODE" for v in per_verdicts
            ):
                verdict = "BENIGN_TEST_CODE"
            elif any(v == "COMPLIANT_QUANTUM_SAFE" for v in per_verdicts):
                verdict = "COMPLIANT_QUANTUM_SAFE"
            else:
                verdict = "NO_CRYPTO_DETECTED"
        else:
            assets, verdict = _analyze_file(args.target)
        emit_outputs(assets, args.format, args.output, target=args.target, seed=args.seed, verdict=verdict)
    except Exception:
        return 3
    for err in scan_errors:
        print(f"scan error: {err}", file=sys.stderr)
    if scan_errors:
        return 6
    if (_time.monotonic() - started) > args.timeout:
        return 5
    return EXIT_FOR_VERDICT.get(verdict, 3)


if __name__ == "__main__":
    sys.exit(main())