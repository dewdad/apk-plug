"""CLI entry point with subcommand dispatch."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from apk_plug import __version__


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for CLI."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


def cmd_init(args: argparse.Namespace) -> int:
    """Handle init subcommand."""
    from apk_plug.stage0_input import route_input, execute_plan
    from apk_plug.workspace import create_workspace

    apk_path = Path(args.apk)
    if not apk_path.exists():
        print(f"Error: File not found: {apk_path}", file=sys.stderr)
        return 1

    workspace_base = Path(args.workspace) if args.workspace else None

    try:
        ws = create_workspace(apk_path, workspace_base=workspace_base)
        print(f"Created workspace: {ws.root}")

        plan = route_input(apk_path, ws.input_dir)
        print(f"Input format: {plan.format.value}")
        print(f"Using tool: {plan.tool.value}")

        if plan.has_obb:
            print(f"OBB files detected: {len(plan.obb_files)}")

        target = execute_plan(plan, ws)
        print(f"Target APK: {target}")

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_decompile(args: argparse.Namespace) -> int:
    """Handle decompile subcommand."""
    from apk_plug.stage1_decompile import run_stage1
    from apk_plug.workspace import load_workspace, find_workspace

    try:
        if args.workspace:
            ws = load_workspace(Path(args.workspace))
        else:
            ws = find_workspace()
            if ws is None:
                print("Error: No workspace found. Run 'apk-plug init' first.", file=sys.stderr)
                return 1

        run_stage1(ws)
        print(f"Decompilation complete: {ws.decompile_smali_dir}")
        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_scan(args: argparse.Namespace) -> int:
    """Handle scan subcommand."""
    from apk_plug.stage2_scan import run_stage2
    from apk_plug.workspace import load_workspace, find_workspace

    try:
        if args.workspace:
            ws = load_workspace(Path(args.workspace))
        else:
            ws = find_workspace()
            if ws is None:
                print("Error: No workspace found. Run 'apk-plug init' first.", file=sys.stderr)
                return 1

        report_path = run_stage2(
            ws,
            mobsf_api_key=args.mobsf_key,
            semgrep_rules=args.semgrep_rules,
        )
        print(f"Scan complete: {report_path}")
        print("\nNext step: Review threat-report.json and perform manual remediation.")
        print("Then run: apk-plug rebuild --keystore <path>")
        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    """Handle verify subcommand."""
    from apk_plug.verify import verify_stage, GateResult
    from apk_plug.workspace import load_workspace, find_workspace

    try:
        if args.workspace:
            ws = load_workspace(Path(args.workspace))
        else:
            ws = find_workspace()
            if ws is None:
                print("Error: No workspace found.", file=sys.stderr)
                return 1

        result = verify_stage(ws, args.stage)

        print(f"Stage {args.stage} verification: {'PASSED' if result.passed else 'FAILED'}")
        for check in result.checks:
            status = "✓" if check.result == GateResult.PASS else "✗" if check.result == GateResult.FAIL else "○"
            print(f"  {status} {check.name}: {check.message}")

        return 0 if result.passed else 1

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_rebuild(args: argparse.Namespace) -> int:
    """Handle rebuild subcommand."""
    from apk_plug.stage4_rebuild import run_stage4, KeystoreError
    from apk_plug.workspace import load_workspace, find_workspace

    try:
        if args.workspace:
            ws = load_workspace(Path(args.workspace))
        else:
            ws = find_workspace()
            if ws is None:
                print("Error: No workspace found.", file=sys.stderr)
                return 1

        signed_apk = run_stage4(
            ws,
            keystore=args.keystore,
            key_alias=args.key_alias,
            keystore_pass=args.keystore_pass,
            key_pass=args.key_pass,
        )
        print(f"Rebuild complete: {signed_apk}")
        print("\nNext step: Run 'apk-plug validate' to verify the fix.")
        return 0

    except KeystoreError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_validate(args: argparse.Namespace) -> int:
    """Handle validate subcommand."""
    from apk_plug.stage5_validate import run_stage5, ValidationError
    from apk_plug.workspace import load_workspace, find_workspace

    try:
        if args.workspace:
            ws = load_workspace(Path(args.workspace))
        else:
            ws = find_workspace()
            if ws is None:
                print("Error: No workspace found.", file=sys.stderr)
                return 1

        results = run_stage5(ws)

        print("Validation complete:")
        print(f"  Passed: {results['passed']}")

        perm_diff = results.get("permission_diff", {})
        if perm_diff.get("removed"):
            print(f"  Permissions removed: {len(perm_diff['removed'])}")
        if perm_diff.get("added"):
            print(f"  Permissions added: {len(perm_diff['added'])} (WARNING)")

        residual = results.get("residual_c2", [])
        if residual:
            print(f"  Residual C2/URLs: {len(residual)} (review recommended)")

        obb_cmds = results.get("obb_commands", [])
        if obb_cmds:
            print("\nOBB push commands (run before testing):")
            for cmd in obb_cmds:
                print(f"  {cmd}")

        return 0 if results["passed"] else 1

    except ValidationError as e:
        print(f"Validation failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="apk-plug",
        description="APK static analysis, threat identification, and rebuild pipeline",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    init_parser = subparsers.add_parser("init", help="Initialize workspace and normalize input")
    init_parser.add_argument("apk", help="Path to APK/AAB/XAPK/APKM/APKS file")
    init_parser.add_argument("--workspace", "-w", help="Workspace base directory")
    init_parser.set_defaults(func=cmd_init)

    # decompile
    decompile_parser = subparsers.add_parser("decompile", help="Decompile APK with jadx and apktool")
    decompile_parser.add_argument("--workspace", "-w", help="Workspace directory")
    decompile_parser.set_defaults(func=cmd_decompile)

    # scan
    scan_parser = subparsers.add_parser("scan", help="Run security scanners and generate threat report")
    scan_parser.add_argument("--workspace", "-w", help="Workspace directory")
    scan_parser.add_argument("--mobsf-key", help="MobSF API key")
    scan_parser.add_argument("--semgrep-rules", help="Path to semgrep rules")
    scan_parser.set_defaults(func=cmd_scan)

    # verify
    verify_parser = subparsers.add_parser("verify", help="Verify stage completion gates")
    verify_parser.add_argument("--stage", "-s", type=int, required=True, choices=[1, 2, 3, 4, 5], help="Stage to verify")
    verify_parser.add_argument("--workspace", "-w", help="Workspace directory")
    verify_parser.set_defaults(func=cmd_verify)

    # rebuild
    rebuild_parser = subparsers.add_parser("rebuild", help="Rebuild, align, and sign APK")
    rebuild_parser.add_argument("--workspace", "-w", help="Workspace directory")
    rebuild_parser.add_argument("--keystore", "-k", help="Path to keystore file")
    rebuild_parser.add_argument("--key-alias", "-a", help="Key alias")
    rebuild_parser.add_argument("--keystore-pass", help="Keystore password")
    rebuild_parser.add_argument("--key-pass", help="Key password")
    rebuild_parser.set_defaults(func=cmd_rebuild)

    # validate
    validate_parser = subparsers.add_parser("validate", help="Post-fix validation and diff")
    validate_parser.add_argument("--workspace", "-w", help="Workspace directory")
    validate_parser.set_defaults(func=cmd_validate)

    args = parser.parse_args()
    setup_logging(args.verbose)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
