"""Export a finished native report without running scanners or making cloud requests."""
import argparse
from pathlib import Path

from src.reporting import load_report


def write_export(report, native_path, destination, *, source_root=None):
    from src.sarif import export_sarif

    native_path = Path(native_path).resolve()
    destination = Path(destination).resolve()
    protected = {native_path}
    if native_path.name == "report.json":
        protected.update(native_path.with_name(name) for name in
                         ("ai_reviews.json", "bandit.json", "findings.json", "semgrep.json"))
    if destination in protected:
        raise ValueError("Choose a SARIF destination separate from the native scan artifacts.")
    return export_sarif(report, destination, source_root=source_root)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="Native report.json or run directory")
    parser.add_argument("destination", type=Path, help="SARIF output file")
    parser.add_argument("--source-root", help="Repository root for source-relative locations (default: scan root)")
    args = parser.parse_args(argv)
    native_path = args.report / "report.json" if args.report.is_dir() else args.report
    try:
        output = write_export(load_report(native_path), native_path, args.destination, source_root=args.source_root)
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        parser.exit(2, f"SARIF export failed: {exc}\n")
    print(f"Exported SARIF: {output}")


if __name__ == "__main__":
    main()
