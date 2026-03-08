"""
Vuln_VAS – Main Orchestrator
Runs all 4 modules in sequence:
  Module 1 → Reconnaissance
  Module 2 → Data Parsing
  Module 3 → Vulnerability Analysis   ← NEW
  Module 4 → Report Generation        ← NEW
"""

import argparse
import json
import sys
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(
        description="Vuln_VAS – Automated Vulnerability Assessment System"
    )
    parser.add_argument("target",  help="Target IP address or domain")
    parser.add_argument(
        "--skip-recon",
        action="store_true",
        help="Skip Module 1 & 2 and load existing recon JSON (use with --recon-file)"
    )
    parser.add_argument(
        "--recon-file",
        default=None,
        help="Path to existing Module 2 output JSON to feed directly into Module 3"
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to save all output files (default: reports/)"
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Skip launching the Streamlit dashboard (export reports only)"
    )
    return parser.parse_args()


def run_pipeline(target: str, recon_data: dict, output_dir: str, launch_dashboard: bool):
    from vulnerability_analysis_module import analyze_services, save_analysis_report
    from reporting_module import export_reports

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # ── MODULE 3 ─────────────────────────────
    print("\n" + "=" * 60)
    print("  MODULE 3 – Vulnerability Analysis")
    print("=" * 60)
    services = recon_data.get("services", [])
    if not services:
        print("[!] No services found in recon data. Exiting.")
        sys.exit(1)

    analysis_report = analyze_services(services, target)
    analysis_path   = save_analysis_report(analysis_report, output_dir)

    # ── MODULE 4 ─────────────────────────────
    print("\n" + "=" * 60)
    print("  MODULE 4 – Report Generation")
    print("=" * 60)
    pdf_path, html_path, json_path = export_reports(analysis_report, output_dir)

    print("\n" + "=" * 60)
    print("  ✅  SCAN COMPLETE")
    print("=" * 60)
    print(f"  Target         : {target}")
    print(f"  Vulnerabilities: {len(analysis_report.get('vulnerabilities', []))}")
    risk = analysis_report.get("risk_summary", {})
    print(f"  Risk Score     : {risk.get('overall_risk_score', 'N/A')} / 100")
    print(f"  Reports saved  : {output_dir}/")
    print("=" * 60)

    if launch_dashboard:
        import subprocess
        print("\n[*] Launching Streamlit dashboard…")
        subprocess.Popen([
            "streamlit", "run", "reporting_module.py",
            "--", analysis_path
        ])


def main():
    args = parse_args()

    # ── Load recon data ───────────────────────
    if args.skip_recon or args.recon_file:
        recon_file = args.recon_file or f"vuln_recon_{args.target.replace('.','_')}.json"
        print(f"[*] Loading recon data from {recon_file}")
        with open(recon_file) as f:
            recon_data = json.load(f)
    else:
        # Run Module 1 & 2 (existing code)
        try:
            from recon_module import run_recon   # your existing module
        except ImportError:
            from recon import run_recon           # fallback name

        print("\n" + "=" * 60)
        print("  MODULE 1 & 2 – Reconnaissance + Data Parsing")
        print("=" * 60)
        recon_data = run_recon(args.target)

    run_pipeline(
        target          = args.target,
        recon_data      = recon_data,
        output_dir      = args.output_dir,
        launch_dashboard= not args.no_dashboard,
    )


if __name__ == "__main__":
    main()
