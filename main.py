from recon_module import run_all_recon
from vulnerability_module import analyze_vulnerabilities
import json

target = input("Enter target IP or domain: ")

print("\nStarting Recon...")

recon = run_all_recon(target)

print("Recon Complete")

services = recon["services"]

print("\nStarting Vulnerability Analysis...")

vulns = analyze_vulnerabilities(services)

final_report = {
    "target": target,
    "recon": recon,
    "vulnerabilities": vulns
}

filename = f"vulnvas_report_{target.replace('.','_')}.json"

with open(filename, "w") as f:

    json.dump(final_report, f, indent=4)

print("\nScan Complete")

print(f"Report saved to {filename}")
