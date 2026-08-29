import argparse
import json
import os
import sys

from src.agent.planner import ReconAgent
from src.utils.scope import ScopeValidator


def export_markdown_report(summary: dict, target: str, output_path: str):
  """Generates an executive Attack Surface summary report in Markdown format."""
  report = f"""# Attack Surface Reconnaissance Report

**Target Seed:** `{target}`  
**Status:** Completed  

---

## Executive Summary

| Entity Metric | Count |
| :--- | :--- |
| **Total Graph Nodes** | {summary.get('total_nodes', 0)} |
| **Total Relationships (Edges)** | {summary.get('total_edges', 0)} |
| **Discovered Domains/Subdomains** | {summary.get('domains', 0)} |
| **Resolved IP Addresses** | {summary.get('ips', 0)} |
| **Open Service Ports** | {summary.get('ports', 0)} |
| **Web Applications Identified** | {summary.get('web_apps', 0)} |

---

## Strategic Recommendations
- **Scope Alignment:** Verify that all discovered subdomains and IPs match active enterprise asset inventories.
- **Port Exposure:** Inspect any non-standard open web ports for legacy administrative interfaces.
"""
  os.makedirs(os.path.dirname(output_path), exist_ok=True)
  with open(output_path, "w") as f:
    f.write(report)


def main():
  parser = argparse.ArgumentParser(
      description="Autonomous Red Team Recon & Surface Analyzer"
  )
  parser.add_argument(
      "-d",
      "--domain",
      required=True,
      help="Target seed domain (e.g., example.com)",
  )
  parser.add_argument(
      "-c",
      "--config",
      default="config/scope.json",
      help="Path to scope config JSON",
  )
  parser.add_argument(
      "-o",
      "--output",
      default="reports",
      help="Output directory for graph and reports",
  )

  args = parser.parse_args()

  # 1. Load Scope Configuration
  if not os.path.exists(args.config):
    print(
        f"[!] Error: Scope configuration file '{args.config}' not found.",
        file=sys.stderr,
    )
    sys.exit(1)

  with open(args.config, "r") as f:
    scope_config = json.load(f)

  validator = ScopeValidator(
      allowed_domains=scope_config.get("allowed_domains", []),
      allowed_cidrs=scope_config.get("allowed_cidrs", []),
      blocked_ips=scope_config.get("blocked_ips", []),
  )

  # 2. Scope Pre-check on Target Seed
  if not validator.is_target_in_scope(args.domain):
    print(
        f"[!] Target domain '{args.domain}' is OUT OF SCOPE according to {args.config}!",
        file=sys.stderr,
    )
    sys.exit(1)

  # 3. Initialize & Execute Recon Agent
  agent = ReconAgent(scope_validator=validator)
  summary = agent.run_recon_cycle(seed_domain=args.domain)

  # 4. Export Artifacts
  json_report_path = os.path.join(
      args.output, f"{args.domain}_attack_graph.json"
  )
  md_report_path = os.path.join(args.output, f"{args.domain}_summary.md")

  agent.graph.export_json(json_report_path)
  export_markdown_report(summary, args.domain, md_report_path)

  print("\n==================================================")
  print(f"[+] Recon Cycle Complete for {args.domain}")
  print(f"[+] Attack Graph JSON saved to: {json_report_path}")
  print(f"[+] Summary Markdown saved to:   {md_report_path}")
  print("==================================================")


if __name__ == "__main__":
  main()