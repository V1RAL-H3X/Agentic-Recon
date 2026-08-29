import json
import logging
from typing import Any, Dict, List, Optional

from src.graph.attack_graph import AttackGraph
from src.tools.discovery import HTTPXTool, SubfinderTool
from src.utils.scope import ScopeValidator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ReconAgent")


class ReconAgent:

  def __init__(self, scope_validator: ScopeValidator):
    self.scope_validator = scope_validator
    self.graph = AttackGraph()
    self.subfinder = SubfinderTool(scope_validator=self.scope_validator)
    self.httpx = HTTPXTool(scope_validator=self.scope_validator)

  def run_recon_cycle(self, seed_domain: str) -> Dict[str, Any]:
    """Executes a multi-stage autonomous recon cycle on a given target domain."""
    logger.info(f"=== Starting Autonomous Recon Cycle on: {seed_domain} ===")

    # Add seed domain to AttackGraph
    self.graph.add_domain(seed_domain)

    # ---------------------------------------------------------
    # STEP 1: Passive Subdomain Enumeration
    # ---------------------------------------------------------
    logger.info(f"[Step 1] Running Subdomain Discovery on {seed_domain}...")
    subfinder_res = self.subfinder.execute(seed_domain)

    discovered_hosts: List[str] = []
    if subfinder_res["status"] == "success" and subfinder_res["data"]:
      for item in subfinder_res["data"]:
        host = item.get("host")
        ip = item.get("ip")
        if host:
          discovered_hosts.append(host)
          self.graph.add_domain(host)
          if ip:
            self.graph.link_domain_to_ip(host, ip)
      logger.info(
          f"Subfinder completed. Discovered {len(discovered_hosts)} subdomains."
      )
    else:
      logger.warning(
          f"Subfinder returned no subdomains or binary unavailable. Adding seed target only."
      )
      discovered_hosts.append(seed_domain)

    # ---------------------------------------------------------
    # STEP 2: Web Service Probing & Fingerprinting
    # ---------------------------------------------------------
    logger.info(
        f"[Step 2] Probing web services across discovered targets..."
    )
    for host in set(discovered_hosts):
      # Probe each discovered target using HTTPX
      httpx_res = self.httpx.execute(host)
      if httpx_res["status"] == "success" and httpx_res["data"]:
        for web_app in httpx_res["data"]:
          url = web_app.get("url", "")
          status_code = web_app.get("status_code", 0)
          title = web_app.get("title", "")
          techs = web_app.get("technologies", [])
          ip = web_app.get("host_ip", "")

          if url:
            self.graph.add_web_app(
                url=url,
                status_code=status_code,
                title=title,
                technologies=techs,
            )
            if ip:
              self.graph.link_domain_to_ip(host, ip)

    # ---------------------------------------------------------
    # STEP 3: Graph Summary & Asset Prioritization
    # ---------------------------------------------------------
    graph_summary = self.graph.get_summary()
    logger.info(
        f"=== Recon Cycle Finished! Graph Summary: {graph_summary} ==="
    )
    return graph_summary

if __name__ == "__main__":
  import os

  # Load scope config
  current_dir = os.path.dirname(os.path.abspath(__file__))
  project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
  config_path = os.path.join(project_root, "config", "scope.json")

  if os.path.exists(config_path):
    with open(config_path, "r") as f:
      config = json.load(f)
  else:
    config = {
        "allowed_domains": ["example.com"],
        "allowed_cidrs": [],
        "blocked_ips": [],
    }

  validator = ScopeValidator(
      allowed_domains=config.get("allowed_domains", []),
      allowed_cidrs=config.get("allowed_cidrs", []),
      blocked_ips=config.get("blocked_ips", []),
  )

  agent = ReconAgent(scope_validator=validator)

  # Test recon execution loop
  summary = agent.run_recon_cycle("example.com")
  print("\n--- Agent Execution Summary ---")
  print(json.dumps(summary, indent=2))