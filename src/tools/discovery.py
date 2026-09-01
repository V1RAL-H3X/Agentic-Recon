import json
from typing import Any, Dict, List
from src.tools.base import BaseTool


class SubfinderTool(BaseTool):

  def __init__(self, scope_validator):
    super().__init__(name="Subfinder", scope_validator=scope_validator)

  def build_command(self, target: str, extra_args: List[str]) -> List[str]:
    # Output json stream for clean parsing
    return ["subfinder", "-d", target, "-silent", "-json"] + extra_args

  def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
    subdomains = []
    for line in raw_output.strip().split("\n"):
      if line.strip():
        try:
          data = json.loads(line)
          subdomains.append({
              "host": data.get("host"),
              "ip": data.get("ip", ""),
              "source": data.get("sources", []),
          })
        except json.JSONDecodeError:
          # Fallback if raw text output is returned
          subdomains.append({"host": line.strip(), "ip": "", "source": []})
    return subdomains


class HTTPXTool(BaseTool):

  def __init__(self, scope_validator):
    super().__init__(name="HTTPX", scope_validator=scope_validator)

  def build_command(self, target: str, extra_args: List[str]) -> List[str]:
    # Probe HTTP/HTTPS ports, grab titles, status codes, and tech stack
    return [
        "httpx",
        "-u",
        target,
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-json",
    ] + extra_args

  def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
    results = []
    for line in raw_output.strip().split("\n"):
      if line.strip():
        try:
          data = json.loads(line)
          results.append({
              "url": data.get("url"),
              "status_code": data.get("status_code"),
              "title": data.get("title", ""),
              "technologies": data.get("tech", []),
              "webserver": data.get("webserver", ""),
              "host_ip": data.get("host", ""),
          })
        except json.JSONDecodeError:
          continue
    return results

  if __name__ == "__main__":
      import os
      from src.scope import ScopeValidator

      # Load config for verification
      current_dir = os.path.dirname(os.path.abspath(__file__))
      project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
      config_path = os.path.join(project_root, "config", "scope.json")

      with open(config_path, "r") as f:
          config = json.load(f)

      validator = ScopeValidator(
          allowed_domains=config.get("allowed_domains", []),
          allowed_cidrs=config.get("allowed_cidrs", []),
          blocked_ips=config.get("blocked_ips", []),
      )

      subfinder = SubfinderTool(scope_validator=validator)

      print("--- Testing Tool Scope Enforcement ---")
      # 1. Test out-of-scope target
      out_scope_res = subfinder.execute("unauthorized-target.com")
      print("Out of scope execution result:", out_scope_res)

      # 2. Test in-scope target (Command won't execute if subfinder binary isn't installed locally yet, but scope check will pass!)
      in_scope_res = subfinder.execute("example.com")
      print("In scope execution result status:", in_scope_res["status"])