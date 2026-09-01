from typing import Dict, Any, Optional
from src.attack_graph import AttackGraph
from src.tools.hexstrike_bridge import HexStrikeBridge


class ReconAgent:
    """
    Main agent orchestration loop. Coordinates scope checks, tool dispatch via HexStrike,
    and attack surface mapping via AttackGraph.
    """

    def __init__(self, target: str, hexstrike_url: str = "http://localhost:8888"):
        self.target = target
        self.graph = AttackGraph()
        self.graph.add_target_node(target)
        self.bridge = HexStrikeBridge(base_url=hexstrike_url)

    def run_task(self, tool_name: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes a recon task. Attempts execution via HexStrikeBridge, falling back
        to direct graph updates or local wrappers if the server is offline.
        """
        print(f"[*] Agent dispatching task: '{tool_name}' against target: '{self.target}'")

        # 1. Scope Check & Server Health
        if not self.bridge.validate_scope(self.target):
            print(f"[-] [Guardrail Blocked] Target '{self.target}' is out of scope!")
            return {"status": "blocked", "reason": "out_of_scope"}

        if not self.bridge.is_alive():
            print(f"[!] HexStrike server offline at {self.bridge.base_url}. Using local fallback mode.")
            # Local fallback / mock execution state for offline development
            return self._execute_fallback(tool_name, params)

        # 2. Dispatch via HexStrike Bridge
        result = self.bridge.execute_tool(tool_name, self.target, params)

        # 3. Ingest normalized results into AttackGraph
        if result.get("status") == "success":
            self._ingest_results(result)

        return result

    def _ingest_results(self, result: Dict[str, Any]) -> None:
        """Parses normalized bridge outputs into AttackGraph nodes and edges."""
        for node in result.get("nodes", []):
            node_type = node.get("type")
            if node_type == "port":
                self.graph.add_port(self.target, node.get("port"), node.get("protocol", "tcp"))
            elif node_type == "service":
                self.graph.add_service(
                    self.target,
                    node.get("port"),
                    node.get("service"),
                    node.get("version")
                )
            elif node_type == "endpoint":
                self.graph.add_endpoint(self.target, node.get("path"), node.get("status_code"))

    def _execute_fallback(self, tool_name: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Simulates tool execution when external services are offline (prevents crashes during development)."""
        print(f"[*] Running local mock ingestion for testing '{tool_name}'...")

        # Simulating open port discovery for development test
        if tool_name in ["nmap", "portscan"]:
            self.graph.add_service(self.target, 443, "https", "TLSv1.3")
            self.graph.add_service(self.target, 80, "http", "nginx/1.18.0")
            return {"status": "success", "mode": "fallback", "target": self.target}

        return {"status": "success", "mode": "fallback", "target": self.target}