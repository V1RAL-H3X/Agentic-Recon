import os
import requests
from typing import Dict, Any, Optional

# Safe scope fallback
try:
    from src.config import ALLOWED_TARGETS
except ImportError:
    ALLOWED_TARGETS = []


class HexStrikeBridge:
    """
    Bridge client connecting agentic-recon to a local or remote HexStrike FastMCP server.
    Ensures pre-execution scope validation before dispatching tool calls.
    """

    def __init__(self, base_url: str = "http://localhost:8888", api_key: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.headers = {"X-API-Key": api_key} if api_key else {}
        self.headers["Content-Type"] = "application/json"

    def is_alive(self) -> bool:
        """Checks if the HexStrike FastMCP server is online and reachable."""
        try:
            response = requests.get(f"{self.base_url}/health", headers=self.headers, timeout=3)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def validate_scope(self, target: str) -> bool:
        """
        Pre-execution guardrail. Ensures target resides within allowed scope bounds
        defined in the framework configuration.
        """
        # Checks if target matches configured allowed domains/IPs
        if hasattr(ALLOWED_TARGETS, "__contains__"):
            return target in ALLOWED_TARGETS
        return True  # Fallback if scope list is managed externally

    def execute_tool(self, tool_name: str, target: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Dispatches execution request to HexStrike server if target passes scope validation.
        """
        if not self.validate_scope(target):
            raise ValueError(f"[Scope Guardrail] Target '{target}' is OUT OF SCOPE. Execution blocked.")

        if not self.is_alive():
            raise ConnectionError(f"[HexStrike Error] Server at {self.base_url} is unreachable.")

        endpoint = f"{self.base_url}/api/tools/{tool_name}"
        payload = {"target": target, **(params or {})}

        try:
            response = requests.post(endpoint, json=payload, headers=self.headers, timeout=120)
            response.raise_for_status()
            return self.normalize_output(tool_name, target, response.json())
        except requests.RequestException as e:
            return {
                "status": "error",
                "tool": tool_name,
                "target": target,
                "error": str(e)
            }

    def normalize_output(self, tool_name: str, target: str, raw_response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Standardizes raw JSON responses from HexStrike into a node-link schema
        ready for insertion into the NetworkX attack graph.
        """
        return {
            "status": "success",
            "tool": tool_name,
            "target": target,
            "nodes": raw_response.get("nodes", []),
            "edges": raw_response.get("edges", []),
            "raw_output": raw_response.get("result", {})
        }