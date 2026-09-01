import json
from typing import Dict, Any, List, Optional


class LLMPlanner:
    """
    Analyzes the current AttackGraph memory state and dynamically selects
    the next optimal reconnaissance task.
    """

    def __init__(self, model_name: str = "mock-gpt-4"):
        self.model_name = model_name

    def generate_prompt(self, graph_summary: Dict[str, Any]) -> str:
        """
        Formats the current AttackGraph memory into a structured prompt context.
        """
        nodes_str = json.dumps(graph_summary.get("nodes", []), indent=2)
        edges_str = json.dumps(graph_summary.get("edges", []), indent=2)

        prompt = f"""
You are the AI Planner for an automated security reconnaissance framework (Agentic-Recon).
Your objective is to inspect the current attack graph and determine the single best NEXT reconnaissance action.

### CURRENT ATTACK GRAPH STATE:
Nodes:
{nodes_str}

Relationships:
{edges_str}

### INSTRUCTIONS:
Select the next logical tool task based on discovered open ports, services, or endpoints.
Respond strictly in JSON format matching this schema:
{{
    "tool": "<tool_name_or_task>",
    "target": "<target_host_or_url>",
    "params": {{}},
    "reasoning": "<short explanation of why this step is next>"
}}
"""
        return prompt.strip()

    def decide_next_action(self, graph_summary: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates graph topology and determines the next execution step.
        Falls back to rule-based heuristic decisions when offline or using mock mode.
        """
        # For development/testing: Deterministic heuristic fallback
        return self._heuristic_decision(graph_summary)

    def _heuristic_decision(self, graph_summary: Dict[str, Any]) -> Dict[str, Any]:
        """
        Rule-based reasoning engine used when direct LLM inference is offline.
        """
        discovered_types = set()
        for node in graph_summary.get("nodes", []):
            node_data = node[1] if len(node) > 1 else {}
            discovered_types.add(node_data.get("type"))

        # Rule 1: If we only have domain nodes, run a port scan
        if "port" not in discovered_types:
            target_domain = graph_summary["nodes"][0][0] if graph_summary.get("nodes") else "target.local"
            return {
                "tool": "portscan",
                "target": target_domain,
                "params": {"ports": "top-100"},
                "reasoning": "No ports discovered yet. Executing port scan to identify open network services."
            }

        # Rule 2: If web services are present, discover endpoints
        if "service" in discovered_types and "endpoint" not in discovered_types:
            target_domain = graph_summary["nodes"][0][0] if graph_summary.get("nodes") else "target.local"
            return {
                "tool": "gobuster",
                "target": target_domain,
                "params": {"wordlist": "common.txt"},
                "reasoning": "Discovered active web services. Initiating directory/endpoint discovery."
            }

        # Default completion state
        return {
            "tool": "complete",
            "target": "",
            "params": {},
            "reasoning": "Attack surface mapping complete for current scope."
        }