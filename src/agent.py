import logging
from typing import Dict, Any, Optional
from .attack_graph import AttackGraph
from .planner import LLMPlanner
from .scope import ScopeValidator
from .tools.hexstrike_bridge import HexStrikeBridge

logging.basicConfig(level=logging.INFO, format="[*] %(message)s")


class ReconAgent:
    """
    Core Autonomous Reconnaissance Agent.
    Coordinates AttackGraph topology state, ScopeValidator guardrails, 
    HexStrikeBridge tool dispatches, and LLMPlanner decision loops.
    """

    def __init__(self, target: str, hexstrike_url: Optional[str] = "http://localhost:8888"):
        self.target = target
        self.graph = AttackGraph()
        self.planner = LLMPlanner()

        # Pass target dynamically into ScopeValidator scope rules
        self.scope = ScopeValidator(
            allowed_domains=[self.target],
            allowed_cidrs=[]
        )

        self.bridge = HexStrikeBridge(api_url=hexstrike_url, use_local_binaries=True)

        # Seed root target into the attack topology
        self.graph.add_target_node(self.target)

    def run_task(self, tool_name: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Validates target scope, executes tool via HexStrikeBridge,
        and ingests live topology data into the AttackGraph.
        """
        if not self.scope.is_in_scope(self.target):
            logging.warning(f"Scope Check Failed: Target '{self.target}' is OUT OF SCOPE.")
            return {"status": "blocked", "reason": "Out of scope"}

        logging.info(f"Agent dispatching task: '{tool_name}' against target: '{self.target}'")

        # 1. Dispatch execution via HexStrikeBridge
        result = self.bridge.execute_tool(tool_name=tool_name, target=self.target, params=params)

        # 2. Ingest parsed tool output directly into AttackGraph
        if result.get("status") == "success":
            parsed_data = result.get("parsed_data", {})

            # Ingest Open Ports & Services
            for item in parsed_data.get("open_ports", []):
                port_num = item.get("port")
                protocol = item.get("protocol", "tcp")
                service_name = item.get("service", "unknown")
                version = item.get("version", "unknown")

                self.graph.add_service(
                    host=self.target,
                    port=port_num,
                    service_name=service_name,
                    version=version,
                    protocol=protocol
                )

            # Ingest Discovered Subdomains
            for sub in parsed_data.get("subdomains", []):
                self.graph.add_target_node(sub)

            # Ingest Exposed Web Endpoints
            for ep in parsed_data.get("endpoints", []):
                path = ep.get("path", "/")
                status = ep.get("status_code", 200)
                self.graph.add_endpoint(host=self.target, path=path, status_code=status)

        return result

    def auto_step(self) -> Dict[str, Any]:
        """
        Executes a single iteration of the autonomous decision loop:
        1. Extract current graph summary state.
        2. Query LLMPlanner for the next optimal recon step.
        3. Dispatch step via run_task() if actionable.
        """
        graph_summary = self.graph.get_summary()
        decision = self.planner.decide_next_action(graph_summary)

        chosen_tool = decision.get("tool")
        reasoning = decision.get("reasoning", "No reasoning provided.")

        logging.info(f"Planner Decision: {chosen_tool} -> {reasoning}")

        if chosen_tool == "complete":
            return {"status": "finished", "reason": reasoning}

        # Dispatch the chosen tool
        task_result = self.run_task(tool_name=chosen_tool, params=decision.get("params"))
        return {
            "status": "in_progress",
            "decision": decision,
            "task_result": task_result
        }