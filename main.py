import argparse
import json
import logging
from src.agents.web_recon import WebReconAgent
from src.attack_graph import AttackGraph
from src.agent import ReconAgent


def main():
    parser = argparse.ArgumentParser(
        description="Agentic-Recon: AI-Driven Security Reconnaissance Framework"
    )

    parser.add_argument(
        "-t", "--target",
        type=str,
        required=True,
        help="Target domain or IP address to perform reconnaissance against"
    )

    parser.add_argument(
        "--task",
        type=str,
        default="portscan",
        help="Single reconnaissance task to execute (ignored if --auto is set)"
    )

    parser.add_argument(
        "--auto",
        action="store_true",
        help="Enable autonomous execution mode where LLMPlanner drives the recon loop"
    )

    parser.add_argument(
        "--max-steps",
        type=int,
        default=5,
        help="Maximum decision loop iterations in --auto mode (default: 5)"
    )

    parser.add_argument(
        "--hexstrike-url",
        type=str,
        default="http://localhost:8888",
        help="Base URL for the HexStrike API bridge"
    )

    parser.add_argument(
        "--web-test",
        action="store_true",
        help="Run standalone WebReconAgent directory fuzzing test"
    )

    parser.add_argument(
        "--export-graph",
        type=str,
        default="graph_export.json",
        help="Path to export final graph summary JSON"
    )

    parser.add_argument(
        "--visualize",
        type=str,
        default="attack_graph.png",
        help="Path to save graph topology visualization image"
    )

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="[*] %(message)s")

    print("=" * 60)
    print(" Agentic-Recon Framework | Autonomous Threat Surface Mapping")
    print("=" * 60)

    # Branch 1: Standalone Web Recon Test via --web-test
    if args.web_test:
        print(f"[*] Mode            : STANDALONE WEB RECON (Gobuster/FFUF)")
        print(f"[*] Target Scope    : {args.target}")
        print("-" * 60)

        target_url = args.target if args.target.startswith("http") else f"http://{args.target}"
        web_agent = WebReconAgent()
        result = web_agent.execute_dir_fuzz(target_url)

        graph = AttackGraph()
        graph.add_node(target_url, node_type="web_service", url=target_url)

        if result.get("status") == "success":
            paths = result.get("discovered_paths", [])
            logging.info(f"Discovered {len(paths)} web endpoints.")
            for item in paths:
                endpoint_url = item["url"]
                graph.add_node(endpoint_url, node_type="endpoint", path=item["path"])
                graph.add_edge(target_url, endpoint_url, relationship="EXPOSES_ENDPOINT")
        else:
            logging.error(f"Web Recon failed: {result.get('reason')}")

        if args.export_graph:
            graph.export_json(args.export_graph)
        if args.visualize:
            graph.visualize(args.visualize)

        print("=" * 60)
        return

    # Branch 2: Core Autonomous / Task Engine (Default behavior)
    print(f"[*] Target Scope    : {args.target}")
    print(f"[*] Mode            : {'AUTONOMOUS (LLM Loop)' if args.auto else f'MANUAL ({args.task})'}")
    print(f"[*] HexStrike Bridge: {args.hexstrike_url}")
    print("-" * 60)

    agent = ReconAgent(target=args.target, hexstrike_url=args.hexstrike_url)

    if args.auto:
        print("[*] Initiating Autonomous Planning Loop...\n")
        step_count = 0
        while step_count < args.max_steps:
            step_count += 1
            print(f"--- [ Loop Step {step_count} / {args.max_steps} ] ---")
            result = agent.auto_step()

            if result.get("status") == "finished":
                print(f"\n[+] Planner signaled completion: {result.get('reason')}")
                break
    else:
        agent.run_task(tool_name=args.task)

    print("-" * 60)
    print("[+] Execution Complete.")
    summary = agent.graph.get_summary()
    print(f"[*] Attack Graph Topology: {summary['total_nodes']} Nodes, {summary['total_edges']} Edges Discovered.")

    for node in summary["nodes"]:
        print(f"    └── Node: {node[0]} | Attributes: {node[1]}")

    if args.export_graph:
        with open(args.export_graph, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"[+] Graph saved to '{args.export_graph}'")

    if args.visualize:
        agent.graph.visualize(args.visualize)

    print("=" * 60)


if __name__ == "__main__":
    main()