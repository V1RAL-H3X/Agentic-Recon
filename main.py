import argparse
import json
import sys
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
        help="Reconnaissance task/tool to execute (e.g., portscan, subdomains)"
    )

    parser.add_argument(
        "--hexstrike-url",
        type=str,
        default="http://localhost:8888",
        help="Base URL for the HexStrike API bridge (default: http://localhost:8888)"
    )

    parser.add_argument(
        "--export-graph",
        type=str,
        help="Path to export the final graph summary JSON (e.g., output.json)"
    )

    parser.add_argument(
        "--visualize",
        type=str,
        help="Path to save the graph visualization image (e.g., attack_graph.png)"
    )

    args = parser.parse_args()

    print("=" * 60)
    print(" Agentic-Recon Framework | Automated Threat Surface Mapping")
    print("=" * 60)
    print(f"[*] Target Scope    : {args.target}")
    print(f"[*] Initial Task    : {args.task}")
    print(f"[*] HexStrike Bridge: {args.hexstrike_url}")
    print("-" * 60)

    # 1. Initialize Agent Engine
    agent = ReconAgent(target=args.target, hexstrike_url=args.hexstrike_url)

    # 2. Execute Task
    result = agent.run_task(tool_name=args.task)

    # 3. Print Results & Graph Topology
    print("-" * 60)
    print("[+] Execution Complete.")
    summary = agent.graph.get_summary()
    print(f"[*] Attack Graph Topology: {summary['total_nodes']} Nodes, {summary['total_edges']} Edges Discovered.")

    for node in summary["nodes"]:
        print(f"    └── Node: {node[0]} | Attributes: {node[1]}")

    # 4. Optional JSON Export
    if args.export_graph:
        with open(args.export_graph, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"[+] Graph saved to '{args.export_graph}'")

    # 5. Optional Graph Visualization Image
    if args.visualize:
        agent.graph.visualize(args.visualize)

    print("=" * 60)


if __name__ == "__main__":
    main()