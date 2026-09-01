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
        "--export-graph",
        type=str,
        help="Path to export the final graph summary JSON (e.g., output.json)"
    )

    parser.add_argument(
        "--visualize",
        type=str,
        help="Path to save graph topology visualization image (e.g., attack_graph.png)"
    )

    args = parser.parse_args()

    print("=" * 60)
    print(" Agentic-Recon Framework | Autonomous Threat Surface Mapping")
    print("=" * 60)
    print(f"[*] Target Scope    : {args.target}")
    print(f"[*] Mode            : {'AUTONOMOUS (LLM Loop)' if args.auto else f'MANUAL ({args.task})'}")
    print(f"[*] HexStrike Bridge: {args.hexstrike_url}")
    print("-" * 60)

    # 1. Instantiate Agent Engine
    agent = ReconAgent(target=args.target, hexstrike_url=args.hexstrike_url)

    # 2. Execution Logic
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

    # 3. Print Results & Graph Summary
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