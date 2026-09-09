import json
import logging
import networkx as nx
import matplotlib.pyplot as plt


class AttackGraph:
    """
    Manages the attack surface directed graph using NetworkX.
    Tracks hosts, open ports, web endpoints, vulnerabilities, and relationships.
    """

    def __init__(self):
        self.graph = nx.DiGraph()

    def add_node(self, node_id: str, **attrs):
        """Adds or updates a node in the graph with optional attributes."""
        self.graph.add_node(node_id, **attrs)

    def add_target_node(self, target: str):
        """Adds the root target node to the graph."""
        self.add_node(target, node_type="web_service", url=target)

    def add_service(self, target: str = None, host: str = None, port: int = None, service_name: str = None,
                    service: str = None, protocol: str = "tcp", state: str = "open", **attrs):
        """Adds a port/service node and links it to the target/host."""
        t = target or host
        s_name = service_name or service or "unknown"
        port_node_id = f"{t}:{port}"

        self.add_node(
            port_node_id,
            node_type="port",
            port=port,
            service=s_name,
            protocol=protocol,
            state=state,
            **attrs
        )
        self.add_edge(t, port_node_id, relationship="HAS_PORT")

    def add_edge(self, u: str, v: str, **attrs):
        """Adds a directed edge between two nodes with optional relationship attributes."""
        self.graph.add_edge(u, v, **attrs)

    def get_summary(self) -> dict:
        """Returns a summary dictionary of nodes, edges, and graph statistics."""
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "nodes": list(self.graph.nodes(data=True)),
            "edges": list(self.graph.edges(data=True))
        }

    def export_json(self, filepath: str = "graph_export.json"):
        """Exports the graph topology and attributes to a JSON file."""
        try:
            data = nx.node_link_data(self.graph)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            logging.info(f"[*] AttackGraph exported to JSON: {filepath}")
        except Exception as e:
            logging.error(f"[!] Failed to export AttackGraph JSON: {str(e)}")

    def visualize(self, filepath: str = "attack_graph.png"):
        """Renders the attack surface graph to an image file with custom styling."""
        if len(self.graph.nodes) == 0:
            logging.warning("[!] AttackGraph is empty. Skipping visual rendering.")
            return

        try:
            plt.figure(figsize=(12, 9))
            pos = nx.spring_layout(self.graph, k=0.5, iterations=50)

            color_map = []
            for _, attrs in self.graph.nodes(data=True):
                node_type = attrs.get("node_type", "default")
                if node_type == "web_service":
                    color_map.append("#3498db")  # Blue
                elif node_type == "endpoint":
                    color_map.append("#2ecc71")  # Green
                elif node_type == "port":
                    color_map.append("#f1c40f")  # Yellow
                elif node_type == "vulnerability":
                    color_map.append("#e74c3c")  # Red
                else:
                    color_map.append("#95a5a6")  # Gray

            nx.draw_networkx_nodes(
                self.graph, pos, node_color=color_map, node_size=2200, alpha=0.9
            )
            nx.draw_networkx_edges(
                self.graph, pos, arrowstyle="->", arrowsize=15, edge_color="#bdc3c7", width=1.5
            )
            nx.draw_networkx_labels(
                self.graph, pos, font_size=8, font_weight="bold"
            )

            plt.title("Agentic-Recon Attack Surface Topology", fontsize=14)
            plt.axis("off")
            plt.tight_layout()
            plt.savefig(filepath, dpi=300, bbox_inches="tight")
            plt.close()
            logging.info(f"[*] AttackGraph visualization rendered to: {filepath}")
        except Exception as e:
            logging.error(f"[!] Failed to visualize AttackGraph: {str(e)}")