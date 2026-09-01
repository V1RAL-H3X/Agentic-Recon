import networkx as nx
from typing import Dict, Any, List, Optional
import matplotlib.pyplot as plt

class AttackGraph:
    """
    In-memory NetworkX graph representing the target's discovered attack surface.
    Tracks subdomains, ports, services, endpoints, and their relationships.
    """

    def __init__(self):
        self.graph = nx.DiGraph()

    def add_target_node(self, target: str) -> None:
        """Adds a root target or subdomain node."""
        if not self.graph.has_node(target):
            self.graph.add_node(target, type="domain")

    def add_port(self, host: str, port: int, protocol: str = "tcp") -> str:
        """
        Links a host node to a port node.
        Relationship: (Host) -[HAS_PORT]-> (Port)
        """
        self.add_target_node(host)
        port_node_id = f"{host}:{port}/{protocol}"

        self.graph.add_node(
            port_node_id,
            type="port",
            port_number=port,
            protocol=protocol
        )
        self.graph.add_edge(host, port_node_id, relationship="HAS_PORT")
        return port_node_id

    def add_service(self, host: str, port: int, service_name: str, version: Optional[str] = None, protocol: str = "tcp") -> str:
        """
        Links a port node to a service node.
        Relationship: (Port) -[RUNS_SERVICE]-> (Service)
        """
        port_node_id = self.add_port(host, port, protocol)
        service_node_id = f"service:{service_name}:{host}:{port}"

        self.graph.add_node(
            service_node_id,
            type="service",
            name=service_name,
            version=version or "unknown"
        )
        self.graph.add_edge(port_node_id, service_node_id, relationship="RUNS_SERVICE")
        return service_node_id

    def add_endpoint(self, host: str, path: str, status_code: Optional[int] = None) -> str:
        """
        Links a host node to a web endpoint node.
        Relationship: (Host) -[EXPOSES_ENDPOINT]-> (Endpoint)
        """
        self.add_target_node(host)
        endpoint_node_id = f"{host}{path}"

        self.graph.add_node(
            endpoint_node_id,
            type="endpoint",
            path=path,
            status_code=status_code
        )
        self.graph.add_edge(host, endpoint_node_id, relationship="EXPOSES_ENDPOINT")
        return endpoint_node_id

    def get_summary(self) -> Dict[str, Any]:
        """Returns node and edge counts grouped by type."""
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "nodes": list(self.graph.nodes(data=True)),
            "edges": list(self.graph.edges(data=True))
        }

    def visualize(self, output_file: str = "attack_graph.png") -> str:
        """
        Renders the AttackGraph to a PNG image with color-coded node types.
        """
        if self.graph.number_of_nodes() == 0:
            print("[!] Cannot render an empty graph.")
            return ""

        plt.figure(figsize=(10, 7))
        pos = nx.spring_layout(self.graph, seed=42)

        # Color mapping by node type
        color_map = []
        for _, data in self.graph.nodes(data=True):
            node_type = data.get("type", "")
            if node_type == "domain":
                color_map.append("#4C72B0")  # Blue
            elif node_type == "port":
                color_map.append("#DD8452")  # Orange
            elif node_type == "service":
                color_map.append("#55A868")  # Green
            elif node_type == "endpoint":
                color_map.append("#C44E52")  # Red
            else:
                color_map.append("#8172B3")  # Purple default

        # Draw nodes & edges
        nx.draw_networkx_nodes(self.graph, pos, node_color=color_map, node_size=1200, alpha=0.9)
        nx.draw_networkx_edges(self.graph, pos, arrowstyle="->", arrowsize=15, edge_color="#888888", width=1.5)
        nx.draw_networkx_labels(self.graph, pos, font_size=8, font_family="sans-serif", font_weight="bold")

        # Edge relationship labels
        edge_labels = nx.get_edge_attributes(self.graph, "relationship")
        nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=edge_labels, font_size=7)

        plt.title("Agentic-Recon Attack Surface Topology", fontsize=12, fontweight="bold")
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(output_file, dpi=300)
        plt.close()

        print(f"[+] Attack graph image generated: '{output_file}'")
        return output_file