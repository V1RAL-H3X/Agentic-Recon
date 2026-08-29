import json
import os
from typing import Any, Dict, List
import networkx as nx


class AttackGraph:

  def __init__(self):
    self.graph = nx.DiGraph()

  def add_domain(self, domain: str, attributes: Dict[str, Any] = None):
    """Adds a domain or subdomain node."""
    node_id = f'domain:{domain.lower().strip()}'
    self.graph.add_node(
        node_id,
        type='Domain',
        name=domain,
        **(attributes or {}),
    )
    return node_id

  def add_ip(self, ip: str, attributes: Dict[str, Any] = None):
    """Adds an IP address node."""
    node_id = f'ip:{ip.strip()}'
    self.graph.add_node(node_id, type='IP', address=ip, **(attributes or {}))
    return node_id

  def add_port(
      self,
      ip: str,
      port: int,
      protocol: str = 'tcp',
      attributes: Dict[str, Any] = None,
  ):
    """Adds a Port node and links it to an IP node via HAS_PORT edge."""
    ip_node = self.add_ip(ip)
    port_node = f'port:{ip}:{port}'
    self.graph.add_node(
        port_node,
        type='Port',
        port=port,
        protocol=protocol,
        **(attributes or {}),
    )
    self.graph.add_edge(ip_node, port_node, relation='HAS_PORT')
    return port_node

  def link_domain_to_ip(self, domain: str, ip: str):
    """Links a Domain to an IP via RESOLVES_TO edge."""
    domain_node = self.add_domain(domain)
    ip_node = self.add_ip(ip)
    self.graph.add_edge(domain_node, ip_node, relation='RESOLVES_TO')

  def add_web_app(
      self, url: str, status_code: int, title: str, technologies: List[str]
  ):
    """Adds a Web Application node and attaches identified technologies."""
    web_node = f'webapp:{url}'
    self.graph.add_node(
        web_node,
        type='WebApp',
        url=url,
        status_code=status_code,
        title=title,
        technologies=technologies,
    )

    # Attach technology tags as separate nodes for relational querying
    for tech in technologies:
      tech_node = f'tech:{tech.lower().strip()}'
      self.graph.add_node(tech_node, type='Technology', name=tech)
      self.graph.add_edge(web_node, tech_node, relation='USES_TECH')

    return web_node

  def get_summary(self) -> Dict[str, Any]:
    """Returns total node counts broken down by entity type."""
    summary = {
        'total_nodes': self.graph.number_of_nodes(),
        'total_edges': self.graph.number_of_edges(),
        'domains': 0,
        'ips': 0,
        'ports': 0,
        'web_apps': 0,
    }
    for _, data in self.graph.nodes(data=True):
      node_type = data.get('type')
      if node_type == 'Domain':
        summary['domains'] += 1
      elif node_type == 'IP':
        summary['ips'] += 1
      elif node_type == 'Port':
        summary['ports'] += 1
      elif node_type == 'WebApp':
        summary['web_apps'] += 1
    return summary

  def export_json(self, filepath: str):
    """Exports the graph data structure to a JSON file for analysis or UI rendering."""
    data = nx.node_link_data(self.graph)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
      json.dump(data, f, indent=2)

if __name__ == "__main__":
  import json

  ag = AttackGraph()

  # Populate dummy recon state
  ag.add_domain("example.com")
  ag.link_domain_to_ip("sub.example.com", "192.0.2.10")
  ag.add_port("192.0.2.10", 443, attributes={"service": "https"})
  ag.add_web_app(
      url="https://sub.example.com",
      status_code=200,
      title="Admin Portal",
      technologies=["React", "Nginx", "Node.js"],
  )

  print("--- Attack Graph Summary Test ---")
  print(json.dumps(ag.get_summary(), indent=2))