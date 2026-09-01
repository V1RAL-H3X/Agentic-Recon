import ipaddress
import json
import os
from typing import List, Union
from urllib.parse import urlparse


class ScopeValidator:

  def __init__(
      self,
      allowed_domains: List[str],
      allowed_cidrs: List[str],
      blocked_ips: List[str] = None,
  ):
    self.allowed_domains = [d.lower().strip() for d in allowed_domains]
    self.allowed_cidrs = []
    for cidr in allowed_cidrs:
      try:
        self.allowed_cidrs.append(ipaddress.ip_network(cidr.strip()))
      except ValueError:
        pass

    self.blocked_ips = []
    for ip in blocked_ips or []:
      try:
        self.blocked_ips.append(ipaddress.ip_address(ip.strip()))
      except ValueError:
        pass

  def is_target_in_scope(self, target: str) -> bool:
    """Validates if a domain, URL, IP address, or CIDR is explicitly in scope."""
    cleaned_target = self._clean_target(target)

    # 1. Try parsing target as IP address
    try:
      ip_obj = ipaddress.ip_address(cleaned_target)
      return self._is_ip_in_scope(ip_obj)
    except ValueError:
      pass  # Target is a domain name, not an IP address

    # 2. Check if target is a domain/subdomain
    return self._is_domain_in_scope(cleaned_target)

  def _clean_target(self, target: str) -> str:
    target = target.strip().lower()
    if target.startswith(('http://', 'https://')):
      parsed = urlparse(target)
      target = parsed.netloc.split(':')[0]  # Strip port if present
    return target

  def _is_ip_in_scope(
      self, ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
  ) -> bool:
    if ip in self.blocked_ips or ip.is_loopback:
      return False

    for cidr in self.allowed_cidrs:
      if ip in cidr:
        return True
    return False

  def _is_domain_in_scope(self, domain: str) -> bool:
    for allowed in self.allowed_domains:
      if domain == allowed or domain.endswith('.' + allowed):
        return True
    return False


if __name__ == '__main__':
  # Locate config/scope.json relative to project root
  current_dir = os.path.dirname(os.path.abspath(__file__))
  project_root = os.path.abspath(os.path.join(current_dir, '', '..'))
  config_path = os.path.join(project_root, '../config', 'scope.json')

  if os.path.exists(config_path):
    with open(config_path, 'r') as f:
      config = json.load(f)

    validator = ScopeValidator(
        allowed_domains=config.get('allowed_domains', []),
        allowed_cidrs=config.get('allowed_cidrs', []),
        blocked_ips=config.get('blocked_ips', []),
    )
  else:
    print(f'[!] Warning: {config_path} not found. Using inline fallback.')
    validator = ScopeValidator(
        allowed_domains=['example.com'],
        allowed_cidrs=['192.0.2.0/24'],
        blocked_ips=['192.0.2.5'],
    )

  print('--- Scope Validator Test Results ---')
  print(
      'sub.example.com -> Scope:', validator.is_target_in_scope('sub.example.com')
  )
  print('evil.com        -> Scope:', validator.is_target_in_scope('evil.com'))
  print(
      '192.0.2.10      -> Scope:', validator.is_target_in_scope('192.0.2.10')
  )
  print('192.0.2.5       -> Scope:', validator.is_target_in_scope('192.0.2.5'))