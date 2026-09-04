import ipaddress
from typing import List, Optional


class ScopeValidator:
    """
    Validates whether domains, subdomains, or IP addresses fall strictly
    within defined target scope guardrails.
    """

    def __init__(self, allowed_domains: Optional[List[str]] = None, allowed_cidrs: Optional[List[str]] = None):
        self.allowed_domains = [d.lower().strip() for d in (allowed_domains or [])]
        self.allowed_cidrs = [ipaddress.ip_network(c.strip()) for c in (allowed_cidrs or [])]

    def is_in_scope(self, target: str) -> bool:
        """
        Checks if a given domain, subdomain, or IP is within scope.
        """
        if not target:
            return False

        target_clean = target.lower().strip()

        # 1. Domain / Subdomain Scope Check
        for domain in self.allowed_domains:
            if target_clean == domain or target_clean.endswith(f".{domain}"):
                return True

        # 2. IP / CIDR Scope Check
        try:
            target_ip = ipaddress.ip_address(target_clean)
            for cidr in self.allowed_cidrs:
                if target_ip in cidr:
                    return True
        except ValueError:
            # Target is a domain string, not an IP address
            pass

        return False