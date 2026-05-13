"""Enrichissement local des adresses IP.

Le but est volontairement simple et hors-ligne : afficher une organisation
probable sans lancer de requete WHOIS/API pendant que le pare-feu tourne.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional


@dataclass(frozen=True)
class NetworkOwner:
    cidr: str
    name: str

    @property
    def network(self) -> ipaddress._BaseNetwork:
        return ipaddress.ip_network(self.cidr)


_OWNERS = [
    NetworkOwner("10.0.0.0/8", "Reseau prive"),
    NetworkOwner("172.16.0.0/12", "Reseau prive"),
    NetworkOwner("192.168.0.0/16", "Reseau prive"),
    NetworkOwner("127.0.0.0/8", "Boucle locale"),
    NetworkOwner("169.254.0.0/16", "Lien local"),
    NetworkOwner("224.0.0.0/4", "Multicast"),
    NetworkOwner("::1/128", "Boucle locale"),
    NetworkOwner("fc00::/7", "Reseau prive IPv6"),
    NetworkOwner("fe80::/10", "Lien local IPv6"),
    NetworkOwner("8.8.8.0/24", "Google"),
    NetworkOwner("8.8.4.0/24", "Google"),
    NetworkOwner("1.1.1.0/24", "Cloudflare"),
    NetworkOwner("1.0.0.0/24", "Cloudflare"),
    NetworkOwner("9.9.9.0/24", "Quad9"),
    NetworkOwner("208.67.222.0/24", "Cisco OpenDNS"),
    NetworkOwner("208.67.220.0/24", "Cisco OpenDNS"),
    NetworkOwner("185.199.108.0/22", "GitHub"),
    NetworkOwner("140.82.112.0/20", "GitHub"),
    NetworkOwner("151.101.0.0/16", "Fastly"),
    NetworkOwner("104.16.0.0/12", "Cloudflare"),
    NetworkOwner("172.64.0.0/13", "Cloudflare"),
    NetworkOwner("13.32.0.0/15", "Amazon CloudFront"),
    NetworkOwner("13.224.0.0/14", "Amazon CloudFront"),
    NetworkOwner("18.64.0.0/14", "Amazon CloudFront"),
    NetworkOwner("52.84.0.0/15", "Amazon CloudFront"),
    NetworkOwner("52.222.128.0/17", "Amazon CloudFront"),
    NetworkOwner("34.64.0.0/10", "Google Cloud"),
    NetworkOwner("35.184.0.0/13", "Google Cloud"),
    NetworkOwner("35.192.0.0/12", "Google Cloud"),
    NetworkOwner("142.250.0.0/15", "Google"),
    NetworkOwner("172.217.0.0/16", "Google"),
    NetworkOwner("172.253.0.0/16", "Google"),
    NetworkOwner("173.194.0.0/16", "Google"),
    NetworkOwner("216.58.192.0/19", "Google"),
    NetworkOwner("40.64.0.0/10", "Microsoft"),
    NetworkOwner("52.96.0.0/12", "Microsoft 365"),
    NetworkOwner("20.0.0.0/8", "Microsoft Azure"),
    NetworkOwner("13.64.0.0/11", "Microsoft Azure"),
    NetworkOwner("31.13.64.0/18", "Meta"),
    NetworkOwner("57.144.0.0/14", "Meta"),
    NetworkOwner("157.240.0.0/16", "Meta"),
]

_NETWORKS = tuple((owner.network, owner.name) for owner in _OWNERS)


@lru_cache(maxsize=8192)
def company_for_ip(ip: str) -> Optional[str]:
    """Retourne l'organisation probable d'une IP sans acces reseau."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    for network, name in _NETWORKS:
        if addr.version == network.version and addr in network:
            return name
    return None
