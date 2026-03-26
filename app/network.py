from __future__ import annotations

import ipaddress
import socket
from typing import List

import psutil

EXCLUDED_INTERFACES = (
    "lo",
    "docker",
    "veth",
    "br-",
    "virbr",
    "utun",
    "tailscale",
    "wg",
    "tun",
    "tap",
)


def _interface_is_excluded(name: str) -> bool:
    lower = name.lower()
    return any(lower.startswith(prefix) for prefix in EXCLUDED_INTERFACES)



def _list_private_interface_addresses() -> dict[str, list[tuple[str, str]]]:
    results: dict[str, list[tuple[str, str]]] = {}
    stats = psutil.net_if_stats()
    for iface_name, addrs in psutil.net_if_addrs().items():
        if _interface_is_excluded(iface_name):
            continue
        iface_stats = stats.get(iface_name)
        if iface_stats and not iface_stats.isup:
            continue

        interface_addresses: list[tuple[str, str]] = []
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            if not addr.address or not addr.netmask:
                continue
            try:
                ip = ipaddress.ip_address(addr.address)
            except ValueError:
                continue
            if ip.is_loopback or not ip.is_private:
                continue
            interface_addresses.append((addr.address, addr.netmask))
        if interface_addresses:
            results[iface_name] = interface_addresses
    return results



def detect_primary_lan_ip() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("10.255.255.255", 1))
            candidate = sock.getsockname()[0]
            ip = ipaddress.ip_address(candidate)
            if ip.is_private:
                return candidate
    except OSError:
        pass

    for _, address_pairs in _list_private_interface_addresses().items():
        for address, _ in address_pairs:
            return address
    return None



def detect_private_ipv4_addresses() -> List[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for _, address_pairs in _list_private_interface_addresses().items():
        for address, _ in address_pairs:
            if address not in seen:
                ordered.append(address)
                seen.add(address)

    primary = detect_primary_lan_ip()
    if primary and primary not in seen:
        ordered.insert(0, primary)

    return ordered



def detect_private_subnets() -> List[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for _, address_pairs in _list_private_interface_addresses().items():
        for address, netmask in address_pairs:
            try:
                network = ipaddress.ip_network(f"{address}/{netmask}", strict=False)
            except ValueError:
                continue
            text = str(network)
            if text not in seen:
                ordered.append(text)
                seen.add(text)

    if not ordered:
        ordered = ["127.0.0.1/32"]
    return ordered



def client_ip_allowed(client_host: str | None, allowed_subnets: list[str]) -> bool:
    if not client_host:
        return False
    try:
        ip = ipaddress.ip_address(client_host)
    except ValueError:
        return False

    if ip.is_loopback:
        return True

    if not allowed_subnets:
        return ip.is_private or ip.is_link_local

    for subnet_text in allowed_subnets:
        try:
            network = ipaddress.ip_network(subnet_text, strict=False)
        except ValueError:
            continue
        if ip in network:
            return True
    return False
