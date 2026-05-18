"""
IP address scanner — collects system, Docker, and external IPs.
Docker dependency is optional; gracefully skipped if not installed.
"""
import socket
import logging

import psutil
import requests

logger = logging.getLogger(__name__)


def get_all_ips() -> dict:
    """
    Collect IP information from multiple sources.

    Returns a dict with keys:
        system_interfaces  – {interface_name: ip}
        docker_containers  – {container_name: ip}  (empty if Docker unavailable)
        external_ip        – public IP string or error message
    """
    result = {
        "system_interfaces": {},
        "docker_containers": {},
        "external_ip": None,
    }

    # --- System network interfaces ---
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                result["system_interfaces"][iface] = addr.address

    # --- Docker containers (optional) ---
    try:
        import docker  # type: ignore
        client = docker.from_env()
        for container in client.containers.list():
            name = container.name
            try:
                networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
                ips = [n.get("IPAddress", "N/A") for n in networks.values() if n.get("IPAddress")]
                result["docker_containers"][name] = ips[0] if ips else "N/A"
            except (KeyError, IndexError):
                result["docker_containers"][name] = "N/A"
    except ImportError:
        logger.debug("docker package not installed — skipping container IP scan.")
    except Exception as e:
        logger.debug("Docker scan error: %s", e)
        result["docker_containers"] = {"error": str(e)}

    # --- External / public IP ---
    try:
        resp = requests.get("https://api.ipify.org", timeout=5)
        resp.raise_for_status()
        result["external_ip"] = resp.text.strip()
    except Exception as e:
        logger.warning("Could not fetch external IP: %s", e)
        result["external_ip"] = f"Error: {e}"

    return result
