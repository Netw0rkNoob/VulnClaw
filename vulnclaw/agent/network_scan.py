"""Network scan planning and weak-link analysis helpers."""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnclaw.agent.context import (
    PentestPhase,
    SessionState,
    StepStatus,
)

NETWORK_SCAN_PROFILES = {"adaptive", "fast", "thorough", "stealth"}

_PRIVILEGED_NMAP_FLAGS = frozenset({"-O", "--osscan-guess"})
_NMAP_PRIVILEGE_ERRORS = (
    "requires root privileges",
    "requires administrator privileges",
    "operation not permitted",
)


def nmap_has_raw_socket_access() -> bool:
    """Return True when nmap can use raw sockets / OS fingerprinting on this host."""
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def without_privileged_nmap_args(args: tuple[str, ...]) -> tuple[str, ...]:
    """Drop root-only nmap flags and downgrade SYN scans to connect scans."""
    result: list[str] = []
    for arg in args:
        if arg in _PRIVILEGED_NMAP_FLAGS:
            continue
        if arg == "-sS":
            if "-sT" not in args and "-sT" not in result:
                result.append("-sT")
            continue
        result.append(arg)
    return tuple(result)


def deescalate_nmap_argv(cmd: list[str]) -> list[str]:
    """Return a copy of an nmap argv list safe for unprivileged execution."""
    if not cmd:
        return cmd
    nmap_cmd, *rest = cmd
    args: list[str] = []
    index = 0
    while index < len(rest):
        arg = rest[index]
        if arg in _PRIVILEGED_NMAP_FLAGS:
            index += 1
            continue
        if arg == "-sS":
            if "-sT" not in rest and "-sT" not in args:
                args.append("-sT")
            index += 1
            continue
        args.append(arg)
        index += 1
    return [nmap_cmd, *args]


def nmap_failure_needs_deescalation(stderr: str) -> bool:
    lowered = (stderr or "").lower()
    return any(message in lowered for message in _NMAP_PRIVILEGE_ERRORS)


@dataclass(frozen=True)
class NmapPlan:
    profile: str
    scan_type: str
    ports: str
    timing: int
    args: tuple[str, ...]
    safe_probe: bool = True


@dataclass(frozen=True)
class WifiScanTarget:
    interface: str
    address: str
    cidr: str


RISK_RULES: list[dict[str, Any]] = [
    {
        "ports": {23},
        "services": {"telnet"},
        "severity": "High",
        "risk": "unencrypted_protocol",
        "reason": "Telnet exposes plaintext authentication and management traffic.",
        "next_action": "Confirm banner and replace with SSH or restrict access.",
    },
    {
        "ports": {21},
        "services": {"ftp"},
        "severity": "Medium",
        "risk": "legacy_file_transfer",
        "reason": "FTP is commonly misconfigured for anonymous or weak authentication.",
        "next_action": "Check banner and anonymous-login exposure without brute force.",
    },
    {
        "ports": {135, 139, 445},
        "services": {"microsoft-ds", "netbios-ssn", "smb"},
        "severity": "Medium",
        "risk": "exposed_windows_file_sharing",
        "reason": "SMB/NetBIOS exposure often leaks host, share, or domain information.",
        "next_action": "Run safe SMB enumeration scripts and verify patch posture.",
    },
    {
        "ports": {3389},
        "services": {"ms-wbt-server", "rdp"},
        "severity": "High",
        "risk": "remote_desktop_exposed",
        "reason": "RDP is a high-value remote access surface.",
        "next_action": "Confirm NLA/TLS posture and restrict exposure.",
    },
    {
        "ports": {1433, 1521, 3306, 5432, 27017},
        "services": {"mysql", "postgresql", "ms-sql-s", "oracle", "mongodb"},
        "severity": "High",
        "risk": "database_exposed",
        "reason": "Database services should rarely be broadly reachable.",
        "next_action": "Confirm service/version and access controls without credential attacks.",
    },
    {
        "ports": {161},
        "services": {"snmp"},
        "severity": "Medium",
        "risk": "snmp_exposed",
        "reason": "SNMP may disclose system and network details.",
        "next_action": "Run safe SNMP discovery and verify community-string exposure only if permitted.",
    },
    {
        "ports": {80, 443, 8000, 8080, 8443, 8888},
        "services": {"http", "https", "http-proxy"},
        "severity": "Low",
        "risk": "web_surface",
        "reason": "Web service requires application-layer fingerprinting.",
        "next_action": "Collect title, headers, TLS details, and obvious admin paths.",
    },
]


def build_nmap_plan(
    *,
    profile: str = "adaptive",
    scan_type: str = "",
    ports: str = "",
    timing: int | None = None,
    prior_recon: dict[str, Any] | None = None,
) -> NmapPlan:
    """Build a deterministic nmap plan from profile and explicit overrides."""
    normalized = (profile or "adaptive").strip().lower()
    if normalized not in NETWORK_SCAN_PROFILES:
        normalized = "adaptive"

    explicit_scan_type = (scan_type or "").strip().lower()
    explicit_ports = (ports or "").strip()
    timing_override = max(0, min(5, int(timing))) if timing is not None else None

    if normalized == "fast":
        plan = NmapPlan(
            profile=normalized,
            scan_type=explicit_scan_type or "service",
            ports=explicit_ports or "1-1000",
            timing=timing_override if timing_override is not None else 4,
            args=("-q", "-sV", "-F"),
        )
    elif normalized == "thorough":
        plan = NmapPlan(
            profile=normalized,
            scan_type=explicit_scan_type or "full",
            ports=explicit_ports or "1-65535",
            timing=timing_override if timing_override is not None else 3,
            args=("-v", "-sV", "-O", "--script", "default,safe"),
        )
    elif normalized == "stealth":
        plan = NmapPlan(
            profile=normalized,
            scan_type=explicit_scan_type or "syn",
            ports=explicit_ports or "1-1000",
            timing=timing_override if timing_override is not None else 1,
            args=("-q", "-sS", "-f"),
        )
    else:
        adaptive_ports = explicit_ports or _ports_from_prior_recon(prior_recon) or "1-1000"
        plan = NmapPlan(
            profile=normalized,
            scan_type=explicit_scan_type or "service",
            ports=adaptive_ports,
            timing=timing_override if timing_override is not None else 3,
            args=("-q", "-sV", "--script", "safe"),
        )

    return plan


def build_nmap_command(
    nmap_cmd: str,
    target: str,
    plan: NmapPlan,
    *,
    privileged: bool | None = None,
) -> list[str]:
    """Render a safe argv list for subprocess-based nmap execution."""
    args = plan.args
    if privileged is None:
        privileged = nmap_has_raw_socket_access()
    if not privileged:
        args = without_privileged_nmap_args(args)
    cmd = [nmap_cmd, *args, f"-T{plan.timing}", "-oX", "-"]
    if plan.ports:
        cmd.extend(["-p", plan.ports])
    cmd.append(target)
    return cmd


def detect_connected_wifi_target() -> WifiScanTarget:
    """Detect the active Wi-Fi IPv4 network to use as the default scan target."""
    candidates = _wifi_interfaces()
    if not candidates:
        raise RuntimeError(
            "No wireless interface was detected. Provide an explicit target, "
            "for example: vulnclaw network-scan 192.168.1.0/24"
        )

    for interface in candidates:
        if not _interface_is_up(interface):
            continue
        target = _interface_ipv4_network(interface)
        if target is not None:
            return target

    raise RuntimeError(
        "A wireless interface was detected, but no active IPv4 Wi-Fi network was found. "
        "Connect to Wi-Fi or provide an explicit target."
    )


def parse_nmap_xml_structured(xml_output: str, target: str) -> dict[str, Any]:
    """Parse nmap XML into structured hosts, services, and weak-link hints."""
    if not xml_output or "<nmaprun" not in xml_output:
        return {
            "target": target,
            "hosts": [],
            "open_services": [],
            "weak_links": [],
            "error": "nmap XML output was not available",
        }

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        return {
            "target": target,
            "hosts": [],
            "open_services": [],
            "weak_links": [],
            "error": f"nmap XML parse failed: {exc}",
        }

    hosts: list[dict[str, Any]] = []
    open_services: list[dict[str, Any]] = []
    weak_links: list[dict[str, Any]] = []

    for host in root.findall(".//host"):
        addrs = [a.get("addr", "") for a in host.findall("address") if a.get("addr")]
        hostnames = [h.get("name", "") for h in host.findall(".//hostname") if h.get("name")]
        status = host.find("status")
        host_ip = addrs[0] if addrs else target
        host_record = {
            "address": host_ip,
            "hostnames": hostnames,
            "status": status.get("state", "unknown") if status is not None else "unknown",
            "ports": [],
        }

        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            scripts = [
                {"id": script.get("id", ""), "output": script.get("output", "")}
                for script in port.findall("script")
            ]
            service_record = {
                "host": host_ip,
                "port": _safe_int(port.get("portid", "")),
                "protocol": port.get("protocol", "tcp"),
                "state": state.get("state", "open"),
                "service": service.get("name", "") if service is not None else "",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
                "extrainfo": service.get("extrainfo", "") if service is not None else "",
                "scripts": scripts,
            }
            host_record["ports"].append(service_record)
            open_services.append(service_record)
            weak_link = classify_weak_link(service_record)
            if weak_link:
                weak_links.append(weak_link)

        hosts.append(host_record)

    return {
        "target": target,
        "hosts": hosts,
        "open_services": open_services,
        "weak_links": sorted(weak_links, key=lambda item: _severity_rank(item["severity"])),
    }


def classify_weak_link(service: dict[str, Any]) -> dict[str, Any] | None:
    port = int(service.get("port") or 0)
    name = str(service.get("service", "") or "").lower()
    for rule in RISK_RULES:
        if port in rule["ports"] or name in rule["services"]:
            host = service.get("host", "")
            return {
                "host": host,
                "port": port,
                "protocol": service.get("protocol", "tcp"),
                "service": service.get("service", ""),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
                "severity": rule["severity"],
                "risk": rule["risk"],
                "reason": rule["reason"],
                "next_action": rule["next_action"],
                "target": f"{host}:{port}" if host and port else host or str(port),
            }
    return None


def summarize_network_scan(structured: dict[str, Any], *, max_items: int = 8) -> str:
    services = structured.get("open_services", [])
    weak_links = structured.get("weak_links", [])
    lines = [
        "Network scan weak-link summary",
        f"- Open services: {len(services)}",
        f"- Weak-link candidates: {len(weak_links)}",
    ]
    for item in weak_links[:max_items]:
        product = " ".join(
            part for part in (item.get("product", ""), item.get("version", "")) if part
        )
        product_suffix = f" ({product})" if product else ""
        lines.append(
            f"- {item['severity']}: {item['target']} {item.get('service', '')}{product_suffix} "
            f"- {item['risk']}: {item['reason']}"
        )
    return "\n".join(lines)


def attach_network_scan_to_session(
    session: SessionState,
    structured: dict[str, Any],
    *,
    profile: str,
    safe_probes: bool = True,
) -> None:
    """Persist network scan facts and weak-link observations for explicit candidate submission."""
    if not structured:
        return

    session.phase = PentestPhase.VULN_DISCOVERY
    network_scans = session.recon_data.setdefault("network_scans", [])
    network_scans.append(
        {
            "target": structured.get("target", session.target or ""),
            "profile": profile,
            "safe_probes": safe_probes,
            "open_services": structured.get("open_services", []),
            "weak_links": structured.get("weak_links", []),
        }
    )
    session.recon_data["network_services"] = _dedupe_services(
        session.recon_data.get("network_services", []), structured.get("open_services", [])
    )

    session.add_step(
        f"network_scan:{structured.get('target', session.target or '')}:{profile}",
        action="network scan",
        target=str(structured.get("target", session.target or "")),
        result=(
            f"{len(structured.get('open_services', []))} open services, "
            f"{len(structured.get('weak_links', []))} weak-link candidates"
        ),
        status=StepStatus.SUCCESS,
        detail=json.dumps(structured, ensure_ascii=False)[:4000],
    )


def target_is_private_literal(target: str) -> bool:
    """Return true when the user explicitly supplied a private/reserved IP or network."""
    text = (target or "").strip()
    try:
        if "/" in text:
            network = ipaddress.ip_network(text, strict=False)
            return network.is_private or network.is_loopback or network.is_link_local
        addr = ipaddress.ip_address(text)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _wifi_interfaces() -> list[str]:
    interfaces: list[str] = []
    try:
        result = subprocess.run(
            ["iw", "dev"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("Interface "):
                    iface = stripped.split(maxsplit=1)[1].strip()
                    if iface and iface not in interfaces:
                        interfaces.append(iface)
    except Exception:
        pass

    sys_net = Path("/sys/class/net")
    try:
        for path in sorted(sys_net.iterdir()):
            if (path / "wireless").exists() and path.name not in interfaces:
                interfaces.append(path.name)
    except Exception:
        pass

    return interfaces


def _interface_is_up(interface: str) -> bool:
    try:
        state = (Path("/sys/class/net") / interface / "operstate").read_text(
            encoding="utf-8"
        )
        return state.strip().lower() in {"up", "unknown"}
    except Exception:
        return True


def _interface_ipv4_network(interface: str) -> WifiScanTarget | None:
    try:
        result = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "dev", interface],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
    except Exception:
        return None

    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        parts = line.split()
        if "inet" not in parts:
            continue
        inet_index = parts.index("inet")
        if inet_index + 1 >= len(parts):
            continue
        cidr = parts[inet_index + 1]
        try:
            iface = ipaddress.ip_interface(cidr)
        except ValueError:
            continue
        network = iface.network
        if network.prefixlen >= 31:
            continue
        return WifiScanTarget(
            interface=interface,
            address=str(iface.ip),
            cidr=str(network),
        )

    return None


def _ports_from_prior_recon(prior_recon: dict[str, Any] | None) -> str:
    if not prior_recon:
        return ""
    ports: set[int] = set()
    for service in prior_recon.get("network_services", []) or []:
        if not isinstance(service, dict):
            continue
        port = _safe_int(service.get("port", ""))
        if port:
            ports.add(port)
    if not ports:
        return ""
    return ",".join(str(port) for port in sorted(ports))


def _dedupe_services(existing: list[Any], current: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for item in existing + current:
        if not isinstance(item, dict):
            continue
        key = f"{item.get('host', '')}:{item.get('port', '')}:{item.get('protocol', '')}"
        by_key[key] = item
    return list(by_key.values())


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _severity_rank(severity: str) -> int:
    return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(severity, 5)
