"""Host pentest toolchain discovery for the Kali full-toolchain mode.

VulnClaw's built-in tools cover the common web surfaces, but a Kali box
ships hundreds of purpose-built pentest binaries the model never learns
about unless we tell it. This module scans ``PATH`` for a curated list of
known pentest tools (optionally cross-checked against ``dpkg``), groups
them by role, and renders a compact system-prompt section so the agent
knows which tools it can reach through ``shell_command``.

Everything here is stdlib-only and gated behind a single flag:

- ``VULNCLAW_SHELL_TOOL_CATALOG=1/true/yes/on`` forces the mode on;
  any other value forces it off;
- when the variable is unset, a ``kali-rolling`` host turns it on
  automatically;
- otherwise the persisted ``safety.shell_tool_catalog`` config field
  (surfaced through ``load_config``) decides.

With the flag off, every public helper here is either never imported by
the prompt/schema/gate call sites or returns empty/false, so the previous
behavior is byte-for-byte unchanged. The scan itself is cached under
``~/.cache/vulnclaw/tool_catalog.json`` for 24h; a cold scan stays under
~5s (one PATH walk, one ``dpkg -l``, and at most one batched ``whatis``).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path

_TRUTHY = ("1", "true", "yes", "on")

#: Hard budget for a cold scan; whatever has been discovered by then is
#: what we keep.
_SCAN_BUDGET_SECONDS = 4.5

#: TTL for the on-disk catalog cache.
_CACHE_TTL_SECONDS = 24 * 3600

CACHE_FILE = Path.home() / ".cache" / "vulnclaw" / "tool_catalog.json"

CATEGORIES = ("recon", "web", "exploit", "crack", "misc")

#: Tools we never auto-approve into the exec-gate trusted set: they all
#: reach the network / read arbitrary files, so silently trusting them
#: would let the model exfiltrate data without a review prompt. They stay
#: discoverable in the prompt block; they just keep prompting at the gate.
_NO_AUTO_TRUST = frozenset(
    {
        "curl",
        "wget",
        "openssl",
        "tcpdump",
        "host",
        "dig",
        "nslookup",
        "netcat",
        "nc",
    }
)

# ── Known-tool registry ──────────────────────────────────────────────────
# Binary name -> category. "宁多勿少": false positives cost one missed
# PATH hit, false negatives cost the model a tool it could have used.
# Kali metapackages that install differently-named binaries live in
# _PACKAGE_BINARIES below instead.

_TOOLS: dict[str, str] = {
    # recon: scanning, enumeration, discovery, AD/SMB, wireless
    "nmap": "recon",
    "masscan": "recon",
    "rustscan": "recon",
    "netdiscover": "recon",
    "amass": "recon",
    "subfinder": "recon",
    "assetfinder": "recon",
    "findomain": "recon",
    "fierce": "recon",
    "dnsrecon": "recon",
    "dnsenum": "recon",
    "dnsmap": "recon",
    "sublist3r": "recon",
    "theharvester": "recon",
    "recon-ng": "recon",
    "aquatone": "recon",
    "nbtscan": "recon",
    "netbios-ns": "recon",
    "arp-scan": "recon",
    "arpwatch": "recon",
    "snmpwalk": "recon",
    "snmpcheck": "recon",
    "snmp-check": "recon",
    "onesixtyone": "crack",
    "enum4linux": "recon",
    "enum4linux-ng": "recon",
    "smbmap": "recon",
    "smbclient": "recon",
    "rpcclient": "recon",
    "rpcdump": "recon",
    "nxc": "recon",
    "netexec": "recon",
    "crackmapexec": "recon",
    "responder": "exploit",
    "respeaker": "recon",
    "nping": "recon",
    "kerbrute": "recon",
    "enumldap": "recon",
    "ldapsearch": "recon",
    "ldapdomaindump": "recon",
    "getadusers": "recon",
    "aircrack-ng": "crack",
    "bully": "crack",
    "reaver": "crack",
    "wash": "recon",
    "kismet": "recon",
    "mdk4": "crack",
    "wavemon": "recon",
    "host": "recon",
    "dig": "recon",
    "nslookup": "recon",
    "whois": "recon",
    "traceroute": "recon",
    # web: content discovery, fuzzing, fingerprinting, crawling
    "sqlmap": "web",
    "nikto": "web",
    "gobuster": "web",
    "ffuf": "web",
    "feroxbuster": "web",
    "dirb": "web",
    "dirbuster": "web",
    "dirsearch": "web",
    "wfuzz": "web",
    "wpscan": "web",
    "whatweb": "web",
    "wafw00f": "web",
    "httpx": "web",
    "httprobe": "web",
    "nuclei": "web",
    "arjun": "web",
    "paramspider": "web",
    "x8": "web",
    "gau": "web",
    "waybackurls": "web",
    "getJS": "web",
    "arachni": "web",
    "skipfish": "web",
    "w3af": "web",
    "zap": "web",
    "burpsuite": "web",
    "zap.sh": "web",
    "curl": "web",
    "wget": "web",
    "httpie": "web",
    "anew": "web",
    "tojson": "web",
    # exploit: frameworks, credential-relay, privesc helpers, scanners
    "msfconsole": "exploit",
    "msfvenom": "exploit",
    "msfrpc": "exploit",
    "msfrpcd": "exploit",
    "msfupdate": "exploit",
    "armitage": "exploit",
    "searchsploit": "exploit",
    "ntlmrelayx": "exploit",
    "ntlmrelayx.py": "exploit",
    "mitmproxy": "exploit",
    "mitmweb": "exploit",
    "mitmdump": "exploit",
    "bettercap": "exploit",
    "psexec.py": "exploit",
    "impacket-psexec": "exploit",
    "smbexec.py": "exploit",
    "impacket-smbexec": "exploit",
    "wmiexec.py": "exploit",
    "impacket-wmiexec": "exploit",
    "atexec.py": "exploit",
    "impacket-atexec": "exploit",
    "dcomexec.py": "exploit",
    "secretsdump.py": "exploit",
    "impacket-secretsdump": "exploit",
    "getTGT.py": "exploit",
    "impacket-getTGT": "exploit",
    "getUsersSPNs.py": "exploit",
    "getNPUsers.py": "exploit",
    "getUserPassPairs.py": "exploit",
    "lookupsid.py": "exploit",
    "impacket-lookupsid": "exploit",
    "smbclient.py": "exploit",
    "impacket-smbclient": "exploit",
    "reg.py": "exploit",
    "services.py": "exploit",
    "ping6relay": "exploit",
    "linpeas": "exploit",
    "linpeas.sh": "exploit",
    "winpeas": "exploit",
    "winPEAS.exe": "exploit",
    "pspy": "exploit",
    "pspy64": "exploit",
    "lse.sh": "exploit",
    "unix-privesc-check": "exploit",
    "linux-smart-enumeration": "exploit",
    # crack: password/hash tooling and wordlist generators
    "hydra": "crack",
    "medusa": "crack",
    "john": "crack",
    "unshadow": "crack",
    "hashcat": "crack",
    "oclhashcat": "crack",
    "crunch": "crack",
    "cupp": "crack",
    "cewl": "crack",
    "pdfcrack": "crack",
    "hash-identifier": "crack",
    "hashid": "crack",
    # misc: forensics, reversing, network plumbing, TLS, containers
    "binwalk": "misc",
    "foremost": "misc",
    "exiftool": "misc",
    "steghide": "misc",
    "zsteg": "misc",
    "stegcracker": "misc",
    "stegosaurus": "misc",
    "strings": "misc",
    "objdump": "misc",
    "readelf": "misc",
    "nm": "misc",
    "radare2": "misc",
    "r2": "misc",
    "rabin2": "misc",
    "rasm2": "misc",
    "ghidra": "misc",
    "ghidraRun": "misc",
    "gdb": "misc",
    "gef": "misc",
    "pwndbg": "misc",
    "edb": "misc",
    "ncat": "misc",
    "socat": "misc",
    "netcat": "misc",
    "nc": "misc",
    "tcpdump": "misc",
    "tshark": "misc",
    "wireshark-cli": "misc",
    "capinfos": "misc",
    "dsniff": "misc",
    "sslstrip": "misc",
    "sslscan": "misc",
    "testssl.sh": "misc",
    "sslyze": "misc",
    "openssl": "misc",
    "yara": "misc",
    "capa": "misc",
    "vol": "misc",
    "vol3": "misc",
    "volatility3": "misc",
    "chkrootkit": "misc",
    "rkhunter": "misc",
    "jsbeautifier": "misc",
    "js-beautify": "misc",
    "jq": "misc",
    "nessuscli": "misc",
    "nesscli": "misc",
    "openvas": "misc",
    "gvm-cli": "misc",
    "gvmctl": "misc",
    "grype": "misc",
    "trivy": "misc",
    "chisel": "misc",
    "chisel-server": "misc",
    "ligolo": "misc",
    "pwnc": "misc",
    "xdotool": "misc",
    "xdpyinfo": "misc",
}

# Kali metapackages whose installed binary names differ from the package
# name. ``dpkg -l`` confirms the package; the binaries are still only
# reported when they are actually executable on PATH.
_PACKAGE_BINARIES: dict[str, list[str]] = {
    "metasploit-framework": ["msfconsole", "msfvenom", "msfrpcd"],
    "exploitdb": ["searchsploit"],
    "impacket-scripts": [
        "psexec.py",
        "smbexec.py",
        "wmiexec.py",
        "atexec.py",
        "secretsdump.py",
        "ntlmrelayx.py",
        "getTGT.py",
        "getUsersSPNs.py",
        "getNPUsers.py",
        "lookupsid.py",
        "smbclient.py",
    ],
    "python3-impacket": ["impacket-psexec", "impacket-wmiexec", "impacket-secretsdump"],
    "bettercap": ["bettercap"],
    "recon-ng": ["recon-ng"],
    "wordlists": [],
    "nmap": ["nmap", "ncat", "nping"],
    "hashcat": ["hashcat", "hashcat-utils"],
    "john": ["john", "unshadow"],
    "hydra": ["hydra", "hydra-wizard"],
    "sqlmap": ["sqlmap"],
    "commix": ["commix"],
    "seclists": [],
}

# Hand-written one-line purpose for the tools the model is most likely to
# reach for. Anything not here falls back to ``whatis`` / an empty string.
_TOOL_DESCRIPTIONS: dict[str, str] = {
    "nmap": "port/service/version scan; NSE scripts",
    "masscan": "internet-scale fast port scanner",
    "rustscan": "fast nmap wrapper with built-in nmap run",
    "netdiscover": "ARP-based live host / MAC discovery",
    "amass": "subdomain enumeration + asset discovery engine",
    "subfinder": "passive subdomain finder",
    "assetfinder": "subdomain / asset finder",
    "findomain": "fast subdomain finder",
    "fierce": "DNS reconnaissance scanner",
    "dnsrecon": "DNS enumeration (records, zone transfer)",
    "dnsenum": "DNS enumeration + subdomain brute-force",
    "sublist3r": "subdomain enumeration tool",
    "theharvester": "OSINT: emails, hosts, employees from public sources",
    "recon-ng": "full-featured OSINT reconnaissance framework",
    "aquatone": "headless-browser screenshotting for discovered hosts",
    "nbtscan": "NetBIOS name scan on local subnets",
    "arp-scan": "ARP host discovery on the LAN",
    "snmpwalk": "query SNMP agents for OID data",
    "onesixtyone": "fast SNMP community-string brute-forcer",
    "enum4linux-ng": "SMB/LDAP enumeration for Windows/Linux hosts",
    "smbmap": "enumerate SMB shares and permissions",
    "smbclient": "connect to SMB shares as a client",
    "rpcclient": "query MSRPC services",
    "nxc": "NetExec — swiss-army knife for AD/SMB/MSRPC",
    "netexec": "NetExec — AD protocol swiss-army knife",
    "crackmapexec": "legacy AD swiss-army knife (predecessor of NetExec)",
    "responder": "LLMNR/NBT-NS/MDNS poisoning, captures NetNTLM hashes",
    "kerbrute": "brute-force / enumerate Kerberos usernames",
    "ldapsearch": "LDAP query client",
    "ldapdomaindump": "dump an AD domain via LDAP",
    "aircrack-ng": "WEP/WPA-PSK cracking suite",
    "bully": "WPS attack suite",
    "reaver": "WPS PIN brute-force attack",
    "host": "DNS lookup utility",
    "dig": "DNS query tool",
    "nslookup": "DNS query tool",
    "whois": "domain/IP registration lookup",
    "traceroute": "network path trace",
    "sqlmap": "automatic SQL injection detection and exploitation",
    "nikto": "web server vulnerability scanner",
    "gobuster": "directory/DNS/S3 brute-forcer",
    "ffuf": "fast web fuzzer (FUZZ placeholder)",
    "feroxbuster": "recursive content discovery tool",
    "dirb": "web content scanner with wordlist",
    "dirbuster": "web directory brute-forcer",
    "dirsearch": "web path brute-forcer with sane defaults",
    "wfuzz": "web application fuzzer",
    "wpscan": "WordPress enumeration and vulnerability scanner",
    "whatweb": "web technology fingerprinter",
    "wafw00f": "identify web application firewalls",
    "httpx": "fast HTTP probe returning status/title/tech",
    "httprobe": "probe which discovered URLs are alive",
    "nuclei": "YAML-template vulnerability scanner",
    "arjun": "HTTP parameter discovery",
    "paramspider": "parameter discovery via archived URLs",
    "gau": "fetch known URLs from archives (Wayback etc.)",
    "waybackurls": "extract archived URLs for a domain",
    "arachni": "web vulnerability scanner framework",
    "skipfish": "fast web crawler / scanner",
    "w3af": "web application attack and audit framework",
    "zap": "OWASP ZAP web scanner (CLI)",
    "burpsuite": "Burp Suite web proxy/scanner",
    "curl": "HTTP(S) client — exact requests with raw headers",
    "wget": "HTTP(S) downloader",
    "httpie": "user-friendly HTTP client",
    "msfconsole": "Metasploit exploit framework console",
    "msfvenom": "Metasploit payload generator",
    "armitage": "Metasploit GUI front-end",
    "searchsploit": "search the Exploit-DB archive",
    "ntlmrelayx": "relay captured NTLM auth (impacket suite)",
    "mitmproxy": "interactive HTTPS interception proxy",
    "mitmweb": "web-UI mitmproxy",
    "mitmdump": "non-interactive mitmproxy",
    "bettercap": "network reconnaissance and MITM framework",
    "psexec.py": "impacket — remote exec via SMB service control",
    "smbexec.py": "impacket — SMB exec without service artifacts",
    "wmiexec.py": "impacket — WMI-based remote exec",
    "atexec.py": "impacket — remote exec via scheduled tasks",
    "secretsdump.py": "impacket — dump local/NTDS hashes and secrets",
    "getTGT.py": "impacket — request Kerberos TGT (AS-REP)",
    "getUsersSPNs.py": "impacket — enumerate Kerberoastable accounts",
    "getNPUsers.py": "impacket — check for AS-REP-roastable users",
    "lookupsid.py": "impacket — SID-based user/group enumeration",
    "smbclient.py": "impacket — interactive SMB client shell",
    "reg.py": "impacket — remote registry query/add/delete",
    "services.py": "impacket — start/stop/query remote services",
    "linpeas": "Linux local privilege-escalation enumerator",
    "winpeas": "Windows local privilege-escalation enumerator",
    "pspy": "unprivileged Linux process monitor",
    "lse.sh": "Linux-Smart-Enumeration script",
    "unix-privesc-check": "legacy Unix privilege audit script",
    "hydra": "parallel login credential brute-forcer",
    "medusa": "parallel login brute-forcer",
    "john": "John the Ripper password cracker",
    "unshadow": "combine passwd+shadow for john",
    "hashcat": "GPU password-cracking suite",
    "oclhashcat": "hashcat (OpenCL build)",
    "crunch": "custom wordlist generator",
    "cupp": "personalized wordlist generator from user info",
    "cewl": "generate wordlist from web-page content",
    "pdfcrack": "PDF file password cracker",
    "hash-identifier": "identify hash types",
    "hashid": "identify hash types",
    "binwalk": "firmware analysis / embedded file extraction",
    "foremost": "file carving / recovery tool",
    "exiftool": "read/write metadata in images and documents",
    "steghide": "steganography encoder/decoder",
    "zsteg": "LSB steganography detector on PNG/BMP",
    "stegcracker": "stego password brute-forcer",
    "strings": "print printable character sequences from binaries",
    "objdump": "disassemble / inspect object files",
    "readelf": "inspect ELF headers and sections",
    "radare2": "reverse-engineering framework",
    "r2": "reverse-engineering framework (short launcher)",
    "rabin2": "radare2 binary information extractor",
    "ghidra": "NSA reverse-engineering suite (GUI/headless)",
    "gdb": "GNU debugger",
    "gef": "GDB multi-arch pwn plugin",
    "pwndbg": "GDB pwn debugging plugin",
    "edb": "x86 debugger for Linux",
    "ncat": "netcat with TLS/listen/exec modes",
    "socat": "bidirectional pipe / relay utility",
    "netcat": "classic TCP/UDP pipe utility",
    "nc": "short launcher for netcat/ncat",
    "tcpdump": "command-line packet capture",
    "tshark": "Wireshark as a command-line tool",
    "wireshark-cli": "Wireshark command-line utilities",
    "capinfos": "capture file summary statistics",
    "dsniff": "credentials sniffer on the wire",
    "sslstrip": "downgrade HTTPS to HTTP for interception",
    "sslscan": "enumerate SSL/TLS cipher and cert settings",
    "testssl.sh": "comprehensive TLS configuration checker",
    "sslyze": "TLS scan for known weaknesses",
    "openssl": "crypto toolkit / TLS client and server",
    "yara": "pattern-match malware / hunt rules engine",
    "capa": "static capability detection for binaries",
    "vol3": "volatility 3 memory forensics",
    "volatility3": "memory forensics framework",
    "chkrootkit": "local rootkit checker",
    "rkhunter": "remote kernel scanner / rootkit checker",
    "jsbeautifier": "beautify and unpack JavaScript",
    "js-beautify": "beautify and unpack JavaScript",
    "jq": "JSON query and transformation CLI",
    "nessuscli": "Nessus vulnerability scanner CLI",
    "openvas": "OpenVAS/GVM vulnerability scanner",
    "gvm-cli": "Greenbone Vulnerability Management CLI",
    "grype": "container/image vulnerability scanner",
    "trivy": "container and filesystem vulnerability scanner",
    "chisel": "fast TCP/UDP tunnel over HTTP",
    "pwnc": "PWN_collector — collection script for privesc data",
}


@dataclass
class ToolEntry:
    """One discovered host tool with its one-line purpose."""

    name: str
    description: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "ToolEntry":
        return cls(
            name=str(raw.get("name", "") or ""),
            description=str(raw.get("description", "") or ""),
        )


# ── Flag resolution ──────────────────────────────────────────────────────


def env_override() -> bool | None:
    """Return the explicit env-var decision, or ``None`` when unset."""
    raw = os.environ.get("VULNCLAW_SHELL_TOOL_CATALOG")
    if raw is None:
        return None
    return raw.strip().lower() in _TRUTHY


@lru_cache(maxsize=1)
def _os_release_text() -> str:
    try:
        return Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def is_kali_rolling() -> bool:
    """True when /etc/os-release declares a kali-rolling image."""
    return "kali-rolling" in _os_release_text()


def toolchain_enabled(config: object = None) -> bool:
    """Resolve the host-toolchain flag.

    Priority: explicit env var > kali-rolling auto-on > persisted config
    field (when a config object is supplied) > off.
    """
    override = env_override()
    if override is not None:
        return override
    if is_kali_rolling():
        return True
    safety = getattr(config, "safety", None)
    return bool(getattr(safety, "shell_tool_catalog", False))


# ── Discovery ────────────────────────────────────────────────────────────


def _scan_path_executables(deadline: float) -> set[str]:
    """Single walk over PATH; returns every executable basename found.

    ``deadline`` is a ``time.monotonic()`` budget: once it passes we stop
    walking further PATH entries and keep whatever has been found so far,
    so a cold scan on a slow/remote PATH mount can never stall startup.
    """
    found: set[str] = set()
    path_entries = os.environ.get("PATH", "").split(os.pathsep)
    for directory in path_entries:
        if time.monotonic() >= deadline:
            break
        if not directory:
            continue
        try:
            with os.scandir(directory) as it:
                for entry in it:
                    try:
                        if entry.is_file() and os.access(entry.path, os.X_OK):
                            found.add(entry.name)
                    except OSError:
                        continue
        except OSError:
            continue
    return found


def _dpkg_installed_names() -> set[str]:
    """Installed Debian package names (first column after status). Empty
    when dpkg is not present (e.g. macOS)."""
    if shutil.which("dpkg") is None:
        return set()
    try:
        proc = subprocess.run(
            ["dpkg", "-l"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    names: set[str] = set()
    for line in (proc.stdout or "").splitlines():
        fields = line.split(None, 2)
        if len(fields) >= 3 and fields[0].startswith(("ii", "hi")):
            names.add(fields[1].split(":", 1)[0])
    return names


def _discover_names(deadline: float) -> list[str]:
    """Known tool names actually executable on this host."""
    executables = _scan_path_executables(deadline)
    names = {name for name in _TOOLS if name in executables}
    if time.monotonic() < deadline:
        installed = _dpkg_installed_names()
        for package, binaries in _PACKAGE_BINARIES.items():
            if package not in installed:
                continue
            for binary in binaries:
                if binary in executables:
                    names.add(binary)
            time_budget_left = deadline - time.monotonic()
            if time_budget_left <= 0:
                break
    return sorted(names)


def _fill_descriptions(entries: list[ToolEntry], deadline: float) -> None:
    """Batch-resolve missing descriptions via a single ``whatis`` call."""
    missing = [entry for entry in entries if not entry.description]
    if not missing or time.monotonic() >= deadline or shutil.which("whatis") is None:
        return
    names = [entry.name for entry in missing]
    timeout = max(0.1, min(2.0, deadline - time.monotonic()))
    try:
        proc = subprocess.run(
            ["whatis", *names],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        raw_output = proc.stdout
    except (OSError, subprocess.SubprocessError):
        return
    resolved: dict[str, str] = {}
    for line in raw_output.splitlines():
        if " - " not in line:
            continue
        head, _, summary = line.partition(" - ")
        tool = head.strip().split("(", 1)[0].strip().lower()
        summary = summary.strip()
        if tool and summary and tool not in resolved:
            resolved[tool] = summary[:120]
    for entry in missing:
        hit = resolved.get(entry.name.lower())
        if hit:
            entry.description = hit


def build_catalog(force: bool = False) -> dict:
    """Discover installed pentest tools grouped by category.

    Result shape (also the on-disk cache schema)::

        {"version": 1, "generated_at": <epoch>, "categories":
            {"recon": [{"name": ..., "description": ...}, ...], ...}}

    The scan runs once per 24h unless ``force`` is set or the cache is
    missing/corrupt; the whole cold path stays under ~5s.
    """
    if not force:
        cached = _load_cache()
        if cached is not None:
            return cached

    deadline = time.monotonic() + _SCAN_BUDGET_SECONDS
    names = _discover_names(deadline)
    entries = [
        ToolEntry(name=name, description=_TOOL_DESCRIPTIONS.get(name, ""))
        for name in names
    ]
    _fill_descriptions(entries, deadline)

    categories: dict[str, list[dict]] = {category: [] for category in CATEGORIES}
    for entry in entries:
        category = _TOOLS.get(entry.name, "misc")
        categories.setdefault(category, []).append(entry.to_dict())

    catalog = {
        "version": 1,
        "generated_at": time.time(),
        "categories": categories,
    }
    _write_cache(catalog)
    return catalog


def _load_cache() -> dict | None:
    try:
        raw = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict) or raw.get("version") != 1:
        return None
    if time.time() - float(raw.get("generated_at", 0) or 0) > _CACHE_TTL_SECONDS:
        return None
    categories = raw.get("categories")
    if not isinstance(categories, dict):
        return None
    return raw


def _write_cache(catalog: dict) -> None:
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = CACHE_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(catalog, ensure_ascii=False), encoding="utf-8")
        tmp.replace(CACHE_FILE)
    except OSError:
        return


# ── Prompt / gate rendering ──────────────────────────────────────────────


def _catalog_total(catalog: dict) -> int:
    categories = catalog.get("categories") or {}
    return sum(len(tools) for tools in categories.values() if isinstance(tools, list))


def format_catalog_for_prompt(catalog: dict) -> str:
    """Render the catalog as one system-prompt section (empty when empty)."""
    total = _catalog_total(catalog)
    if total <= 0:
        return ""
    lines = [
        f"## Host pentest toolchain ({total} tools available via shell_command)",
        "本机已安装以下渗透工具,优先用它们而不是手写 HTTP 请求:",
    ]
    categories = catalog.get("categories") or {}
    for category in CATEGORIES:
        tools = categories.get(category) or []
        if not tools:
            continue
        rendered: list[str] = []
        for tool in tools:
            name = str(tool.get("name", "") or "")
            if not name:
                continue
            description = str(tool.get("description", "") or "").strip()
            rendered.append(f"{name} — {description}" if description else name)
        if rendered:
            lines.append(f"[{category}] " + "; ".join(rendered))
    lines.append("规则:")
    lines.append("- 首次使用不熟悉参数工具先 `tool --help`。")
    lines.append(
        "- recon/exploit/decode/crack 场景必须优先 shell_command 调工具,"
        "内置 fetch 仅做轻量页面读取。"
    )
    lines.append("- 长命令注意 timeout;工具输出要作为 evidence 保留。")
    return "\n".join(lines)


def host_toolchain_prompt_block(config: object = None) -> str:
    """System-prompt section for the enabled mode; empty string when off."""
    if not toolchain_enabled(config):
        return ""
    try:
        catalog = build_catalog()
    except Exception:
        return ""
    return format_catalog_for_prompt(catalog)


def catalog_tool_names() -> list[str]:
    """Flat tool-name list, for merging into the exec-gate trusted set."""
    catalog = build_catalog()
    names: list[str] = []
    for tools in (catalog.get("categories") or {}).values():
        for tool in tools:
            name = str(tool.get("name", "") or "")
            if name:
                names.append(name)
    return names


def catalog_auto_trusted_names() -> list[str]:
    """Discovered names that may join the exec-gate trusted set.

    Same list as ``catalog_tool_names()`` minus ``_NO_AUTO_TRUST``: the
    generic network clients / sniffers keep their per-call approval prompt
    even on a Kali host, because silently trusting them would hand the
    model an unreviewed exfiltration primitive. Comparison is
    case-insensitive so PATH variants (``NC``/``nc``) stay excluded.
    """
    return [name for name in catalog_tool_names() if name.lower() not in _NO_AUTO_TRUST]
