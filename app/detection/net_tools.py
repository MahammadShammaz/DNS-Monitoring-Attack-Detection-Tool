"""
Module 8 — Networking Tools Integration
Wraps tcpdump, dig, nslookup, ss, netstat, ping, traceroute
to provide live network status data for the dashboard.
"""

import subprocess
import shutil
import re
from datetime import datetime


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _run(cmd, timeout=5):
    """Run a shell command safely, return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", 127
    except Exception as e:
        return "", str(e), 1


def _tool_available(name):
    """Check if a CLI tool is installed."""
    return shutil.which(name) is not None


# ─────────────────────────────────────────────
# dig — DNS query
# ─────────────────────────────────────────────

def dig_lookup(domain, record_type="A", dns_server=None):
    """
    Run dig to resolve a domain.
    Returns parsed dict with answers, query time, server.
    """
    cmd = ["dig"]
    if dns_server:
        cmd.append(f"@{dns_server}")
    cmd += [domain, record_type, "+nocomments", "+nocmd", "+stats"]

    stdout, stderr, code = _run(cmd, timeout=10)

    result = {
        "domain": domain,
        "record_type": record_type,
        "dns_server": dns_server or "default",
        "answers": [],
        "query_time_ms": None,
        "server_used": None,
        "raw": stdout,
        "error": stderr if code != 0 else None,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    if not stdout:
        return result

    for line in stdout.splitlines():
        # Parse ANSWER section
        if re.match(r"^\S+\s+\d+\s+IN\s+\S+\s+\S+", line):
            result["answers"].append(line.strip())
        # Query time
        m = re.search(r"Query time: (\d+) msec", line)
        if m:
            result["query_time_ms"] = int(m.group(1))
        # Server
        m = re.search(r"SERVER: ([\d.]+)", line)
        if m:
            result["server_used"] = m.group(1)

    return result


# ─────────────────────────────────────────────
# nslookup — simple resolve
# ─────────────────────────────────────────────

def nslookup(domain, dns_server=None):
    """Run nslookup and return parsed output."""
    cmd = ["nslookup", domain]
    if dns_server:
        cmd.append(dns_server)

    stdout, stderr, code = _run(cmd, timeout=10)

    addresses = []
    server_used = None

    for line in stdout.splitlines():
        m = re.search(r"Address:\s+([\d.]+)(?!#)", line)
        if m:
            addresses.append(m.group(1))
        if line.strip().startswith("Server:"):
            server_used = line.split(":", 1)[-1].strip()

    return {
        "domain": domain,
        "addresses": addresses,
        "server_used": server_used,
        "raw": stdout,
        "error": stderr if code != 0 else None,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ─────────────────────────────────────────────
# ping — reachability
# ─────────────────────────────────────────────

def ping_host(host, count=3):
    """Ping a host, return reachability and avg RTT."""
    cmd = ["ping", "-c", str(count), "-W", "2", host]
    stdout, stderr, code = _run(cmd, timeout=15)

    reachable = (code == 0)
    avg_rtt = None

    m = re.search(r"rtt .* = [\d.]+/([\d.]+)/", stdout)
    if m:
        avg_rtt = float(m.group(1))

    return {
        "host": host,
        "reachable": reachable,
        "avg_rtt_ms": avg_rtt,
        "packets_sent": count,
        "raw": stdout,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ─────────────────────────────────────────────
# traceroute — path tracing
# ─────────────────────────────────────────────

def traceroute(host, max_hops=15):
    """Run traceroute, return list of hops."""
    cmd = ["traceroute", "-m", str(max_hops), "-w", "1", host]
    stdout, stderr, code = _run(cmd, timeout=30)

    hops = []
    for line in stdout.splitlines()[1:]:   # skip header
        m = re.match(r"\s*(\d+)\s+(.*)", line)
        if m:
            hops.append({
                "hop": int(m.group(1)),
                "info": m.group(2).strip()
            })

    return {
        "host": host,
        "hops": hops,
        "hop_count": len(hops),
        "raw": stdout,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ─────────────────────────────────────────────
# ss / netstat — active connections
# ─────────────────────────────────────────────

def get_active_connections():
    """
    Return active network connections using ss (preferred) or netstat.
    Filters for DNS-related (port 53) and established connections.
    """
    if _tool_available("ss"):
        stdout, _, _ = _run(["ss", "-tunp"], timeout=5)
    elif _tool_available("netstat"):
        stdout, _, _ = _run(["netstat", "-tunp"], timeout=5)
    else:
        return {"connections": [], "error": "Neither ss nor netstat available"}

    connections = []
    for line in stdout.splitlines():
        if any(x in line for x in ["ESTAB", "LISTEN", ":53"]):
            parts = line.split()
            if len(parts) >= 5:
                connections.append({
                    "state": parts[1] if len(parts) > 1 else "?",
                    "local": parts[4] if len(parts) > 4 else "?",
                    "peer": parts[5] if len(parts) > 5 else "?",
                    "raw": line.strip()
                })

    return {
        "connections": connections,
        "total": len(connections),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ─────────────────────────────────────────────
# Network interface info
# ─────────────────────────────────────────────

def get_network_interfaces():
    """Return list of network interfaces and their IPs."""
    stdout, _, _ = _run(["ip", "addr", "show"], timeout=5)
    interfaces = []
    current = None

    for line in stdout.splitlines():
        m = re.match(r"^\d+: (\S+):", line)
        if m:
            current = {"name": m.group(1).rstrip(":"), "addresses": [], "state": "?"}
            if "UP" in line:
                current["state"] = "UP"
            elif "DOWN" in line:
                current["state"] = "DOWN"
            interfaces.append(current)
        elif current:
            m = re.search(r"inet ([\d.]+/\d+)", line)
            if m:
                current["addresses"].append(m.group(1))

    return interfaces


# ─────────────────────────────────────────────
# DNS server health check
# ─────────────────────────────────────────────

DNS_SERVERS_TO_CHECK = [
    ("8.8.8.8",   "Google Primary"),
    ("8.8.4.4",   "Google Secondary"),
    ("1.1.1.1",   "Cloudflare Primary"),
    ("9.9.9.9",   "Quad9"),
]


def check_dns_server_status():
    """
    Ping each known DNS server to check reachability.
    Returns list of status dicts.
    """
    results = []
    for ip, name in DNS_SERVERS_TO_CHECK:
        p = ping_host(ip, count=1)
        results.append({
            "name": name,
            "ip": ip,
            "status": "UP" if p["reachable"] else "DOWN",
            "rtt_ms": p["avg_rtt_ms"],
        })
    return results


# ─────────────────────────────────────────────
# Current system resolver info
# ─────────────────────────────────────────────

def get_resolver_info():
    """Read /etc/resolv.conf for current resolver config."""
    try:
        with open("/etc/resolv.conf", "r") as f:
            content = f.read()
        nameservers = []
        search_domains = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) >= 2:
                    nameservers.append(parts[1])
            elif line.startswith("search") or line.startswith("domain"):
                parts = line.split()
                search_domains.extend(parts[1:])
        return {
            "nameservers": nameservers,
            "search_domains": search_domains,
            "raw": content,
        }
    except Exception as e:
        return {"nameservers": [], "search_domains": [], "error": str(e)}


# ─────────────────────────────────────────────
# Full status snapshot for dashboard
# ─────────────────────────────────────────────

def get_network_status_snapshot():
    """
    Returns a full snapshot of network/DNS status for the dashboard.
    Lightweight — avoids long-running commands.
    """
    return {
        "interfaces": get_network_interfaces(),
        "resolver_info": get_resolver_info(),
        "active_connections": get_active_connections(),
        "dns_server_status": check_dns_server_status(),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def get_available_tools():
    """Return dict of which networking tools are installed."""
    tools = ["dig", "nslookup", "ping", "traceroute", "ss", "netstat", "tcpdump", "ip"]
    return {tool: _tool_available(tool) for tool in tools}
