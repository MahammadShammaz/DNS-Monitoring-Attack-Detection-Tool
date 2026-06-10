"""
Module 6 — DNS Configuration Monitoring
Monitors /etc/resolv.conf for changes: new resolvers, changed DNS servers,
suspicious/unknown nameservers.
"""

import time
import hashlib
import sqlite3
from pathlib import Path
from datetime import datetime
from threading import Thread

RESOLV_CONF_PATH = "/etc/resolv.conf"
DATABASE_PATH = "app/database/dns_logs.db"

# Well-known trusted DNS server IPs
TRUSTED_DNS_SERVERS = {
    "8.8.8.8",       # Google
    "8.8.4.4",       # Google
    "1.1.1.1",       # Cloudflare
    "1.0.0.1",       # Cloudflare
    "9.9.9.9",       # Quad9
    "208.67.222.222",  # OpenDNS
    "208.67.220.220",  # OpenDNS
    "127.0.0.53",    # systemd-resolved local stub
    "127.0.1.1",     # common local resolver
}

_current_hash = None
_current_nameservers = []
_config_alerts = []


def initialize_config_table():
    """Create config_alerts table if not exists."""
    Path("app/database").mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS config_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT NOT NULL,
            details TEXT NOT NULL,
            severity TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _save_config_alert(timestamp, alert_type, old_value, new_value, details, severity):
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO config_alerts (timestamp, alert_type, old_value, new_value, details, severity)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (timestamp, alert_type, old_value, new_value, details, severity))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[CONFIG] DB error: {e}")


def read_resolv_conf():
    """Read /etc/resolv.conf and return (content, nameservers list)."""
    try:
        path = Path(RESOLV_CONF_PATH)
        if not path.exists():
            return None, []
        content = path.read_text()
        nameservers = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) >= 2:
                    nameservers.append(parts[1])
        return content, nameservers
    except PermissionError:
        return None, []
    except Exception as e:
        print(f"[CONFIG] Read error: {e}")
        return None, []


def get_file_hash(content):
    if content is None:
        return None
    return hashlib.md5(content.encode()).hexdigest()


def check_for_unknown_resolvers(nameservers):
    """Flag any nameserver not in the trusted list."""
    alerts = []
    for ns in nameservers:
        if ns not in TRUSTED_DNS_SERVERS:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alert = {
                "timestamp": ts,
                "alert_type": "UNTRUSTED_NAMESERVER",
                "old_value": None,
                "new_value": ns,
                "details": f"Nameserver {ns} is not in the trusted DNS server list.",
                "severity": "HIGH"
            }
            _config_alerts.append(alert)
            _save_config_alert(**alert)
            print(f"\n[⚠ CONFIG] Untrusted nameserver detected: {ns}")
            alerts.append(alert)
    return alerts


def check_config_change(old_servers, new_servers):
    """Detect added or removed nameservers."""
    alerts = []
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    added = set(new_servers) - set(old_servers)
    removed = set(old_servers) - set(new_servers)

    for ns in added:
        alert = {
            "timestamp": ts,
            "alert_type": "NAMESERVER_ADDED",
            "old_value": ", ".join(old_servers) or "none",
            "new_value": ns,
            "details": f"New nameserver added: {ns}",
            "severity": "HIGH" if ns not in TRUSTED_DNS_SERVERS else "LOW"
        }
        _config_alerts.append(alert)
        _save_config_alert(**alert)
        print(f"\n[⚠ CONFIG] New nameserver added: {ns}")
        alerts.append(alert)

    for ns in removed:
        alert = {
            "timestamp": ts,
            "alert_type": "NAMESERVER_REMOVED",
            "old_value": ns,
            "new_value": ", ".join(new_servers) or "none",
            "details": f"Nameserver removed: {ns}",
            "severity": "MEDIUM"
        }
        _config_alerts.append(alert)
        _save_config_alert(**alert)
        print(f"\n[INFO CONFIG] Nameserver removed: {ns}")
        alerts.append(alert)

    return alerts


def take_initial_snapshot():
    """Read initial state of resolv.conf."""
    global _current_hash, _current_nameservers
    content, nameservers = read_resolv_conf()
    _current_hash = get_file_hash(content)
    _current_nameservers = nameservers
    print(f"[CONFIG] Initial nameservers: {nameservers or ['(none found)']}")


def poll_config(interval=10):
    """Background thread: poll resolv.conf every `interval` seconds for changes."""
    global _current_hash, _current_nameservers

    take_initial_snapshot()

    while True:
        time.sleep(interval)
        content, new_servers = read_resolv_conf()
        new_hash = get_file_hash(content)

        if new_hash and new_hash != _current_hash:
            print(f"\n[⚠ CONFIG] /etc/resolv.conf changed!")
            check_config_change(_current_nameservers, new_servers)
            check_for_unknown_resolvers(new_servers)
            _current_hash = new_hash
            _current_nameservers = new_servers


def start_config_monitor(interval=10):
    """Start background config monitoring thread."""
    t = Thread(target=poll_config, args=(interval,), daemon=True)
    t.start()
    print("[CONFIG] DNS configuration monitor started.")


def get_current_nameservers():
    """Return the currently tracked nameservers."""
    return list(_current_nameservers)


def get_recent_config_alerts(limit=20):
    """Fetch recent config alerts from DB."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM config_alerts ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def get_config_alert_count():
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM config_alerts")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0
