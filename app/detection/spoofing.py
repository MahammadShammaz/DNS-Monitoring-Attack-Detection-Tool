"""
Module 5 — DNS Spoofing Detection
Detects multiple IPs for same domain, conflicting answers, suspicious TTL values.
"""

from collections import defaultdict
from datetime import datetime
import sqlite3
from pathlib import Path

# In-memory cache: domain -> set of seen IPs
_domain_ip_cache = defaultdict(set)

# In-memory alert log
_spoof_alerts = []

# Known-good TTL range (in seconds)
TTL_MIN = 60
TTL_MAX = 86400  # 24 hours

# Trusted DNS resolvers (public well-known)
TRUSTED_RESOLVERS = {
    "8.8.8.8",      # Google
    "8.8.4.4",      # Google
    "1.1.1.1",      # Cloudflare
    "1.0.0.1",      # Cloudflare
    "9.9.9.9",      # Quad9
    "208.67.222.222",  # OpenDNS
}

DATABASE_PATH = "app/database/dns_logs.db"


def initialize_spoof_table():
    """Create spoof_alerts table if not exists."""
    Path("app/database").mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS spoof_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            domain TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            details TEXT NOT NULL,
            severity TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _save_alert(timestamp, domain, alert_type, details, severity):
    """Persist a spoofing alert to the database."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO spoof_alerts (timestamp, domain, alert_type, details, severity)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, domain, alert_type, details, severity))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[SPOOF] DB error: {e}")


def check_multiple_ips(domain, resolved_ip):
    """
    Detect if a domain suddenly resolves to a different/new IP.
    Returns an alert dict or None.
    """
    domain = domain.rstrip(".").lower()

    if not resolved_ip:
        return None

    previous_ips = _domain_ip_cache[domain]

    if previous_ips and resolved_ip not in previous_ips:
        alert = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "domain": domain,
            "alert_type": "MULTIPLE_IPS",
            "details": f"New IP {resolved_ip} seen. Previous IPs: {', '.join(previous_ips)}",
            "severity": "HIGH"
        }
        _spoof_alerts.append(alert)
        _save_alert(**alert)
        print(f"\n[⚠ SPOOF ALERT] {domain} → {resolved_ip} (was: {', '.join(previous_ips)})")
        _domain_ip_cache[domain].add(resolved_ip)
        return alert

    _domain_ip_cache[domain].add(resolved_ip)
    return None


def check_suspicious_ttl(domain, ttl):
    """
    Flag responses with TTL outside normal range.
    Very low TTL can indicate DNS poisoning.
    """
    domain = domain.rstrip(".").lower()

    if ttl is None:
        return None

    if ttl < TTL_MIN or ttl > TTL_MAX:
        severity = "HIGH" if ttl < 10 else "MEDIUM"
        alert = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "domain": domain,
            "alert_type": "SUSPICIOUS_TTL",
            "details": f"TTL={ttl}s is outside normal range ({TTL_MIN}-{TTL_MAX}s)",
            "severity": severity
        }
        _spoof_alerts.append(alert)
        _save_alert(**alert)
        print(f"\n[⚠ TTL ALERT] {domain} has suspicious TTL={ttl}s")
        return alert

    return None


def check_untrusted_resolver(domain, resolver_ip):
    """
    Flag if the DNS response came from an untrusted/unexpected resolver.
    """
    domain = domain.rstrip(".").lower()

    if resolver_ip and resolver_ip not in TRUSTED_RESOLVERS:
        alert = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "domain": domain,
            "alert_type": "UNTRUSTED_RESOLVER",
            "details": f"Response from untrusted resolver {resolver_ip}",
            "severity": "MEDIUM"
        }
        _spoof_alerts.append(alert)
        _save_alert(**alert)
        print(f"\n[⚠ RESOLVER ALERT] {domain} resolved via untrusted {resolver_ip}")
        return alert

    return None


def analyze_dns_response(domain, resolved_ip, ttl=None, resolver_ip=None):
    """
    Full spoofing analysis on a DNS response.
    Returns list of any triggered alerts.
    """
    alerts = []

    a = check_multiple_ips(domain, resolved_ip)
    if a:
        alerts.append(a)

    b = check_suspicious_ttl(domain, ttl)
    if b:
        alerts.append(b)

    c = check_untrusted_resolver(domain, resolver_ip)
    if c:
        alerts.append(c)

    return alerts


def get_recent_spoof_alerts(limit=20):
    """Fetch recent spoofing alerts from DB."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM spoof_alerts ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def get_spoof_alert_count():
    """Return total count of spoof alerts."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM spoof_alerts")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0
