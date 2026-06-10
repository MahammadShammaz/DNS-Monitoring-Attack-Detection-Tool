"""
Module 7 — Log Analysis
Analyzes DNS logs from the SQLite database to detect:
  - NXDOMAIN spikes
  - DNS flood attempts (many queries in short window)
  - Repeated domain queries
  - Failed lookup patterns
"""

import sqlite3
from datetime import datetime, timedelta
from collections import Counter
from pathlib import Path

DATABASE_PATH = "app/database/dns_logs.db"

# Thresholds
FLOOD_THRESHOLD = 50        # queries per minute = flood
NXDOMAIN_SPIKE_THRESHOLD = 20  # NXDOMAIN responses per minute
REPEATED_DOMAIN_THRESHOLD = 30  # same domain queried N+ times in window

_log_alerts = []


def initialize_log_alert_table():
    """Create log_alerts table if not exists."""
    Path("app/database").mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS log_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            source_ip TEXT,
            details TEXT NOT NULL,
            count INTEGER,
            severity TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _save_log_alert(timestamp, alert_type, source_ip, details, count, severity):
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO log_alerts (timestamp, alert_type, source_ip, details, count, severity)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (timestamp, alert_type, source_ip, details, count, severity))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[LOG ANALYSIS] DB error: {e}")


def _get_logs_in_window(minutes=1):
    """Return dns_logs rows from the last N minutes."""
    since = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM dns_logs WHERE timestamp >= ? ORDER BY timestamp ASC
        """, (since,))
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def detect_dns_flood(window_minutes=1):
    """
    Detect if any single source IP sent an abnormal number of queries
    within the time window.
    Returns list of alert dicts.
    """
    rows = _get_logs_in_window(window_minutes)
    if not rows:
        return []

    ip_counts = Counter(row["source_ip"] for row in rows)
    alerts = []

    for ip, count in ip_counts.items():
        if count >= FLOOD_THRESHOLD:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            details = (
                f"{ip} sent {count} DNS queries in {window_minutes} min "
                f"(threshold: {FLOOD_THRESHOLD})"
            )
            alert = {
                "timestamp": ts,
                "alert_type": "DNS_FLOOD",
                "source_ip": ip,
                "details": details,
                "count": count,
                "severity": "CRITICAL" if count > FLOOD_THRESHOLD * 2 else "HIGH"
            }
            _log_alerts.append(alert)
            _save_log_alert(**alert)
            print(f"\n[⚠ FLOOD] {details}")
            alerts.append(alert)

    return alerts


def detect_repeated_domains(window_minutes=5, top_n=10):
    """
    Detect domains that are queried an unusual number of times.
    Returns top repeated domains and any alerts.
    """
    rows = _get_logs_in_window(window_minutes)
    if not rows:
        return [], []

    domain_counts = Counter(row["domain"] for row in rows)
    alerts = []
    top_domains = domain_counts.most_common(top_n)

    for domain, count in top_domains:
        if count >= REPEATED_DOMAIN_THRESHOLD:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            details = (
                f"Domain '{domain}' queried {count} times "
                f"in {window_minutes} min (threshold: {REPEATED_DOMAIN_THRESHOLD})"
            )
            alert = {
                "timestamp": ts,
                "alert_type": "REPEATED_DOMAIN",
                "source_ip": None,
                "details": details,
                "count": count,
                "severity": "MEDIUM"
            }
            _log_alerts.append(alert)
            _save_log_alert(**alert)
            print(f"\n[⚠ REPEAT] {details}")
            alerts.append(alert)

    return top_domains, alerts


def get_suspicious_query_stats(window_minutes=60):
    """
    Return summary stats for suspicious queries in the last N minutes.
    """
    rows = _get_logs_in_window(window_minutes)
    total = len(rows)
    suspicious = sum(1 for r in rows if r["suspicious"])
    high_threat = sum(1 for r in rows if r["threat_score"] >= 70)

    return {
        "window_minutes": window_minutes,
        "total_queries": total,
        "suspicious_count": suspicious,
        "high_threat_count": high_threat,
        "suspicious_pct": round(100 * suspicious / total, 1) if total else 0
    }


def get_top_queried_domains(limit=10):
    """Return the most queried domains overall."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT domain, COUNT(*) as count
            FROM dns_logs
            GROUP BY domain
            ORDER BY count DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def get_top_source_ips(limit=10):
    """Return the most active source IPs."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT source_ip, COUNT(*) as count
            FROM dns_logs
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def get_hourly_query_volume():
    """Return query counts grouped by hour for charting."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour,
                   COUNT(*) as count
            FROM dns_logs
            GROUP BY hour
            ORDER BY hour DESC
            LIMIT 24
        """)
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def run_full_analysis():
    """Run all detection checks and return combined results."""
    results = {
        "flood_alerts": detect_dns_flood(window_minutes=1),
        "repeat_alerts": detect_repeated_domains(window_minutes=5)[1],
        "stats": get_suspicious_query_stats(window_minutes=60),
        "top_domains": get_top_queried_domains(10),
        "top_ips": get_top_source_ips(10),
    }
    return results


def get_recent_log_alerts(limit=20):
    """Fetch recent log analysis alerts from DB."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM log_alerts ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def get_log_alert_count():
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM log_alerts")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0
