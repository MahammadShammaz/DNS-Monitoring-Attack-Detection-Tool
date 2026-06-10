from flask import Flask, render_template, jsonify
from threading import Thread

from app.capture.sniffer import start_sniffer

from app.database.db import (
    initialize_database,
    fetch_recent_logs,
    get_total_packet_count
)

from app.detection.spoofing import (
    initialize_spoof_table,
    get_recent_spoof_alerts,
    get_spoof_alert_count
)

from app.detection.config_monitor import (
    initialize_config_table,
    start_config_monitor,
    get_recent_config_alerts,
    get_config_alert_count,
    get_current_nameservers
)

from app.detection.log_analysis import (
    initialize_log_alert_table,
    get_recent_log_alerts,
    get_log_alert_count,
    get_top_queried_domains,
    get_top_source_ips,
    get_suspicious_query_stats,
    run_full_analysis
)

from app.detection.net_tools import (
    get_network_status_snapshot,
    get_available_tools,
    dig_lookup,
    nslookup,
    ping_host
)

app = Flask(__name__)


# ─────────────────────────────────────────────
# Main Dashboard
# ─────────────────────────────────────────────

@app.route("/")
def dashboard():
    logs = fetch_recent_logs()
    total_packets = get_total_packet_count()
    spoof_alert_count = get_spoof_alert_count()
    config_alert_count = get_config_alert_count()
    log_alert_count = get_log_alert_count()

    stats = get_suspicious_query_stats(window_minutes=60)
    top_domains = get_top_queried_domains(5)
    nameservers = get_current_nameservers()

    return render_template(
        "dashboard.html",
        logs=logs,
        total_packets=total_packets,
        spoof_alert_count=spoof_alert_count,
        config_alert_count=config_alert_count,
        log_alert_count=log_alert_count,
        stats=stats,
        top_domains=top_domains,
        nameservers=nameservers
    )


# ─────────────────────────────────────────────
# Module 5: Spoofing Alerts Page
# ─────────────────────────────────────────────

@app.route("/spoofing")
def spoofing_page():
    alerts = get_recent_spoof_alerts(50)
    return render_template("spoofing.html", alerts=alerts,
                           total=get_spoof_alert_count())


# ─────────────────────────────────────────────
# Module 6: Config Monitor Page
# ─────────────────────────────────────────────

@app.route("/config")
def config_page():
    alerts = get_recent_config_alerts(50)
    nameservers = get_current_nameservers()
    return render_template("config.html", alerts=alerts,
                           nameservers=nameservers,
                           total=get_config_alert_count())


# ─────────────────────────────────────────────
# Module 7: Log Analysis Page
# ─────────────────────────────────────────────

@app.route("/analysis")
def analysis_page():
    alerts = get_recent_log_alerts(50)
    top_domains = get_top_queried_domains(10)
    top_ips = get_top_source_ips(10)
    stats = get_suspicious_query_stats(60)
    return render_template(
        "analysis.html",
        alerts=alerts,
        top_domains=top_domains,
        top_ips=top_ips,
        stats=stats,
        total=get_log_alert_count()
    )


# ─────────────────────────────────────────────
# Module 8: Network Tools Page
# ─────────────────────────────────────────────

@app.route("/network")
def network_page():
    snapshot = get_network_status_snapshot()
    tools = get_available_tools()
    return render_template("network.html", snapshot=snapshot, tools=tools)


# ─────────────────────────────────────────────
# API Endpoints (JSON)
# ─────────────────────────────────────────────

@app.route("/api/dig/<domain>")
def api_dig(domain):
    return jsonify(dig_lookup(domain))


@app.route("/api/nslookup/<domain>")
def api_nslookup(domain):
    return jsonify(nslookup(domain))


@app.route("/api/ping/<host>")
def api_ping(host):
    return jsonify(ping_host(host))


@app.route("/api/network/status")
def api_network_status():
    return jsonify(get_network_status_snapshot())


@app.route("/api/analysis/run")
def api_run_analysis():
    results = run_full_analysis()
    # Convert sqlite Row objects to dicts for JSON serialization
    results["flood_alerts"] = [dict(a) for a in results["flood_alerts"]]
    results["repeat_alerts"] = [dict(a) for a in results["repeat_alerts"]]
    return jsonify(results)


# ─────────────────────────────────────────────
# Background threads
# ─────────────────────────────────────────────

def run_background_sniffer():
    start_sniffer()


if __name__ == "__main__":

    # Initialize all database tables
    initialize_database()
    initialize_spoof_table()
    initialize_config_table()
    initialize_log_alert_table()

    # Start DNS config monitor
    start_config_monitor(interval=15)

    # Start packet sniffer in background thread
    sniffer_thread = Thread(target=run_background_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        use_reloader=False   # Prevents double-starting threads
    )
