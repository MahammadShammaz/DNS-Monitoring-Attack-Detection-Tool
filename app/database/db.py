import sqlite3
from pathlib import Path

DATABASE_PATH = "app/database/dns_logs.db"


def get_connection():

    connection = sqlite3.connect(DATABASE_PATH)

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():

    Path("app/database").mkdir(parents=True, exist_ok=True)

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dns_logs (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        timestamp TEXT NOT NULL,

        source_ip TEXT NOT NULL,

        destination_ip TEXT NOT NULL,

        domain TEXT NOT NULL,

        query_type TEXT NOT NULL,

        suspicious BOOLEAN,

        threat_score INTEGER
    )
""")

    connection.commit()
    connection.close()


def insert_dns_log(dns_data):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO dns_logs (
            timestamp,
            source_ip,
            destination_ip,
            domain,
            query_type,
            suspicious,
            threat_score
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (

        dns_data["timestamp"],
        dns_data["source_ip"],
        dns_data["destination_ip"],
        dns_data["domain"],
        dns_data["query_type"],
        dns_data["suspicious"],
        dns_data["threat_score"]
    ))

    connection.commit()
    connection.close()


def get_total_packet_count():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*) FROM dns_logs
    """)

    total = cursor.fetchone()[0]

    connection.close()

    return total


def fetch_recent_logs(limit=20):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM dns_logs
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    logs = cursor.fetchall()

    connection.close()

    return logs