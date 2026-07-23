import sqlite3
import os
from typing import List, Dict, Any

class HeimdallDatabase:
    """
    Manages SQLite database persistence for security alerts, blocked IPs, and system events.
    """

    def __init__(self, db_path: str = "heimdall.db"):
        self.db_path = db_path
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_title TEXT,
                severity TEXT,
                source_ip TEXT,
                username TEXT,
                description TEXT,
                count INTEGER,
                timestamp TEXT,
                raw_log TEXT,
                action_taken TEXT
            )
        ''')

        # Blocked IPs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                reason TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()
        conn.close()

    def save_alert(self, alert: Dict[str, Any], action_taken: str = "LOGGED"):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (rule_title, severity, source_ip, username, description, count, timestamp, raw_log, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.get("rule_title"),
            alert.get("severity"),
            alert.get("source_ip"),
            alert.get("username"),
            alert.get("description"),
            alert.get("count"),
            alert.get("timestamp"),
            alert.get("raw_log"),
            action_taken
        ))
        conn.commit()
        conn.close()

    def record_blocked_ip(self, ip: str, reason: str):
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO blocked_ips (ip, reason) VALUES (?, ?)
            ''', (ip, reason))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        conn.close()

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_stats(self) -> Dict[str, Any]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) as total FROM alerts')
        total_alerts = cursor.fetchone()["total"]

        cursor.execute('SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity')
        severity_counts = {row["severity"]: row["count"] for row in cursor.fetchall()}

        cursor.execute('SELECT COUNT(*) as total FROM blocked_ips')
        total_blocked = cursor.fetchone()["total"]
        conn.close()

        return {
            "total_alerts": total_alerts,
            "severity_breakdown": severity_counts,
            "total_blocked_ips": total_blocked
        }
