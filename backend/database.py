import sqlite3
from datetime import datetime

DATABASE = "phishing_dashboard.db"


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            classification TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_analysis(
    sender,
    subject,
    body,
    risk_score,
    classification,
    risk_level
):
    connection = get_connection()

    connection.execute(
        """
        INSERT INTO analyses
        (sender, subject, body, risk_score,
         classification, risk_level, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sender,
            subject,
            body,
            risk_score,
            classification,
            risk_level,
            datetime.now().isoformat(timespec="seconds")
        )
    )

    connection.commit()
    connection.close()


def get_analyses():
    connection = get_connection()

    rows = connection.execute(
        """
        SELECT *
        FROM analyses
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]