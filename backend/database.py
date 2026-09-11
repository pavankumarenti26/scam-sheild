import sqlite3
from pathlib import Path


# Database will be stored inside the backend folder
BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "scamshield.db"


def get_connection():
    connection = sqlite3.connect(
        DATABASE_PATH,
        check_same_thread=False
    )

    connection.row_factory = sqlite3.Row

    return connection


def init_database():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            threat_type TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            recommendation TEXT,
            reasons TEXT,
            input_summary TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_threat(
    threat_type,
    risk_score,
    risk_level,
    recommendation,
    reasons,
    input_summary
):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO threats (
            threat_type,
            risk_score,
            risk_level,
            recommendation,
            reasons,
            input_summary
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            threat_type,
            risk_score,
            risk_level,
            recommendation,
            reasons,
            input_summary
        )
    )

    connection.commit()

    threat_id = cursor.lastrowid

    connection.close()

    return threat_id


def get_recent_threats(limit=20):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            timestamp,
            threat_type,
            risk_score,
            risk_level,
            recommendation,
            reasons,
            input_summary
        FROM threats
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )

    rows = cursor.fetchall()

    connection.close()

    return [dict(row) for row in rows]


def delete_all_threats():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("DELETE FROM threats")

    connection.commit()

    connection.close()