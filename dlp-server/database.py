"""
database.py — SQLite storage cho DLP events
Schema khớp hoàn toàn với alerts.json hiện tại
"""
import sqlite3
import json
from datetime import datetime
from typing import Optional

DB_PATH = "dlp_events.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Tạo bảng nếu chưa có — an toàn khi gọi nhiều lần"""
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            machine_name TEXT    NOT NULL DEFAULT 'unknown',
            received_at  TEXT    NOT NULL,

            -- Các field giữ nguyên từ alerts.json
            timestamp    TEXT,
            risk_score   REAL,
            action       TEXT,
            file_path    TEXT,
            file_name    TEXT,
            keywords     TEXT,   -- lưu dạng JSON array string
            window_title TEXT,
            process_name TEXT,
            user         TEXT,
            source       TEXT,
            is_clipboard INTEGER
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_received  ON events(received_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_action    ON events(action)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_risk      ON events(risk_score)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_machine   ON events(machine_name)")
    conn.commit()
    conn.close()
    print("[DB] Initialized:", DB_PATH)


def insert_event(machine_name: str, event: dict) -> int:
    """Lưu 1 event vào DB. Trả về id mới."""
    conn = get_conn()
    cur = conn.execute("""
        INSERT INTO events (
            machine_name, received_at,
            timestamp, risk_score, action,
            file_path, file_name, keywords,
            window_title, process_name,
            user, source, is_clipboard
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        machine_name,
        datetime.utcnow().isoformat(),
        event.get("timestamp"),
        event.get("risk_score", 0),
        (event.get("action") or "").lower(),
        event.get("file_path"),
        event.get("file_name"),
        json.dumps(event.get("keywords") or []),
        event.get("window_title"),
        event.get("process_name"),
        event.get("user"),
        event.get("source"),
        1 if event.get("is_clipboard") else 0,
    ))
    new_id = cur.lastrowid
    conn.commit()
    conn.close()
    return new_id


def insert_batch(machine_name: str, events: list) -> int:
    """Lưu nhiều events cùng lúc. Trả về số lượng đã lưu."""
    if not events:
        return 0
    conn = get_conn()
    now = datetime.utcnow().isoformat()
    rows = [(
        machine_name, now,
        e.get("timestamp"),
        e.get("risk_score", 0),
        (e.get("action") or "").lower(),
        e.get("file_path"),
        e.get("file_name"),
        json.dumps(e.get("keywords") or []),
        e.get("window_title"),
        e.get("process_name"),
        e.get("user"),
        e.get("source"),
        1 if e.get("is_clipboard") else 0,
    ) for e in events]

    conn.executemany("""
        INSERT INTO events (
            machine_name, received_at,
            timestamp, risk_score, action,
            file_path, file_name, keywords,
            window_title, process_name,
            user, source, is_clipboard
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, rows)
    conn.commit()
    conn.close()
    return len(rows)


def query_events(
    limit: int = 500,
    action: Optional[str] = None,
    min_risk: float = 0,
    max_risk: float = 10,
    machine: Optional[str] = None,
) -> list[dict]:
    """Truy vấn events với filter. Trả về list dict."""
    conn = get_conn()
    sql = """
        SELECT * FROM events
        WHERE risk_score BETWEEN ? AND ?
    """
    params: list = [min_risk, max_risk]

    if action:
        sql += " AND action = ?"
        params.append(action.lower())
    if machine:
        sql += " AND machine_name = ?"
        params.append(machine)

    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    conn.close()

    result = []
    for r in rows:
        d = dict(r)
        d["keywords"] = json.loads(d["keywords"] or "[]")
        d["is_clipboard"] = bool(d["is_clipboard"])
        result.append(d)
    return result


def get_stats() -> dict:
    """Thống kê tổng hợp cho KPI cards."""
    conn = get_conn()

    total       = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_high  = conn.execute("SELECT COUNT(*) FROM events WHERE risk_score >= 7").fetchone()[0]
    total_alert = conn.execute("SELECT COUNT(*) FROM events WHERE action = 'alerted'").fetchone()[0]
    total_block = conn.execute("SELECT COUNT(*) FROM events WHERE action = 'blocked'").fetchone()[0]

    machines = conn.execute(
        "SELECT machine_name, COUNT(*) as cnt FROM events GROUP BY machine_name"
    ).fetchall()

    # Top keywords
    kw_rows = conn.execute(
        "SELECT keywords FROM events WHERE keywords != '[]' ORDER BY id DESC LIMIT 1000"
    ).fetchall()
    kw_count: dict = {}
    for row in kw_rows:
        for kw in json.loads(row[0] or "[]"):
            kw_count[kw] = kw_count.get(kw, 0) + 1
    top_kw = sorted(kw_count.items(), key=lambda x: -x[1])[:10]

    conn.close()
    return {
        "total": total,
        "high_plus": total_high,
        "alerted": total_alert,
        "blocked": total_block,
        "machines": [{"name": r[0], "count": r[1]} for r in machines],
        "top_keywords": [{"keyword": k, "count": v} for k, v in top_kw],
    }


def get_machines() -> list[str]:
    conn = get_conn()
    rows = conn.execute("SELECT DISTINCT machine_name FROM events ORDER BY machine_name").fetchall()
    conn.close()
    return [r[0] for r in rows]
