"""
main.py — FastAPI server trung tâm cho DLP
Chạy: uvicorn main:app --host 0.0.0.0 --port 8000
"""
import secrets
import hashlib
from fastapi import FastAPI, Request, Header, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
import uvicorn

from database import init_db, insert_event, insert_batch, query_events, get_stats, get_machines

# ============================================================
# API KEYS — mỗi máy endpoint có 1 key riêng
# Format: "api-key-value": "Tên máy hiển thị trên dashboard"
#
# Cách tạo key mới:
#   python -c "import secrets; print(secrets.token_urlsafe(32))"
# ============================================================
AGENT_KEYS = {
    "dlp-key-may-ketoan-01":  "PC-KeToan-01",
    "dlp-key-may-nhansu-02":  "PC-NhanSu-02",
    "dlp-key-may-admin":      "PC-Admin",
    # Thêm máy mới vào đây, rồi restart server
}

# Key riêng cho dashboard (admin xem)
DASHBOARD_KEY = "admin-dashboard-secret-key"

# ============================================================
app = FastAPI(title="DLP Central Server", version="1.0")
init_db()


# ---- Helper xác thực ----
def require_agent(x_api_key: str | None) -> str:
    """Trả về machine_name nếu hợp lệ, raise 401 nếu không."""
    if not x_api_key or x_api_key not in AGENT_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return AGENT_KEYS[x_api_key]


# ============================================================
# ENDPOINT: Nhận event từ DLP agent
# ============================================================

@app.post("/api/events")
async def receive_event(
    request: Request,
    x_api_key: str = Header(None)
):
    """Nhận 1 event đơn lẻ từ endpoint."""
    machine = require_agent(x_api_key)
    data = await request.json()
    new_id = insert_event(machine, data)
    return {"status": "ok", "id": new_id, "machine": machine}


@app.post("/api/events/batch")
async def receive_batch(
    request: Request,
    x_api_key: str = Header(None)
):
    """Nhận nhiều events cùng lúc (list). Hiệu quả hơn khi gửi theo đợt."""
    machine = require_agent(x_api_key)
    data = await request.json()

    if not isinstance(data, list):
        raise HTTPException(status_code=400, detail="Payload must be a JSON array")

    count = insert_batch(machine, data)
    return {"status": "ok", "saved": count, "machine": machine}


# ============================================================
# ENDPOINT: Dashboard đọc dữ liệu
# ============================================================

@app.get("/api/events")
async def list_events(
    limit:      int   = Query(500, le=2000),
    action:     str   = Query(None),
    min_risk:   float = Query(0),
    max_risk:   float = Query(10),
    machine:    str   = Query(None),
):
    """Truy vấn events với filter — dashboard gọi endpoint này."""
    return query_events(
        limit=limit,
        action=action,
        min_risk=min_risk,
        max_risk=max_risk,
        machine=machine,
    )


@app.get("/api/stats")
async def stats():
    """KPI tổng hợp cho dashboard header."""
    return get_stats()


@app.get("/api/machines")
async def machines():
    """Danh sách máy đã kết nối."""
    return get_machines()


@app.get("/api/events/{event_id}")
async def get_event_detail(event_id: int):
    """Lấy chi tiết một event theo ID."""
    conn = __import__('sqlite3').connect("dlp_events.db")
    conn.row_factory = __import__('sqlite3').Row
    row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")
    
    import json
    result = dict(row)
    result["keywords"] = json.loads(result["keywords"] or "[]")
    result["is_clipboard"] = bool(result["is_clipboard"])
    return result


# ============================================================
# SERVE DASHBOARD
# ============================================================
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return FileResponse("static/index.html")


# ============================================================
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
