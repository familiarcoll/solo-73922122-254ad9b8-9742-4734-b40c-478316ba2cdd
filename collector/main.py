"""采集网页(FastAPI):提交 HTTP URL,经 GuardedFetcher 裁决后下载原件。

管理配置(环境变量):
  ALLOWED_CIDRS        许可网段,逗号分隔(默认 172.28.0.0/25)
  ALLOWED_PORTS        许可端口,逗号分隔(默认 8080)
  MAX_REDIRECTS        最大跳转次数(默认 3)
  MAX_BYTES            原件大小上限(默认 262144 = 256 KiB)
  FORBIDDEN_STATS_URL  禁区服务计数接口(演示用管理通道,见 README)
  DNS_RESET_URL        DNS 换址复位的管理接口(演示用)
  SCENARIO_SOURCE_BASE 页面场景按钮使用的观测源地址
  SCENARIO_REBIND_URL  页面场景按钮使用的 DNS 换址地址
  DOWNLOAD_DIR         原件保存目录
"""

from __future__ import annotations

import http.client
import json
import os
import re
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel

from .guard import GuardedFetcher

BASE_DIR = Path(__file__).resolve().parent
STATIC_PAGE = BASE_DIR / "static" / "index.html"


def _env_list(name: str, default: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


ALLOWED_CIDRS = _env_list("ALLOWED_CIDRS", "172.28.0.0/25")
ALLOWED_PORTS = [int(p) for p in _env_list("ALLOWED_PORTS", "8080")]
MAX_REDIRECTS = int(os.environ.get("MAX_REDIRECTS", "3"))
MAX_BYTES = int(os.environ.get("MAX_BYTES", str(256 * 1024)))
FORBIDDEN_STATS_URL = os.environ.get(
    "FORBIDDEN_STATS_URL", "http://forbidden.hydro.local:8080/stats"
)
DNS_RESET_URL = os.environ.get("DNS_RESET_URL", "http://dns.hydro.local:8081/reset")
SCENARIO_SOURCE_BASE = os.environ.get(
    "SCENARIO_SOURCE_BASE", "http://source.hydro.local:8080"
).rstrip("/")
SCENARIO_REBIND_URL = os.environ.get(
    "SCENARIO_REBIND_URL", "http://rebind.hydro.local:8080/rebind"
)
DOWNLOAD_DIR = Path(os.environ.get("DOWNLOAD_DIR", str(BASE_DIR.parent / "data" / "downloads")))
DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

fetcher = GuardedFetcher(
    ALLOWED_CIDRS, ALLOWED_PORTS, max_redirects=MAX_REDIRECTS, max_bytes=MAX_BYTES
)

app = FastAPI(title="水文数据接入采集")
_lock = threading.Lock()
_attempts: list[dict] = []
_seq = 0


def _internal_get(url: str, timeout: float = 4.0) -> tuple[int, bytes]:
    """管理通道直连(禁区计数 / DNS 复位)。不经 GuardedFetcher:
    这是管理员配置的固定地址,不接收用户输入,见 README「已知限制」。"""
    parsed = urlparse(url)
    conn = http.client.HTTPConnection(
        parsed.hostname, parsed.port or 80, timeout=timeout
    )
    try:
        conn.request("GET", parsed.path or "/")
        resp = conn.getresponse()
        return resp.status, resp.read(65536)
    finally:
        conn.close()


def _safe_base(url: str) -> str:
    base = os.path.basename(urlparse(url).path) or "download.bin"
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:80]
    return base or "download.bin"


class FetchReq(BaseModel):
    url: str
    scenario: str = ""


@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse(STATIC_PAGE.read_text(encoding="utf-8"))


@app.get("/api/config")
def config():
    return {
        "allowed_cidrs": ALLOWED_CIDRS,
        "allowed_ports": ALLOWED_PORTS,
        "max_redirects": MAX_REDIRECTS,
        "max_bytes": MAX_BYTES,
        "scenarios": {
            "normal": f"{SCENARIO_SOURCE_BASE}/obs.csv",
            "relative": f"{SCENARIO_SOURCE_BASE}/redirect-rel",
            "forbidden": f"{SCENARIO_SOURCE_BASE}/redirect-forbidden",
            "rebind": SCENARIO_REBIND_URL,
            "oversize": f"{SCENARIO_SOURCE_BASE}/big.csv",
            "loop": f"{SCENARIO_SOURCE_BASE}/loop",
        },
    }


@app.post("/api/fetch")
def do_fetch(req: FetchReq):
    global _seq
    url = req.url.strip()
    if not url:
        return JSONResponse({"ok": False, "error": "URL 为空"}, status_code=400)
    if req.scenario == "rebind" and DNS_RESET_URL:
        # 演示便利:换址场景先把演示 DNS 复位到「首查返回正常地址」状态
        try:
            _internal_get(DNS_RESET_URL)
        except Exception:
            pass
    outcome = fetcher.fetch(url)
    record = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "input_url": url,
        "scenario": req.scenario,
        "ok": outcome.ok,
        "error": outcome.error,
        "final_url": outcome.final_url,
        "size": len(outcome.data) if outcome.ok else 0,
        "content_type": outcome.content_type if outcome.ok else "",
        "file": None,
        "orig_name": None,
        "hops": [
            {
                "url": h.url,
                "host": h.host,
                "port": h.port,
                "addresses": h.addresses,
                "connected_to": h.connected_to,
                "status": h.status,
                "decision": h.decision,
            }
            for h in outcome.hops
        ],
    }
    if outcome.ok:
        orig = _safe_base(outcome.final_url)
        saved = f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}-{orig}"
        (DOWNLOAD_DIR / saved).write_bytes(outcome.data)
        record["file"] = saved
        record["orig_name"] = orig
    with _lock:
        _seq += 1
        record["id"] = _seq
        _attempts.append(record)
    return record


@app.get("/api/attempts")
def attempts():
    with _lock:
        return list(reversed(_attempts))


@app.get("/api/downloads/{name}")
def download(name: str):
    with _lock:
        rec = next((r for r in _attempts if r.get("file") == name), None)
    if rec is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return FileResponse(
        DOWNLOAD_DIR / name,
        filename=rec["orig_name"] or name,
        media_type=rec["content_type"] or "application/octet-stream",
    )


@app.get("/api/forbidden-count")
def forbidden_count():
    try:
        status, body = _internal_get(FORBIDDEN_STATS_URL)
        data = json.loads(body)
        return {"ok": True, "status": status, "count": data.get("requests"), "raw": data}
    except Exception as exc:  # 禁区服务不可达也要如实展示
        return {"ok": False, "error": str(exc)}
