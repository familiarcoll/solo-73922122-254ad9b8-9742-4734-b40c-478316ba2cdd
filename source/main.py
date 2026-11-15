"""本地观测源:提供观测 CSV、相对/绝对跳转、跳入禁区跳转、换址跳转、超限文件、跳转循环。"""

import os

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

app = FastAPI(title="hydro-observation-source")

SELF_BASE = os.environ.get("SELF_BASE", "http://source.hydro.local:8080").rstrip("/")
FORBIDDEN_URL = os.environ.get("FORBIDDEN_URL", "http://forbidden.hydro.local:8080/secret")
REBIND_URL = os.environ.get("REBIND_URL", "http://rebind.hydro.local:8080/final")

CSV_HEADER = "station,ts,level_m,flow_m3s\n"
CSV_ROWS = "".join(
    f"HY-{i:02d},2026-11-15T0{i % 10}:00:00Z,{10 + i * 0.37:.2f},{40 + i * 1.6:.1f}\n"
    for i in range(1, 9)
)
OBS_CSV = CSV_HEADER + CSV_ROWS

BIG_LINE = "HY-99,2026-11-15T00:00:00Z,10.123,20.456,extra-padding-field\n"
BIG_CSV = CSV_HEADER + BIG_LINE * ((300 * 1024) // len(BIG_LINE) + 1)  # > 256 KiB


@app.get("/")
def root():
    return {
        "service": "observation-source",
        "endpoints": [
            "/obs.csv", "/big.csv", "/redirect-rel", "/redirect-abs",
            "/redirect-forbidden", "/rebind", "/final", "/loop",
        ],
    }


@app.get("/obs.csv")
def obs_csv():
    return PlainTextResponse(OBS_CSV, media_type="text/csv")


@app.get("/big.csv")
def big_csv():
    return PlainTextResponse(BIG_CSV, media_type="text/csv")


@app.get("/redirect-rel")
def redirect_rel():
    """相对跳转:应被正常接续。"""
    return RedirectResponse("/obs.csv", status_code=302)


@app.get("/redirect-abs")
def redirect_abs():
    """绝对跳转(同源)。"""
    return RedirectResponse(f"{SELF_BASE}/obs.csv", status_code=302)


@app.get("/redirect-forbidden")
def redirect_forbidden():
    """跳入禁区:下一跳解析到禁区地址,必须被拒绝。"""
    return RedirectResponse(FORBIDDEN_URL, status_code=302)


@app.get("/rebind")
def rebind():
    """DNS 换址:跳回 rebind 主机,第二次解析将变成禁区地址。"""
    return RedirectResponse(REBIND_URL, status_code=302)


@app.get("/final")
def final():
    return PlainTextResponse(CSV_HEADER + "HY-77,2026-11-15T07:00:00Z,9.99,33.3\n",
                             media_type="text/csv")


@app.get("/echo-host")
def echo_host(request: Request):
    """回显 Host 头:验证采集端连已核对地址时仍保留原 Host。"""
    return PlainTextResponse(request.headers.get("host", ""))


@app.get("/loop")
def loop():
    """自跳转:用于验证超过 3 次跳转即拒绝。"""
    return RedirectResponse("/loop", status_code=302)
