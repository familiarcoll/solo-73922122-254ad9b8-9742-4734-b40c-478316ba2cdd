"""禁区服务:模拟采集机网络可达的内网管理服务。

除 /stats 外的所有请求都会计入 requests 计数——只要防护生效,
计数就应保持不变。/stats 供采集网页的管理通道读取计数。
"""

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

app = FastAPI(title="forbidden-internal-mgmt")
_requests = 0


@app.middleware("http")
async def count_requests(request: Request, call_next):
    global _requests
    if not request.url.path.startswith("/stats"):
        _requests += 1
    return await call_next(request)


@app.get("/")
def root():
    return PlainTextResponse("INTERNAL MANAGEMENT CONSOLE — 禁区,禁止外部访问\n")


@app.get("/secret")
def secret():
    return PlainTextResponse("TOP-SECRET: internal device credentials / 内网设备口令\n")


@app.get("/stats")
def stats():
    return {"service": "forbidden-internal-mgmt", "requests": _requests}
