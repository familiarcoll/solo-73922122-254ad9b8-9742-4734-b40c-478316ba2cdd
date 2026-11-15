#!/usr/bin/env python3
"""本地自测:不依赖 Docker,在 127.0.0.x 上启动 DNS / 观测源 / 禁区服务 / 采集网页,
验证 SSRF 防护的关键行为。运行:python3 tests/selftest.py

拓扑(对应 compose 中的 172.28.0.x):
  127.0.0.1:15353/UDP  演示 DNS(rebind.hydro.local 首查好、再查坏)
  127.0.0.1:18081      DNS 管理复位
  127.0.0.1:18080      观测源
  127.0.0.2:28080      禁区服务(许可网段 127.0.0.1/32 之外)
  127.0.0.1:8000       采集网页
"""

from __future__ import annotations

import http.client
import json
import os
import random
import socket
import struct
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.update({
    # 观测源跳转目标
    "SELF_BASE": "http://source.hydro.local:18080",
    "FORBIDDEN_URL": "http://forbidden.hydro.local:28080/secret",
    "REBIND_URL": "http://rebind.hydro.local:18080/final",
    # 演示 DNS
    "SOURCE_IP": "127.0.0.1",
    "FORBIDDEN_IP": "127.0.0.2",
    "DNS_IP": "127.0.0.1",
    "WEB_IP": "127.0.0.1",
    "DNS_PORT": "15353",
    "CONTROL_PORT": "18081",
    # 采集网页(管理员配置)
    "ALLOWED_CIDRS": "127.0.0.1/32",
    "ALLOWED_PORTS": "18080,28080",
    "FORBIDDEN_STATS_URL": "http://127.0.0.2:28080/stats",
    "DNS_RESET_URL": "http://127.0.0.1:18081/reset",
    "SCENARIO_SOURCE_BASE": "http://source.hydro.local:18080",
    "SCENARIO_REBIND_URL": "http://rebind.hydro.local:18080/rebind",
    "DOWNLOAD_DIR": tempfile.mkdtemp(prefix="hydro-dl-"),
})

import uvicorn  # noqa: E402

import collector.main as webmain  # noqa: E402
import dns.server as dnsserver  # noqa: E402
import forbidden.main as forbiddenmod  # noqa: E402
import source.main as sourcemod  # noqa: E402
from collector.guard import GuardedFetcher  # noqa: E402

PASSED = 0
FAILED = 0


def check(name, cond, detail=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  PASS  {name}")
    else:
        FAILED += 1
        print(f"  FAIL  {name}  {detail}")


# ---- 通过真实 UDP 查询演示 DNS 的解析器(供 GuardedFetcher 注入) ----
def udp_resolve(host, server=("127.0.0.1", 15353)):
    qid = random.randint(0, 65535)
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in host.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(q, server)
        data, _ = sock.recvfrom(512)
    finally:
        sock.close()
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if rid != qid or flags & 0xF != 0:
        raise OSError(f"DNS 查询失败 rcode={flags & 0xF}")
    i = 12
    for _ in range(qd):  # 跳过问题段
        while True:
            ln = data[i]
            i += 1
            if ln == 0:
                break
            if ln & 0xC0:
                i += 1
                break
            i += ln
        i += 4
    addrs = []
    for _ in range(an):
        if data[i] & 0xC0:
            i += 2
        else:
            while data[i] != 0:
                i += 1 + data[i]
            i += 1
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            addrs.append(socket.inet_ntoa(data[i:i + 4]))
        i += rdlen
    return addrs


def start_uvicorn(app, host, port):
    cfg = uvicorn.Config(app=app, host=host, port=port, log_level="error")
    server = uvicorn.Server(cfg)
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(200):
        if server.started:
            return server
        time.sleep(0.05)
    raise RuntimeError(f"{host}:{port} 启动失败")


def http_get(host, port, path):
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def http_post_json(host, port, path, payload):
    body = json.dumps(payload).encode()
    conn = http.client.HTTPConnection(host, port, timeout=15)
    try:
        conn.request("POST", path, body=body,
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def forbidden_count():
    status, body = http_get("127.0.0.2", 28080, "/stats")
    return json.loads(body)["requests"]


def main():
    print("== 启动演示服务 ==")
    dnsserver.start_control()
    threading.Thread(target=dnsserver.serve_dns, daemon=True).start()
    start_uvicorn(sourcemod.app, "127.0.0.1", 18080)
    start_uvicorn(forbiddenmod.app, "127.0.0.2", 28080)
    webmain.fetcher = GuardedFetcher(["127.0.0.1/32"], [18080, 28080],
                                     resolver=udp_resolve)
    start_uvicorn(webmain.app, "127.0.0.1", 8000)
    time.sleep(0.2)

    guard = GuardedFetcher(["127.0.0.1/32"], [18080, 28080], resolver=udp_resolve)

    print("== DNS 服务行为 ==")
    check("source 静态解析", udp_resolve("source.hydro.local") == ["127.0.0.1"])
    check("forbidden 静态解析", udp_resolve("forbidden.hydro.local") == ["127.0.0.2"])
    http_get("127.0.0.1", 18081, "/reset")
    check("rebind 首查返回正常地址", udp_resolve("rebind.hydro.local") == ["127.0.0.1"])
    check("rebind 再查换成禁区地址", udp_resolve("rebind.hydro.local") == ["127.0.0.2"])
    http_get("127.0.0.1", 18081, "/reset")
    check("reset 后 rebind 恢复首查正常", udp_resolve("rebind.hydro.local") == ["127.0.0.1"])
    try:
        udp_resolve("nosuch.hydro.local")
        check("未知名字 NXDOMAIN", False)
    except OSError:
        check("未知名字 NXDOMAIN", True)

    print("== 防护抓取器(GuardedFetcher) ==")
    r = guard.fetch("http://source.hydro.local:18080/obs.csv")
    check("正常采集成功", r.ok and r.data.startswith(b"station,ts"), r.error)
    check("正常采集单跳", len(r.hops) == 1)

    r = guard.fetch("http://source.hydro.local:18080/echo-host")
    check("连接已核对地址且保留原 Host",
          r.ok and r.data == b"source.hydro.local:18080",
          f"got {r.data!r} err={r.error}")
    check("实际连接 IP 为已核对地址", r.ok and r.hops[-1].connected_to == "127.0.0.1")

    r = guard.fetch("http://source.hydro.local:18080/redirect-rel")
    check("相对跳转正常接续", r.ok and len(r.hops) == 2
          and r.hops[1].url == "http://source.hydro.local:18080/obs.csv", r.error)

    r = guard.fetch("http://source.hydro.local:18080/redirect-abs")
    check("绝对跳转(同源)成功", r.ok, r.error)

    r = guard.fetch("http://source.hydro.local:18080/big.csv")
    check("超过 256 KiB 拒绝", not r.ok and "上限" in (r.error or ""), r.error)

    r = guard.fetch("http://source.hydro.local:18080/loop")
    check("超过 3 次跳转拒绝", not r.ok and "超过 3 次" in (r.error or ""), r.error)

    r = guard.fetch("http://source.hydro.local:9999/obs.csv")
    check("许可外端口拒绝", not r.ok and "端口" in (r.error or ""), r.error)

    r = guard.fetch("https://source.hydro.local:18080/obs.csv")
    check("非 http 方案拒绝", not r.ok and "http" in (r.error or ""), r.error)

    r = guard.fetch("http://user@source.hydro.local:18080/obs.csv")
    check("携带用户信息拒绝", not r.ok, r.error)

    # 默认解析器(系统 getaddrinfo)路径:IP 字面量 URL
    g2 = GuardedFetcher(["127.0.0.1/32"], [18080, 28080])
    r = g2.fetch("http://127.0.0.1:18080/obs.csv")
    check("默认解析器+IP 字面量采集成功", r.ok and r.data.startswith(b"station,ts"),
          r.error)

    # 解析结果混有禁区地址:整跳拒绝
    g3 = GuardedFetcher(["127.0.0.1/32"], [18080, 28080],
                        resolver=lambda h: ["127.0.0.1", "127.0.0.2"])
    r = g3.fetch("http://source.hydro.local:18080/obs.csv")
    check("解析混有禁区地址整跳拒绝", not r.ok and "禁区" in (r.error or ""), r.error)

    c0 = forbidden_count()
    r = guard.fetch("http://source.hydro.local:18080/redirect-forbidden")
    check("跳转入禁区拒绝", not r.ok and "禁区" in (r.error or ""), r.error)
    check("跳转入禁区:禁区计数不变", forbidden_count() == c0)

    r = guard.fetch("http://forbidden.hydro.local:28080/secret")
    check("直连禁区 URL 拒绝", not r.ok and "禁区" in (r.error or ""), r.error)
    check("直连禁区:禁区计数不变", forbidden_count() == c0)

    http_get("127.0.0.1", 18081, "/reset")
    r = guard.fetch("http://rebind.hydro.local:18080/rebind")
    check("DNS 换址:第二跳拒绝", not r.ok and "禁区" in (r.error or ""), r.error)
    check("DNS 换址:首跳落在正常地址",
          len(r.hops) == 2 and r.hops[0].connected_to == "127.0.0.1",
          f"hops={[(h.connected_to, h.addresses) for h in r.hops]}")
    check("DNS 换址:第二跳解析到禁区地址",
          len(r.hops) == 2 and r.hops[1].addresses == ["127.0.0.2"])
    check("DNS 换址:禁区计数不变", forbidden_count() == c0)

    status, _ = http_get("127.0.0.2", 28080, "/secret")  # 管理面直连,证明网络可达
    check("禁区服务网络可达(防护是唯一屏障)", status == 200)
    check("直连后禁区计数 +1", forbidden_count() == c0 + 1)

    print("== 采集网页(HTTP 端到端) ==")
    status, body = http_get("127.0.0.1", 8000, "/")
    check("首页可访问", status == 200 and "水文".encode() in body)

    status, body = http_get("127.0.0.1", 8000, "/api/config")
    cfg = json.loads(body)
    check("配置接口返回许可策略",
          status == 200 and cfg["allowed_cidrs"] == ["127.0.0.1/32"]
          and cfg["allowed_ports"] == [18080, 28080])

    status, body = http_post_json("127.0.0.1", 8000, "/api/fetch",
                                  {"url": cfg["scenarios"]["normal"], "scenario": "normal"})
    rec = json.loads(body)
    check("网页正常采集成功", status == 200 and rec["ok"] and rec["file"], rec.get("error"))
    if rec.get("file"):
        status, data = http_get("127.0.0.1", 8000, f"/api/downloads/{rec['file']}")
        check("原件可下载且内容一致",
              status == 200 and data.startswith(b"station,ts"))

    status, body = http_post_json("127.0.0.1", 8000, "/api/fetch",
                                  {"url": cfg["scenarios"]["forbidden"],
                                   "scenario": "forbidden"})
    rec = json.loads(body)
    check("网页跳转入禁区被拒", not rec["ok"] and "禁区" in (rec["error"] or ""))

    status, body = http_post_json("127.0.0.1", 8000, "/api/fetch",
                                  {"url": cfg["scenarios"]["rebind"],
                                   "scenario": "rebind"})
    rec = json.loads(body)
    check("网页 DNS 换址被拒(网页先复位演示 DNS)",
          not rec["ok"] and "禁区" in (rec["error"] or ""), rec.get("error"))

    status, body = http_get("127.0.0.1", 8000, "/api/forbidden-count")
    fc = json.loads(body)
    check("禁区计数接口可用", fc.get("ok") and fc["count"] == c0 + 1, body)

    status, body = http_get("127.0.0.1", 8000, "/api/attempts")
    check("采集记录完整", status == 200 and len(json.loads(body)) == 3)

    print(f"\n结果: {PASSED} 通过, {FAILED} 失败")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
