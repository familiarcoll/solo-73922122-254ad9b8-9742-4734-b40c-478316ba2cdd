"""演示用极简 IPv4 DNS 服务(仅 A 记录,纯标准库)。

区域(默认后缀 hydro.local,可用 ZONE 环境变量修改):
  source.<zone>    -> SOURCE_IP     (静态,正常观测源)
  forbidden.<zone> -> FORBIDDEN_IP  (静态,禁区服务)
  dns.<zone>       -> DNS_IP        (静态,本服务,供管理通道复位)
  web.<zone>       -> WEB_IP        (静态,采集网页)
  rebind.<zone>    -> 复位后第一次 A 查询返回 REBIND_GOOD_IP(正常地址),
                      之后返回 REBIND_BAD_IP(禁区地址)——模拟 DNS 换址攻击。

管理接口(HTTP,CONTROL_PORT,默认 8081):
  GET /reset  复位 rebind 状态(下一次查询又返回正常地址)
  GET /state  查看查询统计
"""

from __future__ import annotations

import json
import os
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ZONE = os.environ.get("ZONE", "hydro.local")
STATIC_MAP = {
    f"source.{ZONE}": os.environ.get("SOURCE_IP", "172.28.0.10"),
    f"forbidden.{ZONE}": os.environ.get("FORBIDDEN_IP", "172.28.0.200"),
    f"dns.{ZONE}": os.environ.get("DNS_IP", "172.28.0.53"),
    f"web.{ZONE}": os.environ.get("WEB_IP", "172.28.0.5"),
}
REBIND_NAME = f"rebind.{ZONE}"
REBIND_GOOD = os.environ.get("REBIND_GOOD_IP", STATIC_MAP[f"source.{ZONE}"])
REBIND_BAD = os.environ.get("REBIND_BAD_IP", STATIC_MAP[f"forbidden.{ZONE}"])
TTL = int(os.environ.get("TTL", "5"))
DNS_PORT = int(os.environ.get("DNS_PORT", "53"))
CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "8081"))

_lock = threading.Lock()
_rebind_good_next = True
_stats = {"queries": 0, "rebind_good": 0, "rebind_bad": 0, "nxdomain": 0, "refused": 0}


def reset_rebind() -> None:
    global _rebind_good_next
    with _lock:
        _rebind_good_next = True


def resolve_a(name: str):
    """返回 A 记录列表;名字不属于本区域返回 None。"""
    global _rebind_good_next
    name = name.rstrip(".").lower()
    if name in STATIC_MAP:
        return [STATIC_MAP[name]]
    if name == REBIND_NAME:
        with _lock:
            good = _rebind_good_next
            _rebind_good_next = False
            _stats["rebind_good" if good else "rebind_bad"] += 1
        ip = REBIND_GOOD if good else REBIND_BAD
        print(f"[dns] REBIND {name} -> {ip} ({'good' if good else 'BAD/forbidden'})",
              flush=True)
        return [ip]
    return None


def _parse_question(packet: bytes):
    if len(packet) < 12:
        return None
    qid, flags, qd, _an, _ns, _ar = struct.unpack("!HHHHHH", packet[:12])
    if qd < 1:
        return None
    labels = []
    i = 12
    while True:
        if i >= len(packet):
            return None
        ln = packet[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0:  # 压缩指针:查询里极少见,跳过即可
            i += 2
            break
        labels.append(packet[i + 1:i + 1 + ln].decode("ascii", "replace"))
        i += 1 + ln
    if i + 4 > len(packet):
        return None
    qtype, qclass = struct.unpack("!HH", packet[i:i + 4])
    return qid, flags, ".".join(labels), qtype, qclass, i + 4


def _build_response(qid, qflags, question: bytes, answers, rcode: int) -> bytes:
    flags = 0x8000 | (qflags & 0x0100) | 0x0080 | rcode  # QR + RD + RA + rcode
    out = struct.pack("!HHHHHH", qid, flags, 1, len(answers), 0, 0) + question
    for ip in answers:
        out += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, TTL, 4) + socket.inet_aton(ip)
    return out


def handle_query(packet: bytes):
    parsed = _parse_question(packet)
    if parsed is None:
        return None
    qid, qflags, name, qtype, _qclass, qend = parsed
    question = packet[12:qend]
    in_zone = name.rstrip(".").lower().endswith(ZONE)
    with _lock:
        _stats["queries"] += 1
    answers = resolve_a(name) if qtype == 1 else None
    if answers:
        print(f"[dns] A {name} -> {', '.join(answers)}", flush=True)
        return _build_response(qid, qflags, question, answers, 0)
    if qtype != 1 and resolve_a(name):
        # 非 A 查询(如 AAAA):名字存在但无此类型记录
        return _build_response(qid, qflags, question, [], 0)
    with _lock:
        _stats["nxdomain" if in_zone else "refused"] += 1
    print(f"[dns] {name} type={qtype} -> {'NXDOMAIN' if in_zone else 'REFUSED'}",
          flush=True)
    return _build_response(qid, qflags, question, [], 3 if in_zone else 5)


def serve_dns() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", DNS_PORT))
    print(f"[dns] UDP/{DNS_PORT} zone={ZONE} rebind {REBIND_GOOD} -> {REBIND_BAD}",
          flush=True)
    while True:
        data, addr = sock.recvfrom(512)
        try:
            resp = handle_query(data)
        except Exception as exc:  # 单个坏包不应拖垮服务
            print(f"[dns] bad query from {addr}: {exc}", flush=True)
            continue
        if resp:
            sock.sendto(resp, addr)


class _Control(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/reset"):
            reset_rebind()
            body = json.dumps({"reset": True}).encode()
            code = 200
        elif self.path.startswith("/state"):
            with _lock:
                body = json.dumps({**_stats, "rebind_good_next": _rebind_good_next}).encode()
            code = 200
        else:
            body = b'{"error": "not found"}'
            code = 404
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_control() -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("0.0.0.0", CONTROL_PORT), _Control)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"[dns] control HTTP/{CONTROL_PORT} (/reset /state)", flush=True)
    return httpd


def main() -> None:
    start_control()
    serve_dns()


if __name__ == "__main__":
    main()
