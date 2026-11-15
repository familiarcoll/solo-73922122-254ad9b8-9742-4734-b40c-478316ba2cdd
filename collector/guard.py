"""SSRF 防护抓取器(采集边界的核心防线)。

安全模型(白名单制):
- 仅支持 http://、仅 IPv4;管理员配置许可网段(ALLOWED_CIDRS)与许可端口(ALLOWED_PORTS)。
- 每一跳连接前解析主机名,核对**全部**解析地址:任何一个落在许可网段之外
  (即"禁区")整跳即被拒绝。
- 实际连接使用**已核对的地址**(直接连 IP),并保留原 Host 头;
  连接阶段不再触发任何新的 DNS 解析,因此 DNS 事后换址(重绑定)无法把
  请求带进禁区。
- 重定向逐跳重新裁决(相对跳转用 urljoin 正常接续);超过 max_redirects 次
  跳转或任一步失败,本次采集整体失败,不开放下载。
- 响应体超过 max_bytes(默认 256 KiB)即拒绝,不落盘。
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

MAX_BYTES_DEFAULT = 256 * 1024  # 256 KiB
MAX_REDIRECTS_DEFAULT = 3
CONNECT_TIMEOUT = 8.0
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
USER_AGENT = "hydro-collector/1.0"


class FetchError(Exception):
    """采集失败的可读原因(可安全展示给操作员)。"""


@dataclass
class Hop:
    url: str
    host: str = ""
    port: int = 0
    addresses: list[str] = field(default_factory=list)
    connected_to: str = ""
    status: int | None = None
    decision: str = ""


@dataclass
class FetchOutcome:
    ok: bool
    error: str | None
    hops: list[Hop]
    final_url: str = ""
    data: bytes = b""
    content_type: str = ""


def default_resolver(host: str) -> list[str]:
    """系统解析器,仅取 IPv4(A 记录)。"""
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    addrs: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in addrs:
            addrs.append(ip)
    return addrs


class GuardedFetcher:
    """按白名单裁决的逐跳抓取器。resolver 可注入(便于测试/复现 DNS 换址)。"""

    def __init__(
        self,
        allowed_cidrs,
        allowed_ports,
        max_redirects: int = MAX_REDIRECTS_DEFAULT,
        max_bytes: int = MAX_BYTES_DEFAULT,
        resolver=default_resolver,
        timeout: float = CONNECT_TIMEOUT,
    ):
        self.networks = [ipaddress.ip_network(c) for c in allowed_cidrs]
        self.allowed_ports = {int(p) for p in allowed_ports}
        self.max_redirects = int(max_redirects)
        self.max_bytes = int(max_bytes)
        self.resolver = resolver
        self.timeout = timeout

    # ---- 单跳裁决 ------------------------------------------------------
    def _check_hop(self, url: str, hop: Hop):
        """裁决一跳;解析到的信息逐步写入 hop(即使最终被拒也留痕)。"""
        parsed = urlparse(url)
        if parsed.scheme != "http":
            raise FetchError(f"仅支持 http:// 链接(收到 scheme: {parsed.scheme or '无'})")
        if parsed.username or parsed.password:
            raise FetchError("URL 不允许携带用户信息")
        host = parsed.hostname
        if not host:
            raise FetchError("URL 缺少主机名")
        try:
            port = parsed.port if parsed.port is not None else 80
        except ValueError:
            raise FetchError("端口非法")
        hop.host, hop.port = host, port
        if port not in self.allowed_ports:
            raise FetchError(f"端口 {port} 不在许可端口 {sorted(self.allowed_ports)} 内")
        try:
            addrs = self.resolver(host)
        except (socket.gaierror, OSError) as exc:
            raise FetchError(f"主机 {host} 解析失败: {exc}")
        if not addrs:
            raise FetchError(f"主机 {host} 无 IPv4 解析结果")
        hop.addresses = list(addrs)
        clean: list[str] = []
        for a in addrs:
            try:
                ip = ipaddress.ip_address(a)
            except ValueError:
                raise FetchError(f"解析结果含非法地址 {a!r},已拒绝")
            if ip.version != 4:
                raise FetchError(f"解析结果含非 IPv4 地址 {a},已拒绝")
            if not any(ip in net for net in self.networks):
                raise FetchError(f"解析地址 {a} 落入禁区(许可网段之外),已拒绝")
            if a not in clean:
                clean.append(a)
        return parsed, host, port, clean

    # ---- 主流程 --------------------------------------------------------
    def fetch(self, url: str) -> FetchOutcome:
        hops: list[Hop] = []
        current = url
        redirects = 0
        while True:
            hop = Hop(url=current)
            hops.append(hop)
            try:
                parsed, host, port, addrs = self._check_hop(current, hop)
            except FetchError as exc:
                hop.decision = f"拒绝:{exc}"
                return FetchOutcome(False, str(exc), hops)
            hop.decision = "放行(全部解析地址均在许可网段,端口许可)"

            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            host_header = host if port == 80 else f"{host}:{port}"

            resp = None
            conn = None
            last_err: Exception | None = None
            for addr in addrs:  # 只尝试已核对的地址
                try:
                    conn = http.client.HTTPConnection(addr, port, timeout=self.timeout)
                    conn.request(
                        "GET",
                        path,
                        headers={
                            "Host": host_header,  # 保留原 Host
                            "User-Agent": USER_AGENT,
                            "Accept": "*/*",
                            "Connection": "close",
                        },
                    )
                    resp = conn.getresponse()
                    hop.connected_to = addr
                    break
                except (http.client.HTTPException, OSError) as exc:
                    last_err = exc
                    if conn is not None:
                        conn.close()
                    conn = None
            if resp is None:
                msg = f"连接 {host}({', '.join(addrs)}):{port} 失败: {last_err}"
                hop.decision = f"失败:{msg}"
                return FetchOutcome(False, msg, hops)

            try:
                hop.status = resp.status
                if resp.status in REDIRECT_STATUSES:
                    loc = resp.getheader("Location")
                    resp.read()  # 排干响应体
                    if not loc:
                        msg = f"跳转响应({resp.status})缺少 Location 头"
                        hop.decision = f"失败:{msg}"
                        return FetchOutcome(False, msg, hops)
                    redirects += 1
                    if redirects > self.max_redirects:
                        msg = f"跳转次数超过 {self.max_redirects} 次,已拒绝"
                        hop.decision = f"失败:{msg}"
                        return FetchOutcome(False, msg, hops)
                    current = urljoin(current, loc)  # 相对跳转在此正常接续
                    hop.decision = f"重定向({resp.status})-> {current},进入下一跳重新裁决"
                    continue
                if resp.status != 200:
                    resp.read()
                    msg = f"上游返回状态 {resp.status}"
                    hop.decision = f"失败:{msg}"
                    return FetchOutcome(False, msg, hops)
                data = resp.read(self.max_bytes + 1)
                if len(data) > self.max_bytes:
                    msg = f"原件超过 {self.max_bytes} 字节(256 KiB)上限,已拒绝"
                    hop.decision = f"失败:{msg}"
                    return FetchOutcome(False, msg, hops)
                ctype = resp.getheader("Content-Type") or "application/octet-stream"
                hop.decision = "完成(200 OK,大小合规)"
                return FetchOutcome(
                    True, None, hops, final_url=current, data=data, content_type=ctype
                )
            except (http.client.HTTPException, OSError) as exc:
                msg = f"读取响应失败: {exc}"
                hop.decision = f"失败:{msg}"
                return FetchOutcome(False, msg, hops)
            finally:
                conn.close()
