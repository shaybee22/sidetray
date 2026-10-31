#!/usr/bin/env python3
"""Minimal WebSocket client for smoke-test.sh (standard library only).

    ws_probe.py URL [--token T] [--cacert FILE] [--count N] [--timeout S] [--ready FILE]

Connects to URL (ws:// or wss://) with `Authorization: Bearer T`.
- Handshake refused: prints `rejected <http status>` and exits 2.
- Accepted: waits for the server's hello, sends a ping and waits for the pong,
  then creates --ready FILE (if given). After that it prints every other
  message as one JSON line, until it has N of them or --timeout seconds pass.
"""

import argparse
import base64
import json
import os
import socket
import ssl
import struct
import sys
import time
from urllib.parse import urlsplit


def connect(url: str, token: str | None, cacert: str | None) -> tuple[socket.socket, int, bytes]:
    u = urlsplit(url)
    port = u.port or (443 if u.scheme == "wss" else 80)
    sock = socket.create_connection((u.hostname, port), timeout=10)
    if u.scheme == "wss":
        ctx = ssl.create_default_context(cafile=cacert)
        sock = ctx.wrap_socket(sock, server_hostname=u.hostname)
    key = base64.b64encode(os.urandom(16)).decode()
    lines = [
        f"GET {u.path or '/'} HTTP/1.1",
        f"Host: {u.netloc}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if token:
        lines.append(f"Authorization: Bearer {token}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1]) if head.startswith(b"HTTP/") else 0
    return sock, status, rest


class Reader:
    def __init__(self, sock: socket.socket, buf: bytes):
        self.sock, self.buf = sock, buf

    def need(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("connection closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def frame(self) -> tuple[int, bytes]:
        b0, b1 = self.need(2)
        n = b1 & 0x7F
        if n == 126:
            n = struct.unpack(">H", self.need(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", self.need(8))[0]
        mask = self.need(4) if b1 & 0x80 else None
        data = self.need(n)
        if mask:
            data = bytes(c ^ mask[i % 4] for i, c in enumerate(data))
        return b0 & 0x0F, data


def send(sock: socket.socket, opcode: int, data: bytes) -> None:
    mask = os.urandom(4)
    n = len(data)
    head = bytes([0x80 | opcode])
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 65536:
        head += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack(">Q", n)
    sock.sendall(head + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(data)))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("url")
    p.add_argument("--token")
    p.add_argument("--cacert")
    p.add_argument("--count", type=int, default=0)
    p.add_argument("--timeout", type=float, default=10)
    p.add_argument("--ready")
    a = p.parse_args()

    sock, status, rest = connect(a.url, a.token, a.cacert)
    if status != 101:
        print(f"rejected {status}")
        return 2
    r = Reader(sock, rest)
    deadline = time.monotonic() + a.timeout
    ready = False
    got = 0
    while time.monotonic() < deadline and (not ready or got < a.count):
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        try:
            op, data = r.frame()
        except (socket.timeout, TimeoutError):
            break
        except EOFError:
            print(json.dumps({"type": "_closed"}), flush=True)
            break
        if op == 9:
            send(sock, 10, data)
            continue
        if op == 8:
            print(json.dumps({"type": "_closed"}), flush=True)
            break
        if op != 1:
            continue
        msg = json.loads(data)
        if msg.get("type") == "hello":
            send(sock, 1, b'{"type":"ping"}')
        elif msg.get("type") == "pong" and not ready:
            ready = True
            if a.ready:
                open(a.ready, "w").close()
        else:
            print(json.dumps(msg), flush=True)
            got += 1
    try:
        send(sock, 8, struct.pack(">H", 1000))
    except OSError:
        pass
    sock.close()
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(main())
