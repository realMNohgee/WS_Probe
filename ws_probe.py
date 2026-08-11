#!/usr/bin/env python3
"""
WS_Probe — WebSocket client for testing and debugging.
Connect, send, listen, benchmark. Zero dependencies, pure Python stdlib.

Pure RFC 6455 implementation using socket + ssl.
Handles text frames, close, ping/pong.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import select
import socket
import ssl
import struct
import sys
import time
from datetime import datetime, timezone
from typing import Any


WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OPCODES = {
    0x1: "text",
    0x2: "binary",
    0x8: "close",
    0x9: "ping",
    0xA: "pong",
}

CLOSE_CODES = {
    1000: "normal",
    1001: "going_away",
    1002: "protocol_error",
    1003: "unsupported_data",
    1005: "no_status",
    1006: "abnormal",
    1007: "invalid_payload",
    1008: "policy_violation",
    1009: "too_large",
    1010: "extension_needed",
    1011: "unexpected_error",
}


# ── WebSocket Implementation ─────────────────────────────────────────────────

class WebSocketError(Exception):
    """Base WebSocket error."""
    pass


class WebSocketTimeout(WebSocketError):
    """Operation timed out."""
    pass


class WebSocketClosed(WebSocketError):
    """Connection closed."""
    pass


class WebSocketFrame:
    """A single WebSocket frame."""

    def __init__(
        self,
        fin: bool,
        opcode: int,
        payload: bytes,
        mask_key: bytes | None = None,
    ):
        self.fin = fin
        self.opcode = opcode
        self.payload = payload
        self.mask_key = mask_key

    @property
    def opcode_name(self) -> str:
        return OPCODES.get(self.opcode, f"0x{self.opcode:02x}")

    @property
    def is_text(self) -> bool:
        return self.opcode == 0x1

    @property
    def is_close(self) -> bool:
        return self.opcode == 0x8

    @property
    def is_ping(self) -> bool:
        return self.opcode == 0x9

    @property
    def is_pong(self) -> bool:
        return self.opcode == 0xA

    def text(self) -> str:
        return self.payload.decode("utf-8", errors="replace")

    @staticmethod
    def encode(frame: WebSocketFrame) -> bytes:
        """Encode a frame for sending (client → server: MUST be masked)."""
        b1 = (0x80 if frame.fin else 0x00) | (frame.opcode & 0x0F)
        payload = frame.payload
        length = len(payload)
        mask_key = frame.mask_key if frame.mask_key else os.urandom(4)

        result = bytearray()
        result.append(b1)

        if length < 126:
            result.append(0x80 | length)
        elif length < 65536:
            result.append(0x80 | 126)
            result.extend(struct.pack("!H", length))
        else:
            result.append(0x80 | 127)
            result.extend(struct.pack("!Q", length))

        result.extend(mask_key)
        for i, b in enumerate(payload):
            result.append(b ^ mask_key[i % 4])

        return bytes(result)

    @staticmethod
    def parse(data: bytes) -> tuple[WebSocketFrame, int]:
        """Parse a frame from raw bytes. Returns (frame, bytes_consumed)."""
        if len(data) < 2:
            raise WebSocketError("Frame too short")

        b1 = data[0]
        b2 = data[1]

        fin = bool(b1 & 0x80)
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        length = b2 & 0x7F

        offset = 2

        if length == 126:
            if len(data) < offset + 2:
                raise WebSocketError("Frame too short for extended 16-bit length")
            length = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2
        elif length == 127:
            if len(data) < offset + 8:
                raise WebSocketError("Frame too short for extended 64-bit length")
            length = struct.unpack("!Q", data[offset:offset + 8])[0]
            offset += 8

        mask_key = None
        if masked:
            if len(data) < offset + 4:
                raise WebSocketError("Frame too short for mask key")
            mask_key = data[offset:offset + 4]
            offset += 4

        if len(data) < offset + length:
            raise WebSocketError("Frame too short for payload")

        payload = bytearray(data[offset:offset + length])
        if masked and mask_key:
            for i in range(len(payload)):
                payload[i] ^= mask_key[i % 4]

        frame = WebSocketFrame(fin, opcode, bytes(payload), mask_key)
        consumed = offset + length
        return frame, consumed


class WebSocket:
    """RFC 6455 WebSocket client."""

    def __init__(self, url: str, timeout: float = 10.0):
        self.url = url
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.ssl_sock: ssl.SSLSocket | None = None
        self._buffer = bytearray()
        self._handshake_headers: dict[str, str] = {}
        self._handshake_status: int = 0
        self._handshake_reason: str = ""

    def _parse_url(self) -> tuple[str, int, str, bool]:
        """Parse ws:// or wss:// URL. Returns (host, port, path, use_ssl)."""
        url = self.url
        if url.startswith("wss://"):
            use_ssl = True
            default_port = 443
            url = url[6:]
        elif url.startswith("ws://"):
            use_ssl = False
            default_port = 80
            url = url[5:]
        else:
            raise WebSocketError(f"Invalid WebSocket URL: {self.url}")

        # Split host:port from path
        if "/" in url:
            host_part, _, path = url.partition("/")
        else:
            host_part = url
            path = ""

        path = "/" + path if path else "/"

        if ":" in host_part:
            host, _, port_str = host_part.partition(":")
            try:
                port = int(port_str)
            except ValueError:
                raise WebSocketError(f"Invalid port: {port_str}")
        else:
            host = host_part
            port = default_port

        return host, port, path, use_ssl

    def connect(self) -> dict[str, Any]:
        """Open the WebSocket connection and perform the handshake."""
        host, port, path, use_ssl = self._parse_url()

        # Resolve DNS
        addrs = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        af, socktype, proto, canonname, sa = addrs[0]

        self.sock = socket.socket(af, socktype, proto)
        self.sock.settimeout(self.timeout)

        t_start = time.monotonic()
        self.sock.connect(sa)
        connect_rtt = time.monotonic() - t_start

        if use_ssl:
            ctx = ssl.create_default_context()
            # Disable hostname check for server_name to work but also check
            ctx.check_hostname = True
            self.ssl_sock = ctx.wrap_socket(self.sock, server_hostname=host)
            raw_sock = self.ssl_sock
        else:
            raw_sock = self.sock

        # Generate key
        nonce = base64.b64encode(os.urandom(16)).decode()
        expected_accept = base64.b64encode(
            hashlib.sha1((nonce + WS_GUID).encode()).digest()
        ).decode()

        # Build handshake request
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {nonce}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )

        t_handshake = time.monotonic()
        raw_sock.sendall(request.encode())

        # Read response
        response_data = b""
        while b"\r\n\r\n" not in response_data:
            chunk = raw_sock.recv(4096)
            if not chunk:
                raise WebSocketError("Connection closed during handshake")
            response_data += chunk

        t_handshake_end = time.monotonic()
        handshake_rtt = t_handshake_end - t_handshake

        # Parse response
        header_end = response_data.index(b"\r\n\r\n") + 4
        header_bytes = response_data[:header_end]
        self._buffer = bytearray(response_data[header_end:])

        header_text = header_bytes.decode("utf-8", errors="replace")
        lines = header_text.split("\r\n")
        status_line = lines[0]

        # Parse status line: "HTTP/1.1 101 Switching Protocols"
        parts = status_line.split(" ", 2)
        if len(parts) < 2:
            raise WebSocketError(f"Invalid HTTP response: {status_line}")
        self._handshake_status = int(parts[1])
        self._handshake_reason = parts[2] if len(parts) > 2 else ""

        if self._handshake_status != 101:
            raise WebSocketError(
                f"Handshake failed: {self._handshake_status} {self._handshake_reason}"
            )

        # Parse headers
        for line in lines[1:]:
            if ": " in line:
                key, _, value = line.partition(": ")
                self._handshake_headers[key.lower()] = value

        # Verify accept
        actual_accept = self._handshake_headers.get("sec-websocket-accept", "")
        if actual_accept != expected_accept:
            raise WebSocketError(
                f"Sec-WebSocket-Accept mismatch: expected {expected_accept}, got {actual_accept}"
            )

        return {
            "url": self.url,
            "host": host,
            "port": port,
            "path": path,
            "ssl": use_ssl,
            "connect_rtt_ms": round(connect_rtt * 1000, 2),
            "handshake_rtt_ms": round(handshake_rtt * 1000, 2),
            "handshake_status": self._handshake_status,
            "handshake_reason": self._handshake_reason,
            "handshake_headers": dict(self._handshake_headers),
            "sec_websocket_key": nonce,
            "sec_websocket_accept": actual_accept,
        }

    def recv_frame(self) -> WebSocketFrame:
        """Receive a single WebSocket frame. Blocks until one is available."""
        raw_sock = self.ssl_sock or self.sock
        assert raw_sock is not None

        deadline = time.monotonic() + self.timeout

        while True:
            # Try to parse a frame from the buffer
            try:
                frame, consumed = WebSocketFrame.parse(bytes(self._buffer))
                self._buffer = self._buffer[consumed:]
                return frame
            except WebSocketError:
                pass  # Need more data

            remaining = max(0, deadline - time.monotonic())
            if remaining <= 0:
                raise WebSocketTimeout("Timed out waiting for frame")

            # Wait for data
            ready, _, _ = select.select([raw_sock], [], [], remaining)
            if not ready:
                raise WebSocketTimeout("Timed out waiting for frame")

            chunk = raw_sock.recv(65536)
            if not chunk:
                raise WebSocketClosed("Connection closed by peer")
            self._buffer.extend(chunk)

    def send_frame(self, opcode: int, payload: bytes) -> None:
        """Send a frame."""
        raw_sock = self.ssl_sock or self.sock
        assert raw_sock is not None

        frame = WebSocketFrame(fin=True, opcode=opcode, payload=payload)
        raw_sock.sendall(WebSocketFrame.encode(frame))

    def send_text(self, message: str) -> None:
        """Send a text message."""
        self.send_frame(0x1, message.encode("utf-8"))

    def send_ping(self, payload: bytes = b"") -> None:
        """Send a ping frame."""
        self.send_frame(0x9, payload)

    def send_close(self, code: int = 1000, reason: str = "") -> None:
        """Send a close frame."""
        payload = struct.pack("!H", code) + reason.encode("utf-8")
        try:
            self.send_frame(0x8, payload)
        except Exception:
            pass  # Best effort

    def close(self) -> None:
        """Close the connection."""
        if self.ssl_sock:
            try:
                self.ssl_sock.close()
            except Exception:
                pass
            self.ssl_sock = None
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


# ── CLI ──────────────────────────────────────────────────────────────────────

def add_format_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )


def format_output(data: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(data, indent=2, default=str)
    return ""


def cmd_connect(args: argparse.Namespace) -> None:
    """Connect to a WebSocket server, print handshake, wait for first message."""
    ws = WebSocket(args.ws_url, timeout=args.timeout)

    try:
        info = ws.connect()
    except Exception as e:
        result = {"error": str(e), "url": args.ws_url}
        if args.format == "json":
            print(json.dumps(result, indent=2))
        else:
            print(f"❌ Connection failed: {e}")
        sys.exit(1)

    if args.format == "json":
        print(json.dumps(info, indent=2, default=str))
        ws.close()
        return

    # Text output
    print(f"━━━ WS_Probe — Connect ━━━")
    print(f"  URL:      {info['url']}")
    print(f"  Host:     {info['host']}:{info['port']}")
    print(f"  TLS:      {'yes' if info['ssl'] else 'no'}")
    print(f"  TCP RTT:  {info['connect_rtt_ms']} ms")
    print()
    print(f"  Handshake: HTTP/1.1 {info['handshake_status']} {info['handshake_reason']}")
    print(f"  Handshake RTT: {info['handshake_rtt_ms']} ms")
    print(f"  Sec-WebSocket-Key:    {info['sec_websocket_key']}")
    print(f"  Sec-WebSocket-Accept: {info['sec_websocket_accept']}")
    print()

    # Receive first message
    try:
        frame = ws.recv_frame()
        now = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:12]
        if frame.is_text:
            print(f"  [{now}] ← {frame.text()}")
        elif frame.is_close:
            code = 1005
            reason = ""
            if len(frame.payload) >= 2:
                code = struct.unpack("!H", frame.payload[:2])[0]
                reason = frame.payload[2:].decode("utf-8", errors="replace")
            print(f"  [{now}] ← CLOSE ({code} {CLOSE_CODES.get(code, '?')}): {reason}")
        else:
            print(f"  [{now}] ← [{frame.opcode_name}] {len(frame.payload)} bytes")
    except WebSocketTimeout:
        print(f"  (no message received within {args.timeout}s)")
    except WebSocketClosed:
        print("  Connection closed before first message.")

    ws.close()


def cmd_send(args: argparse.Namespace) -> None:
    """Send N messages, print responses."""
    ws = WebSocket(args.ws_url, timeout=args.timeout)
    results: list[dict[str, Any]] = []

    try:
        info = ws.connect()
    except Exception as e:
        result = {"error": str(e), "url": args.ws_url}
        if args.format == "json":
            print(json.dumps(result, indent=2))
        else:
            print(f"❌ Connection failed: {e}")
        sys.exit(1)

    count = args.count
    wait = args.wait

    if args.format == "json":
        # JSON mode: collect all, print at end
        for i in range(count):
            t_send = time.monotonic()
            ws.send_text(args.message)
            entry: dict[str, Any] = {"n": i + 1, "sent": args.message}

            try:
                frame = ws.recv_frame()
                t_recv = time.monotonic()
                entry["rtt_ms"] = round((t_recv - t_send) * 1000, 2)
                if frame.is_text:
                    entry["response"] = frame.text()
                elif frame.is_close:
                    code = 1005
                    if len(frame.payload) >= 2:
                        code = struct.unpack("!H", frame.payload[:2])[0]
                    entry["response"] = {"close": code}
                else:
                    entry["response"] = {"opcode": frame.opcode_name, "bytes": len(frame.payload)}
            except (WebSocketTimeout, WebSocketClosed) as e:
                entry["response"] = None
                entry["error"] = str(e)

            results.append(entry)
            if i < count - 1 and wait > 0:
                time.sleep(wait)

        ws.close()
        print(json.dumps({"connect": info, "messages": results}, indent=2, default=str))
        return

    # Text mode
    print(f"━━━ WS_Probe — Send ━━━")
    print(f"  Connected to {info['host']}:{info['port']} (RTT: {info['handshake_rtt_ms']} ms)")
    print(f"  Sending {count} message(s): \"{args.message}\"")
    print()

    for i in range(count):
        t_send = time.monotonic()
        ws.send_text(args.message)
        sent_at = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:12]
        print(f"  [{sent_at}] → \"{args.message}\"", end="")

        try:
            frame = ws.recv_frame()
            t_recv = time.monotonic()
            rtt = round((t_recv - t_send) * 1000, 2)
            recv_at = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:12]
            if frame.is_text:
                print(f"  [{recv_at}] ← \"{frame.text()}\"  ({rtt} ms)")
            elif frame.is_close:
                code = 1005
                if len(frame.payload) >= 2:
                    code = struct.unpack("!H", frame.payload[:2])[0]
                print(f"  [{recv_at}] ← CLOSE ({code})  ({rtt} ms)")
            else:
                print(f"  [{recv_at}] ← [{frame.opcode_name}] {len(frame.payload)}B  ({rtt} ms)")
        except WebSocketTimeout:
            print(f"  (timeout)")
        except WebSocketClosed:
            print(f"  (closed)")
            break

        if i < count - 1 and wait > 0:
            time.sleep(wait)

    ws.close()


def cmd_listen(args: argparse.Namespace) -> None:
    """Listen for N messages, print with timestamps."""
    ws = WebSocket(args.ws_url, timeout=args.timeout)
    messages: list[dict[str, Any]] = []

    try:
        info = ws.connect()
    except Exception as e:
        result = {"error": str(e), "url": args.ws_url}
        if args.format == "json":
            print(json.dumps(result, indent=2))
        else:
            print(f"❌ Connection failed: {e}")
        sys.exit(1)

    if args.format == "json":
        while len(messages) < args.count:
            try:
                frame = ws.recv_frame()
                now = datetime.now(timezone.utc).isoformat()
                entry: dict[str, Any] = {"n": len(messages) + 1, "timestamp": now}

                if frame.is_text:
                    entry["type"] = "text"
                    entry["data"] = frame.text()
                elif frame.is_close:
                    entry["type"] = "close"
                    if len(frame.payload) >= 2:
                        entry["code"] = struct.unpack("!H", frame.payload[:2])[0]
                        entry["reason"] = frame.payload[2:].decode("utf-8", errors="replace")
                    messages.append(entry)
                    break
                elif frame.is_ping:
                    entry["type"] = "ping"
                elif frame.is_pong:
                    entry["type"] = "pong"
                else:
                    entry["type"] = frame.opcode_name
                    entry["bytes"] = len(frame.payload)

                messages.append(entry)
            except WebSocketTimeout:
                messages.append({"n": len(messages) + 1, "error": "timeout"})
                break
            except WebSocketClosed:
                messages.append({"n": len(messages) + 1, "error": "closed"})
                break

        ws.close()
        print(json.dumps({"connect": info, "messages": messages}, indent=2, default=str))
        return

    # Text mode
    print(f"━━━ WS_Probe — Listen ━━━")
    print(f"  Connected to {info['host']}:{info['port']}")
    print(f"  Listening for up to {args.count} message(s)...")
    print()

    while len(messages) < args.count:
        try:
            frame = ws.recv_frame()
            now = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:12]
            if frame.is_text:
                print(f"  [{now}] ← {frame.text()}")
                messages.append({"type": "text", "data": frame.text()})
            elif frame.is_close:
                code = 1005
                reason = ""
                if len(frame.payload) >= 2:
                    code = struct.unpack("!H", frame.payload[:2])[0]
                    reason = frame.payload[2:].decode("utf-8", errors="replace")
                print(f"  [{now}] ← CLOSE ({code} {CLOSE_CODES.get(code, '?')}): {reason}")
                break
            elif frame.is_ping:
                print(f"  [{now}] ← PING")
            elif frame.is_pong:
                print(f"  [{now}] ← PONG")
            else:
                print(f"  [{now}] ← [{frame.opcode_name}] {len(frame.payload)} bytes")
                messages.append({})
        except WebSocketTimeout:
            print(f"  (timeout — no message within {args.timeout}s)")
            break
        except WebSocketClosed:
            print("  Connection closed.")
            break

    ws.close()


def cmd_bench(args: argparse.Namespace) -> None:
    """Benchmark: send N pings, measure latency stats."""
    ws = WebSocket(args.ws_url, timeout=args.timeout)

    try:
        info = ws.connect()
    except Exception as e:
        result = {"error": str(e), "url": args.ws_url}
        if args.format == "json":
            print(json.dumps(result, indent=2))
        else:
            print(f"❌ Connection failed: {e}")
        sys.exit(1)

    num = args.messages
    rtts: list[float] = []
    errors = 0

    if args.format != "json":
        print(f"━━━ WS_Probe — Bench ━━━")
        print(f"  Server:   {info['host']}:{info['port']} ({'wss' if info['ssl'] else 'ws'})")
        print(f"  Pings:    {num}")
        print()

    for i in range(num):
        payload = struct.pack("!Q", i) + os.urandom(4)  # 12-byte ping payload
        t_send = time.monotonic()
        try:
            ws.send_ping(payload)
        except Exception as e:
            errors += 1
            if args.format != "json":
                print(f"  [{i+1}/{num}] send error: {e}")
            continue

        try:
            frame = ws.recv_frame()
            t_recv = time.monotonic()
            if frame.is_pong:
                rtt = (t_recv - t_send) * 1000
                rtts.append(rtt)
            else:
                errors += 1
        except (WebSocketTimeout, WebSocketClosed):
            errors += 1

    if not rtts:
        result = {"error": "No successful pings", "url": args.ws_url}
        if args.format == "json":
            print(json.dumps(result, indent=2))
        else:
            print("  ❌ No successful pings.")
        ws.close()
        sys.exit(1)

    rtts.sort()
    n = len(rtts)
    min_rtt = rtts[0]
    max_rtt = rtts[-1]
    avg_rtt = sum(rtts) / n

    def percentile(data: list[float], p: float) -> float:
        k = (len(data) - 1) * p / 100
        f = int(k)
        c = min(f + 1, len(data) - 1)
        return data[f] + (k - f) * (data[c] - data[f]) if f < len(data) - 1 else data[f]

    p50 = percentile(rtts, 50)
    p95 = percentile(rtts, 95)
    p99 = percentile(rtts, 99)

    bench_result = {
        "connect": info,
        "total_pings": num,
        "successful": n,
        "errors": errors,
        "latency_ms": {
            "min": round(min_rtt, 2),
            "max": round(max_rtt, 2),
            "avg": round(avg_rtt, 2),
            "p50": round(p50, 2),
            "p95": round(p95, 2),
            "p99": round(p99, 2),
        },
    }

    if args.format == "json":
        ws.close()
        print(json.dumps(bench_result, indent=2, default=str))
        return

    print(f"  Results ({n}/{num} successful, {errors} errors):")
    print(f"  ┌─────────────┬──────────┐")
    print(f"  │ Min         │ {min_rtt:>7.2f} ms │")
    print(f"  │ Max         │ {max_rtt:>7.2f} ms │")
    print(f"  │ Avg         │ {avg_rtt:>7.2f} ms │")
    print(f"  │ P50         │ {p50:>7.2f} ms │")
    print(f"  │ P95         │ {p95:>7.2f} ms │")
    print(f"  │ P99         │ {p99:>7.2f} ms │")
    print(f"  └─────────────┴──────────┘")

    ws.close()


def cmd_echo(args: argparse.Namespace) -> None:
    """Interactive echo mode: type messages, see responses."""
    ws = WebSocket(args.ws_url, timeout=args.timeout)

    try:
        info = ws.connect()
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        sys.exit(1)

    print(f"━━━ WS_Probe — Echo ━━━")
    print(f"  Connected to {info['host']}:{info['port']} ({'wss' if info['ssl'] else 'ws'})")
    print(f"  Type messages, press Enter to send. Ctrl+C or /quit to exit.")
    print()

    import readline  # noqa: F401 — enables line editing

    while True:
        try:
            line = input("> ").strip()
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            break

        if line.lower() in ("/quit", "/exit", "/q"):
            print("  Bye.")
            break

        if line.lower() == "/ping":
            t = time.monotonic()
            ws.send_ping(b"echo-ping")
            try:
                frame = ws.recv_frame()
                rtt = round((time.monotonic() - t) * 1000, 2)
                print(f"  ← PONG ({rtt} ms)")
            except WebSocketTimeout:
                print(f"  (ping timeout)")
            continue

        if not line:
            continue

        t_send = time.monotonic()
        ws.send_text(line)

        try:
            frame = ws.recv_frame()
            rtt = round((time.monotonic() - t_send) * 1000, 2)
            if frame.is_text:
                print(f"  ← {frame.text()}  ({rtt} ms)")
            elif frame.is_close:
                code = 1005
                if len(frame.payload) >= 2:
                    code = struct.unpack("!H", frame.payload[:2])[0]
                print(f"  ← CLOSE ({code})")
                break
            else:
                print(f"  ← [{frame.opcode_name}] {len(frame.payload)}B  ({rtt} ms)")
        except WebSocketTimeout:
            print(f"  (timeout)")
        except WebSocketClosed:
            print(f"  Connection closed.")
            break

    ws.close()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="WS_Probe — WebSocket client for testing and debugging.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # Common parent with --format
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    # connect
    p_connect = sub.add_parser(
        "connect", parents=[common],
        help="Connect to a WebSocket server and show handshake details",
    )
    p_connect.add_argument("ws_url", help="WebSocket URL (ws:// or wss://)")
    p_connect.add_argument(
        "--timeout", type=float, default=10.0, help="Connection timeout in seconds (default: 10)"
    )

    # send
    p_send = sub.add_parser(
        "send", parents=[common],
        help="Send messages and print responses",
    )
    p_send.add_argument("ws_url", help="WebSocket URL (ws:// or wss://)")
    p_send.add_argument("message", help="Message text to send")
    p_send.add_argument("--count", type=int, default=1, help="Number of messages to send (default: 1)")
    p_send.add_argument("--wait", type=float, default=0.0, help="Seconds to wait between sends (default: 0)")
    p_send.add_argument("--timeout", type=float, default=10.0, help="Timeout per message in seconds (default: 10)")

    # listen
    p_listen = sub.add_parser(
        "listen", parents=[common],
        help="Listen for incoming WebSocket messages",
    )
    p_listen.add_argument("ws_url", help="WebSocket URL (ws:// or wss://)")
    p_listen.add_argument("--timeout", type=float, default=30.0, help="Timeout in seconds (default: 30)")
    p_listen.add_argument("--count", type=int, default=10, help="Number of messages to wait for (default: 10)")

    # bench
    p_bench = sub.add_parser(
        "bench", parents=[common],
        help="Benchmark WebSocket latency with ping/pong",
    )
    p_bench.add_argument("ws_url", help="WebSocket URL (ws:// or wss://)")
    p_bench.add_argument("--messages", type=int, default=100, help="Number of pings to send (default: 100)")
    p_bench.add_argument("--timeout", type=float, default=5.0, help="Timeout per ping in seconds (default: 5)")

    # echo
    p_echo = sub.add_parser(
        "echo", parents=[common],
        help="Interactive echo mode — type messages and see responses",
    )
    p_echo.add_argument("ws_url", help="WebSocket URL (ws:// or wss://)")
    p_echo.add_argument("--timeout", type=float, default=10.0, help="Timeout in seconds (default: 10)")

    args = parser.parse_args(argv)

    if args.command == "connect":
        cmd_connect(args)
    elif args.command == "send":
        cmd_send(args)
    elif args.command == "listen":
        cmd_listen(args)
    elif args.command == "bench":
        cmd_bench(args)
    elif args.command == "echo":
        cmd_echo(args)


if __name__ == "__main__":
    main()
