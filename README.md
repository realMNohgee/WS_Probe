# WS_Probe 🔌
![CI](https://github.com/realMNohgee/WS_Probe/actions/workflows/ci.yml/badge.svg) ![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg) ![License](https://img.shields.io/badge/license-MIT-blue.svg)

**WebSocket client for testing and debugging.** Connect, send, listen, benchmark. Zero dependencies, pure Python stdlib.

Pure RFC 6455 implementation using `socket` + `ssl`. Handles text frames, close, ping/pong, TLS, and benchmark statistics — no pip install required.

> Part of the **Agent Infrastructure** suite — probing and debugging tools for people building on WebSocket-based services and realtime APIs.

## One tool, many domains

| Domain | What WS_Probe does for you |
|---|---|
| 🔌 **WebSocket Debugging** | Connect, send, listen — inspect every frame and handshake detail |
| 📊 **Latency Benchmarking** | Ping/pong RTT with min/max/avg/p50/p95/p99 percentiles |
| 🧪 **API Testing** | Send messages, verify responses, check timing — with JSON output for CI |
| 🖥️ **Interactive Exploration** | Echo mode: type messages live and see instant responses |

## Install

```bash
git clone git@github.com:realMNohgee/WS_Probe.git
cd WS_Probe
python3 ws_probe.py --help
```

## Quick start

```bash
# Connect and see handshake details
python3 ws_probe.py connect wss://echo.websocket.org

# Send messages and see round-trip times
python3 ws_probe.py send wss://echo.websocket.org "hello" --count 5

# Benchmark with 100 pings
python3 ws_probe.py bench wss://echo.websocket.org --messages 100

# Interactive echo mode
python3 ws_probe.py echo wss://echo.websocket.org
```

### JSON output (for scripts and CI)

```bash
python3 ws_probe.py bench wss://echo.websocket.org --messages 20 --format json
```

```json
{
  "latency_ms": {
    "min": 21.69,
    "max": 173.33,
    "avg": 94.95,
    "p50": 87.22,
    "p95": 163.9,
    "p99": 171.44
  }
}
```

## Commands

| Command | Description |
|---|---|
| `connect <url>` | Open connection, show handshake, wait for first message |
| `send <url> <msg>` | Send N messages, print responses with RTT |
| `listen <url>` | Listen for incoming messages, print with timestamps |
| `bench <url>` | Send N pings, measure min/max/avg/p50/p95/p99 latency |
| `echo <url>` | Interactive mode — type messages, see responses live |

All commands support `--format text|json` and `--timeout SEC`.

## License

MIT — see [LICENSE](LICENSE).

---

🧰 **[Tool on Hermtica Marketplace](https://hermtica.com/marketplace)** — the open, agent-agnostic marketplace for AI agent tools.
