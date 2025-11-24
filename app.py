from flask import Flask, render_template, jsonify, request
import socket
import threading
import time
import random
from collections import deque
import plotly.graph_objects as go
import plotly
import json
from werkzeug.serving import WSGIRequestHandler
import requests
from urllib.parse import urlparse
import builtins as _builtins
import logging
import sys

# make all prints line-buffered for VS Code terminal visibility
_orig_print = _builtins.print
def print(*args, **kwargs):  # type: ignore[override]
    kwargs.setdefault("flush", True)
    return _orig_print(*args, **kwargs)

# configure logging to stdout so VS Code terminal shows requests
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    stream=sys.stdout,
    force=True,
)
LOG = logging.getLogger("dashboard")

# ============== GLOBAL DATA ==============
PACKET_LOG = []          # Wireshark-style log
packet_times = deque(maxlen=200)
packet_types = deque(maxlen=200)

stats = {"normal": 0, "malicious": 0, "blocked": 0, "load": 0}

normal_packets = 0
malicious_packets = 0
blocked_packets = 0
server_load = 0

TRAFFIC_HISTORY = []
ALERT_THRESHOLD = 10
last_alert_time = 0
COOLDOWN = 5
simulation_active = False
tcp_thread_started = False

app = Flask(__name__)

# ============== IDS CHECK ==============
def check_ids():
    global server_load, last_alert_time
    TRAFFIC_HISTORY.append(time.time())

    if len(TRAFFIC_HISTORY) > 100:
        TRAFFIC_HISTORY.pop(0)

    if len(TRAFFIC_HISTORY) >= ALERT_THRESHOLD:
        recent = TRAFFIC_HISTORY[-ALERT_THRESHOLD:]
        if time.time() - min(recent) < 1.0:
            now = time.time()
            if now - last_alert_time > COOLDOWN:
                last_alert_time = now
                print("[IDS] Traffic spike detected!")
                server_load += 1
                stats["load"] = server_load


# ============ FIREWALL ==============
def is_blocked(ip, port):
    BLOCKED_IPS = []
    BLOCKED_PORTS = [80, 443]
    return (ip in BLOCKED_IPS) or (port in BLOCKED_PORTS)

def record_blocked(ip, port, reason="Blocked by firewall", force=False):
    """Record a blocked packet so UI shows firewall activity."""
    global blocked_packets
    if not simulation_active and not force:
        return
    blocked_packets += 1
    stats["blocked"] = blocked_packets
    packet_types.append("blocked")
    PACKET_LOG.append({
        "ip": ip,
        "port": port,
        "timestamp": time.time(),
        "raw": f"FIREWALL BLOCK: {reason}"
    })
    check_ids()
    LOG.info("[FW] Blocked %s:%s (%s)", ip, port, reason)


# ============ HANDLE CLIENT ==============
def handle_client(client_socket, client_address):
    global normal_packets, malicious_packets, blocked_packets
    client_ip, client_port = client_address

    try:
        data = client_socket.recv(1024).decode("utf-8", errors="ignore")
    except:
        client_socket.close()
        return

    # firewall
    if is_blocked(client_ip, client_port):
        record_blocked(client_ip, client_port, "Inbound TCP blocked")
        print(f"[FW] Blocked {client_ip}:{client_port}")
        client_socket.close()
        return

    record_packet(client_ip, client_port, data)
    client_socket.close()

def record_packet(ip, port, data, force=False):
    """Update logs, stats, and IDS counters for a given packet payload."""
    global normal_packets, malicious_packets
    if not simulation_active and not force:
        return
    preview = (data or "(empty)")[:60].replace("\n", "\\n")
    print(f"[PKT] {ip}:{port} -> {preview}")
    LOG.info("[PKT] %s:%s -> %s", ip, port, preview)

    PACKET_LOG.append({
        "ip": ip,
        "port": port,
        "timestamp": time.time(),
        "raw": data
    })

    if data and ("scan" in data.lower() or "flood" in data.lower()):
        malicious_packets += 1
        packet_types.append("malicious")
        stats["malicious"] = malicious_packets
        print(f"[CLASSIFY] Malicious count: {malicious_packets}")
    else:
        normal_packets += 1
        packet_types.append("normal")
        stats["normal"] = normal_packets
        print(f"[CLASSIFY] Normal count: {normal_packets}")

    packet_times.append(time.time())
    check_ids()


# ============= TCP SERVER ==============
def tcp_server():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 12345))
    server.listen(5)
    print("TCP Defender running on 127.0.0.1:12345")

    while True:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True).start()


# =============== SIMULATED ATTACK ===============
def simulate_attack():
    global simulation_active
    print("[SIM] Port Scan starting...")
    attacker_ip = f"192.168.0.{random.randint(2,254)}"
    for port in range(1, 1025, 50):
        # Every 4th scan gets blocked to show firewall action
        if port % 200 == 1:
            record_blocked(attacker_ip, port, f"Port scan blocked on {port}")
        else:
            record_packet(attacker_ip, port, f"PORT SCAN ATTEMPT on port {port}")
        time.sleep(0.005)

    print("[SIM] Flood Attack starting...")
    start = time.time()
    while time.time() - start < 5:
        payload = "NORMAL PACKET" if random.random() < 0.2 else "FLOOD PACKET"
        dest_port = random.randint(1000, 65000)
        # Occasionally the firewall drops a flood packet
        if random.random() < 0.12:
            record_blocked(attacker_ip, dest_port, "Flood packet dropped")
        else:
            record_packet(attacker_ip, dest_port, payload)
        time.sleep(0.01)

    print("Attack simulation done.")
    simulation_active = False

def reset_state():
    global PACKET_LOG, packet_times, packet_types
    global stats, normal_packets, malicious_packets, blocked_packets, server_load, TRAFFIC_HISTORY, simulation_active
    PACKET_LOG.clear()
    packet_times.clear()
    packet_types.clear()
    stats = {"normal": 0, "malicious": 0, "blocked": 0, "load": 0}
    normal_packets = 0
    malicious_packets = 0
    blocked_packets = 0
    server_load = 0
    TRAFFIC_HISTORY = []
    simulation_active = False


def ensure_tcp_server():
    global tcp_thread_started
    if tcp_thread_started:
        return
    threading.Thread(target=tcp_server, daemon=True).start()
    tcp_thread_started = True


# =============== ROUTES ===============
@app.route("/")
def dashboard():
    fig = go.Figure()

    if packet_times:
        t = list(packet_times)
        types = list(packet_types)

        malicious_count = [types[:i].count("malicious") for i in range(len(types))]
        normal_count = [types[:i].count("normal") for i in range(len(types))]

        fig.add_trace(go.Scatter(x=t, y=malicious_count, mode="lines", name="Malicious", line=dict(color="red")))
        fig.add_trace(go.Scatter(x=t, y=normal_count, mode="lines", name="Normal", line=dict(color="green")))

    fig.update_layout(title="Live Traffic Monitor", xaxis_title="Time", yaxis_title="Packets")
    graph_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("index.html", graph_json=graph_json, stats=stats)


@app.route("/start_attack", methods=["POST"])
def start_attack_route():
    global simulation_active
    reset_state()
    simulation_active = True
    print("[HTTP] /start_attack triggered", flush=True)
    LOG.info("[HTTP] /start_attack triggered")
    threading.Thread(target=simulate_attack, daemon=True).start()
    return jsonify({"status": "Attack started!"})


def _port_from_url(url: str) -> int:
    parsed = urlparse(url)
    if parsed.port:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    return 80


@app.route("/scan_url", methods=["POST"])
def scan_url():
    """Fetch a URL and log the response as a packet."""
    global simulation_active
    body = request.get_json(silent=True) or {}
    target_url = (body.get("url") or "").strip()

    if not target_url:
        return jsonify({"error": "URL is required"}), 400

    try:
        simulation_active = True  # allow recording even if attack not running
        resp = requests.get(target_url, timeout=3)
        status = resp.status_code
        size = len(resp.content or b"")
        port = _port_from_url(target_url)
        payload = f"URL {target_url} response {status} | size {size}"
        record_packet("external-server", port, payload, force=True)
        print(f"[HTTP] /scan_url captured {target_url} code={status} size={size}", flush=True)
        LOG.info("[HTTP] /scan_url captured %s code=%s size=%s", target_url, status, size)
        return jsonify({"status": "captured", "code": status, "size": size})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
 


@app.route("/api/packets")
def api_packets():
    return jsonify(PACKET_LOG[-200:])   # last 200 packets Wireshark-style


@app.route("/api/stats")
def api_stats():
    return jsonify(stats)

@app.route("/api/reset", methods=["POST"])
def api_reset():
    reset_state()
    return jsonify({"status": "reset"})


# ================= MAIN =================
if __name__ == "__main__":

    class VerboseHandler(WSGIRequestHandler):
        def log(self, type, message, *args):
            try:
                formatted = message % args
            except TypeError:
                formatted = message
            method = getattr(self, "command", "?")
            path = getattr(self, "path", "?")
            print(f"[HTTP] {self.address_string()} {method} {path} -> {formatted}")

    reset_state()
    app.run(debug=True, port=5000, use_reloader=False, request_handler=VerboseHandler)
