import socket
import threading
import time
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from collections import deque
import tkinter as tk
from tkinter import ttk
from scapy.all import IP, TCP, send  # For packet handling

# Firewall rules
BLOCKED_IPS = []  # Empty for demo
BLOCKED_PORTS = [80, 443]

# IDS
TRAFFIC_HISTORY = []  # List for safe
ALERT_THRESHOLD = 10

# Stats
normal_packets = 0
malicious_packets = 0
blocked_packets = 0
server_load = 0

# Viz data (deque for recent)
packet_times = deque(maxlen=100)  # More for line plot
packet_types = deque(maxlen=100)

# Log counter for less spam
log_counter = 0

# Tkinter GUI (same, but add summary button optional)
def create_gui():
    root = tk.Tk()
    root.title("Cybersecurity Dashboard")
    root.geometry("400x300")

    ttk.Label(root, text="Normal Packets:").pack()
    normal_label = ttk.Label(root, text=0)
    normal_label.pack()

    ttk.Label(root, text="Malicious Packets:").pack()
    malicious_label = ttk.Label(root, text=0)
    malicious_label.pack()

    ttk.Label(root, text="Blocked Packets:").pack()
    blocked_label = ttk.Label(root, text=0)
    blocked_label.pack()

    ttk.Label(root, text="Server Load:").pack()
    load_label = ttk.Label(root, text=0)
    load_label.pack()

    def update_gui():
        normal_label.config(text=normal_packets)
        malicious_label.config(text=malicious_packets)
        blocked_label.config(text=blocked_packets)
        load_label.config(text=server_load)
        root.after(1000, update_gui)

    update_gui()
    return root

# IDS Check (rate-based)
def check_ids():
    global server_load
    TRAFFIC_HISTORY.append(time.time())
    if len(TRAFFIC_HISTORY) > 100:
        TRAFFIC_HISTORY.pop(0)
    if len(TRAFFIC_HISTORY) >= ALERT_THRESHOLD:
        recent = TRAFFIC_HISTORY[-ALERT_THRESHOLD:]
        if time.time() - min(recent) < 1.0:
            print("IDS ALERT: Traffic spike detected! Possible flood attack.")
            server_load += 1

# Firewall
def is_blocked(client_ip, port):
    if client_ip in BLOCKED_IPS or port in BLOCKED_PORTS:
        return True
    return False

# Handle client (less logs)
def handle_client(client_socket, client_address):
    global normal_packets, malicious_packets, blocked_packets, log_counter
    client_ip, client_port = client_address
    print(f"Connection from {client_ip}:{client_port}")

    if is_blocked(client_ip, client_port):
        print(f"FIREWALL: Blocked connection from {client_ip}:{client_port}")
        blocked_packets += 1
        client_socket.close()
        return

    try:
        data = client_socket.recv(1024).decode('utf-8', errors='ignore')
        if data:
            log_counter += 1
            if log_counter % 10 == 0:  # Log every 10th
                print(f"Received (sample #{log_counter}): {data[:50]}...")  # Short
            if 'scan' in data.lower() or 'flood' in data.lower():
                malicious_packets += 1
                packet_types.append('malicious')
                if log_counter % 10 == 0:
                    print("Detected: Malicious packet (Attack)!")
            else:
                normal_packets += 1
                packet_types.append('normal')
                if log_counter % 10 == 0:
                    print("Detected: Normal packet.")
            check_ids()
            packet_times.append(time.time())
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

# Server
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 12345))
    server.listen(5)
    print("Server listening on 127.0.0.1:12345... (Defender Active)")

    root = create_gui()
    root.update()

    while True:
        try:
            client_socket, client_address = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
        except Exception as e:
            print(f"Server error: {e}")

# Viz (Dynamic Line Plot: Cumulative rate, green/normal red/malicious)
fig, ax = plt.subplots()
def animate(frame):
    ax.clear()
    if packet_times:
        times_list = list(packet_times)
        num_points = len(times_list)
        recent_types = list(packet_types)[-num_points:]
        # Cumulative count for line
        malicious_cum = [recent_types[:i+1].count('malicious') for i in range(num_points)]
        normal_cum = [recent_types[:i+1].count('normal') for i in range(num_points)]
        ax.plot(times_list, malicious_cum, 'r-', label='Malicious (Red)', linewidth=2)
        ax.plot(times_list, normal_cum, 'g-', label='Normal (Green)', linewidth=2)
        ax.set_title("Network Traffic Monitor (Line Plot: Cumulative Packets)")
        ax.set_xlabel("Time (Recent)")
        ax.set_ylabel("Cumulative Packets")
        ax.legend()
        plt.tight_layout()

ani = FuncAnimation(fig, animate, interval=500, cache_frame_data=False)  # Faster update

if __name__ == "__main__":
    server_thread = threading.Thread(target=start_server)
    server_thread.start()
    time.sleep(1)
    plt.show()
    