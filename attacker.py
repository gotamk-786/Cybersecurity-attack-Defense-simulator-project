import socket
import time
import random  # For dynamic normal mix
from scapy.all import IP, TCP, send

SERVER_IP = '127.0.0.1'
SERVER_PORT = 12345

def port_scan():
    print("=== Phase 2: Starting Port Scan Attack ===")
    open_ports = []
    for port in range(1, 1025, 50):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.05)
            result = sock.connect_ex((SERVER_IP, port))
            if result == 0:
                open_ports.append(port)
                print(f"Port {port} appears open (vulnerable)!")
            sock.close()
        except:
            pass
    print(f"Scan complete. Open ports found: {open_ports}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_IP, SERVER_PORT))
        sock.send(b"PORT SCAN ATTACK")
        sock.close()
    except:
        pass
    return open_ports

def flood_attack(duration=5):
    print(f"=== Phase 2: Starting Flood Attack for {duration} seconds ===")
    start_time = time.time()
    packet_count = 0
    normal_count = 0
    while time.time() - start_time < duration:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((SERVER_IP, SERVER_PORT))
            if random.random() < 0.1:  # 10% normal mix for dynamic
                sock.send(b"NORMAL PACKET TEST")  # Random normal
                normal_count += 1
            else:
                sock.send(b"FLOOD ATTACK PACKET #" + str(packet_count).encode())
                packet_count += 1
            sock.close()
        except:
            pass
        time.sleep(0.01)
    print(f"Flood sent {packet_count} malicious + {normal_count} normal packets (dynamic mix).")

    print("Advanced Scapy Flood...")
    try:
        pkt = IP(dst=SERVER_IP)/TCP(dport=SERVER_PORT, flags='S')
        send(pkt, count=50, inter=0.02, verbose=0)
    except Exception as e:
        print(f"Scapy flood error: {e}")

if __name__ == "__main__":
    time.sleep(2)
    port_scan()
    time.sleep(1)
    flood_attack(5)
    print("All attacks complete. Check dashboard for dynamic traffic.")