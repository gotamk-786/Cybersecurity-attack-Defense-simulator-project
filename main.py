import subprocess
import threading
import time
import os

print("=== Cybersecurity Attack & Defense Simulator Starting ===")
print("Based on Proposal: Phases 1-4 (Networking, Attacks, Defense, Visualization)")

# Start server in background
def start_server():
    subprocess.Popen(['python', 'server.py'], cwd=os.getcwd())

# Start attacker after delay
def start_attacker():
    time.sleep(3)  # Let server boot
    subprocess.Popen(['python', 'attacker.py'], cwd=os.getcwd())

if __name__ == "__main__":
    server_process = threading.Thread(target=start_server)
    server_process.start()
    attacker_process = threading.Thread(target=start_attacker)
    attacker_process.start()
    print("Server & Attacks running. Watch:")
    print("- Terminal: Logs, IDS Alerts, Firewall Blocks")
    print("- GUI Window: Tkinter Dashboard (Stats)")
    print("- Graph Window: Matplotlib (Green=Normal, Red=Malicious)")
    print("- Tools: Socket (Networking), Scapy (Packets), Matplotlib (Viz)")
    print("Press Ctrl+C to stop. For Wireshark: Run separately to capture localhost:8080.")
    try:
        server_process.join()
    except KeyboardInterrupt:
        print("\nSimulator stopped.")