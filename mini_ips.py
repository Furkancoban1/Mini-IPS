import scapy.all as scapy
import time
import logging
import subprocess
import ctypes
from collections import defaultdict
import json
import sqlite3
import threading
import os
import socket

# --- Setup Local IP ---
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()

# --- Dynamic Parameters (Replaces static variables) ---
CONFIG_FILE = "config.json"
cfg = {
    "syn_threshold": 150, "time_limit": 1, "port_threshold": 15,
    "port_window": 5, "honeypot": 23, "behavior_timeout": 10, "ban_duration": 300
}

def config_watcher():
    # Arkada sürekli config dosyasını kontrol eder
    global cfg
    while True:
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r") as f:
                    cfg.update(json.load(f))
        except Exception:
            pass
        time.sleep(2)

# Watcher thread'i başlat
threading.Thread(target=config_watcher, daemon=True).start()

# --- Signatures & Whitelist ---
DPI_SIGNATURES = [
    "unionselect", "or1=1", "etc/passwd", "<script>", "cmd.exe"
]

blocked_ips = set()
whitelist = (LOCAL_IP, "127.0.0.1")

# --- Trackers ---
packet_history = defaultdict(list)
port_history = defaultdict(list)
http_tracker = defaultdict(lambda: {"start_time": 0, "data": ""})

# --- Logging & Database ---
logging.basicConfig(filename="ips_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

db_lock = threading.Lock()
conn = sqlite3.connect("ips_logs.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    ip TEXT, attack TEXT, action TEXT, timestamp REAL
)
""")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_attack ON logs(attack)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_action ON logs(action)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip ON logs(ip)")
conn.commit()

last_commit_time = time.time()

def log_event(ip, attack, action):
    global last_commit_time
    current_time = time.time()

    log_data = {"ip": ip, "attack": attack, "action": action, "timestamp": current_time}
    try:
        with open("ips_log.json", "a") as f:
            f.write(json.dumps(log_data) + "\n")
    except Exception:
        pass

    with db_lock:
        try:
            cursor.execute("INSERT INTO logs VALUES (?, ?, ?, ?)", (ip, attack, action, current_time))
            if current_time - last_commit_time > 5:
                conn.commit()
                last_commit_time = current_time
        except Exception:
            pass

def _show_popup(title, msg):
    try:
        ctypes.windll.user32.MessageBoxW(0, msg, title, 0x30)
    except:
        pass

def give_alert(title, msg):
    t = threading.Thread(target=_show_popup, args=(title, msg))
    t.daemon = True
    t.start()

def is_whitelisted(ip):
    return ip.startswith(whitelist)

def unblock_ip(ip):
    cmd = f'netsh advfirewall firewall delete rule name="IPS_Block_{ip}"'
    subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if ip in blocked_ips:
        blocked_ips.remove(ip)
        print(f"\n[UNBLOCK] {ip} removed (Timeout).")
        log_event(ip, "TIMEOUT", "UNBLOCK")

def block_ip(ip, attack_name):
    if ip in blocked_ips:
        return

    print(f"\n[BLOCK] Blocking {ip} for {attack_name}.")
    subprocess.run(f'netsh advfirewall firewall delete rule name="IPS_Block_{ip}"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cmd = f'netsh advfirewall firewall add rule name="IPS_Block_{ip}" dir=in action=block remoteip={ip}'

    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        blocked_ips.add(ip)
        logging.info(f"Blocked: {ip} due to {attack_name}")
        log_event(ip, attack_name, "BLOCK")

        print(f"[FIREWALL] Rule added for {ip}.")
        give_alert("IPS Alert", f"Blocked {ip} ({attack_name})")

        # Dinamik ban_duration kullanımı
        timer_thread = threading.Timer(cfg["ban_duration"], unblock_ip, args=[ip])
        timer_thread.daemon = True
        timer_thread.start()

    except subprocess.CalledProcessError:
        print(f"[ERROR] Could not block {ip}.")

def process_packet(packet):
    try:
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            current_time = time.time()

            if is_whitelisted(src_ip):
                return

            # 1. DPI Engine
            if packet.haslayer(scapy.Raw):
                try:
                    raw_payload = packet[scapy.Raw].load.decode(errors='ignore').lower()
                    normalized_payload = raw_payload.replace(" ", "").replace("/**/", "")

                    for signature in DPI_SIGNATURES:
                        if signature in normalized_payload and src_ip not in blocked_ips:
                            print(f"\n[ALERT] DPI: Malicious payload from {src_ip}")
                            logging.info(f"DPI alert from {src_ip}")
                            block_ip(src_ip, "DPI")
                            return

                    # 2. Behavioral Analysis
                    if packet.haslayer(scapy.TCP):
                        dport = packet[scapy.TCP].dport
                        if dport == 80 or dport == 443:
                            if http_tracker[src_ip]["start_time"] == 0:
                                http_tracker[src_ip]["start_time"] = current_time

                            http_tracker[src_ip]["data"] += raw_payload

                            if len(http_tracker[src_ip]["data"]) > 4096:
                                http_tracker[src_ip] = {"start_time": 0, "data": ""}

                            if "\r\n\r\n" in http_tracker[src_ip]["data"]:
                                http_tracker[src_ip] = {"start_time": 0, "data": ""}
                            else:
                                # Dinamik behavior_timeout kullanımı
                                if current_time - http_tracker[src_ip]["start_time"] > cfg["behavior_timeout"]:
                                    if src_ip not in blocked_ips:
                                        print(f"\n[ALERT] BEHAVIOR: Slow HTTP from {src_ip}")
                                        logging.info(f"Behavioral alert from {src_ip}")
                                        block_ip(src_ip, "BEHAVIOR")
                                        return
                except Exception:
                    pass

            if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
                dport = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].dport

                # 3. Honeypot (Dinamik port kullanımı)
                if dport == cfg["honeypot"] and src_ip not in blocked_ips:
                    print(f"\n[ALERT] HONEYPOT: Triggered by {src_ip}")
                    logging.info(f"Honeypot trigger from {src_ip}")
                    block_ip(src_ip, "HONEYPOT")
                    return

                # 4. Port Scan (Dinamik window ve threshold kullanımı)
                port_history[src_ip] = [(p, t) for (p, t) in port_history[src_ip] if current_time - t <= cfg["port_window"]]
                port_history[src_ip].append((dport, current_time))
                unique_ports = set([p for (p, t) in port_history[src_ip]])

                if len(unique_ports) > cfg["port_threshold"] and src_ip not in blocked_ips:
                    print(f"\n[ALERT] PORT SCAN: Detected from {src_ip}")
                    logging.info(f"Port scan from {src_ip}")
                    block_ip(src_ip, "PORT_SCAN")
                    return

            # 5. SYN Flood (Dinamik window ve threshold kullanımı)
            if packet.haslayer(scapy.TCP) and (int(packet[scapy.TCP].flags) & 0x02):
                packet_history[src_ip] = [t for t in packet_history[src_ip] if current_time - t <= cfg["time_limit"]]
                packet_history[src_ip].append(current_time)

                if len(packet_history[src_ip]) > cfg["syn_threshold"] and src_ip not in blocked_ips:
                    print(f"\n[ALERT] SYN FLOOD: Detected from {src_ip}")
                    block_ip(src_ip, "SYN_FLOOD")
    except Exception:
        pass

def start_sniffing():
    print("=" * 60)
    print(" [Mini-IPS Active] Strict Rule-Based Engine")
    print(f" Protected IP: {LOCAL_IP}")
    print(" (Engine automatically syncing with config.json...)")
    print("=" * 60)
    scapy.sniff(store=False, prn=process_packet)

if __name__ == "__main__":
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print("\n\n[!] Shutting down Mini-IPS safely...")
        try:
            conn.commit()
            conn.close()
        except:
            pass
        os._exit(0)