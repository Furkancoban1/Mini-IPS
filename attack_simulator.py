import scapy.all as scapy
import time
import socket


# --- Setup Local IP ---
def get_local_ip():
    # Gets local IP address automatically
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


TARGET_IP = get_local_ip()


def print_info(title):
    # Prints formatted section headers
    print(f"\n[{title}]")
    print("-" * 50)


def attack_port_scan():
    # Simulates a basic port scan (Ports 20-40)
    attacker_ip = "YOUR_SPOOFED_IP_HERE"
    print_info("Test 1: Port Scan")
    print(f" -> Target IP: {TARGET_IP} | Source IP: {attacker_ip}")
    print(" -> Sending SYN packets to ports 40-60")

    for port in range(40, 60):
        pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src=attacker_ip, dst=TARGET_IP) / scapy.TCP(dport=port,
                                                                                                          flags="S")
        scapy.sendp(pkt, verbose=False)
        time.sleep(0.05)


def attack_sqli():
    # Simulates an application layer SQLi attack
    attacker_ip = "YOUR_SPOOFED_IP_HERE"
    print_info("Test 2: Application Layer Attack (SQLi)")
    print(f" -> Target IP: {TARGET_IP} | Source IP: {attacker_ip}")
    print(" -> Injecting malicious HTTP payload with 'UNION SELECT'...")

    payload = "GET /login.php?user=admin' UNION SELECT 1,2-- HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n"
    pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src=attacker_ip, dst=TARGET_IP) / scapy.TCP(dport=80,
                                                                                                      flags="PA") / scapy.Raw(
        load=payload)
    scapy.sendp(pkt, verbose=False)


def attack_honeypot():
    # Simulates triggering the Telnet honeypot
    attacker_ip = "YOUR_SPOOFED_IP_HERE"
    print_info("Test 3: Honeypot Trigger")
    print(f" -> Target IP: {TARGET_IP} | Source IP: {attacker_ip}")
    print(" -> Sending unauthorized connection request to Telnet (Port 23)...")

    pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src=attacker_ip, dst=TARGET_IP) / scapy.TCP(dport=23,
                                                                                                      flags="S")
    scapy.sendp(pkt, verbose=False)


def attack_syn_flood():
    # Simulates a volumetric SYN flood attack
    attacker_ip = "YOUR_SPOOFED_IP_HERE"
    print_info("Test 4: Volumetric Attack (SYN Flood)")
    print(f" -> Target IP: {TARGET_IP} | Source IP: {attacker_ip}")
    print(" -> Flooding target with 200 SYN packets...")

    pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src=attacker_ip, dst=TARGET_IP) / scapy.TCP(dport=80,
                                                                                                      flags="S")
    scapy.sendp(pkt, count=200, verbose=False)


def attack_slow_http():
    # Simulates a Slowloris / Slow HTTP attack
    attacker_ip = "YOUR_SPOOFED_IP_HERE"
    print_info("Test 5: Behavioral Attack (Slow HTTP)")
    print(f" -> Target IP: {TARGET_IP} | Source IP: {attacker_ip}")
    print(" -> Sending incomplete HTTP request and holding connection open for 11 seconds...")

    # 1. Send first incomplete chunk
    payload1 = "GET / HTTP/1.1\r\nHost: vulnerable.com\r\n"
    pkt1 = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src=attacker_ip, dst=TARGET_IP) / scapy.TCP(dport=80,
                                                                                                       flags="PA") / scapy.Raw(
        load=payload1)
    scapy.sendp(pkt1, verbose=False)

    # 2. Wait longer than the behavior_timeout (10 seconds)
    time.sleep(11)

    # 3. Send second chunk to trigger the evaluation
    payload2 = "X-Keep-Alive: true\r\n"
    pkt2 = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src=attacker_ip, dst=TARGET_IP) / scapy.TCP(dport=80,
                                                                                                       flags="PA") / scapy.Raw(
        load=payload2)
    scapy.sendp(pkt2, verbose=False)


if __name__ == "__main__":
    print("*" * 55)
    print("  Network Attack Simulator (Final Project)           ")
    print(f"  System IP Address: {TARGET_IP}                     ")
    print("*" * 55)
    time.sleep(2)

    attack_port_scan()
    time.sleep(3)

    attack_sqli()
    time.sleep(3)

    attack_honeypot()
    time.sleep(3)

    attack_syn_flood()
    time.sleep(3)

    attack_slow_http()

    print("\n" + "=" * 55)
    print("[+] Test scenario completed successfully.")
    print("[!] Please check the NIPS terminal to verify that")
    print("    all 5 IPs have been successfully blocked.")
    print("=" * 55)