from scapy.all import IP, ICMP, send
import time

ip_tinta = "127.0.0.1"

print("[*] Încărcăm tunul ICMP...")
print(f"[*] Lansăm un potop de 70 de pachete Ping către {ip_tinta} într-o fracțiune de secundă!")

pachet_ping = IP(dst=ip_tinta) / ICMP(type=8)

for i in range(70):
    send(pachet_ping, verbose=False)

print("[+] Atacul a fost livrat. Uită-te pe SIEM!")