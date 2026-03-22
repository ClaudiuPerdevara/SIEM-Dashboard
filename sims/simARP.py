from scapy.all import Ether, ARP, sendp
import time

ip_tinta = "192.168.1.1"
mac_real = "00:11:22:33:44:55"
mac_hacker = "aa:bb:cc:dd:ee:ff"

# Numele interfeței trebuie să fie EXACT același pe care ascultă sniffer-ul tău
interfata_test = "Software Loopback Interface 1"

print("[*] 1. Trimitem MAC-ul legitim...")
# TRUCUL AICI: Îmbrăcăm ARP-ul într-un pachet de rețea fizică (Ether) și folosim sendp() în loc de send()
pachet_bun = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst="127.0.0.1", psrc=ip_tinta, hwsrc=mac_real)
sendp(pachet_bun, iface=interfata_test, verbose=False)

time.sleep(2)

print("[*] 2. Lansam atacul de interceptare (Spoofing)...")
pachet_otravit = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst="127.0.0.1", psrc=ip_tinta, hwsrc=mac_hacker)
sendp(pachet_otravit, iface=interfata_test, verbose=False)

print("[+] Atacul a fost fortat pe retea!")