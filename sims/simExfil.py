import socket
import time

tinta = "127.0.0.1"
port_tinta = 9090

print("[*] Începem exfiltrarea de date (Descărcare bază de date clienți)...")

bagaj_greu = b"X" * 10000

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((tinta, port_tinta))

    for i in range(1, 7):
        s.send(bagaj_greu)
        print(f" -> Pachetul {i} trimis (10 KB)")
        time.sleep(0.1)

    s.close()
    print("[+] Datele au părăsit rețeaua. Uită-te pe SIEM!")
except Exception as e:
    print(f"[!] Eroare la conectare: Ai uitat să pornești 'python -m http.server 9090' într-un terminal? Detalii: {e}")