import socket
import time

tinta = "127.0.0.1"
porturi_vizate = [21, 22, 23, 80, 443]

print(f"[*] Inițiem scanarea porturilor pe IP-ul: {tinta}")

for port in porturi_vizate:
    try:
        print(f" -> Trimit pachet TCP către portul {port}...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        s.connect((tinta, port))
        s.close()
    except:
        pass
    time.sleep(0.5)

print("[+] Atac simulat finalizat!")