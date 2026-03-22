import socket
import time

tinta = "127.0.0.1"
port_tinta = 80

print(f"[*] Lansăm testul de stres (Arsenal Evaziune SQLi) către {tinta}...")

# Aici este "mizeria" - payload-uri obfuscate menite să testeze TOATE filtrele SIEM-ului tău
payloads_atac = [
    # 1. Tautologie text -> Ar trebui prinsă de filtrul REGEX 2
    "GET /login?user='hacker'='hacker' HTTP/1.1\r\n",

    # 2. Tautologie numerică -> Ar trebui prinsă de filtrul REGEX 1
    "POST /api/data HTTP/1.1\r\n\r\nuser_id=99=99",

    # 3. Injecție Matematică -> Ar trebui prinsă de HEURISTICA STRUCTURALĂ
    "GET /?search=admin' OR 1920+2=1922; HTTP/1.1\r\n",

    # 4. Obfuscare cu comentarii SQL -> Ar trebui CURĂȚATĂ de normalizator și prinsă de SEMNĂTURI
    "GET /?query=U/**/N/**/I/**/O/**/N%20S/**/E/**/L/**/E/**/C/**/T HTTP/1.1\r\n",

    # 5. Double URL Encoding (un 'OR 1=1' ascuns adânc) -> Ar trebui CURĂȚAT și prins
    "POST /form HTTP/1.1\r\n\r\nuser=admin%2520%254F%2552%2520%2531%253D%2531"
]

for payload in payloads_atac:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((tinta, port_tinta))

        s.send(payload.encode())
        s.close()

        print(f" -> Am trimis:: {payload.strip()}")
    except:
        print(" -> [!] Eroare la conexiune (dar pachetul e pe rețea)")

    time.sleep(1.5)

print("[+] Baraj de artilerie finalizat! Verifică alertele din SIEM!")