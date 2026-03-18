from scapy.all import sniff, IP, TCP, Raw
import sqlite3, requests, threading, time, re
from queue import Queue
import urllib.parse

# Importăm interfața grafică
from gui_dashboard import SIEMApp

packet_queue = Queue()
attackers = {}
syn_track = {}
LIMITA_SYN = 50


conexiune = sqlite3.connect("alerte.db", check_same_thread=False)
cursor = conexiune.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS istoric (ip TEXT, mesaj TEXT)")
cursor.execute("DELETE FROM istoric")
conexiune.commit()
print("[DB] Baza de date a fost resetată cu succes pentru o nouă sesiune.")


def clean_payload(payload_brut):
    payload=urllib.parse.unquote(urllib.parse.unquote(payload_brut))
    #sterg comentariile pe mai multe linii /* */
    payload = re.sub(r'/\*.*?\*/', '', payload)
    #sterg comentariile pe o linie
    payload = re.sub(r'(--|#).*', '', payload)
    #scot din spatii sa am doar unul ' ' nu '       '
    payload = re.sub(r'\s+', ' ', payload)

    return payload.strip().lower()

def verify_rep(ip_atac):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': 'b475e1445b9e4e241acc3c01349aac43fbed8aa69cede7d90e26ee8c73d749be6625c35024861ed6'
    }
    parametri = {'ipAddress': ip_atac, 'maxAgeInDays': '90'}

    try:
        raspuns = requests.get(url, headers=headers, params=parametri, timeout=5)
        if raspuns.status_code == 200:
            date = raspuns.json()
            scor = date['data']['abuseConfidenceScore']
            print(f"[THREAT INTEL] IP-ul {ip_atac} are scorul de risc: {scor}%")
    except:
        pass


def detect_portscan(ip, port):
    if ip not in attackers:
        attackers[ip] = set()

    if port < 1024:
        attackers[ip].add(port)

    if len(attackers[ip]) == 4:
        print(f"[ALERTA] IP-ul {ip} scaneaza porturile: {attackers[ip]}")
        cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)", (ip, "Posibil Port Scan"))
        conexiune.commit()

        attackers[ip].clear()

        if not ip.startswith("192.168.") and not ip.startswith("127.0.0."):
            verify_rep(ip)


def detect_dos(ip, flags):

    if flags == 'S':
        timp_curent = time.time()

        if ip not in syn_track:
            syn_track[ip] = {"count": 1, "primul": timp_curent}
        else:
            syn_track[ip]["count"] += 1

        timp_scurs = timp_curent - syn_track[ip]["primul"]

        if timp_scurs <= 1:
            if syn_track[ip]["count"] > LIMITA_SYN:
                print(f"[ALERTA CRITICA] Atac DoS (SYN Flood) detectat de la {ip}!")
                cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)", (ip, "Atac DoS (SYN Flood)"))
                conexiune.commit()

                syn_track[ip] = {"count": 0, "primul": timp_curent}
        else:
            syn_track[ip] = {"count": 1, "primul": timp_curent}


def detect_dpi(pachet, ip_sursa):
    from scapy.all import Raw

    if pachet.haslayer(Raw):
        payload_brut = pachet[Raw].load.decode('utf-8', errors='ignore').lower()
        payload=clean_payload(payload_brut)

        caractere_logice = re.findall(r'[=\'\(\)\+\-\*/]', payload)
        nr_operatori=len(caractere_logice)
        are_logica_booleana = bool(re.search(r'\b(or|and)\b', payload))

        if are_logica_booleana and nr_operatori >= 3:
            print(f"[ALERTA DPI] Anomaly/Structure Attack (Posibil SQLi Avansat) de la {ip_sursa}!")
            cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)",
                           (ip_sursa, "SQL Injection Structural (Evaziune detectată)"))
            conexiune.commit()
            return

        # tipar: 2=2
        if re.search(r"(\d+)\s*=\s*\1", payload):
            print(f"[ALERTA DPI] SQL Injection (Tautologie Numerică) de la {ip_sursa}!")
            cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)", (ip_sursa, "SQLi Regex (Ex: 2=2)"))
            conexiune.commit()
            return

        # tipar: 'text'='text'
        if re.search(r"(['\"])(.*?)\1\s*=\s*\1\2\1", payload):
            print(f"[ALERTA DPI] SQL Injection (Tautologie Text) de la {ip_sursa}!")
            cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)", (ip_sursa, "SQL Injection Regex (Ex: 'a'='a')"))
            conexiune.commit()
            return

        baza_semnaturi = {
            "SQL Injection": ["drop table", "union select", "xp_cmdshell"],
            "Cross-Site Scripting (XSS)": ["<script>", "javascript:", "onerror="],
            "Directory Traversal": ["../../../", "/etc/passwd", "boot.ini"],
            "Command Injection": ["wget ", "curl ", "bash -i", "powershell -enc"]
        }

        for categorie, lista_cuvinte in baza_semnaturi.items():
            for cuvant in lista_cuvinte:
                if cuvant in payload:
                    print(f"[ALERTA DPI] {categorie} detectat de la {ip_sursa}. Semnătură: '{cuvant}'")
                    mesaj_db = f"{categorie} ({cuvant})"
                    cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)", (ip_sursa, mesaj_db))
                    conexiune.commit()
                    return

def process_packet(pachet):
    if pachet.haslayer(IP) and pachet.haslayer(TCP):
        ip_sursa = pachet[IP].src
        port_dest = pachet[TCP].dport
        steaguri_tcp = pachet[TCP].flags

        #verific pachetul de mai multe chestii
        detect_portscan(ip_sursa, port_dest)
        detect_dos(ip_sursa, steaguri_tcp)
        detect_dpi(pachet, ip_sursa)

def worker():
    while True:
        pachet = packet_queue.get()
        process_packet(pachet)
        packet_queue.task_done()

thread_analiza = threading.Thread(target=worker, daemon=True)
thread_analiza.start()
print("Motorul de analiza a pornit in fundal.")

def start_sniffer():
    print("Sniffer-ul e activ si scaneaza traficul...")
    sniff(iface="Software Loopback Interface 1", filter="tcp", prn=lambda x: packet_queue.put(x), store=0)

thread_sniffer = threading.Thread(target=start_sniffer, daemon=True)
thread_sniffer.start()

# pornesc intefata
if __name__ == "__main__":
    app = SIEMApp()
    app.mainloop()