from scapy.all import sniff, IP, TCP, Raw, ARP, ICMP
import sqlite3, requests, threading, time, re
from queue import Queue
import urllib.parse

from gui_dashboard import SIEMApp

packet_queue = Queue()
attackers = {}
syn_track = {}
arp_table = {}
icmp_track={}
bruteforce_track={}
exfil_track={}

LIMITA_SYN = 50

conexiune = sqlite3.connect("alerte.db", check_same_thread=False)
cursor = conexiune.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS istoric (ip TEXT, mesaj TEXT)")
cursor.execute("DELETE FROM istoric")
conexiune.commit()
print("[DB] Database successfully reset for the new session.")

def clean_payload(payload_brut):
    payload = urllib.parse.unquote(urllib.parse.unquote(payload_brut))
    # Remove multi-line comments /* */
    payload = re.sub(r'/\*.*?\*/', '', payload)
    # Remove single-line comments
    payload = re.sub(r'(--|#).*', '', payload)
    # Reduce multiple spaces to a single space
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
            print(f"[THREAT INTEL] IP {ip_atac} has a risk score of: {scor}%")
    except:
        pass

def detect_portscan(ip, port):
    if ip not in attackers:
        attackers[ip] = set()

    if port < 1024:
        attackers[ip].add(port)

    if len(attackers[ip]) == 4:
        print(f"[ALERT] IP {ip} is scanning ports: {attackers[ip]}")
        cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)", (ip, "Possible Port Scan"))
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
                print(f"[CRITICAL ALERT] DoS Attack (SYN Flood) detected from {ip}!")
                cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)", (ip, "DoS Attack (SYN Flood)"))
                conexiune.commit()

                syn_track[ip] = {"count": 0, "primul": timp_curent}
        else:
            syn_track[ip] = {"count": 1, "primul": timp_curent}

def detect_bruteforce(payload, ip_sursa):
    if "post" in payload and ("user" in payload or "username" in payload) and ("pass" in payload or "password" in payload):
        timp_curent = time.time()
        print(f"[DEBUG] WAF-ul a interceptat un pachet de login de la {ip_sursa}!")

        if ip_sursa not in bruteforce_track:
            bruteforce_track[ip_sursa] = {"count": 1, "primul": timp_curent}
        else:
            # Dacă l-am mai văzut, doar creștem count-ul
            bruteforce_track[ip_sursa]["count"] += 1

        timp_scurs = timp_curent - bruteforce_track[ip_sursa]["primul"]

        if timp_scurs <= 5.0:
            if bruteforce_track[ip_sursa]["count"] >= 5: # Am pus >= 5 ca să o dea mai repede
                print(f"[CRITICAL ALERT] HTTP Brute-Force detected from {ip_sursa}!")
                cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)",
                               (ip_sursa, "HTTP Brute-Force (Password Cracking)"))
                conexiune.commit()

                bruteforce_track[ip_sursa] = {"count": 0, "primul": timp_curent}
        else:
            bruteforce_track[ip_sursa] = {"count": 1, "primul": timp_curent}


def detect_exfiltration(pachet):
    if pachet.haslayer(IP):
        ipsrc = pachet[IP].src
        dimensiune = len(pachet)

        if ipsrc == "127.0.0.1" or ipsrc.startswith("192.168."):
            timp_curent = time.time()

            if ipsrc not in exfil_track:
                exfil_track[ipsrc] = {"total_bytes": dimensiune, "primul": timp_curent}
            else:
                exfil_track[ipsrc]["total_bytes"] += dimensiune

            timp_scurs = timp_curent - exfil_track[ipsrc]["primul"]

            if timp_scurs <= 3.0:
                if exfil_track[ipsrc]["total_bytes"] > 50000:
                    print(f"[CRITICAL ALERT] Data Exfiltration detected from {ipsrc}! ({exfil_track[ipsrc]['total_bytes']} bytes)")
                    cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)",
                                   (ipsrc, "Data Exfiltration (Volum Anormal)"))
                    conexiune.commit()

                    exfil_track[ipsrc] = {"total_bytes": 0, "primul": timp_curent}
            else:
                exfil_track[ipsrc] = {"total_bytes": dimensiune, "primul": timp_curent}

def detect_icmp_flood(pachet):
    if pachet.haslayer(ICMP) and pachet[ICMP].type==8:
        ipsrc=pachet[IP].src

        timp_curent=time.time()

        if ipsrc not in icmp_track:
            icmp_track[ipsrc] = {"count": 1, "primul": timp_curent}
        else:
            icmp_track[ipsrc]["count"] += 1

        timp_scurs = timp_curent - icmp_track[ipsrc]["primul"]

        if timp_scurs <= 1:
            if icmp_track[ipsrc]["count"] > LIMITA_SYN:
                print(f"[CRITICAL ALERT] ICMP Flood detected from {ipsrc}!")
                cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)", (ipsrc, "ICMP Flood"))
                conexiune.commit()

                icmp_track[ipsrc] = {"count": 0, "primul": timp_curent}
        else:
            icmp_track[ipsrc] = {"count": 1, "primul": timp_curent}

def detect_dpi(pachet, ip_sursa):
    from scapy.all import Raw

    if pachet.haslayer(Raw):
        payload_brut = pachet[Raw].load.decode('utf-8', errors='ignore').lower()
        payload = clean_payload(payload_brut)

        detect_bruteforce(payload, ip_sursa)

        caractere_logice = re.findall(r'[=\'\(\)\+\-\*/]', payload)
        nr_operatori = len(caractere_logice)
        are_logica_booleana = bool(re.search(r'\b(or|and)\b', payload))

        if are_logica_booleana and nr_operatori >= 3:
            print(f"[DPI ALERT] Anomaly/Structure Attack (Possible Advanced SQLi) from {ip_sursa}!")
            cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)",
                           (ip_sursa, "Structural SQL Injection (Evasion detected)"))
            conexiune.commit()
            return

        # Pattern: 2=2
        if re.search(r"(\d+)\s*=\s*\1", payload):
            print(f"[DPI ALERT] SQL Injection (Numeric Tautology) from {ip_sursa}!")
            cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)", (ip_sursa, "Regex SQLi (Ex: 2=2)"))
            conexiune.commit()
            return

        # Pattern: 'text'='text'
        if re.search(r"(['\"])(.*?)\1\s*=\s*\1\2\1", payload):
            print(f"[DPI ALERT] SQL Injection (Text Tautology) from {ip_sursa}!")
            cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)", (ip_sursa, "Regex SQLi (Ex: 'a'='a')"))
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
                    print(f"[DPI ALERT] {categorie} detected from {ip_sursa}. Signature: '{cuvant}'")
                    mesaj_db = f"{categorie} ({cuvant})"
                    cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)", (ip_sursa, mesaj_db))
                    conexiune.commit()
                    return

def detect_arp_spoof(pachet):
    if pachet.haslayer(ARP) and pachet[ARP].op == 2:
        ipsrc = pachet[ARP].psrc
        macsrc = pachet[ARP].hwsrc

        if ipsrc in arp_table:
            mac2 = arp_table[ipsrc]
            if mac2 != macsrc:
                mesaj_alerta = f"ARP Spoofing: {mac2} -> {macsrc}"
                print(f"[CRITICAL ALERT] Traffic intercepted! IP {ipsrc} changed its MAC address!")
                cursor.execute("INSERT INTO istoric (ip, mesaj) VALUES (?, ?)", (ipsrc, mesaj_alerta))
                conexiune.commit()
        else:
            arp_table[ipsrc] = macsrc

def process_packet(pachet):
    detect_arp_spoof(pachet)
    detect_icmp_flood(pachet)
    detect_exfiltration(pachet)

    if pachet.haslayer(IP) and pachet.haslayer(TCP):
        ip_sursa = pachet[IP].src
        port_dest = pachet[TCP].dport
        steaguri_tcp = pachet[TCP].flags

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
print("Analysis engine started in the background.")

def start_sniffer():
    print("Sniffer is active and scanning traffic...")
    sniff(iface="Software Loopback Interface 1", filter="tcp or arp or icmp", prn=lambda x: packet_queue.put(x), store=0)

thread_sniffer = threading.Thread(target=start_sniffer, daemon=True)
thread_sniffer.start()

if __name__ == "__main__":
    app = SIEMApp()
    app.mainloop()