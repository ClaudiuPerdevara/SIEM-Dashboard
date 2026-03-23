from scapy.all import IP, TCP, send
import time


def simulate_ssh_bruteforce():
    print("🚀 Începem simularea atacului SSH Brute-Force (Layer 4)...")

    target_ip = "127.0.0.1"
    target_port = 22  # Portul standard pentru SSH

    print(f"[*] Trimitem cereri rapide de conectare (SYN) către {target_ip}:{target_port}")
    print("[*] Radarul va declanșa alerta la a 5-a încercare în mai puțin de 10 secunde.\n")

    # Trimitem 7 pachete pentru a forța pragul de alertă
    for i in range(1, 8):
        pkt = IP(dst=target_ip) / TCP(dport=target_port, flags='S')
        send(pkt, verbose=False)
        print(f" -> Încercarea de login #{i} (Pachet SYN trimis)")
        time.sleep(0.5)  # Trage ca o mitralieră la jumătate de secundă

    print("\n✅ Atac finalizat! Verifică dashboard-ul SIEM pentru alerta 'SSH Brute-Force (Port 22)'.")


if __name__ == "__main__":
    simulate_ssh_bruteforce()