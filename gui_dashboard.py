import customtkinter as ctk
import sqlite3
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class SIEMApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SOC Analytics")
        self.geometry("1400x850")

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Optimization counter
        self.total_alerte = 0

        # ==========================================
        # 1. SIDEBAR MENU
        # ==========================================
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)

        self.logo = ctk.CTkLabel(self.sidebar, text="🛡️ SIEM Menu", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo.grid(row=0, column=0, padx=20, pady=(30, 20))

        self.btn_dash = ctk.CTkButton(self.sidebar, text="Main Dashboard", fg_color="#1f538d")
        self.btn_dash.grid(row=1, column=0, padx=20, pady=10)

        self.btn_hunt = ctk.CTkButton(self.sidebar, text="Threat Hunting", fg_color="transparent", border_width=1,
                                      text_color=("gray10", "#DCE4EE"))
        self.btn_hunt.grid(row=2, column=0, padx=20, pady=10)

        self.btn_setari = ctk.CTkButton(self.sidebar, text="System Settings", fg_color="transparent")
        self.btn_setari.grid(row=6, column=0, padx=20, pady=(10, 20))

        # ==========================================
        # 2. MAIN VIEW (DASHBOARD)
        # ==========================================
        self.main_view = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_view.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

        self.main_view.grid_columnconfigure(0, weight=1)
        self.main_view.grid_rowconfigure(1, weight=2)
        self.main_view.grid_rowconfigure(2, weight=1)

        # --- A. KPI CARDS ---
        self.kpi_frame = ctk.CTkFrame(self.main_view, fg_color="transparent")
        self.kpi_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        self.kpi_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.lbl_total = self.create_kpi_card(self.kpi_frame, "Total Threats", "0", 0)
        self.lbl_critice = self.create_kpi_card(self.kpi_frame, "Critical Alerts (DoS/ARP)", "0", 1)
        self.lbl_ips = self.create_kpi_card(self.kpi_frame, "Unique IPs", "0", 2)

        # --- B. CHARTS AREA ---
        self.charts_frame = ctk.CTkFrame(self.main_view, fg_color="transparent")
        self.charts_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 20))
        self.charts_frame.grid_columnconfigure((0, 1), weight=1)
        self.charts_frame.grid_rowconfigure(0, weight=1)

        self.pie_frame = ctk.CTkFrame(self.charts_frame)
        self.pie_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        self.draw_initial_chart(self.pie_frame)

        self.trend_frame = ctk.CTkFrame(self.charts_frame)
        self.trend_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        ctk.CTkLabel(self.trend_frame, text="[ Trend Line Chart will be placed here ]", text_color="gray").pack(
            expand=True)

        # --- C. TERMINAL / LOGS ---
        self.logs_frame = ctk.CTkFrame(self.main_view)
        self.logs_frame.grid(row=2, column=0, sticky="nsew")
        self.logs_frame.grid_columnconfigure(0, weight=1)
        self.logs_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(self.logs_frame, text="Live Threat Feed", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0,
                                                                                                     sticky="w",
                                                                                                     padx=15,
                                                                                                     pady=(10, 0))

        self.terminal = ctk.CTkTextbox(self.logs_frame, font=("Consolas", 13), fg_color="#0d1117", text_color="#00ff41")
        self.terminal.grid(row=1, column=0, sticky="nsew", padx=15, pady=(5, 15))

        self.live_update()

    def create_kpi_card(self, parent, title, value, column):
        """Draws a KPI card and returns the value label for dynamic updates"""
        card = ctk.CTkFrame(parent)
        card.grid(row=0, column=column, sticky="ew", padx=10)

        lbl_title = ctk.CTkLabel(card, text=title, font=("Roboto", 14), text_color="gray")
        lbl_title.pack(pady=(15, 0))

        lbl_value = ctk.CTkLabel(card, text=value, font=("Roboto", 36, "bold"))
        lbl_value.pack(pady=(0, 15))

        return lbl_value

    def draw_initial_chart(self, parent):
        """Configures the Matplotlib canvas for Dark Mode"""
        self.fig = Figure(figsize=(4, 3), dpi=100)
        self.fig.patch.set_facecolor('#2b2b2b')

        self.ax = self.fig.add_subplot(111)
        self.ax.pie([1], labels=['Clean Traffic'], colors=['#4a4a4a'], textprops={'color': "w"})
        self.ax.set_title("Attack Distribution", color="white")

        self.canvas = FigureCanvasTkAgg(self.fig, master=parent)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(expand=True, fill="both", padx=10, pady=10)

    def refresh_pie_chart(self, c_dos, c_scan, c_sqli, c_arp, c_icmp, c_exfil, c_brute):
        """Redraws the pie chart slices with real data"""
        self.ax.clear()

        raw_labels = ['DoS (SYN Flood)', 'Port Scan', 'SQL Injection', 'ARP Spoofing', 'ICMP Flood', 'Data Exfiltration', 'HTTP Brute-Force']
        raw_sizes = [c_dos, c_scan, c_sqli, c_arp, c_icmp, c_exfil, c_brute]
        raw_colors = [
            '#ef233c',  # Roșu aprins de alertă
            '#ffbe0b',  # Galben-Portocaliu saturat
            '#fb5607',  # Portocaliu de foc
            '#f193ec',  # Magenta intens
            '#8338ec',  # Violet electric (nu neon)
            '#5793ec',  # Albastru mediteranean
            '#06d6a0'  # Turcoaz aprins
        ]

        final_labels = []
        final_sizes = []
        final_colors = []

        for i in range(len(raw_sizes)):
            if raw_sizes[i] > 0:
                final_labels.append(raw_labels[i])
                final_sizes.append(raw_sizes[i])
                final_colors.append(raw_colors[i])

        if len(final_sizes) == 0:
            self.ax.pie([1], labels=['Clean Traffic'], colors=['#4a4a4a'], textprops={'color': "w"})
        else:
            self.ax.pie(final_sizes, labels=final_labels, colors=final_colors, autopct='%1.1f%%', startangle=90,
                        textprops={'color': "w", 'weight': 'bold', 'fontsize': 10})

        self.ax.set_title("Attack Distribution", color="white")
        self.canvas.draw()

    def live_update(self):
        try:
            conn = sqlite3.connect("alerte.db")
            cursor = conn.cursor()

            # --- 1. Terminal Logs ---
            cursor.execute("SELECT rowid, ip, mesaj FROM istoric ORDER BY rowid DESC LIMIT 15")
            alerte = cursor.fetchall()

            self.terminal.delete("0.0", "end")
            if not alerte:
                self.terminal.insert("end", "[INFO] System active. No threats detected yet...\n")
            else:
                for alerta in alerte:
                    # Formatted the output to English
                    self.terminal.insert("end", f"[{alerta[0]}] 🔴 ALERT: IP: {alerta[1]} | Reason: {alerta[2]}\n")

            # --- 2. Update KPI and Chart (only if new data exists) ---
            cursor.execute("SELECT COUNT(*) FROM istoric")
            numar_curent_alerte = cursor.fetchone()[0]

            if numar_curent_alerte > self.total_alerte:
                self.total_alerte = numar_curent_alerte

                # A. Update KPI Numbers
                self.lbl_total.configure(text=str(numar_curent_alerte))

                cursor.execute("SELECT COUNT(DISTINCT ip) FROM istoric")
                ip_unice = cursor.fetchone()[0]
                self.lbl_ips.configure(text=str(ip_unice))

                cursor.execute("SELECT COUNT(*) FROM istoric WHERE mesaj LIKE '%DoS%' OR mesaj LIKE '%ARP%'")
                critice = cursor.fetchone()[0]
                self.lbl_critice.configure(text=str(critice))

                # B. Update Chart
                cursor.execute("SELECT mesaj FROM istoric")
                mesaje = cursor.fetchall()
                c_dos, c_scan, c_sqli, c_arp, c_brute, c_exfil, c_icmp = 0, 0, 0, 0, 0, 0, 0

                for m in mesaje:
                    text_mesaj = m[0]
                    if "DoS" in text_mesaj:
                        c_dos += 1
                    elif "Scan" in text_mesaj:
                        c_scan += 1
                    elif "SQL" in text_mesaj:
                        c_sqli += 1
                    elif "ARP" in text_mesaj:
                        c_arp += 1
                    elif "Brute" in text_mesaj:
                        c_brute += 1
                    elif "ICMP" in text_mesaj:
                        c_icmp += 1
                    elif "Exfil" in text_mesaj:
                        c_exfil += 1



                self.refresh_pie_chart(c_dos, c_scan, c_sqli, c_arp, c_icmp, c_exfil, c_brute)

            conn.close()
        except Exception as e:
            pass

        self.after(1000, self.live_update)


if __name__ == "__main__":
    app = SIEMApp()
    app.mainloop()