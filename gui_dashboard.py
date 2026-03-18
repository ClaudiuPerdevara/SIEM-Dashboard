import customtkinter as ctk
import sqlite3
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class SIEMApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SIEM Analytics Dashboard")
        self.geometry("1100x700")  # Fereastră mai mare pentru grafice


        ctk.set_appearance_mode("light")

        # --- CONFIGURAREA GRID-ULUI (Tabelul invizibil) ---
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=0)  # Rândul de titlu
        self.grid_rowconfigure(1, weight=1)  # Rândul cu grafice
        self.grid_rowconfigure(2, weight=1)  # Rândul cu log-uri

        # --- TITLUL ---
        self.label_titlu = ctk.CTkLabel(self, text="Monitoring & Performance", font=("Roboto", 28, "bold"))
        self.label_titlu.grid(row=0, column=0, columnspan=2, pady=20, sticky="w", padx=20)

        # --- ZONA DE GRAFICE (Rândul 1) ---
        # Creăm un Frame (o cutie) pentru primul grafic
        self.frame_grafic = ctk.CTkFrame(self)
        self.frame_grafic.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")
        self.deseneaza_grafic_test(self.frame_grafic)

        self.frame_statistici = ctk.CTkFrame(self)
        self.frame_statistici.grid(row=1, column=1, padx=20, pady=10, sticky="nsew")
        self.label_statistici = ctk.CTkLabel(self.frame_statistici,
                                             text="și alte metrici",
                                             font=("Roboto", 16))
        self.label_statistici.pack(expand=True)

        # --- ZONA DE LOG-URI (Rândul 2) ---
        self.textbox = ctk.CTkTextbox(self, font=("Consolas", 12), fg_color="#1E1E1E", text_color="#00FF00")
        self.textbox.grid(row=2, column=0, columnspan=2, padx=20, pady=20, sticky="nsew")

        # Pornim actualizarea
        self.actualizare_live()

    def deseneaza_grafic_test(self, parinte):
        """Desenează un grafic statistic folosind matplotlib"""
        fig = Figure(figsize=(4, 3), dpi=100)
        fig.patch.set_facecolor('#EBEBEB')  # Culoarea fundalului

        ax = fig.add_subplot(111)
        labels = ['Port Scan', 'Trafic Curat', 'Erori']
        sizes = [15, 80, 5]
        culori = ['#ff9999', '#66b3ff', '#99ff99']

        ax.pie(sizes, labels=labels, colors=culori, autopct='%1.1f%%', startangle=90)
        ax.set_title("Distribuție Trafic")

        # Lipim graficul în interfața Tkinter
        canvas = FigureCanvasTkAgg(fig, master=parinte)
        canvas.draw()
        canvas.get_tk_widget().pack(expand=True, fill="both", padx=10, pady=10)

    def actualizare_live(self):
        try:
            conn = sqlite3.connect("alerte.db")
            cursor = conn.cursor()
            cursor.execute("SELECT rowid, ip, mesaj FROM istoric ORDER BY rowid DESC LIMIT 15")
            alerte = cursor.fetchall()
            conn.close()

            self.textbox.delete("0.0", "end")
            if not alerte:
                self.textbox.insert("end", "[INFO] Sistem activ. Nu s-au detectat amenințări încă...\n")
            else:
                for alerta in alerte:
                    self.textbox.insert("end", f"[{alerta[0]}] 🔴 ALERTĂ: IP: {alerta[1]} | Motiv: {alerta[2]}\n")
        except:
            pass
        self.after(1000, self.actualizare_live)


if __name__ == "__main__":
    app = SIEMApp()
    app.mainloop()