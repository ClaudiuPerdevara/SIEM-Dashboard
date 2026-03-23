import customtkinter as ctk
import tkinter.ttk as ttk
import sqlite3
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
import psutil

from pyparsing import White

BG = "#101013"
SIDEBAR_BG = "#16161b"
CARD = "#1d1d24"
CARD2 = "#24242e"
BORDER = "#2a2a35"

ACCENT = "#7c5cfc"
GREEN = "#22c55e"
DANGER = "#ef4444"
WARNING = "#f59e0b"
TEAL = "#2dd4bf"
PINK = "#ec4899"

TEXT = "#f1f0f5"
DIM = "#6b6b80"

MONO = "Consolas"


def _F(size: int, weight: str = "normal") -> ctk.CTkFont:
    for family in ("Outfit", "Segoe UI Variable Display", "Segoe UI", "Helvetica Neue"):
        try:
            return ctk.CTkFont(family=family, size=size, weight=weight)
        except Exception:
            pass
    return ctk.CTkFont(size=size, weight=weight)


class SIEMApp(ctk.CTk):
    _SB_OPEN = 218

    def __init__(self):
        super().__init__()
        self.title("SOC Analytics")
        self.geometry("1600x920")
        self.minsize(1200, 720)
        self.configure(fg_color=BG)
        ctk.set_appearance_mode("dark")

        self.total_alerte = 0
        self.total_pachete = 0
        self.current_view = "dashboard"

        # Trackere pentru update-uri delta (scroll continuu, fără refresh enervant)
        self.last_terminal_id = 0
        self._last_packet_id = 0

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self._build_sidebar()
        self._build_dashboard()
        self._build_hunting()
        self._build_placeholders()

        self.live_update()

    # ═══════════════════════════════════════════════════════════════════════
    #  SIDEBAR (STATIC & STABIL)
    # ═══════════════════════════════════════════════════════════════════════
    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=self._SB_OPEN, corner_radius=0, fg_color=SIDEBAR_BG)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_columnconfigure(0, weight=1)

        self._nav = []

        def sep(row):
            ctk.CTkFrame(self.sidebar, height=1, fg_color=BORDER).grid(row=row, column=0, sticky="ew", padx=12,
                                                                       pady=(8, 2))

        def section(row, txt):
            lbl = ctk.CTkLabel(self.sidebar, text=f"  {txt}", font=_F(14, "bold"), text_color="#e0e0e1", anchor="w")
            lbl.grid(row=row, column=0, sticky="ew", padx=14, pady=(10, 2))

        def nav(row, icon, label, cmd, attr):
            btn = ctk.CTkButton(self.sidebar, text=f"  {icon}   {label}", anchor="w", font=_F(15,"bold"),
                                fg_color="transparent", hover_color="#22222e", text_color="White", height=40,
                                corner_radius=8, command=cmd)
            btn.grid(row=row, column=0, padx=8, pady=2, sticky="ew")
            setattr(self, attr, btn)
            self._nav.append((btn, icon, label))

        ctk.CTkFrame(self.sidebar, fg_color="transparent", height=6).grid(row=0, column=0)
        self._ico = ctk.CTkLabel(self.sidebar, text="⬡", font=_F(28, "bold"), text_color=ACCENT)
        self._ico.grid(row=1, column=0, pady=(14, 2))
        self._nm = ctk.CTkLabel(self.sidebar, text="SOC Analytics", font=_F(13, "bold"), text_color=TEXT)
        self._nm.grid(row=2, column=0, pady=(0, 2))

        sep(10)
        section(5, "MAIN")
        nav(6, " ", "Dashboard", self.show_dashboard, "btn_dash")
        nav(7, " ", "Threats Logs", self.show_hunting, "btn_logs")
        nav(8, " ", "Network Map", self.show_network, "btn_net")
        nav(9, " ", "Active Alerts", self.show_alerts, "btn_alr")
        sep(10)
        section(11, "ANALYSIS")
        nav(12, " ", "Reports", self.show_reports, "btn_rep")
        nav(13, " ", "Audit Log", self.show_audit, "btn_aud")
        sep(14)
        section(15, "SYSTEM")
        nav(16, " ", "Settings", lambda: None, "btn_cfg")
        nav(17, " ", "Help & Docs", lambda: None, "btn_hlp")

        self.sidebar.grid_rowconfigure(18, weight=1)
        self._ver = ctk.CTkLabel(self.sidebar, text="build 2025.06", font=_F(9), text_color="#2a2a35")
        self._ver.grid(row=19, column=0, pady=(0, 12))

        self._set_active(self.btn_dash)

    def _set_active(self, active_btn):
        for btn, _, __ in self._nav:
            if btn is active_btn:
                btn.configure(fg_color="#272232", text_color=ACCENT)
            else:
                btn.configure(fg_color="transparent", text_color=DIM)

    # ═══════════════════════════════════════════════════════════════════════
    #  DASHBOARD (4 COLOANE)
    # ═══════════════════════════════════════════════════════════════════════
    def _build_dashboard(self):
        self.main_view = ctk.CTkFrame(self, corner_radius=0, fg_color=BG)
        self.main_view.grid(row=0, column=1, sticky="nsew")
        self.main_view.grid_columnconfigure(0, weight=1)
        self.main_view.grid_rowconfigure(2, weight=3)
        self.main_view.grid_rowconfigure(3, weight=1)

        tb = ctk.CTkFrame(self.main_view, fg_color=CARD, height=52, corner_radius=0)
        tb.grid(row=0, column=0, sticky="ew")
        tb.grid_columnconfigure(1, weight=1)
        tb.grid_propagate(False)

        ctk.CTkLabel(tb, text="  ⬡  Security Operations Center", font=_F(15, "bold"), text_color=TEXT).grid(row=0,column=0,padx=14,pady=14,sticky="w")
        self._lbl_clock = ctk.CTkLabel(tb, text="", font=ctk.CTkFont(family=MONO, size=12), text_color=DIM)
        self._lbl_clock.grid(row=0, column=2, padx=10)
        self._live_lbl = ctk.CTkLabel(tb, text="● LIVE", font=_F(11, "bold"), text_color=GREEN)
        self._live_lbl.grid(row=0, column=3, padx=(0, 18))
        self._tick()
        self._blink()

        kf = ctk.CTkFrame(self.main_view, fg_color="transparent")
        kf.grid(row=1, column=0, sticky="ew", padx=16, pady=(12, 6))
        for c in range(4): kf.grid_columnconfigure(c, weight=1)

        self.lbl_total = self._kpi(kf, "◆", "TOTAL THREATS", "0", DANGER, 0)
        self.lbl_critice = self._kpi(kf, "⚡", "CRITICAL EVENTS", "0", WARNING, 1)
        self.lbl_ips = self._kpi(kf, "◎", "UNIQUE ATTACKERS", "0", TEAL, 2)
        self.lbl_packets = self._kpi(kf, "◈", "PACKETS CAPTURED", "0", GREEN, 3)


        cf = ctk.CTkFrame(self.main_view, fg_color="transparent")
        cf.grid(row=2, column=0, sticky="nsew", padx=16, pady=4)

        cf.grid_columnconfigure(0, weight=4)  # Pie Chart (mai strâns)
        cf.grid_columnconfigure(1, weight=5)  # Bar Chart
        cf.grid_columnconfigure(2, weight=4)  # Top Attackers
        cf.grid_columnconfigure(3, weight=4)  # NOU: IPS Firewall Blocks
        cf.grid_rowconfigure(0, weight=1)

        pie_card = ctk.CTkFrame(cf, fg_color=CARD, corner_radius=12)
        pie_card.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        self._build_pie(pie_card)

        bar_card = ctk.CTkFrame(cf, fg_color=CARD, corner_radius=12)
        bar_card.grid(row=0, column=1, sticky="nsew", padx=4)
        self._build_bar(bar_card)

        top_card = ctk.CTkFrame(cf, fg_color=CARD, corner_radius=12)
        top_card.grid(row=0, column=2, sticky="nsew", padx=4)
        self._build_top_panel(top_card)

        # Panoul pentru Firewall
        ips_card = ctk.CTkFrame(cf, fg_color=CARD, corner_radius=12)
        ips_card.grid(row=0, column=3, sticky="nsew", padx=(5, 0))
        self._build_ips_panel(ips_card)

        # ── BOTTOM ROW (Split: 70% Terminal / 30% Sensor Health) ───────────────
        bottom_frame = ctk.CTkFrame(self.main_view, fg_color="transparent")
        bottom_frame.grid(row=3, column=0, sticky="nsew", padx=16, pady=(4, 14))
        bottom_frame.grid_columnconfigure(0, weight=8)  # 80% spațiu pentru Log-uri
        bottom_frame.grid_columnconfigure(1, weight=2)  # 20% spațiu pentru Senzor
        bottom_frame.grid_rowconfigure(0, weight=1)

        # 1. TERMINALUL
        log_card = ctk.CTkFrame(bottom_frame, fg_color=CARD, corner_radius=12)
        log_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        log_card.grid_columnconfigure(0, weight=1)
        log_card.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(log_card, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 2))
        ctk.CTkLabel(hdr, text="●", font=_F(11, "bold"), text_color=DANGER).pack(side="left")
        ctk.CTkLabel(hdr, text="  Live Alert Feed", font=_F(16, "bold"), text_color=TEXT).pack(side="left")

        self.terminal = ctk.CTkTextbox(log_card, font=(MONO, 13), fg_color="#0b0b0f", text_color="#d4d4d4",
                                       corner_radius=8, border_width=0)
        self.terminal.grid(row=1, column=0, sticky="nsew", padx=10, pady=(2, 10))
        self.terminal.insert("end", "[SYS] System secure — monitoring active...\n")

        # 2. SENSOR NODE HEALTH
        sys_card = ctk.CTkFrame(bottom_frame, fg_color=CARD, corner_radius=12)
        sys_card.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        sys_card.grid_columnconfigure(1, weight=1)

        sys_hdr = ctk.CTkFrame(sys_card, fg_color="transparent")
        sys_hdr.grid(row=0, column=0, columnspan=2, sticky="ew", padx=14, pady=(10, 6))
        ctk.CTkLabel(sys_hdr, text="Sensor Health", font=_F(16, "bold"), text_color=TEXT).pack(side="left")
        ctk.CTkLabel(sys_hdr, text="ONLINE", font=_F(10, "bold"), text_color=BG, fg_color=GREEN, corner_radius=4,
                     width=50).pack(side="right")

        # Funcție ajutătoare pentru a desena liniile de metrici rapid
        def add_metric(row, label, val_text, progress_val, color):
            ctk.CTkLabel(sys_card, text=label, font=_F(11, "bold"), text_color=DIM).grid(row=row, column=0, sticky="w",
                                                                                         padx=14, pady=(8, 0))
            val_lbl = ctk.CTkLabel(sys_card, text=val_text, font=ctk.CTkFont(family=MONO, size=12, weight="bold"),
                                   text_color=TEXT)
            val_lbl.grid(row=row, column=1, sticky="e", padx=14, pady=(8, 0))

            pb = ctk.CTkProgressBar(sys_card, height=4, progress_color=color, fg_color=BORDER, corner_radius=2)
            pb.grid(row=row + 1, column=0, columnspan=2, sticky="ew", padx=14, pady=(4, 4))
            pb.set(progress_val)
            return val_lbl, pb

        # Adăugăm metricile (pe viitor le putem lega la librăria 'psutil' ca să fie live)
        self.lbl_cpu, self.pb_cpu = add_metric(3, "CPU LOAD", "0", 0.00, ACCENT)
        self.lbl_ram, self.pb_ram = add_metric(6, "MEMORY USAGE", "0 GB", 0.0, TEAL)
        self.lbl_net, self.pb_net = add_metric(9, "NETWORK I/O", "", 0.00, PINK)


    def _kpi(self, parent, icon, title, val, color, col):
        card = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=12)
        card.grid(row=0, column=col, sticky="ew", padx=5, pady=4)
        card.grid_columnconfigure(0, weight=1)
        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 0))
        ctk.CTkLabel(top, text=icon, font=_F(13), text_color=color).pack(side="left")
        ctk.CTkLabel(top, text=f"  {title}", font=_F(10, "bold"), text_color=DIM).pack(side="left")
        lbl = ctk.CTkLabel(card, text=val, font=_F(42, "bold"), text_color=color)
        lbl.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 10))
        ctk.CTkFrame(card, fg_color=color, height=3, corner_radius=0).grid(row=2, column=0, sticky="ew")
        return lbl

    def _build_pie(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(parent, text="Attack Types Distribution", font=_F(18, "bold"), text_color=TEXT).grid(row=0, column=0, sticky="ew", pady=(12, 0))

        # Facem figura pătrată/mai înaltă pentru a lăsa loc jos
        self.fig = Figure(figsize=(4, 4), dpi=100)
        self.fig.patch.set_facecolor(CARD)

        # Centrăm graficul pe orizontală și ridicăm "podeaua" (bottom=0.4) pentru a face loc legendei
        self.fig.subplots_adjust(left=0.05, right=0.95, top=0.95, bottom=0.4)

        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor(CARD)
        self.ax.pie([1], colors=["#22222e"])
        self.canvas = FigureCanvasTkAgg(self.fig, master=parent)
        self.canvas.draw()
        self.canvas.get_tk_widget().grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

    def refresh_pie_chart(self, c_dos, c_scan, c_sqli, c_arp, c_icmp, c_exfil, c_brute, c_dns, c_ssh):
        if hasattr(self, "_hover_cid"): self.fig.canvas.mpl_disconnect(self._hover_cid)
        self.ax.clear()

        self.fig.subplots_adjust(left=0.05, right=0.95, top=0.95, bottom=0.4)

        ALL_LABELS = ["DoS", "Scan", "SQLi/XSS", "ARP", "ICMP", "Exfil", "HTTP Brute", "DNS Leak", "SSH Brute"]
        ALL_SIZES = [c_dos, c_scan, c_sqli, c_arp, c_icmp, c_exfil, c_brute, c_dns, c_ssh]
        ALL_COLORS = [DANGER, WARNING, "#f97316", ACCENT, PINK, TEAL, GREEN, "#a3e635", "#e879f9"]

        filtered = [(l, s, c) for l, s, c in zip(ALL_LABELS, ALL_SIZES, ALL_COLORS) if s > 0]
        if not filtered:
            self.ax.pie([1], colors=["#22222e"])
            self.canvas.draw()
            return

        labels, sizes, colors = zip(*filtered)
        wedges, _ = self.ax.pie(sizes, colors=colors, startangle=90, wedgeprops={"edgecolor": CARD, "linewidth": 1.5})
        total = sum(sizes)

        # === MUTĂM LEGENDA JOS ȘI O PUNEM PE 2 COLOANE ===
        leg = self.ax.legend(wedges, labels,
                             title="Threat Vectors",
                             loc="upper center",  # Aliniere sus-centru relativ la cutia legendei
                             bbox_to_anchor=(0.5, -0.05),  # Punctul de ancorare sub grafic
                             ncol=3,  # Împărțim pe 2 coloane ca să arate compact!
                             framealpha=0, labelcolor="white", fontsize=9)

        leg.get_title().set_color(DIM)
        leg.get_title().set_fontsize(10)
        leg.get_title().set_fontweight("bold")

        annot = self.ax.annotate("", xy=(0, 0), xytext=(18, 18), textcoords="offset points",
                                 bbox=dict(boxstyle="round,pad=0.45", fc="#101013", ec=ACCENT, lw=1.2), color=TEXT,
                                 fontsize=9, fontweight="bold", zorder=10)
        annot.set_visible(False)

        def hover(event):
            vis = False
            if event.inaxes == self.ax:
                for i, w in enumerate(wedges):
                    if w.contains(event)[0]:
                        annot.xy = (event.xdata, event.ydata)
                        annot.set_text(f"{labels[i]}\n{(sizes[i] / total * 100):.1f}%  ·  {sizes[i]} alerts")
                        annot.get_bbox_patch().set_edgecolor(colors[i])
                        annot.set_visible(True)
                        vis = True
                        break
            if not vis and annot.get_visible(): annot.set_visible(False)
            self.canvas.draw_idle()

        self._hover_cid = self.fig.canvas.mpl_connect("motion_notify_event", hover)
        self.canvas.draw()

    def _build_bar(self, parent):
        parent.grid_columnconfigure(0, weight=1);
        parent.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(parent, text="Protocol Traffic Breakdown", font=_F(18, "bold"), text_color=TEXT).grid(row=0,
                                                                                                           column=0,
                                                                                                           sticky="ew",
                                                                                                           padx=14,
                                                                                                           pady=(12, 0))
        self.fig2 = Figure(figsize=(5, 3), dpi=90);
        self.fig2.patch.set_facecolor(CARD)
        self.ax2 = self.fig2.add_subplot(111);
        self._style_ax2()
        self.fig2.subplots_adjust(left=0.09, right=0.97, top=0.93, bottom=0.14)
        self.ax2.bar(["TCP", "UDP", "ICMP", "ARP", "DNS"], [0] * 5, color=[ACCENT, GREEN, DANGER, WARNING, TEAL],
                     edgecolor="none", width=0.5)
        self.canvas2 = FigureCanvasTkAgg(self.fig2, master=parent);
        self.canvas2.draw()
        self.canvas2.get_tk_widget().grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

    def _style_ax2(self):
        self.ax2.set_facecolor("#0b0b0f")
        self.ax2.tick_params(colors=DIM, labelsize=9)
        for sp in self.ax2.spines.values(): sp.set_edgecolor(BORDER)
        self.ax2.grid(axis="y", color=BORDER, linestyle="--", linewidth=0.5, alpha=0.5)

    def _refresh_bar(self, cursor):
        try:
            cursor.execute(
                "SELECT protocol, COUNT(*) AS cnt FROM captura_retea GROUP BY protocol ORDER BY cnt DESC LIMIT 6")
            rows = cursor.fetchall()
            if not rows: return
            self.ax2.clear()
            protos = [r[0] or "OTHER" for r in rows];
            counts = [r[1] for r in rows];
            pal = [ACCENT, GREEN, DANGER, WARNING, TEAL, PINK]
            bars = self.ax2.bar(protos, counts, color=pal[:len(protos)], edgecolor="none", width=0.52)
            mx = max(counts)
            for bar, val in zip(bars, counts):
                self.ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + mx * 0.02, str(val), ha="center",
                              va="bottom", color=TEXT, fontsize=9, fontweight="bold")
            self._style_ax2()
            self.fig2.subplots_adjust(left=0.09, right=0.97, top=0.93, bottom=0.14)
            self.canvas2.draw()
        except Exception as e:
            print(f"[Bar] {e}")

    def _build_top_panel(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)

        # Titlu centrat perfect
        ctk.CTkLabel(
            parent,
            text="Top Threat Actors",
            font=_F(16, "bold"),
            text_color=TEXT
        ).grid(row=0, column=0, sticky="ew", pady=(14, 4))

        self.top_inner = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        self.top_inner.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.top_inner.grid_columnconfigure(0, weight=1)

    def update_top_attackers(self, cursor):
        # 1. Curățăm interfața la fiecare refresh
        for w in self.top_inner.winfo_children():
            w.destroy()

        # 2. Extragem Top 5
        cursor.execute("SELECT ip, COUNT(*) AS total FROM istoric GROUP BY ip ORDER BY total DESC LIMIT 5")
        rows = cursor.fetchall()

        # 3. Starea "Gol" (fără atacuri)
        if not rows:
            ctk.CTkLabel(
                self.top_inner,
                text="No threats detected yet.",
                font=_F(12),
                text_color=DIM
            ).grid(row=0, column=0, pady=40)
            return

        mx = rows[0][1]  # Referința pentru 100% din bara de progres (liderul)
        medals = ["#FFD700", "#C0C0C0", "#CD7F32", TEAL, TEAL]  # Aur, Argint, Bronz

        # 4. Generăm lista
        for rank, (ip, count) in enumerate(rows, 1):
            # Cardul pentru rândul curent
            rf = ctk.CTkFrame(self.top_inner, fg_color=CARD2, corner_radius=8)
            rf.grid(row=rank - 1, column=0, sticky="ew", pady=4)
            rf.grid_columnconfigure(1, weight=1)

            # Badge Rank (Medalia)
            ctk.CTkLabel(
                rf,
                text=f"{rank}.",
                font=_F(13, "bold"),
                text_color=medals[rank - 1],
                width=35
            ).grid(row=0, column=0, padx=(10, 5), pady=(10, 2))

            # Adresa IP (Albă, Curată, Monospaced)
            ctk.CTkLabel(
                rf,
                text=ip,
                font=ctk.CTkFont(family=MONO, size=14, weight="bold"),
                text_color=TEXT,
                anchor="w"
            ).grid(row=0, column=1, sticky="ew", padx=5, pady=(10, 2))

            # Numărul de atacuri + severitate
            sev = DANGER if count > 20 else WARNING if count > 5 else GREEN
            ctk.CTkLabel(
                rf,
                text=f"{count} hits",
                font=_F(13, "bold"),
                text_color=sev
            ).grid(row=0, column=2, padx=(5, 14), pady=(10, 2))

            # Fundalul barei de progres
            bg = ctk.CTkFrame(rf, fg_color=BORDER, corner_radius=4, height=4)
            bg.grid(row=1, column=0, columnspan=3, sticky="ew", padx=14, pady=(0, 12))

            # Umplerea barei de progres
            fill_w = max(8, int((count / mx) * 200))  # Proporțional cu liderul
            ctk.CTkFrame(
                bg,
                fg_color=sev,
                corner_radius=4,
                height=4,
                width=fill_w
            ).grid(row=0, column=0, sticky="w")


    # ═══════════════════════════════════════════════════════════════════════
    #  IPS FIREWALL PANEL
    # ═══════════════════════════════════════════════════════════════════════
    def _build_ips_panel(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 4))

        ctk.CTkLabel(hdr, text="Firewall Blocks",
                     font=_F(12, "bold"), text_color=TEXT).pack(side="left")

        self.ips_status_badge = ctk.CTkLabel(hdr, text="OFFLINE",
                                             font=_F(9, "bold"), text_color="#101013",
                                             fg_color=DIM, corner_radius=4, width=50, height=20)
        self.ips_status_badge.pack(side="right")

        self.ips_inner = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        self.ips_inner.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self.ips_inner.grid_columnconfigure(0, weight=1)

        warn_lbl = ctk.CTkLabel(self.ips_inner,
                                text="IPS Engine Inactive.\n\nWaiting for Auto-Ban\nmodule integration...",
                                font=_F(11), text_color=DIM, justify="center")
        warn_lbl.grid(row=0, column=0, pady=40)

    def _tick(self):
        self._lbl_clock.configure(text=time.strftime(" %Y-%m-%d   %H:%M:%S "))
        self.after(1000, self._tick)

    def _blink(self):
        cur = self._live_lbl.cget("text_color")
        self._live_lbl.configure(text_color=GREEN if cur != GREEN else "#0a3a1a")
        self.after(900, self._blink)

    # ═══════════════════════════════════════════════════════════════════════
    #  THREAT HUNTING (CU INSPECTOR, FILTER & ALERTS)
    # ═══════════════════════════════════════════════════════════════════════

    def _build_hunting(self):
        self.hunting_view = ctk.CTkFrame(self, corner_radius=0, fg_color=BG)
        self.hunting_view.grid_columnconfigure(0, weight=1)
        self.hunting_view.grid_rowconfigure(1, weight=5)
        self.hunting_view.grid_rowconfigure(2, weight=3)

        fb = ctk.CTkFrame(self.hunting_view, fg_color=CARD, height=56, corner_radius=0)
        fb.grid(row=0, column=0, sticky="ew")

        ctk.CTkLabel(fb, text="⊕  Deep Packet Inspection", font=_F(14, "bold"), text_color=TEXT).pack(side="left",
                                                                                                      padx=20)

        self.filter_var = ctk.StringVar()
        ctk.CTkEntry(fb, placeholder_text="Caută ID, Protocol, IP sau Conținut Payload (ex: UNION, HTTP)",
                     textvariable=self.filter_var, font=_F(12), width=360).pack(side="left", padx=14, pady=12)

        ctk.CTkButton(fb, text="Filter", width=80, font=_F(12), fg_color=ACCENT, hover_color="#6448d8",
                      command=lambda: self.refresh_treeview(clear=True)).pack(side="left", padx=3)
        ctk.CTkButton(fb, text="Reset", width=80, font=_F(12), fg_color="#2a2a35", hover_color="#33333f",
                      command=self.clear_filter).pack(side="left", padx=3)

        self.auto_refresh_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(fb, text="Live Capture", font=_F(12), variable=self.auto_refresh_var).pack(side="right",
                                                                                                   padx=20)

        self.tree_container = ctk.CTkFrame(self.hunting_view, corner_radius=0, fg_color="transparent")
        self.tree_container.grid(row=1, column=0, sticky="nsew", padx=10, pady=(10, 5))
        self.tree_container.grid_columnconfigure(0, weight=1);
        self.tree_container.grid_rowconfigure(0, weight=1)

        self.setup_wireshark_table()

        # ── Packet Inspector ──
        self.inspector_frame = ctk.CTkFrame(self.hunting_view, fg_color=CARD, corner_radius=8)
        self.inspector_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(5, 10))
        self.inspector_frame.grid_columnconfigure(0, weight=1);
        self.inspector_frame.grid_rowconfigure(1, weight=1)

        insp_hdr = ctk.CTkFrame(self.inspector_frame, fg_color="transparent")
        insp_hdr.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
        ctk.CTkLabel(insp_hdr, text="📄 Packet Inspector", font=_F(13, "bold"), text_color=TEXT).pack(side="left")

        self.current_format = "ASCII"

        def btn(txt, cmd_val):
            return ctk.CTkButton(insp_hdr, text=txt, width=60, height=24, font=_F(11, "bold"),
                                 fg_color=ACCENT if txt == "ASCII" else BORDER,
                                 command=lambda: self.change_inspector_format(cmd_val))

        self.btn_raw = btn("RAW", "RAW");
        self.btn_raw.pack(side="right", padx=2)
        self.btn_hex = btn("HEX", "HEX");
        self.btn_hex.pack(side="right", padx=2)
        self.btn_ascii = btn("ASCII", "ASCII");
        self.btn_ascii.pack(side="right", padx=2)

        self.selected_packet_data = None
        self.inspector_text = ctk.CTkTextbox(self.inspector_frame, font=(MONO, 12), fg_color="#0b0b0f", text_color=TEAL,
                                             border_width=0)
        self.inspector_text.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.inspector_text.insert("end", "Select a packet from the table above to inspect its payload...")
        self.inspector_text.configure(state="disabled")

    def setup_wireshark_table(self):
        style = ttk.Style();
        style.theme_use("default")
        style.configure("Treeview", background="#0b0b0f", foreground="#c9d1d9", fieldbackground="#0b0b0f",
                        borderwidth=0, rowheight=27, font=(MONO, 11))
        style.configure("Treeview.Heading", background=CARD, foreground=TEXT, relief="flat", font=(MONO, 10, "bold"))
        style.map("Treeview", background=[("selected", ACCENT)])

        cols = ("id", "timp", "sursa", "destinatie", "protocol", "lungime", "info")
        self.tree = ttk.Treeview(self.tree_container, columns=cols, show="headings", style="Treeview")

        for col, heading, width, anchor in [("id", "No.", 55, "center"), ("timp", "Time", 160, "center"),
                                            ("sursa", "Source", 130, "center"),
                                            ("destinatie", "Destination", 130, "center"),
                                            ("protocol", "Protocol", 110, "center"),
                                            ("lungime", "Length", 68, "center"), ("info", "Info", 0, "w")]:
            self.tree.heading(col, text=heading);
            self.tree.column(col, width=width, anchor=anchor, stretch=(col == "info"))
        self.tree.grid(row=0, column=0, sticky="nsew")

        self.scrollbar = ttk.Scrollbar(self.tree_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.grid(row=0, column=1, sticky="ns")

        self.tree.bind("<<TreeviewSelect>>", self.on_packet_select)

        # Culori Protocoale & ALERTE
        self.tree.tag_configure("ALERT", background="#3f0a12", foreground="#fca5a5", font=(MONO, 11, "bold"))
        self.tree.tag_configure("SSH", background="#1a0b1c", foreground="#e879f9", font=(MONO, 11, "bold"))
        self.tree.tag_configure("TCP", background="#0d1020", foreground="#79c0ff")
        self.tree.tag_configure("UDP", background="#130f00", foreground="#f59e0b")
        self.tree.tag_configure("ICMP", background="#180606", foreground="#ef4444")
        self.tree.tag_configure("ARP", background="#061508", foreground="#22c55e")
        self.tree.tag_configure("DNS", background="#150c22", foreground="#c084fc")
        self.tree.tag_configure("HTTP", background="#160c00", foreground="#fb923c", font=(MONO, 11, "bold"))
        self.tree.tag_configure("DEFAULT", background="#12121a", foreground=DIM)

    def on_packet_select(self, event):
        selected_items = self.tree.selection()
        if not selected_items: return
        self.auto_refresh_var.set(False)  # Oprește scrollul când analizezi
        self.selected_packet_data = self.tree.item(selected_items[0], "values")
        self.render_inspector()

    def change_inspector_format(self, fmt):
        self.current_format = fmt
        self.btn_ascii.configure(fg_color=ACCENT if fmt == "ASCII" else BORDER)
        self.btn_hex.configure(fg_color=ACCENT if fmt == "HEX" else BORDER)
        self.btn_raw.configure(fg_color=ACCENT if fmt == "RAW" else BORDER)
        self.render_inspector()

    def render_inspector(self):
        if not self.selected_packet_data: return
        p_id, p_time, p_src, p_dst, p_proto, p_len, p_info = self.selected_packet_data

        self.inspector_text.configure(state="normal")
        self.inspector_text.delete("0.0", "end")

        header = f"Frame {p_id}: {p_len} bytes on wire ({p_proto})\nArrival Time: {p_time}\n"
        header += f"Internet Protocol Version 4, Src: {p_src}, Dst: {p_dst}\n" + "━" * 80 + "\n\n"
        self.inspector_text.insert("end", header)

        if str(p_info).startswith("NO_PAYLOAD:"):
            self.inspector_text.insert("end", f"Empty Packet Frame (Routing/Handshake only)\nSummary: {p_info[12:]}")
            self.inspector_text.configure(state="disabled")
            return

        try:
            raw_bytes = bytes.fromhex(str(p_info))
            if self.current_format == "ASCII":
                ascii_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes)
                lines = [ascii_text[i:i + 80] for i in range(0, len(ascii_text), 80)]
                self.inspector_text.insert("end", "\n".join(lines))
            elif self.current_format == "HEX":
                for i in range(0, len(raw_bytes), 16):
                    chunk = raw_bytes[i:i + 16]
                    hex_part = " ".join(f"{b:02X}" for b in chunk)
                    ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                    self.inspector_text.insert("end", f"{i:04X}  {hex_part:<47}  {ascii_part}\n")
            elif self.current_format == "RAW":
                self.inspector_text.insert("end", repr(raw_bytes))
        except:
            self.inspector_text.insert("end", f"Error parsing packet payload.\nRaw Data: {p_info}")
        self.inspector_text.configure(state="disabled")

    def clear_filter(self):
        self.filter_var.set("")
        self.refresh_treeview(clear=True)

    def refresh_treeview(self, clear=False):
        if self.current_view != "hunting": return
        flt = self.filter_var.get().strip().upper()

        if clear:
            for item in self.tree.get_children(): self.tree.delete(item)
            self._last_packet_id = 0

        try:
            conn = sqlite3.connect("alerte.db")
            cur = conn.cursor()

            # Luăm datele (toate dacă filtrăm/resetăm, sau doar delta pentru live)
            if clear:
                cur.execute(
                    "SELECT id,timp,sursa,destinatie,protocol,lungime,info FROM captura_retea ORDER BY id DESC LIMIT 1000")
                rows = list(reversed(cur.fetchall()))
            else:
                cur.execute(
                    "SELECT id,timp,sursa,destinatie,protocol,lungime,info FROM captura_retea WHERE id > ? ORDER BY id ASC",
                    (self._last_packet_id,))
                rows = cur.fetchall()
            conn.close()

            for p in rows:
                p_id, p_time, p_src, p_dst, p_proto, p_len, p_info_raw = p
                self._last_packet_id = max(self._last_packet_id, p_id)

                proto = str(p_proto).upper()
                p_info = str(p_info_raw)

                # Decodăm pentru inspecție și detecție
                try:
                    decoded_info = bytes.fromhex(p_info).decode('utf-8',
                                                                errors='ignore').upper() if not p_info.startswith(
                        "NO_PAYLOAD") else p_info.upper()
                except:
                    decoded_info = p_info.upper()

                # --- Detecție Protocol Inteligent ---
                if "TCP" in proto and any(x in decoded_info for x in ["GET /", "POST /", "HTTP/1."]):
                    proto = "HTTP"
                elif "TCP" in proto and (p_src == "22" or p_dst == "22" or "SSH-" in decoded_info):
                    proto = "SSH"

                # --- Căutare Avansată (Filtru General) ---
                if flt and flt not in str(p_id) and flt not in proto and flt not in str(p_src) and flt not in str(
                        p_dst) and flt not in decoded_info:
                    continue

                    # --- Threat Highlighting (Detectăm Alertele direct în pachet) ---
                is_alert = False
                if any(k in decoded_info for k in
                       ["UNION SELECT", "DROP TABLE", "SCRIPT>", "1=1", "OR 1=1", "ETC/PASSWD", "CMD.EXE", "PASSWORD"]):
                    is_alert = True
                    proto = "SQLi/XSS" if "POST" not in decoded_info else "HTTP Brute"
                elif "ICMP" in proto and int(p_len) > 1000:
                    is_alert = True;
                    proto = "ICMP Death"
                elif "DNS" in proto and len(decoded_info) > 60:
                    is_alert = True;
                    proto = "DNS Leak"

                # Etichetare pentru culori
                tag = "ALERT" if is_alert else proto if proto in ["HTTP", "DNS", "TCP", "UDP", "ICMP", "ARP",
                                                                  "SSH"] else "DEFAULT"

                self.tree.insert("", "end", values=(p_id, p_time, p_src, p_dst, proto, p_len, p_info_raw), tags=(tag,))

            if self.auto_refresh_var.get() and rows:
                self.tree.yview_moveto(1)
        except Exception as e:
            print(f"[Treeview] {e}")

    # ═══════════════════════════════════════════════════════════════════════
    #  PLACEHOLDER VIEWS
    # ═══════════════════════════════════════════════════════════════════════
    def _build_placeholders(self):
        for attr, icon, title, sub in [
            ("network_view", "◎", "Network Map", "Visual host topology — coming soon"),
            ("alerts_view", "◆", "Active Alerts", "Rule-based alert management — coming soon"),
            ("reports_view", "▦", "Reports", "Scheduled PDF / CSV exports — coming soon"),
            ("audit_view", "≡", "Audit Log", "Full operator activity log — coming soon"),
        ]:
            f = ctk.CTkFrame(self, corner_radius=0, fg_color=BG)
            f.grid_columnconfigure(0, weight=1);
            f.grid_rowconfigure(0, weight=1)
            inner = ctk.CTkFrame(f, fg_color=CARD, corner_radius=14, width=440, height=210)
            inner.grid(row=0, column=0);
            inner.grid_propagate(False);
            inner.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(inner, text=icon, font=_F(46, "bold"), text_color=ACCENT).grid(row=0, column=0, pady=(30, 6))
            ctk.CTkLabel(inner, text=title, font=_F(22, "bold"), text_color=TEXT).grid(row=1, column=0)
            ctk.CTkLabel(inner, text=sub, font=_F(12), text_color=DIM).grid(row=2, column=0, pady=(6, 30))
            setattr(self, attr, f)

    # ═══════════════════════════════════════════════════════════════════════
    #  VIEW SWITCHERS
    # ═══════════════════════════════════════════════════════════════════════
    _ALL_VIEWS = ["main_view", "hunting_view", "network_view", "alerts_view", "reports_view", "audit_view"]

    def _switch(self, view_attr, btn, key):
        for a in self._ALL_VIEWS: getattr(self, a).grid_forget()
        getattr(self, view_attr).grid(row=0, column=1, sticky="nsew")
        self._set_active(btn)
        self.current_view = key

    def show_dashboard(self):
        self._switch("main_view", self.btn_dash, "dashboard")

    def show_network(self):
        self._switch("network_view", self.btn_net, "network")

    def show_alerts(self):
        self._switch("alerts_view", self.btn_alr, "alerts")

    def show_reports(self):
        self._switch("reports_view", self.btn_rep, "reports")

    def show_audit(self):
        self._switch("audit_view", self.btn_aud, "audit")

    def show_hunting(self):
        self._switch("hunting_view", self.btn_logs, "hunting")
        self.refresh_treeview(clear=True)  # Forțează reîncărcarea fresh când intri pe pagină

    # ═══════════════════════════════════════════════════════════════════════
    #  LIVE UPDATE LOOP (DASHBOARD)
    # ═══════════════════════════════════════════════════════════════════════
    def live_update(self):
        try:
            conn = sqlite3.connect("alerte.db")
            cur = conn.cursor()

            if self.current_view == "dashboard":

                cur.execute("SELECT rowid, ip, mesaj FROM istoric WHERE rowid > ? ORDER BY rowid ASC",
                            (self.last_terminal_id,))
                noi_alerte = cur.fetchall()

                if noi_alerte:
                    if self.last_terminal_id == 0:
                        self.terminal.delete("0.0", "end")

                    for aid, ip, msg in noi_alerte:
                        # 1. Căutăm datele pachetului
                        cur.execute("SELECT MAX(id) FROM captura_retea WHERE sursa = ?", (ip,))
                        pkt_res = cur.fetchone()

                        if pkt_res and pkt_res[0]:
                            pkt_id = pkt_res[0]
                            cur.execute("SELECT destinatie, protocol, lungime FROM captura_retea WHERE id = ?",
                                        (pkt_id,))
                            detalii = cur.fetchone()
                            if detalii:
                                dst_ip, proto, length = detalii
                                pkt_str = f"PKT:{pkt_id:05d}"
                            else:
                                dst_ip, proto, length = "UNKNOWN", "---", 0
                                pkt_str = "PKT:-----"
                        else:
                            dst_ip, proto, length = "UNKNOWN", "---", 0
                            pkt_str = "PKT:-----"

                        # 2. Etichetăm dacă e critic sau doar avertisment
                        is_critical = any(kw in msg for kw in ["DoS", "ARP", "Exfil", "Leak", "SQL"])
                        alert_tag = "🔴 CRIT" if is_critical else "🟡 WARN"

                        # 3. Formatare vizuală pe 3 rânduri (mult mai aerisit!)
                        log_line = f"[{aid:04d}] {alert_tag} | {pkt_str} | PROTO: {proto:<5} | SIZE: {length} Bytes\n"
                        log_line += f"       ↳ TRAFIC: {ip:<15} ➔  {dst_ip:<15}\n"
                        log_line += f"       ↳ MOTIV:  {msg}\n"
                        log_line += "       " + "─" * 70 + "\n"

                        self.terminal.insert("end", log_line)
                        self.last_terminal_id = aid

                    self.terminal.see("end")

                # --- Pachete și Alerte (KPIs & Charts) ---
                cur.execute("SELECT COUNT(*) FROM captura_retea")
                n_pkt = cur.fetchone()[0]
                self.lbl_packets.configure(text=str(n_pkt))

                cur.execute("SELECT COUNT(*) FROM istoric")
                n_alr = cur.fetchone()[0]

                if n_alr > self.total_alerte or n_pkt > self.total_pachete:
                    self.total_alerte = n_alr
                    self.total_pachete = n_pkt
                    self.lbl_total.configure(text=str(n_alr))

                    cur.execute("SELECT COUNT(DISTINCT ip) FROM istoric")
                    self.lbl_ips.configure(text=str(cur.fetchone()[0]))

                    cur.execute(
                        "SELECT COUNT(*) FROM istoric WHERE mesaj LIKE '%DoS%' OR mesaj LIKE '%ARP%' OR mesaj LIKE '%Exfil%'")
                    self.lbl_critice.configure(text=str(cur.fetchone()[0]))

                    cur.execute("SELECT mesaj FROM istoric")
                    c = {k: 0 for k in ["dos", "scan", "sqli", "arp", "brute", "icmp", "exfil", "dns", "ssh"]}
                    for (t,) in cur.fetchall():
                        if "DoS" in t:
                            c["dos"] += 1
                        elif "Scan" in t:
                            c["scan"] += 1
                        elif "SQL" in t:
                            c["sqli"] += 1
                        elif "ARP" in t:
                            c["arp"] += 1
                        elif "HTTP Brute" in t:
                            c["brute"] += 1
                        elif "ICMP" in t:
                            c["icmp"] += 1
                        elif "Exfil" in t:
                            c["exfil"] += 1
                        elif "DNS" in t:
                            c["dns"] += 1
                        elif "SSH" in t:
                            c["ssh"] += 1

                    self.refresh_pie_chart(c["dos"], c["scan"], c["sqli"], c["arp"], c["icmp"], c["exfil"], c["brute"],
                                           c["dns"], c["ssh"])
                    self._refresh_bar(cur)
                    self.update_top_attackers(cur)

                #  SENSOR NODE HEALTH
                # 1. CPU
                cpu_pct = psutil.cpu_percent(interval=None)
                self.lbl_cpu.configure(text=f"{cpu_pct:.1f}%")
                self.pb_cpu.set(cpu_pct / 100.0)
                # Schimbăm culoarea dacă procesorul se încinge
                self.pb_cpu.configure(
                    progress_color=DANGER if cpu_pct > 80 else WARNING if cpu_pct > 50 else ACCENT)

                # 2. RAM
                ram = psutil.virtual_memory()
                ram_gb = ram.used / (1024 ** 3)
                self.lbl_ram.configure(text=f"{ram_gb:.1f} GB")
                self.pb_ram.set(ram.percent / 100.0)
                self.pb_ram.configure(
                    progress_color=DANGER if ram.percent > 85 else WARNING if ram.percent > 70 else TEAL)

                # 3. NETWORK (Calculăm MB/s)
                if not hasattr(self, "last_net_bytes"):
                    self.last_net_bytes = psutil.net_io_counters().bytes_recv + psutil.net_io_counters().bytes_sent

                current_net = psutil.net_io_counters().bytes_recv + psutil.net_io_counters().bytes_sent
                net_diff = current_net - self.last_net_bytes
                self.last_net_bytes = current_net

                mbps = net_diff / (1024 * 1024)  # Transformăm bytes în Megabytes
                self.lbl_net.configure(text=f"{mbps:.2f} MB/s")

                # Presupunem un maxim vizual de 50 MB/s pentru a umple bara
                net_prog = min(mbps / 50.0, 1.0)
                self.pb_net.set(net_prog)
                self.pb_net.configure(progress_color=DANGER if mbps > 25 else PINK)

            elif self.current_view == "hunting" and self.auto_refresh_var.get():
                cur.execute("SELECT COUNT(*) FROM captura_retea")
                n = cur.fetchone()[0]
                if n > self.total_pachete:
                    self.total_pachete = n
                    self.refresh_treeview(clear=False)  # Delta Update

            conn.close()
        except Exception as e:
            pass

        self.after(1000, self.live_update)


if __name__ == "__main__":
    app = SIEMApp()
    app.mainloop()