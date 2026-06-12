#!/usr/bin/env python3
"""
gui.py — Interfaccia grafica (Tkinter) del WP4.

È un semplice strato di presentazione sopra il pacchetto `wp4`: non contiene
logica crittografica, ma invoca le stesse entità usate da demo.py/test.
Permette di condurre interattivamente un'intera elezione:

  1. Setup     — configura tesi ed elettorato, inizializza la PKI e l'elezione.
  2. Voto      — autentica un elettore, esprime e cifra la scheda, ottiene la ricevuta.
  3. Urna      — mostra il bulletin board pubblico (schede, Merkle root, K).
  4. Risultato — chiude le urne, conta, e mostra verifica individuale e universale.

Esecuzione:  python3 gui.py   
"""

import sys
import tkinter as tk
import tkinter.font as tkfont
from tkinter import messagebox, ttk

from wp4.authority import VoteRejected
from wp4.commission import BLANK_ID
from wp4.election import Election
from wp4.idp import AuthenticationError
from wp4.pki import CertificateRejected
from wp4.verifier import verify_election

DEFAULT_THESES = [
    "Tesi A — Crittografia post-quantistica",
    "Tesi B — Privacy nei sistemi distribuiti",
    "Tesi C — Sicurezza dei protocolli IoT",
]
DEFAULT_ELECTORATE = [
    "stud01:pwd-stud01", "stud02:pwd-stud02", "stud03:pwd-stud03",
    "stud04:pwd-stud04", "doc01:pwd-doc01", "doc02:pwd-doc02",
]

# --------------------------------------------------------------------------- #
# Palette
# --------------------------------------------------------------------------- #
BG = "#f3f5f9"         # sfondo applicazione
CARD = "#ffffff"       # sfondo card
BORDER = "#e3e8f0"     # bordo card / contorni leggeri
PRIMARY = "#2f6fed"    # blu accento
PRIMARY_DK = "#2257c8"
PRIMARY_DIS = "#b8c9f3"
SUCCESS = "#1f9d57"
SUCCESS_DK = "#188047"
SUCCESS_DIS = "#aedcc1"
DANGER = "#c0392b"      # esito negativo (verifica fallita)
TEXT = "#1c2533"       # testo principale
MUTED = "#788397"      # testo secondario
HEADER = "#101728"     # banda superiore
GHOST_HOVER = "#eef2fb"

PAD = 16
RADIUS = 16
BTN_RADIUS = 13


def _round_points(x1, y1, x2, y2, r):
    """Punti per un rettangolo ad angoli arrotondati (con smooth=True)."""
    return [
        x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
        x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
        x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
    ]


# --------------------------------------------------------------------------- #
# Widget custom: pulsante ad angoli arrotondati
# --------------------------------------------------------------------------- #
class RoundedButton(tk.Canvas):
    """
    Pulsante con angoli arrotondati. ttk non offre bottoni arrotondati, quindi
    lo "disegnamo" a mano su un Canvas: una forma arrotondata riempita + il testo
    al centro. Gestiamo noi i colori al passaggio del mouse e lo stato disabilitato.
    `variant` sceglie la combinazione di colori (primary/go/ghost).
    """

    # Combinazioni di colori per ogni variante: fill=normale, active=hover,
    # fg=testo, dis/disfg=stato disabilitato, outline=bordo (solo "ghost").
    _VARIANTS = {
        "primary": dict(fill=PRIMARY, active=PRIMARY_DK, fg="#ffffff",
                        dis=PRIMARY_DIS, disfg="#ffffff", outline=None),
        "go": dict(fill=SUCCESS, active=SUCCESS_DK, fg="#ffffff",
                   dis=SUCCESS_DIS, disfg="#ffffff", outline=None),
        "ghost": dict(fill=None, active=GHOST_HOVER, fg=PRIMARY,
                      dis=None, disfg=MUTED, outline=BORDER),
    }

    def __init__(self, parent, text, command=None, variant="primary",
                 parent_bg=BG, font=None, padx=20, pady=11, min_width=0):
        self._font = font or tkfont.nametofont("TkDefaultFont")
        self._text = text
        self._radius = BTN_RADIUS
        self.command = command
        self.variant = variant
        self.parent_bg = parent_bg
        self._state = "normal"

        c = dict(self._VARIANTS[variant])
        if variant == "ghost":
            c["fill"] = parent_bg
            c["dis"] = parent_bg
        self._c = c

        w = max(min_width, self._font.measure(text) + 2 * padx)
        h = self._font.metrics("linespace") + 2 * pady
        super().__init__(parent, width=w, height=h, bg=parent_bg,
                         highlightthickness=0, bd=0, takefocus=0)
        self._bw, self._bh = w, h

        self._paint(c["fill"], c["fg"])
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)
        self.configure(cursor="hand2")

    def _paint(self, fill, fg):
        """Ridisegna il pulsante: forma arrotondata + testo. Usato ad ogni cambio."""
        self.delete("all")
        outline = self._c["outline"] or fill
        self.create_polygon(
            _round_points(1, 1, self._bw - 1, self._bh - 1, self._radius),
            smooth=True, fill=fill, outline=outline,
            width=1 if self._c["outline"] else 0,
        )
        self.create_text(self._bw / 2, self._bh / 2, text=self._text,
                         fill=fg, font=self._font)

    # API compatibile con ttk: .configure(state=...)
    def configure(self, **kw):  # noqa: D401
        if "state" in kw:
            self._set_state(kw.pop("state"))
        if kw:
            super().configure(**kw)
    config = configure

    def _set_state(self, state):
        self._state = state
        if state == "disabled":
            self._paint(self._c["dis"], self._c["disfg"])
            super().configure(cursor="")
        else:
            self._paint(self._c["fill"], self._c["fg"])
            super().configure(cursor="hand2")

    def _on_enter(self, _e):
        if self._state == "normal":
            self._paint(self._c["active"], self._c["fg"])

    def _on_leave(self, _e):
        if self._state == "normal":
            self._paint(self._c["fill"], self._c["fg"])

    def _on_press(self, _e):
        if self._state == "normal":
            self._paint(self._c["active"], self._c["fg"])

    def _on_release(self, e):
        if self._state != "normal":
            return
        inside = 0 <= e.x <= self._bw and 0 <= e.y <= self._bh
        self._paint(self._c["active"] if inside else self._c["fill"], self._c["fg"])
        if inside and self.command:
            self.command()


# --------------------------------------------------------------------------- #
# Widget custom: card ad angoli arrotondati (auto-altezza)
# --------------------------------------------------------------------------- #
class RoundedCard(ttk.Frame):
    """
    Card ad angoli arrotondati robusta: un contenitore Frame che si dimensiona
    naturalmente dal contenuto (`inner`), con un Canvas *dietro* che disegna lo
    sfondo arrotondato. L'inner è inset di `pad` (>= raggio) così gli angoli
    quadrati del frame restano dentro l'area arrotondata e non si vedono.
    """

    def __init__(self, parent, parent_bg=BG, fill=CARD, border=BORDER,
                 radius=14, pad=PAD):
        super().__init__(parent, style="Tab.TFrame")
        self.radius = radius
        self.fill = fill
        self.border = border
        self._bg_canvas = tk.Canvas(self, bg=parent_bg, highlightthickness=0, bd=0)
        self._bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.inner = ttk.Frame(self, style="Card.TFrame")
        self.inner.pack(fill="both", expand=True, padx=pad, pady=pad)
        self.inner.lift()
        self.bind("<Configure>", self._draw)

    def _draw(self, e):
        self._bg_canvas.delete("all")
        self._bg_canvas.create_polygon(
            _round_points(1, 1, e.width - 1, e.height - 1, self.radius),
            smooth=True, fill=self.fill, outline=self.border, width=1,
        )


class VotingGUI(tk.Tk):
    """
    Finestra principale dell'applicazione. È SOLO presentazione: ogni azione
    dell'utente chiama i metodi del package 'wp4' (gli stessi di demo.py).
    Lo stato dell'elezione vive negli attributi qui sotto; i metodi 'on_*' sono
    i callback dei pulsanti e '_build_*' costruiscono le 4 schede.
    """

    def __init__(self) -> None:
        super().__init__()
        self.title("Voto elettronico sicuro · Premio \"Tesi dell'Anno\"")
        self.geometry("980x740")
        self.minsize(900, 680)
        self.configure(bg=BG)

        # --- Stato dell'applicazione ---
        self.election: Election | None = None         # l'elezione in corso (o None)
        self.credentials: dict[str, str] = {}          # {voter_id: password}
        self.voters: dict[str, object] = {}            # voter_id -> Voter (con fascicolo)
        self.current_voter = None                      # elettore autenticato in attesa di votare
        self.tallied = False                           # lo scrutinio è stato eseguito?
        self._scroll_canvases: list[tk.Canvas] = []    # schede con scroll verticale

        # Costruzione dell'interfaccia (font, stili, widget) e stato iniziale.
        self._init_fonts()
        self._init_style()
        self._build_widgets()
        self._set_phase_state()

    # ------------------------------------------------------------------ #
    # Tema, font e stili
    # ------------------------------------------------------------------ #
    def _init_fonts(self) -> None:
        """Definisce i font usati nell'interfaccia (titoli, testo, monospazio…)."""
        family = "Helvetica Neue"
        self.f_base = tkfont.Font(family=family, size=13)
        self.f_small = tkfont.Font(family=family, size=11)
        self.f_h1 = tkfont.Font(family=family, size=21, weight="bold")
        self.f_card = tkfont.Font(family=family, size=13, weight="bold")
        self.f_mono = tkfont.Font(family="Menlo", size=11)
        self.f_result = tkfont.Font(family=family, size=14)
        self.option_add("*Font", self.f_base)

    def _init_style(self) -> None:
        """
        Configura l'aspetto (colori, padding, bordi) dei widget ttk: header,
        card, schede del notebook, form, tabella dell'urna, barra di stato.
        È solo "estetica": non influisce sulla logica del protocollo.
        """
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".", background=BG, foreground=TEXT, font=self.f_base)

        style.configure("Header.TFrame", background=HEADER)
        style.configure("HeaderTitle.TLabel", background=HEADER,
                        foreground="#ffffff", font=self.f_h1)
        style.configure("HeaderSub.TLabel", background=HEADER,
                        foreground="#8b97ad", font=self.f_small)

        style.configure("Card.TFrame", background=CARD)
        style.configure("Card.TLabel", background=CARD, foreground=TEXT)
        style.configure("CardTitle.TLabel", background=CARD, foreground=TEXT,
                        font=self.f_card)
        style.configure("Hint.TLabel", background=CARD, foreground=MUTED,
                        font=self.f_small)
        style.configure("HintBG.TLabel", background=BG, foreground=MUTED,
                        font=self.f_small)
        style.configure("Success.TLabel", background=CARD, foreground=SUCCESS_DK)
        style.configure("Info.TLabel", background=CARD, foreground=PRIMARY_DK)

        # Notebook (schede del flusso) — minimale, senza bordi
        style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(6, 6, 6, 0))
        style.configure("TNotebook.Tab", font=self.f_base, padding=(20, 11),
                        background=BG, foreground=MUTED, borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", BG)],
                  foreground=[("selected", PRIMARY_DK), ("active", TEXT)])
        style.configure("Tab.TFrame", background=BG)

        # Form
        style.configure("Card.TRadiobutton", background=CARD, foreground=TEXT,
                        font=self.f_base)
        style.map("Card.TRadiobutton", background=[("active", CARD)],
                  indicatorcolor=[("selected", PRIMARY)])
        style.configure("TCombobox", padding=7, fieldbackground="#ffffff",
                        bordercolor=BORDER, arrowcolor=MUTED)
        style.configure("TEntry", padding=7, fieldbackground="#ffffff",
                        bordercolor=BORDER)

        # Treeview (urna)
        style.configure("Treeview", background=CARD, fieldbackground=CARD,
                        foreground=TEXT, rowheight=30, borderwidth=0, font=self.f_small)
        style.configure("Treeview.Heading", font=self.f_card, background="#eef2f8",
                        foreground=MUTED, padding=8, relief="flat")
        style.map("Treeview", background=[("selected", "#dde9ff")],
                  foreground=[("selected", TEXT)])
        style.configure("Vertical.TScrollbar", background="#dfe5ef",
                        troughcolor=CARD, borderwidth=0, arrowsize=12)

        # Status bar
        style.configure("Status.TLabel", background="#e7ebf3", foreground=MUTED,
                        font=self.f_small, padding=(14, 8))

    # ------------------------------------------------------------------ #
    # Helper di costruzione UI
    # ------------------------------------------------------------------ #
    def _card(self, parent, title=None, hint=None):
        """Card bianca ad angoli arrotondati; ritorna il frame-corpo (bg CARD)."""
        card = RoundedCard(parent, parent_bg=BG)
        card.pack(fill="x", padx=PAD, pady=9)
        inner = card.inner
        if title:
            ttk.Label(inner, text=title, style="CardTitle.TLabel").pack(
                anchor="w", pady=(0, 0))
        if hint:
            ttk.Label(inner, text=hint, style="Hint.TLabel", wraplength=840,
                      justify="left").pack(anchor="w", pady=(3, 0))
        body = ttk.Frame(inner, style="Card.TFrame")
        body.pack(fill="both", expand=True, pady=(12 if (title or hint) else 0, 0))
        return body

    def _styled_text(self, parent, **kw):
        """Crea un riquadro di testo con lo stile dell'app (usato per la verifica)."""
        return tk.Text(parent, relief="flat", highlightthickness=1,
                       highlightbackground=BORDER, highlightcolor=PRIMARY,
                       background="#fbfcfe", foreground=TEXT, padx=12, pady=9,
                       font=self.f_small, **kw)

    def _readonly_text(self, parent, content, height):
        """Riquadro di testo in sola lettura (definito da codice, non editabile)."""
        txt = tk.Text(parent, relief="flat", highlightthickness=1,
                      highlightbackground=BORDER, background="#f1f4f9",
                      foreground=MUTED, padx=12, pady=9, font=self.f_small,
                      height=height, cursor="arrow", wrap="none")
        txt.insert("1.0", content)
        txt.configure(state="disabled")  # non modificabile da interfaccia
        return txt

    def _tab_hint(self, parent, text):
        """Riga di aiuto in cima a una scheda, che ne spiega lo scopo all'utente."""
        ttk.Label(parent, text=text, style="HintBG.TLabel", wraplength=900,
                  justify="left").pack(anchor="w", padx=PAD + 2, pady=(PAD, 2))

    # ------------------------------------------------------------------ #
    # Costruzione interfaccia
    # ------------------------------------------------------------------ #
    def _build_widgets(self) -> None:
        """Costruisce l'intera finestra: header, le 4 schede del notebook e la
        barra di stato. Attiva inoltre lo scroll con la rotellina del mouse."""
        header = ttk.Frame(self, style="Header.TFrame")
        header.pack(fill="x")
        inner = ttk.Frame(header, style="Header.TFrame")
        inner.pack(fill="x", padx=24, pady=16)
        ttk.Label(inner, text="Voto elettronico sicuro",
                  style="HeaderTitle.TLabel").pack(anchor="w")
        ttk.Label(inner, text="Premio \"Tesi dell'Anno\" dell'Ateneo · WP4",
                  style="HeaderSub.TLabel").pack(anchor="w", pady=(2, 0))

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=14, pady=(8, 0))

        self._build_setup_tab()
        self._build_vote_tab()
        self._build_board_tab()
        self._build_tally_tab()

        self.status = tk.StringVar(value="Pronto. Inizia dalla scheda «① Setup».")
        ttk.Label(self, textvariable=self.status, style="Status.TLabel",
                  anchor="w").pack(fill="x", side="bottom")

        # Scroll con la rotellina del mouse: un unico gestore globale instrada
        # l'evento al canvas scrollabile che si trova sotto il puntatore.
        self.bind_all("<MouseWheel>", self._on_mousewheel)
        self.bind_all("<Button-4>", self._on_mousewheel)   # Linux scroll su
        self.bind_all("<Button-5>", self._on_mousewheel)   # Linux scroll giù

    # ------------------------------------------------------------------ #
    # Schede con scroll verticale
    # ------------------------------------------------------------------ #
    def _scrollable_tab(self, title):
        """Aggiunge una scheda al notebook con scroll verticale (canvas +
        scrollbar + rotellina). Ritorna il frame interno in cui inserire i
        contenuti: header e barra di stato restano sempre visibili."""
        outer = ttk.Frame(self.nb, style="Tab.TFrame")
        self.nb.add(outer, text=title)

        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = ttk.Frame(canvas, style="Tab.TFrame")
        window = canvas.create_window((0, 0), window=inner, anchor="nw")

        # La scrollregion segue l'altezza reale del contenuto e l'inner segue la larghezza del canvas (wrap dei testi corretto).
        inner.bind("<Configure>",
                   lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfigure(window, width=e.width))

        self._scroll_canvases.append(canvas)
        return inner

    def _on_mousewheel(self, event):
        """Instrada lo scroll al canvas scrollabile sotto il puntatore (così non
        scrollano tutte le schede insieme e non confligge con la Treeview)."""
        w = self.winfo_containing(event.x_root, event.y_root)
        while w is not None:
            if w in self._scroll_canvases:
                break
            w = getattr(w, "master", None)
        if w is None:
            return
        if event.num == 4:
            w.yview_scroll(-1, "units")
        elif event.num == 5:
            w.yview_scroll(1, "units")
        elif sys.platform == "darwin":
            w.yview_scroll(-1 * event.delta, "units")
        else:
            w.yview_scroll(int(-1 * (event.delta / 120)), "units")

    # ---- Tab 1: Setup ------------------------------------------------- #
    def _build_setup_tab(self) -> None:
        """Scheda 1 — Setup: mostra tesi ed elettorato (sola lettura) e il
        pulsante per inizializzare PKI ed entità."""
        tab = self._scrollable_tab("①  Setup")
        self._tab_hint(tab, "Tesi candidate ed elettorato sono definiti da codice e mostrati "
                            "qui in sola lettura. Premi «Inizializza elezione» per creare le "
                            "chiavi e i certificati di tutte le entità.")

        body = self._card(tab, "Tesi candidate",
                          "Sola lettura — modificabili solo da codice (DEFAULT_THESES).")
        self.txt_theses = self._readonly_text(body, "\n".join(DEFAULT_THESES), height=5)
        self.txt_theses.pack(fill="x")

        body2 = self._card(tab, "Elettorato",
                           "Sola lettura — modificabili solo da codice (DEFAULT_ELECTORATE).")
        self.txt_voters = self._readonly_text(body2, "\n".join(DEFAULT_ELECTORATE), height=7)
        self.txt_voters.pack(fill="x")

        actions = ttk.Frame(tab, style="Tab.TFrame")
        actions.pack(fill="x", padx=PAD, pady=12)
        self.btn_init = RoundedButton(actions, "Inizializza elezione",
                                      command=self.on_setup, variant="primary",
                                      parent_bg=BG, font=self.f_base)
        self.btn_init.pack(side="left")
        RoundedButton(actions, "Reset", command=self.on_reset, variant="ghost",
                      parent_bg=BG, font=self.f_base).pack(side="left", padx=10)

        self.lbl_setup = ttk.Label(tab, text="", style="HintBG.TLabel",
                                   foreground=SUCCESS_DK, justify="left", wraplength=900)
        self.lbl_setup.pack(anchor="w", padx=PAD + 2, pady=(0, PAD))

    # ---- Tab 2: Voto -------------------------------------------------- #
    def _build_vote_tab(self) -> None:
        """Scheda 2 — Voto: tre sezioni in sequenza, (1) identificazione/token,
        (2) scelta e invio della scheda, (3) verifica individuale per elettore."""
        tab = self._scrollable_tab("②  Voto")
        self.tab_vote = tab
        self._tab_hint(tab, "Identifica l'elettore, scegli la preferenza e invia: "
                            "la scheda viene cifrata prima di lasciare il dispositivo.")

        # 1 · Autenticazione
        top = self._card(tab, "1 · Identificazione dell'elettore",
                         "L'Identity Provider rilascia un token anonimo: non contiene la tua identità.")
        row = ttk.Frame(top, style="Card.TFrame")
        row.pack(fill="x")
        ttk.Label(row, text="Elettore", style="Card.TLabel").grid(row=0, column=0, sticky="w")
        self.cmb_voter = ttk.Combobox(row, state="readonly", width=18, font=self.f_base)
        self.cmb_voter.grid(row=1, column=0, padx=(0, 14), pady=(3, 0))
        self.cmb_voter.bind("<<ComboboxSelected>>", self._autofill_password)
        ttk.Label(row, text="Password", style="Card.TLabel").grid(row=0, column=1, sticky="w")
        # Password in sola lettura: si auto-inserisce alla scelta dell'elettore
        # e non è mai modificabile a mano (è un credenziale istituzionale fissa).
        self.pwd_var = tk.StringVar()
        self.ent_pwd = ttk.Entry(row, width=20, show="•", font=self.f_base,
                                 textvariable=self.pwd_var, state="readonly")
        self.ent_pwd.grid(row=1, column=1, padx=(0, 14), pady=(3, 0))
        self.btn_auth = RoundedButton(row, "Autentica", command=self.on_authenticate,
                                      variant="primary", parent_bg=CARD, font=self.f_base)
        self.btn_auth.grid(row=1, column=2, pady=(3, 0))
        self.lbl_token = ttk.Label(top, text="", style="Info.TLabel",
                                   wraplength=840, justify="left")
        self.lbl_token.pack(anchor="w", pady=(12, 0))

        # 2 · Scheda
        mid = self._card(tab, "2 · Scheda elettorale", "Seleziona una sola opzione.")
        self.choice_var = tk.IntVar(value=-1)
        self.choice_frame = ttk.Frame(mid, style="Card.TFrame")
        self.choice_frame.pack(fill="x")
        self.btn_vote = RoundedButton(mid, "Cifra e invia il voto", command=self.on_vote,
                                      variant="go", parent_bg=CARD, font=self.f_base)
        self.btn_vote.pack(anchor="w", pady=(14, 0))
        self.lbl_receipt = ttk.Label(mid, text="", style="Success.TLabel",
                                     wraplength=840, justify="left")
        self.lbl_receipt.pack(anchor="w", pady=(12, 0))

        # 3 · Verifica individuale
        bot = self._card(tab, "3 · Verifica individuale",
                         "Scegli un elettore che ha votato: la verifica viene mostrata solo "
                         "per quello selezionato (disponibile dopo la chiusura delle urne).")
        vrow = ttk.Frame(bot, style="Card.TFrame")
        vrow.pack(fill="x")
        ttk.Label(vrow, text="Elettore", style="Card.TLabel").grid(row=0, column=0, sticky="w")
        self.cmb_verify = ttk.Combobox(vrow, state="readonly", width=18, font=self.f_base)
        self.cmb_verify.grid(row=1, column=0, padx=(0, 14), pady=(3, 0))
        # Cambiando elettore l'esito precedente viene nascosto (non è il suo).
        self.cmb_verify.bind("<<ComboboxSelected>>",
                             lambda _e: self.lbl_verify_ind.config(text=""))
        self.btn_verify_ind = RoundedButton(vrow, "Verifica il voto",
                                            command=self.on_verify_individual,
                                            variant="ghost", parent_bg=CARD, font=self.f_base)
        self.btn_verify_ind.grid(row=1, column=1, pady=(3, 0))
        self.lbl_verify_ind = ttk.Label(bot, text="", style="Card.TLabel",
                                        justify="left", wraplength=840)
        self.lbl_verify_ind.pack(anchor="w", pady=(12, 0))

    # ---- Tab 3: Urna / Bulletin Board --------------------------------- #
    def _build_board_tab(self) -> None:
        """Scheda 3 — Urna pubblica: una tabella (Treeview) con le schede cifrate
        registrate e un riepilogo (Merkle root, K, opzioni). Ha già il proprio
        scroll interno, quindi non usa il wrapper scrollabile."""
        tab = ttk.Frame(self.nb, style="Tab.TFrame")
        self.nb.add(tab, text="③  Urna pubblica")
        self._tab_hint(tab, "Registro pubblico e immutabile (append-only). Chiunque può "
                            "consultarlo: contiene solo schede cifrate, mai le identità.")

        card = self._card(tab, "Bulletin Board")
        info = ttk.Frame(card, style="Card.TFrame")
        info.pack(fill="x")
        self.lbl_board_info = ttk.Label(info, text="", style="Card.TLabel", justify="left")
        self.lbl_board_info.pack(side="left")
        RoundedButton(info, "Aggiorna", command=self.refresh_board, variant="ghost",
                      parent_bg=CARD, font=self.f_base).pack(side="right")

        table = ttk.Frame(card, style="Card.TFrame")
        table.pack(fill="both", expand=True, pady=(12, 0))
        cols = ("idx", "ct", "ts")
        self.tree = ttk.Treeview(table, columns=cols, show="headings", height=13)
        self.tree.heading("idx", text="#")
        self.tree.heading("ct", text="SCHEDA CIFRATA  ct  (PREFISSO)")
        self.tree.heading("ts", text="TIMESTAMP")
        self.tree.column("idx", width=46, anchor="center")
        self.tree.column("ct", width=380)
        self.tree.column("ts", width=320)
        self.tree.tag_configure("odd", background="#f7f9fd")
        vsb = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

    # ---- Tab 4: Scrutinio & verifica ---------------------------------- #
    def _build_tally_tab(self) -> None:
        """Scheda 4 — Risultato: pulsanti per chiudere/scrutinare ed eseguire la
        verifica universale, più il riquadro col risultato ufficiale."""
        tab = self._scrollable_tab("④  Risultato")
        self._tab_hint(tab, "Chiudi le urne per avviare lo scrutinio, poi lascia che "
                            "chiunque verifichi pubblicamente la correttezza del risultato.")

        actions = ttk.Frame(tab, style="Tab.TFrame")
        actions.pack(fill="x", padx=PAD, pady=(8, 2))
        self.btn_close = RoundedButton(actions, "Chiudi urne e scrutina",
                                       command=self.on_tally, variant="primary",
                                       parent_bg=BG, font=self.f_base)
        self.btn_close.pack(side="left")
        self.btn_verify_univ = RoundedButton(actions, "Verifica universale",
                                             command=self.on_verify_universal, variant="go",
                                             parent_bg=BG, font=self.f_base)
        self.btn_verify_univ.pack(side="left", padx=10)

        res = self._card(tab, "Risultato ufficiale")
        self.lbl_result = ttk.Label(res, text="L'elezione non è ancora stata scrutinata.",
                                    style="Card.TLabel", justify="left", font=self.f_result)
        self.lbl_result.pack(anchor="w")

        ver = self._card(tab, "Verifica universale",
                         "Eseguibile da un osservatore esterno con i soli dati pubblici.")
        self.txt_verify = self._styled_text(ver, height=11, state="disabled")
        self.txt_verify.configure(font=self.f_mono)
        self.txt_verify.pack(fill="both", expand=True)

    # ================================================================== #
    #  LOGICA / CALLBACK
    # ================================================================== #
    def _set_phase_state(self) -> None:
        """Abilita/disabilita i controlli in base alla fase corrente."""
        ready = self.election is not None
        voting = ready and not self.tallied
        # Finché un token è stato rilasciato ma il voto non è ancora stato
        # confermato, l'elettore è "vincolato": non si può cambiare elettore né
        # ri-autenticare. Abbandonare un token già emesso lo renderebbe
        # inutilizzabile (l'IdP non lo rivaluta, flag voted già a True) e
        # aprirebbe a un riuso/replay. Il cambio elettore si riabilita solo a
        # voto confermato.
        selecting = voting and self.current_voter is None
        for w in (self.cmb_voter, self.ent_pwd, self.btn_auth):
            if not selecting:
                w.configure(state="disabled")
            elif w is self.btn_auth:
                w.configure(state="normal")
            else:  # combobox e password: usabili ma non modificabili a mano
                w.configure(state="readonly")
        self.btn_vote.configure(state="normal" if voting else "disabled")
        self.btn_close.configure(state="normal" if voting else "disabled")
        self.cmb_verify.configure(state="readonly" if ready else "disabled")
        self.btn_verify_ind.configure(state="normal" if ready else "disabled")
        self.btn_verify_univ.configure(state="normal" if self.tallied else "disabled")

    def _autofill_password(self, _evt=None) -> None:
        """Quando si sceglie un elettore: inserisce la sua password (sola lettura)
        e pulisce gli esiti della selezione precedente."""
        vid = self.cmb_voter.get()
        self.pwd_var.set(self.credentials.get(vid, ""))
        self.lbl_token.config(text="")
        self.lbl_receipt.config(text="")
        self.lbl_verify_ind.config(text="")

    def on_setup(self) -> None:
        """Pulsante «Inizializza elezione»: legge i dati di default, crea
        l'oggetto Election (PKI + entità) e prepara le schede per la votazione."""
        # Tesi ed elettorato sono definiti da codice (sola lettura in GUI).
        theses = [t.strip() for t in DEFAULT_THESES if t.strip()]
        creds: dict[str, str] = {}
        for line in DEFAULT_ELECTORATE:
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                messagebox.showerror("Errore", f"Riga elettorato non valida nel codice: {line!r}\n"
                                               "Usa il formato  id:password")
                return
            vid, pwd = line.split(":", 1)
            creds[vid.strip()] = pwd.strip()
        if not theses or not creds:
            messagebox.showerror("Errore", "Servono almeno una tesi e un elettore (DEFAULT_*).")
            return

        self.status.set("Inizializzazione PKI ed entità in corso…")
        self.update_idletasks()
        self.election = Election("premio-tesi-2026", theses)
        self.election.setup(creds)
        self.credentials = creds
        self.voters = {}
        self.current_voter = None
        self.tallied = False

        self.cmb_voter["values"] = list(creds.keys())
        self.cmb_voter.set("")
        self._refresh_verify_voters()   # nessun votante ancora -> elenco vuoto
        self._build_choices()
        self.lbl_setup.config(
            text=f"✓ Elezione inizializzata.  CA: {self.election.ca.name}  ·  "
                 f"tesi: {len(theses)} (+ scheda bianca)  ·  N_elig: {len(creds)}\n"
                 f"   Certificati X.509 emessi, CRL pubblicata, lista candidati firmata.")
        self.lbl_result.config(text="L'elezione non è ancora stata scrutinata.")
        self._clear_verify_text()
        self.refresh_board()
        self._set_phase_state()
        self.status.set("Setup completato. Vai alla scheda «② Voto».")
        self.nb.select(1)

    def on_reset(self) -> None:
        """Pulsante «Reset»: azzera tutto lo stato e svuota i campi, tornando
        alla situazione iniziale (nessuna elezione)."""
        self.election = None
        self.credentials = {}
        self.voters = {}
        self.current_voter = None
        self.tallied = False
        self.cmb_voter["values"] = []
        self.cmb_voter.set("")
        self.cmb_verify["values"] = []
        self.cmb_verify.set("")
        self.pwd_var.set("")
        self.choice_var.set(-1)
        self.lbl_token.config(text="")
        self.lbl_receipt.config(text="")
        self.lbl_verify_ind.config(text="")
        self.lbl_setup.config(text="")
        self.lbl_result.config(text="L'elezione non è ancora stata scrutinata.")
        for r in self.tree.get_children():
            self.tree.delete(r)
        self.lbl_board_info.config(text="")
        self._clear_verify_text()
        self._set_phase_state()
        self.status.set("Reset eseguito. Inizia dalla scheda «① Setup».")

    def _build_choices(self) -> None:
        """Crea i radio-button della scheda elettorale dalla lista dei candidati
        (le tesi in ordine, poi la scheda bianca in fondo)."""
        for w in self.choice_frame.winfo_children():
            w.destroy()
        self.choice_var.set(-1)
        titles = self.election.bb.get("candidates")["titles"]
        ordered = [(cid, t) for cid, t in titles.items() if cid != BLANK_ID]
        ordered.append((BLANK_ID, titles[BLANK_ID]))
        for cid, title in ordered:
            ttk.Radiobutton(self.choice_frame, text=title, value=cid,
                            variable=self.choice_var,
                            style="Card.TRadiobutton").pack(anchor="w", pady=4)

    def on_authenticate(self) -> None:
        """Pulsante «Autentica»: chiede il token all'IdP per l'elettore scelto.
        Se va a buon fine, vincola l'elettore fino alla conferma del voto."""
        vid = self.cmb_voter.get()
        pwd = self.ent_pwd.get()
        if not vid:
            messagebox.showwarning("Attenzione", "Seleziona un elettore.")
            return
        if vid in self.voters and getattr(self.voters[vid], "fascicolo", None):
            messagebox.showinfo("Già votato",
                                f"L'elettore {vid} ha già espresso il proprio voto (unicità).")
            return
        try:
            voter = self.election.new_voter(vid, pwd)
            nonce, _ = voter.authenticate(self.election.idp, self.election.bb)
            self.current_voter = voter
            self.lbl_token.config(
                text=f"✓ Token rilasciato (nonce N = {nonce[:8].hex()}…, firmato dall'IdP). "
                     f"Nessuna informazione identificativa nel token.")
            self.lbl_receipt.config(text="")
            self.lbl_verify_ind.config(text="")
            # Token emesso: vincola l'elettore finché non conferma il voto.
            self._set_phase_state()
            self.status.set(f"{vid} autenticato. Seleziona una preferenza e vota "
                            "(cambio elettore bloccato fino alla conferma).")
        except AuthenticationError as exc:
            messagebox.showerror("Autenticazione fallita", str(exc))
        except CertificateRejected as exc:
            messagebox.showerror("Certificato rifiutato (hard-fail)", str(exc))

    def on_vote(self) -> None:
        """Pulsante «Cifra e invia il voto»: cifra la scheda e la invia all'AE.
        A voto confermato sblocca la selezione e azzera token/scheda/password."""
        if self.current_voter is None:
            messagebox.showwarning("Attenzione", "Autenticati prima di votare.")
            return
        choice = self.choice_var.get()
        if choice == -1:
            messagebox.showwarning("Attenzione", "Seleziona una preferenza (o la scheda bianca).")
            return
        try:
            receipt = self.current_voter.cast_vote(self.election.ae, choice, self.election.bb)
        except VoteRejected as exc:
            messagebox.showerror("Voto rifiutato", str(exc))
            return
        except CertificateRejected as exc:
            messagebox.showerror("Certificato rifiutato (hard-fail)", str(exc))
            return
        self.voters[self.current_voter.voter_id] = self.current_voter
        self._refresh_verify_voters()   # l'elettore ora è verificabile
        self.lbl_receipt.config(
            text=f"✓ Voto cifrato (RSA-OAEP) e registrato.\n"
                 f"   Ricevuta ρ firmata dall'AE su ct = {receipt['ct'][:8].hex()}…\n"
                 f"   Timestamp: {receipt['timestamp']}")
        self.current_voter = None
        self.cmb_voter.set("")
        self.pwd_var.set("")
        self.choice_var.set(-1)   # azzera la selezione della scheda (privacy)
        self.lbl_token.config(text="")
        # Voto confermato: sblocca la selezione di un nuovo elettore.
        self._set_phase_state()
        self.refresh_board()
        self.status.set(f"Voto registrato. Schede nell'urna: {len(self.election.bb)}.")

    def _refresh_verify_voters(self) -> None:
        """Aggiorna l'elenco selezionabile con i soli elettori che hanno votato."""
        voted = [vid for vid, v in self.voters.items() if getattr(v, "fascicolo", None)]
        self.cmb_verify["values"] = voted
        if self.cmb_verify.get() not in voted:
            self.cmb_verify.set("")

    def on_verify_individual(self) -> None:
        vid = self.cmb_verify.get()
        if not vid:
            messagebox.showinfo("Verifica individuale",
                                "Seleziona un elettore che ha votato.")
            return
        v = self.voters.get(vid)
        if v is None or not getattr(v, "fascicolo", None):
            messagebox.showinfo("Verifica individuale",
                                f"L'elettore {vid} non ha ancora votato.")
            return
        if not self.tallied:
            messagebox.showinfo(
                "Verifica individuale",
                "La verifica individuale completa (inclusione via Merkle proof + "
                "presenza in D) è disponibile dopo la chiusura delle urne.\n\n"
                "Vai alla scheda «④ Risultato» e premi «Chiudi urne e scrutina».")
            return
        ok = v.verify_individual(self.election.ae, self.election.bb)
        self.lbl_verify_ind.config(
            text=(f"Elettore {vid}:  "
                  + ("✓ voto verificato — incluso nell'urna e conteggiato correttamente."
                     if ok else "✗ verifica FALLITA.")),
            foreground=SUCCESS_DK if ok else DANGER)

    def refresh_board(self) -> None:
        """Ridisegna la tabella dell'urna e il riepilogo (schede, Merkle root, K)."""
        for r in self.tree.get_children():
            self.tree.delete(r)
        if self.election is None:
            return
        bb = self.election.bb
        for i, e in enumerate(bb.entries, start=1):
            tag = "odd" if i % 2 else ""
            self.tree.insert("", "end", tags=(tag,),
                             values=(i, e["ct"][:24].hex() + "…", e["timestamp"]))
        root = bb.current_root()
        root_txt = root[:12].hex() + "…" if root else "—"
        tc = bb.get("token_count")
        k_txt = f"   ·   Token emessi K: {tc['K']}" if tc else ""
        cand = bb.get("candidates")
        c_txt = f"   ·   Opzioni: {len(cand['C'])}" if cand else ""
        self.lbl_board_info.config(
            text=f"Schede registrate: {len(bb)}   ·   Merkle root: {root_txt}{k_txt}{c_txt}\n"
                 f"Ogni inserimento aggiorna e firma la Merkle root (integrità verificabile).")

    def on_tally(self) -> None:
        """Pulsante «Chiudi urne e scrutina»: chiude le urne, esegue lo scrutinio
        e mostra il risultato ufficiale (conteggi e vincitore)."""
        if self.election is None or self.tallied:
            return
        if len(self.election.bb) == 0:
            if not messagebox.askyesno("Nessun voto",
                                       "Nessuna scheda registrata. Chiudere comunque?"):
                return
        out = self.election.close_and_tally()
        self.tallied = True
        T = out["tally"]["T"]
        titles = self.election.bb.get("candidates")["titles"]
        lines = ["Conteggio:"]
        for cid, count in T.items():
            label = titles[cid]
            lines.append(f"   {count:>2} voti   {label}")
        winner = max((c for c in T if c != BLANK_ID), key=lambda c: T[c])
        valid = len(out["tally"]["D"])
        invalid = len(out["tally"]["I"])
        lines.append("")
        lines.append(f"Schede valide: {valid}  ·  invalide: {invalid}  ·  "
                     f"K: {self.election.bb.get('token_count')['K']}")
        lines.append(f"Vincitore: {titles[winner]}  ({T[winner]} voti)")
        self.lbl_result.config(text="\n".join(lines))
        self.refresh_board()
        self._set_phase_state()
        self.status.set("Scrutinio completato. Esegui la verifica universale.")
        self.nb.select(3)

    def on_verify_universal(self) -> None:
        """Pulsante «Verifica universale»: esegue tutti i controlli pubblici e
        ne stampa l'esito passo per passo nel riquadro."""
        if not self.tallied:
            return
        checks = verify_election(self.election.bb, self.election.ca_public)
        self._clear_verify_text()
        self.txt_verify.configure(state="normal")
        for name, res in checks.items():
            if name == "OK":
                continue
            self.txt_verify.insert("end", f"[{'OK ' if res else 'KO '}]  {name}\n")
        self.txt_verify.insert("end", "\n")
        overall = "ELEZIONE VERIFICATA ✓" if checks["OK"] else "VERIFICA FALLITA ✗"
        self.txt_verify.insert("end", f">>> Esito complessivo: {overall}\n")
        self.txt_verify.configure(state="disabled")
        self.status.set("Verifica universale eseguita.")

    def _clear_verify_text(self) -> None:
        """Svuota il riquadro della verifica universale."""
        self.txt_verify.configure(state="normal")
        self.txt_verify.delete("1.0", "end")
        self.txt_verify.configure(state="disabled")


if __name__ == "__main__":
    VotingGUI().mainloop()
