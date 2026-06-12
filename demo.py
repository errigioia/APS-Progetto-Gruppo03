#!/usr/bin/env python3
"""
demo.py — Scenario completo e "narrato" del protocollo di voto.

Esegue un'intera elezione del Premio "Tesi dell'Anno" simulando in-process tutte
le entità (CA, Commissione, IdP, AE, Bulletin Board, Elettori). È pensato per
essere letto dall'alto verso il basso e seguire il protocollo passo passo:

  1. setup e distribuzione delle chiavi (PKI X.509 + CRL);
  2. autenticazione, votazione e ricevute;
  3. chiusura, scrutinio e pubblicazione del risultato;
  4. verifica individuale (elettore) e universale (osservatore);
  5. controlli "negativi": il sistema deve RIFIUTARE doppio voto, token
     contraffatto e certificato revocato (hard-fail).

Esecuzione:  python3 demo.py
"""

from wp4 import crypto_utils as cu
from wp4.authority import VoteRejected
from wp4.commission import BLANK_ID, encode_choice
from wp4.election import Election
from wp4.idp import AuthenticationError, token_message
from wp4.pki import CertificateRejected
from wp4.verifier import verify_election


# Piccole funzioni di stampa, solo per rendere l'output leggibile.
def banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)


def step(msg: str) -> None:
    print(f"  - {msg}")


# Dati dell'elezione di esempio.
THESES = [
    "Tesi A — Crittografia post-quantistica",
    "Tesi B — Privacy nei sistemi distribuiti",
    "Tesi C — Sicurezza dei protocolli IoT",
]

# Elettorato: studenti e docenti, tutti con peso identico (1 elettore = 1 voto).
ELECTORATE = {
    "stud01": "pwd-stud01",
    "stud02": "pwd-stud02",
    "stud03": "pwd-stud03",
    "stud04": "pwd-stud04",
    "stud05": "pwd-stud05",
    "doc01": "pwd-doc01",
    "doc02": "pwd-doc02",
    "doc03": "pwd-doc03",
}

# Preferenza di ciascun elettore (id 1..k = tesi, BLANK_ID = scheda bianca).
PREFERENCES = {
    "stud01": 1, "stud02": 2, "stud03": 1, "stud04": 3,
    "stud05": 1, "doc01": 2, "doc02": 1, "doc03": BLANK_ID,
}


# --------------------------------------------------------------------------- #
def run_full_election() -> None:
    """Conduce l'elezione "felice", dal setup alla verifica universale."""

    banner("FASE 0 — SETUP E DISTRIBUZIONE DELLE CHIAVI (PKI X.509 + CRL)")
    election = Election(election_id="premio-tesi-2026", theses=THESES)
    election.setup(ELECTORATE)
    step(f"CA dedicata creata: {election.ca.name} (self-signed, ancora di fiducia)")
    step("Certificati X.509 emessi per IdP, AE(firma), AE(cifra), Commissione")
    step("CRL iniziale (vuota) pubblicata sul bulletin board")
    step(f"Lista candidati firmata dalla Commissione: {len(THESES)} tesi + scheda bianca")
    step(f"Registro R caricato e N_elig={len(ELECTORATE)} firmato e pubblicato")

    banner("FASE 1+2 — AUTENTICAZIONE E VOTAZIONE")
    voters = {}
    for vid, pwd in ELECTORATE.items():
        v = election.new_voter(vid, pwd)
        v.authenticate(election.idp, election.bb)              # ottiene il token
        receipt = v.cast_vote(election.ae, PREFERENCES[vid], election.bb)  # vota
        voters[vid] = v
        step(f"{vid:>7}  ha votato  ->  ricevuta su ct={receipt['ct'][:6].hex()}…")
    step(f"Schede registrate sul bulletin board: {len(election.bb)}")

    banner("FASE 3 — NOTA SULLA VERIFICA INDIVIDUALE")
    step("La verifica individuale completa avviene DOPO la chiusura (serve la root finale).")

    banner("FASE 4 — CHIUSURA E SCRUTINIO")
    out = election.close_and_tally()
    closure, tally = out["closure"], out["tally"]
    step(f"Urne chiuse — Merkle root finale: {closure['merkle_root_final'][:8].hex()}…")
    step(f"Token emessi K = {election.bb.get('token_count')['K']}")
    step(f"Schede valide: {len(tally['D'])}  |  invalide: {len(tally['I'])}")

    # Stampa del risultato ufficiale.
    print("\n  Risultato ufficiale:")
    titles = election.bb.get("candidates")["titles"]
    T = tally["T"]
    for cid, count in T.items():
        label = "Scheda bianca" if cid == BLANK_ID else titles[cid]
        print(f"      {count:>2} voti   {label}")
    # Vincitore: si esclude la scheda bianca dal confronto.
    thesis_counts = {c: T[c] for c in T if c != BLANK_ID}
    max_votes = max(thesis_counts.values()) if thesis_counts else 0
    if max_votes == 0:
        print("\n  >>> Vincitore: nessuno — nessuna preferenza espressa per le tesi.")
    else:
        top = [c for c, v in thesis_counts.items() if v == max_votes]
        if len(top) == 1:
            print(f"\n  >>> Vincitore: {titles[top[0]]}  ({max_votes} voti)")
        else:
            tied = ", ".join(titles[c] for c in top)
            print(f"\n  >>> Pareggio ({max_votes} voti ciascuno): {tied}")

    banner("FASE 3 (post-chiusura) — VERIFICA INDIVIDUALE DELL'ELETTORE")
    all_ok = all(
        v.verify_individual(election.ae, election.bb) for v in voters.values()
    )
    step(f"Tutti gli elettori verificano il proprio voto (F): {all_ok}")

    banner("FASE 5 — VERIFICA UNIVERSALE (osservatore esterno)")
    checks = verify_election(election.bb, election.ca_public)
    for name, ok in checks.items():
        if name != "OK":
            print(f"      [{'OK ' if ok else 'KO '}] {name}")
    print(f"\n  >>> Esito complessivo verifica universale: {checks['OK']}")


# --------------------------------------------------------------------------- #
def run_security_validations() -> None:
    """
    Controlli "negativi": dimostrano che il sistema RIFIUTA gli abusi.
    Ogni blocco crea una piccola elezione a parte e prova un attacco.
    """
    banner("VALIDAZIONI FUNZIONALI DELLE PROPRIETÀ DI SICUREZZA")

    # --- Unicità: lo stesso elettore prova ad autenticarsi due volte ---------- #
    e = Election("test-unicita", THESES)
    e.setup({"u1": "p1"})
    v = e.new_voter("u1", "p1")
    v.authenticate(e.idp, e.bb)
    v.cast_vote(e.ae, 1, e.bb)
    try:
        e.new_voter("u1", "p1").authenticate(e.idp, e.bb)  # ha già votato
        print("  [KO ] Unicità: secondo voto NON bloccato")
    except AuthenticationError:
        print("  [OK ] Unicità: secondo tentativo di autenticazione bloccato (flag voted)")

    # --- Doppio voto: stesso token, ma scheda diversa ------------------------- #
    nonce, sigma_N = v._token  # token già speso da u1
    fake_ct = cu.rsa_encrypt(e.ae.enc_public_key, encode_choice(2) + cu.new_nonce())
    try:
        e.ae.cast_vote((nonce, sigma_N, fake_ct), e.bb.get("crl"))
        print("  [KO ] Doppio voto (token riusato) NON bloccato")
    except VoteRejected:
        print("  [OK ] Doppio voto: token già speso con ct diverso -> scartato")

    # --- Recovery: re-invio IDENTICO dello stesso voto (deve essere accettato) - #
    same_ct = v.fascicolo["ct"]
    receipt = e.ae.cast_vote((nonce, sigma_N, same_ct), e.bb.get("crl"))
    esito = "OK " if receipt.get("resent") else "KO "
    print(f"  [{esito}] Recovery: re-invio identico riconosciuto (resent={receipt.get('resent')})")

    # --- Autenticità: token con firma contraffatta (di un'altra chiave) ------- #
    e2 = Election("test-autenticita", THESES)
    e2.setup({"u1": "p1"})
    attacker_key = cu.generate_rsa_keypair()
    fnonce = cu.new_nonce()
    forged_sig = cu.rsa_sign(attacker_key, token_message(fnonce, e2.election_id))
    ct = cu.rsa_encrypt(e2.ae.enc_public_key, encode_choice(1) + cu.new_nonce())
    try:
        e2.ae.cast_vote((fnonce, forged_sig, ct), e2.bb.get("crl"))
        print("  [KO ] Autenticità: token contraffatto accettato")
    except VoteRejected:
        print("  [OK ] Autenticità: token con firma non valida -> scartato")

    # --- Hard-fail: certificato dell'IdP revocato ----------------------------- #
    e3 = Election("test-revoca", THESES)
    e3.setup({"u1": "p1"})
    e3.revoke(e3.idp.cert)  # la CA revoca il certificato dell'IdP
    try:
        e3.new_voter("u1", "p1").authenticate(e3.idp, e3.bb)
        print("  [KO ] Hard-fail: autenticazione su cert revocato NON bloccata")
    except CertificateRejected:
        print("  [OK ] Hard-fail: certificato IdP revocato -> autenticazione interrotta")


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    run_full_election()
    run_security_validations()
    print("\nDemo completata.\n")
