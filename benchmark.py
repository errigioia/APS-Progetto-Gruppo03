#!/usr/bin/env python3
"""
benchmark.py — Misure di prestazione del protocollo.

Raccoglie le metriche richieste dalla traccia:
  1) costo delle singole operazioni crittografiche;
  2) dimensione dei messaggi scambiati;
  3) tempi delle fasi e latenza delle verifiche al crescere del numero di elettori.

Esecuzione:  python3 benchmark.py
Salva un riepilogo in results/benchmark.csv.
"""

import csv
import os
import statistics
import time

from wp4 import crypto_utils as cu
from wp4.commission import encode_choice
from wp4.election import Election
from wp4.verifier import verify_election

THESES = ["Tesi A", "Tesi B", "Tesi C"]


# --------------------------------------------------------------------------- #
def timeit(funzione, ripetizioni: int) -> tuple[float, float]:
    """
    Esegue 'funzione' per 'ripetizioni' volte e misura il tempo di ciascuna.
    Restituisce (media in ms, deviazione standard in ms).
    """
    tempi = []
    for _ in range(ripetizioni):
        inizio = time.perf_counter()
        funzione()
        tempi.append((time.perf_counter() - inizio) * 1000.0)  # secondi -> ms
    deviazione = statistics.stdev(tempi) if len(tempi) > 1 else 0.0
    return statistics.mean(tempi), deviazione


def section(title: str) -> None:
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)


# --------------------------------------------------------------------------- #
# 1) Costo delle singole primitive crittografiche
# --------------------------------------------------------------------------- #
def micro_benchmarks() -> list[dict]:
    section("1) COSTO DELLE OPERAZIONI CRITTOGRAFICHE (media su N esecuzioni)")
    righe = []

    # Prepariamo chiavi e dati di prova da riutilizzare nelle misure.
    priv = cu.generate_rsa_keypair()
    pub = priv.public_key()
    msg = encode_choice(1) + cu.new_nonce()      # scheda in chiaro: voto || r (36 byte)
    ct = cu.rsa_encrypt(pub, msg)
    sig = cu.rsa_sign(priv, cu.sha256(b"payload"))

    # (nome, funzione da misurare, numero di ripetizioni).
    operazioni = [
        ("RSA-2048 keygen",            lambda: cu.generate_rsa_keypair(),         20),
        ("RSA-OAEP encrypt (scheda)",  lambda: cu.rsa_encrypt(pub, msg),          200),
        ("RSA-OAEP decrypt (scheda)",  lambda: cu.rsa_decrypt(priv, ct),          200),
        ("RSA-PSS sign",               lambda: cu.rsa_sign(priv, cu.sha256(b"x")), 200),
        ("RSA-PSS verify",             lambda: cu.rsa_verify(pub, sig, cu.sha256(b"payload")), 200),
        ("SHA-256 (64 byte)",          lambda: cu.sha256(b"x" * 64),              5000),
    ]
    print(f"  {'operazione':<32}{'media (ms)':>14}{'std (ms)':>12}{'iter':>8}")
    print("  " + "-" * 66)
    for nome, funzione, ripetizioni in operazioni:
        media, deviazione = timeit(funzione, ripetizioni)
        print(f"  {nome:<32}{media:>14.4f}{deviazione:>12.4f}{ripetizioni:>8}")
        righe.append({"categoria": "operazione_crypto", "voce": nome,
                      "valore": f"{media:.4f}", "unita": "ms"})
    return righe


# --------------------------------------------------------------------------- #
# 2) Dimensione dei messaggi scambiati
# --------------------------------------------------------------------------- #
def message_sizes() -> list[dict]:
    section("2) DIMENSIONE DEI MESSAGGI SCAMBIATI")

    # Conduciamo una mini-elezione con 100 elettori, così la prova di Merkle ha
    # una profondità realistica.
    n = 100
    creds = {f"u{i:03d}": f"p{i}" for i in range(n)}
    e = Election("bench-sizes", THESES)
    e.setup(creds)

    primo = None
    for vid, pwd in creds.items():
        v = e.new_voter(vid, pwd)
        nonce, sigma_N = v.authenticate(e.idp, e.bb)
        receipt = v.cast_vote(e.ae, 1, e.bb)
        if primo is None:
            primo = v  # teniamo il primo elettore per misurare la sua prova di Merkle

    ct = primo.fascicolo["ct"]
    proof = e.bb.proof_for(ct)
    proof_bytes = sum(len(h) for h, _ in proof) if proof else 0
    proof_hashes = len(proof) if proof else 0

    misure = [
        ("Nonce N", len(nonce)),
        ("Firma token sigma_N", len(sigma_N)),
        ("Token T = (N, sigma_N)", len(nonce) + len(sigma_N)),
        ("Scheda cifrata ct (RSA-OAEP)", len(ct)),
        ("Messaggio di voto M_vote = (N, sigma_N, ct)", len(nonce) + len(sigma_N) + len(ct)),
        ("Ricevuta rho", len(receipt["rho"])),
        (f"Merkle proof ({n} schede su BB, {proof_hashes} hash)", proof_bytes),
    ]
    print(f"  {'messaggio':<46}{'byte':>10}")
    print("  " + "-" * 56)
    righe = []
    for nome, byte in misure:
        print(f"  {nome:<46}{byte:>10}")
        righe.append({"categoria": "dimensione_messaggio", "voce": nome,
                      "valore": str(byte), "unita": "byte"})
    return righe


# --------------------------------------------------------------------------- #
# 3) Tempi delle fasi e latenza delle verifiche al variare dell'elettorato
# --------------------------------------------------------------------------- #
def scaling_benchmarks(numeri_elettori: list[int]) -> list[dict]:
    section("3) TEMPI DELLE FASI E LATENZE AL VARIARE DEL NUMERO DI ELETTORI")
    print(f"  {'N elettori':>11}{'voto tot (ms)':>16}{'voto/el (ms)':>15}"
          f"{'scrutinio (ms)':>16}{'verif.indiv (ms)':>18}{'verif.univ (ms)':>17}")
    print("  " + "-" * 92)

    righe = []
    for n in numeri_elettori:
        creds = {f"v{i:05d}": f"pwd{i}" for i in range(n)}
        e = Election(f"bench-{n}", THESES)
        e.setup(creds)

        # Autenticazione di tutti gli elettori (NON cronometrata: misuriamo il voto).
        voters = []
        for vid, pwd in creds.items():
            v = e.new_voter(vid, pwd)
            v.authenticate(e.idp, e.bb)
            voters.append(v)

        # Fase di votazione: cifratura + invio + registrazione + ricevuta.
        t0 = time.perf_counter()
        for i, v in enumerate(voters):
            v.cast_vote(e.ae, (i % len(THESES)) + 1, e.bb)
        voto_totale = (time.perf_counter() - t0) * 1000.0

        # Scrutinio: chiusura + decifrazione + conteggio + firma.
        t0 = time.perf_counter()
        e.close_and_tally()
        scrutinio = (time.perf_counter() - t0) * 1000.0

        # Latenza media della verifica individuale (su un campione di elettori).
        campione = voters[: min(20, n)]
        t0 = time.perf_counter()
        for v in campione:
            v.verify_individual(e.ae, e.bb)
        verif_indiv = (time.perf_counter() - t0) * 1000.0 / len(campione)

        # Latenza della verifica universale (l'intero controllo pubblico).
        verif_univ, _ = timeit(lambda: verify_election(e.bb, e.ca_public), 5)

        voto_per_elettore = voto_totale / n
        print(f"  {n:>11}{voto_totale:>16.2f}{voto_per_elettore:>15.3f}"
              f"{scrutinio:>16.2f}{verif_indiv:>18.3f}{verif_univ:>17.2f}")
        righe.append({"categoria": "scaling", "voce": f"N={n}",
                      "valore": f"voto_tot={voto_totale:.2f};voto_el={voto_per_elettore:.3f};"
                                f"scrutinio={scrutinio:.2f};vind={verif_indiv:.3f};"
                                f"vuniv={verif_univ:.2f}",
                      "unita": "ms"})
    return righe


# --------------------------------------------------------------------------- #
def main() -> None:
    print("Benchmark WP4 — voto elettronico sicuro (RSA-2048, SHA-256)")
    righe = []
    righe += micro_benchmarks()
    righe += message_sizes()
    righe += scaling_benchmarks([10, 50, 100, 200])

    # Salva tutto in un CSV riepilogativo.
    os.makedirs("results", exist_ok=True)
    percorso = os.path.join("results", "benchmark.csv")
    with open(percorso, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["categoria", "voce", "valore", "unita"])
        writer.writeheader()
        writer.writerows(righe)
    print(f"\nRiepilogo salvato in {percorso}\n")


if __name__ == "__main__":
    main()
