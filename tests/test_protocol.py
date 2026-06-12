#!/usr/bin/env python3
"""
Test del protocollo di voto.

Per ogni proprietà di sicurezza c'è un test. Sono di due tipi:
  * "happy path": il sistema fa la cosa giusta quando tutto è regolare;
  * test negativi: il sistema RIFIUTA un abuso (doppio voto, token falso, ecc.).

Si può eseguire in due modi:
  * python3 -m pytest tests/
  * python3 tests/test_protocol.py
"""

import os
import sys

# Permette di importare il package `wp4` anche eseguendo direttamente questo file.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wp4 import crypto_utils as cu
from wp4.authority import VoteRejected, receipt_message
from wp4.commission import BLANK_ID, encode_choice
from wp4.election import Election
from wp4.idp import AuthenticationError, token_message
from wp4.pki import CertificateRejected
from wp4.verifier import verify_election

THESES = ["Tesi A", "Tesi B", "Tesi C"]


def _run_election(prefs):
    """
    Helper: conduce un'intera elezione date le preferenze {voter_id: scelta}.
    Restituisce (election, voters) per i controlli successivi.
    """
    creds = {vid: f"pwd-{vid}" for vid in prefs}
    e = Election("test", THESES)
    e.setup(creds)
    voters = {}
    for vid in prefs:
        v = e.new_voter(vid, creds[vid])
        v.authenticate(e.idp, e.bb)
        v.cast_vote(e.ae, prefs[vid], e.bb)
        voters[vid] = v
    e.close_and_tally()
    return e, voters


# --------------------------------------------------------------------------- #
def test_happy_path_e_conteggio():
    """Conteggio corretto: 2 voti a Tesi 1, 1 a Tesi 2, 1 scheda bianca."""
    prefs = {"a": 1, "b": 1, "c": 2, "d": BLANK_ID}
    e, _ = _run_election(prefs)
    T = e.bb.get("result")["T"]
    assert T[1] == 2 and T[2] == 1 and T[3] == 0 and T[BLANK_ID] == 1
    assert len(e.bb.get("decryption")["D"]) == 4   # 4 schede valide
    assert len(e.bb.get("decryption")["I"]) == 0   # nessuna scheda invalida


def test_verifica_individuale():
    """Ogni elettore onesto verifica con successo il proprio voto."""
    e, voters = _run_election({"a": 1, "b": 2})
    for v in voters.values():
        assert v.verify_individual(e.ae, e.bb) is True


def test_verifica_universale():
    """La verifica universale (tutti i controlli pubblici) ha esito positivo."""
    e, _ = _run_election({"a": 1, "b": 2, "c": 3})
    checks = verify_election(e.bb, e.ca_public)
    assert checks["OK"] is True


def test_unicita_doppia_autenticazione():
    """Unicità: lo stesso elettore non può autenticarsi una seconda volta."""
    e = Election("t", THESES)
    e.setup({"a": "p"})
    v = e.new_voter("a", "p")
    v.authenticate(e.idp, e.bb)
    v.cast_vote(e.ae, 1, e.bb)
    try:
        e.new_voter("a", "p").authenticate(e.idp, e.bb)
        assert False, "doppia autenticazione non bloccata"
    except AuthenticationError:
        pass  # comportamento atteso


def test_doppio_voto_token_riusato():
    """Doppio voto: stesso token ma scheda diversa -> l'AE lo rifiuta."""
    e = Election("t", THESES)
    e.setup({"a": "p"})
    v = e.new_voter("a", "p")
    v.authenticate(e.idp, e.bb)
    v.cast_vote(e.ae, 1, e.bb)
    nonce, sigma_N = v._token
    altra_scheda = cu.rsa_encrypt(e.ae.enc_public_key, encode_choice(2) + cu.new_nonce())
    try:
        e.ae.cast_vote((nonce, sigma_N, altra_scheda), e.bb.get("crl"))
        assert False, "doppio voto non bloccato"
    except VoteRejected:
        pass    # comportamento atteso


def test_recovery_reinvio_identico():
    """Recovery: re-inviare lo STESSO identico voto è legittimo (resent=True)."""
    e = Election("t", THESES)
    e.setup({"a": "p"})
    v = e.new_voter("a", "p")
    v.authenticate(e.idp, e.bb)
    v.cast_vote(e.ae, 1, e.bb)
    nonce, sigma_N = v._token
    receipt = e.ae.cast_vote((nonce, sigma_N, v.fascicolo["ct"]), e.bb.get("crl"))
    assert receipt.get("resent") is True


def test_token_contraffatto():
    """Autenticità: un token firmato da una chiave diversa dall'IdP è rifiutato."""
    e = Election("t", THESES)
    e.setup({"a": "p"})
    attaccante = cu.generate_rsa_keypair()
    nonce = cu.new_nonce()
    firma_falsa = cu.rsa_sign(attaccante, token_message(nonce, e.election_id))
    ct = cu.rsa_encrypt(e.ae.enc_public_key, encode_choice(1) + cu.new_nonce())
    try:
        e.ae.cast_vote((nonce, firma_falsa, ct), e.bb.get("crl"))
        assert False, "token contraffatto accettato"
    except VoteRejected:
        pass    # comportamento atteso


def test_hard_fail_certificato_revocato():
    """Hard-fail: se il certificato dell'IdP è revocato, l'autenticazione si blocca."""
    e = Election("t", THESES)
    e.setup({"a": "p"})
    e.revoke(e.idp.cert)
    v = e.new_voter("a", "p")
    try:
        v.authenticate(e.idp, e.bb)
        assert False, "autenticazione su cert revocato non bloccata"
    except CertificateRejected:
        pass    # comportamento atteso


def test_ricevuta_contraffatta_fallisce_verifica():
    """Integrità: una ricevuta non firmata dall'AE fa fallire la verifica individuale."""
    e, voters = _run_election({"a": 1})
    v = voters["a"]
    # Sostituiamo la ricevuta con una firmata da una chiave NON dell'AE.
    chiave_finta = cu.generate_rsa_keypair()
    v.fascicolo["rho"] = cu.rsa_sign(
        chiave_finta, receipt_message(v.fascicolo["ct"], v.fascicolo["timestamp"], e.election_id)
    )
    assert v.verify_individual(e.ae, e.bb) is False


# --------------------------------------------------------------------------- #
# Runner integrato: esegue tutti i test_* e stampa un riepilogo (senza pytest).
# --------------------------------------------------------------------------- #
def _main():
    tests = [fn for nome, fn in sorted(globals().items()) if nome.startswith("test_")]
    passati = 0
    for test in tests:
        try:
            test()
            print(f"  [PASS] {test.__name__}")
            passati += 1
        except AssertionError as exc:
            print(f"  [FAIL] {test.__name__}: {exc}")
        except Exception as exc:
            print(f"  [ERR ] {test.__name__}: {type(exc).__name__}: {exc}")
    print(f"\n{passati}/{len(tests)} test superati.")
    return 0 if passati == len(tests) else 1


if __name__ == "__main__":
    raise SystemExit(_main())
