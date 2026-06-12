"""
verifier — Verifica universale dell'elezione.

Chiunque (un candidato, la Commissione, un osservatore esterno) può controllare
che il risultato sia corretto usando SOLO i dati pubblici del bulletin board e la
chiave pubblica della CA. Non serve alcun segreto.

La funzione verify_election() esegue tutti i controlli e restituisce un
dizionario "nome del controllo -> esito" più la chiave "OK" con l'esito globale
(che è semplicemente l'AND di tutti gli altri). I passi sono:

  0.     i certificati di AE (firma), IdP e Commissione sono validi e non
         revocati (CRL hard-fail): sono le chiavi con cui si verificano le firme;
  -      la lista dei candidati è firmata dalla Commissione;
  1.     la chiusura dell'urna è firmata dall'AE;
  2.     ricalcolando la Merkle root si riottiene quella firmata (integrità);
  3.     la lista di decifrazione D è coerente con l'urna  (|BB| = |D| + |I|);
  3-bis. bilancio dei voti  m <= K <= N_elig  (firme di Commissione e IdP);
  4.     ricalcolando i conteggi da D si riottiene T;
  5.     il risultato T è firmato dall'AE.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from . import crypto_utils as cu
from .authority import closure_message, result_message
from .bulletin_board import BulletinBoard
from .commission import candidate_list_digest, decode_choice
from .pki import CertificateRejected, check_certificate


def verify_election(bb: BulletinBoard, ca_public: RSAPublicKey) -> dict[str, bool]:
    """Esegue tutti i controlli pubblici e ne restituisce gli esiti."""
    checks: dict[str, bool] = {}

    # Recupera tutti gli artefatti pubblici prodotti durante l'elezione.
    election_id = bb.get("election_id")
    candidates = bb.get("candidates")
    closure = bb.get("closure")
    decryption = bb.get("decryption")
    result = bb.get("result")
    eligibility = bb.get("eligibility")
    token_count = bb.get("token_count")

    # Se manca anche solo un artefatto, non possiamo verificare nulla.
    if not all([candidates, closure, decryption, result, eligibility, token_count]):
        return {"OK": False, "artefatti_presenti": False}
    checks["artefatti_presenti"] = True

    # Chiavi pubbliche delle entità (lette dai certificati pubblicati).
    ae_sign_pub = bb.get("ae_certs")["sign"].public_key()
    commission_pub = candidates["cert"].public_key()
    idp_pub = bb.get("idp_cert").public_key()
    valid_options = set(candidates["C"])

    # Passo 0: Tutti i certificati usati dalla verifica devono essere
    # validi e non revocati (CRL hard-fail): AE (firma), IdP e Commissione.
    # Le chiavi pubbliche con cui verifichiamo sigma_close, sigma_result,
    # sigma_count e sigma_elig provengono da questi certificati: fidarsi di un
    # certificato non validato contro pk_CA vanificherebbe i controlli successivi.
    crl = bb.get("crl")
    passo0 = True
    for cert in (bb.get("ae_certs")["sign"], bb.get("idp_cert"), candidates["cert"]):
        try:
            check_certificate(cert, crl, ca_public)
        except CertificateRejected:
            passo0 = False
    checks["passo0_crl_certificati"] = passo0

    # --- La lista dei candidati è autentica (firmata dalla Commissione)? ------- #
    checks["lista_candidati_firmata"] = cu.rsa_verify(
        commission_pub, candidates["sigma_C"], candidate_list_digest(candidates["C"])
    )

    # --- Passo 1: la chiusura dell'urna è firmata dall'AE? --------------------- #
    root_final = closure["merkle_root_final"]
    ts_close = closure["timestamp_close"]
    checks["passo1_chiusura"] = cu.rsa_verify(
        ae_sign_pub, closure["sigma_close"], closure_message(ts_close, root_final)
    )

    # --- Passo 2: ricalcolando la Merkle root si riottiene quella firmata? ----- #
    recomputed_root = bb.recompute_root() or cu.sha256(b"")
    checks["passo2_merkle_root"] = (recomputed_root == root_final)

    # --- Passo 3: la lista di decifrazione D è coerente con l'urna? ------------ #
    # D = coppie (ct, voto) delle schede valide;  I = ct delle schede invalide.
    D = decryption["D"]
    I = decryption["I"]

    # Tre insiemi di ciphertext: quelli davvero nell'urna, quelli dichiarati
    # validi (da D) e quelli dichiarati invalidi (da I).
    ct_urna = {entry["ct"] for entry in bb.entries}
    ct_validi = {ct for (ct, voto) in D}
    ct_invalidi = set(I)

    # La lista D/I è coerente solo se valgono TUTTE queste condizioni:
    # 1) ogni ct dichiarato valido esiste davvero nell'urna;
    ct_validi_esistono = all(ct in ct_urna for (ct, voto) in D)
    # 2) ogni voto decifrato è un'opzione ammessa (una tesi o la scheda bianca);
    voti_ammessi = all(voto in valid_options for (ct, voto) in D)
    # 3) ogni ct dichiarato invalido esiste davvero nell'urna;
    ct_invalidi_esistono = all(ct in ct_urna for ct in I)
    # 4) validi e invalidi insieme coprono ESATTAMENTE l'urna
    #    (nessuna scheda dimenticata e nessuna inventata);
    coprono_tutta_urna = (ct_validi | ct_invalidi) == ct_urna
    # 5) anche i numeri tornano:  |urna| = |valide| + |invalide|.
    numeri_tornano = len(bb) == len(D) + len(I)

    checks["passo3_consistenza_D"] = (
        ct_validi_esistono
        and voti_ammessi
        and ct_invalidi_esistono
        and coprono_tutta_urna
        and numeri_tornano
    )

    # --- Passo 3-bis: bilancio dei voti  m <= K <= N_elig ---------------------- #
    # m = schede valide, K = token emessi (firmato dall'IdP), N_elig = aventi diritto
    # (firmato dalla Commissione). La catena impedisce ballot stuffing e over-issuance.
    n_elig = eligibility["N_elig"]
    k = token_count["K"]
    m = len(D)
    sig_elig_ok = cu.rsa_verify(
        commission_pub, eligibility["sigma_elig"],
        cu.sha256(f"{n_elig}|{election_id}".encode()),
    )
    sig_count_ok = cu.rsa_verify(
        idp_pub, token_count["sigma_count"],
        cu.sha256(f"{k}|{election_id}".encode()),
    )
    checks["passo3bis_bilancio"] = sig_elig_ok and sig_count_ok and (m <= k <= n_elig)

    # --- Passo 4: ricalcolando i conteggi da D si riottiene T? ----------------- #
    recomputed_counts = {decode_choice(o): 0 for o in candidates["C"]}
    for _, cv in D:
        recomputed_counts[decode_choice(cv)] += 1
    checks["passo4_conteggio"] = (recomputed_counts == result["T"])

    # --- Passo 5: il risultato è firmato dall'AE? ------------------------------ #
    counts_in_order = [recomputed_counts[decode_choice(o)] for o in candidates["C"]]
    checks["passo5_firma_risultato"] = cu.rsa_verify(
        ae_sign_pub, result["sigma_result"], result_message(counts_in_order, ts_close)
    )

    # Esito globale: tutti i controlli (esclusa la chiave "OK" stessa) devono passare.
    checks["OK"] = all(esito for nome, esito in checks.items() if nome != "OK")
    return checks
