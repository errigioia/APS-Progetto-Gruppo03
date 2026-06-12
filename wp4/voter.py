"""
voter — Elettore.

L'elettore è il "client" del sistema. Fa tre cose:
  1. authenticate(): si fa riconoscere dall'IdP e ottiene il token;
  2. cast_vote(): prepara la scheda, la cifra per l'AE e la invia;
  3. verify_individual(): dopo lo scrutinio, controlla da solo che il suo voto
     sia finito nell'urna ed sia stato contato correttamente.

Dopo aver votato, l'elettore conserva in locale un "fascicolo di verifica"
F = (cv, r, ct, rho, timestamp), che è tutto ciò che gli serve per la verifica.

Ogni volta che usa un certificato (dell'IdP o dell'AE), lo controlla con la CRL
secondo la politica hard-fail (pki.check_certificate).
"""

from __future__ import annotations

from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from . import crypto_utils as cu
from .authority import ElectionAuthority, receipt_message
from .bulletin_board import BulletinBoard, canonical_entry_bytes
from .commission import encode_choice
from .idp import IdentityProvider, Token
from .pki import check_certificate


class Voter:
    def __init__(
        self, voter_id: str, password: str, election_id: str, ca_public: RSAPublicKey
    ) -> None:
        self.voter_id = voter_id
        self._password = password
        self.election_id = election_id
        self._ca_public = ca_public            # pk_CA, ricevuta fuori banda
        self._token: Token | None = None       # token ottenuto dall'IdP
        self.fascicolo: dict[str, Any] | None = None  # F = (cv, r, ct, rho, timestamp)

    # ----------------------------------------------------------------- #
    def _verified_public_key(
        self, bb: BulletinBoard, cert: x509.Certificate
    ) -> RSAPublicKey:
        """
        Verifica un certificato (firma della CA + validità + CRL hard-fail) usando
        la CRL pubblicata sul bulletin board, e ne estrae la chiave pubblica.
        Solleva CertificateRejected se qualcosa non va.
        """
        crl = bb.get("crl")
        check_certificate(cert, crl, self._ca_public)
        return cert.public_key()

    # ----------------------------------------------------------------- #
    # 1) Autenticazione
    # ----------------------------------------------------------------- #
    def authenticate(self, idp: IdentityProvider, bb: BulletinBoard) -> Token:
        """
        Apre il "canale" con l'IdP verificando il suo certificato (hard-fail sulla
        CRL) e poi richiede il token con le proprie credenziali.
        """
        self._verified_public_key(bb, idp.cert)  # se il cert IdP è revocato -> errore
        self._token = idp.authenticate(self.voter_id, self._password)
        return self._token

    # ----------------------------------------------------------------- #
    # 2) Votazione
    # ----------------------------------------------------------------- #
    def cast_vote(
        self, ae: ElectionAuthority, choice_id: int, bb: BulletinBoard
    ) -> dict[str, Any]:
        """
        Prepara la scheda, la cifra con la chiave pubblica dell'AE e la invia
        insieme al token. Conserva poi il fascicolo F per la verifica futura.
        """
        if self._token is None:
            raise RuntimeError("elettore non autenticato: nessun token disponibile")

        # Passo 1 — prepara la scheda in chiaro: m = voto || nonce_personale.
        # Il nonce r aumenta l'entropia ed è un segreto dell'elettore.
        cv = encode_choice(choice_id)
        r = cu.new_nonce()
        m = cv + r
        # Prende ek_AE dal certificato di cifratura (verificato via CRL) e cifra.
        enc_public = self._verified_public_key(bb, ae.cert_enc)
        ct = cu.rsa_encrypt(enc_public, m)

        # Passo 2 — invia il voto. Prima ricontrolla il certificato di FIRMA dell'AE
        # (hard-fail): è quello con cui l'AE firmerà la ricevuta.
        self._verified_public_key(bb, ae.cert_sign)
        nonce, sigma_N = self._token
        receipt = ae.cast_vote((nonce, sigma_N, ct), bb.get("crl"))

        # Passo 6 — conserva il fascicolo di verifica F.
        self.fascicolo = {
            "cv": cv,
            "r": r,
            "ct": ct,
            "rho": receipt["rho"],
            "timestamp": receipt["timestamp"],
        }
        return receipt

    # ----------------------------------------------------------------- #
    # 3) Verifica individuale — VerifyVote(F, BB, D, pk_AE)
    # ----------------------------------------------------------------- #
    def verify_individual(self, ae: ElectionAuthority, bb: BulletinBoard) -> bool:
        """
        Controllo autonomo in tre passi (dopo la chiusura delle urne):
          1. la ricevuta è una firma valida dell'AE sul mio ct?
          2. il mio ct è davvero nell'urna? (prova di inclusione di Merkle)
          3. nella lista D il mio ct è associato al voto che ho espresso?
        Restituisce True solo se tutti e tre i controlli passano.
        """
        if self.fascicolo is None:
            raise RuntimeError("nessun fascicolo di verifica disponibile")
        F = self.fascicolo

        # Passo 0 — verifica il certificato di firma dell'AE (CRL hard-fail) e ne
        # ricava la chiave pubblica per i controlli successivi.
        ae_sign_public = self._verified_public_key(bb, ae.cert_sign)

        # Passo 1 — autenticità della ricevuta.
        if not cu.rsa_verify(
            ae_sign_public,
            F["rho"],
            receipt_message(F["ct"], F["timestamp"], self.election_id),
        ):
            return False

        # Passo 2 — inclusione nell'urna tramite prova di Merkle, confrontata con
        # la root finale "congelata" alla chiusura.
        closure = bb.get("closure")
        if closure is None:
            return False  # le urne non sono ancora chiuse
        root_final = closure["merkle_root_final"]
        proof = bb.proof_for(F["ct"])
        entry = {"ct": F["ct"], "timestamp": F["timestamp"], "h_ct": cu.sha256(F["ct"])}
        if not cu.MerkleTree.verify_proof(canonical_entry_bytes(entry), proof, root_final):
            return False

        # Passo 3 — nella lista pubblica D, il mio ct deve risultare associato al
        # voto che ho effettivamente espresso (cv).
        decryption = bb.get("decryption")
        if decryption is None:
            return False
        for ct_i, cv_i in decryption["D"]:
            if ct_i == F["ct"]:
                return cv_i == F["cv"]
        return False  # la mia scheda non compare tra quelle valide in D
