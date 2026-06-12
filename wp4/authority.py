"""
authority — Autorità Elettorale / AE 

È l'urna del sistema: riceve le schede cifrate, le registra sul bulletin board,
rilascia le ricevute e, a urne chiuse, esegue lo scrutinio. NON sa autenticare
gli elettori (è compito dell'IdP) e non ne conosce l'identità.

Separazione delle chiavi: l'AE ha DUE coppie RSA distinte, una per la firma e
una per la cifratura. Così la stessa chiave non viene riusata per scopi
diversi e si può tenere offline quella di decifrazione fino allo scrutinio:
  * (firma)     -> ricevute, Merkle root, messaggio di chiusura, risultato;
  * (cifratura) -> serve solo a cifrare/decifrare le schede.

Il flusso di un voto è descritto passo passo dentro cast_vote().
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from . import crypto_utils as cu
from .bulletin_board import BulletinBoard
from .commission import CANDIDATE_ID_BYTES, decode_choice
from .idp import token_message
from .pki import CertificateAuthority, check_certificate

# Un messaggio di voto è la tripla (nonce, firma del nonce, scheda cifrata).
VoteMessage = tuple[bytes, bytes, bytes]

# Testo fisso del messaggio di chiusura delle urne.
CLOSE_TAG = b"ELEZIONI CHIUSE"


def receipt_message(ct: bytes, timestamp: str, election_id: str) -> bytes:
    """Messaggio firmato nella ricevuta: H(ct || timestamp || election_id)."""
    return cu.sha256(ct + b"|" + timestamp.encode() + b"|" + election_id.encode())


def closure_message(timestamp_close: str, merkle_root: bytes) -> bytes:
    """Messaggio di chiusura: H('ELEZIONI CHIUSE' || ts_close || MerkleRoot_final)."""
    return cu.sha256(CLOSE_TAG + b"|" + timestamp_close.encode() + b"|" + merkle_root)


def result_message(counts_in_order: list[int], timestamp_close: str) -> bytes:
    """Messaggio del risultato: H(conteggi nell'ordine di C || ts_close)."""
    payload = b"".join(count.to_bytes(4, "big") for count in counts_in_order)
    return cu.sha256(payload + b"|" + timestamp_close.encode())


class VoteRejected(Exception):
    """Sollevata quando l'AE scarta un messaggio di voto."""


def _now_iso() -> str:
    """Timestamp corrente in formato ISO (stringa), usato nelle voci dell'urna."""
    return dt.datetime.now(dt.timezone.utc).isoformat()


class ElectionAuthority:
    def __init__(
        self, ca: CertificateAuthority, bb: BulletinBoard, election_id: str
    ) -> None:
        self.election_id = election_id
        self.bb = bb
        self._ca_public: RSAPublicKey = ca.public_key

        # Due coppie di chiavi distinte (separazione delle chiavi).
        self._sign_key = cu.generate_rsa_keypair()   # firma: ricevute, root, ...
        self._enc_key = cu.generate_rsa_keypair()     # cifratura: solo le schede
        self.cert_sign: x509.Certificate = ca.issue_certificate(
            "Autorita-Elettorale-Firma", self._sign_key.public_key(), usage="sign"
        )
        self.cert_enc: x509.Certificate = ca.issue_certificate(
            "Autorita-Elettorale-Cifra", self._enc_key.public_key(), usage="encrypt"
        )

        # Stato della raccolta dei voti.
        self._used_nonces: set[bytes] = set()              # insieme U: nonce già spesi
        self._nonce_to_ct: dict[bytes, bytes] = {}          # nonce -> scheda registrata
        self._nonce_to_receipt: dict[bytes, dict[str, Any]] = {}  # nonce -> ricevuta
        self._closed = False

        # Riferimenti all'IdP (ricevuti fuori banda nella fase di setup).
        self._idp_cert: x509.Certificate | None = None
        self._idp_public: RSAPublicKey | None = None

    @property
    def sign_public_key(self) -> RSAPublicKey:
        """Chiave pubblica di firma dell'AE (verifica ricevute, root, risultato)."""
        return self._sign_key.public_key()

    @property
    def enc_public_key(self) -> RSAPublicKey:
        """Chiave pubblica di cifratura: la usano gli elettori per cifrare la scheda."""
        return self._enc_key.public_key()

    def register_idp(self, idp_cert: x509.Certificate, idp_public: RSAPublicKey) -> None:
        """Riceve fuori banda il certificato e la chiave pubblica dell'IdP."""
        self._idp_cert = idp_cert
        self._idp_public = idp_public

    # ----------------------------------------------------------------- #
    # Fase di votazione 
    # ----------------------------------------------------------------- #
    def cast_vote(self, vote: VoteMessage, crl) -> dict[str, Any]:
        """
        Riceve un messaggio di voto, lo controlla e (se valido) lo registra,
        restituendo la ricevuta. Solleva VoteRejected su qualsiasi controllo fallito.
        """
        if self._closed:
            raise VoteRejected("urne chiuse")
        if self._idp_public is None or self._idp_cert is None:
            raise VoteRejected("IdP non registrato presso l'AE")

        nonce, sigma_N, ct = vote

        # (0) CRL hard-fail sul certificato dell'IdP: se è revocato (o la CRL non
        #  è disponibile) il token non vale più 
        check_certificate(self._idp_cert, crl, self._ca_public)

        # (1) La firma del token è davvero dell'IdP?
        if not cu.rsa_verify(self._idp_public, sigma_N, token_message(nonce, self.election_id)):
            raise VoteRejected("firma del token non valida")

        # (2) Il token è già stato usato? (insieme U dei nonce spesi)
        if nonce in self._used_nonces:
            previous_ct = self._nonce_to_ct[nonce]
            if ct == previous_ct:
                # Stesso identico voto re-inviato: è legittimo.
                # Restituiamo la ricevuta già emessa, marcandola come re-invio.
                receipt = dict(self._nonce_to_receipt[nonce])
                receipt["resent"] = True
                return receipt
            # Stesso token ma scheda diversa = tentativo di doppio voto: scartato.
            raise VoteRejected("doppio voto: nonce già speso con ciphertext diverso")

        # (3) Registra il nonce PRIMA di procedere (neutralizza le race condition).
        self._used_nonces.add(nonce)
        self._nonce_to_ct[nonce] = ct

        # (4) Aggiunge la scheda al bulletin board e firma la nuova Merkle root.
        timestamp = _now_iso()
        entry = {"ct": ct, "timestamp": timestamp, "h_ct": cu.sha256(ct)}
        self.bb.add_vote_entry(entry)
        root = self.bb.current_root()
        sigma_root = cu.rsa_sign(
            self._sign_key, cu.sha256(root + b"|" + timestamp.encode())
        )
        self.bb.add_signed_root(root, timestamp, sigma_root)

        # (5) Emette la ricevuta firmata e la conserva (per il recovery / re-invio).
        rho = cu.rsa_sign(self._sign_key, receipt_message(ct, timestamp, self.election_id))
        receipt = {"ct": ct, "timestamp": timestamp, "rho": rho, "resent": False}
        self._nonce_to_receipt[nonce] = dict(receipt)
        return receipt

    # ----------------------------------------------------------------- #
    # Scrutinio
    # ----------------------------------------------------------------- #
    def close_election(self) -> dict[str, Any]:
        """
        Passo 1 — chiusura delle urne. Pubblica un messaggio di chiusura firmato
        che "congela" la Merkle root finale: da qui in poi l'urna non cambia più.
        """
        if self._closed:
            raise RuntimeError("urne già chiuse")
        self._closed = True
        ts_close = _now_iso()
        # Se nessuno ha votato la root è None: usiamo H("") come root convenzionale.
        root_final = self.bb.current_root() or cu.sha256(b"")
        sigma_close = cu.rsa_sign(self._sign_key, closure_message(ts_close, root_final))
        closure = {
            "timestamp_close": ts_close,
            "merkle_root_final": root_final,
            "sigma_close": sigma_close,
        }
        self.bb.post("closure", closure)
        return closure

    def tally(self) -> dict[str, Any]:
        """
        Passi 2-5 — decifra le schede, scarta le invalide, conta e firma il
        risultato. Pubblica: D (coppie ct->voto), I (schede invalide), T (conteggi)
        e la firma sul risultato.
        """
        if not self._closed:
            raise RuntimeError("impossibile scrutinare: urne ancora aperte")
        candidates = self.bb.get("candidates")
        valid_options = set(candidates["C"])      # opzioni di voto ammesse
        ts_close = self.bb.get("closure")["timestamp_close"]

        decryption: list[tuple[bytes, bytes]] = []   # D = {(ct, voto)}
        invalid: list[bytes] = []                      # I = schede non valide
        counts = {decode_choice(o): 0 for o in candidates["C"]}  # conteggi per opzione

        for entry in self.bb.entries:
            ct = entry["ct"]
            try:
                # Decifra con la chiave privata di cifratura: m = voto || nonce_r.
                m = cu.rsa_decrypt(self._enc_key, ct)
                cv = m[:CANDIDATE_ID_BYTES]   # i primi 4 byte sono l'id dell'opzione
            except Exception:
                invalid.append(ct)            # decifratura fallita -> scheda invalida
                continue
            if cv in valid_options:
                decryption.append((ct, cv))
                counts[decode_choice(cv)] += 1
            else:
                invalid.append(ct)            # opzione non in lista -> scheda invalida

        # Conteggi nell'ordine canonico di C, per costruire e firmare il risultato.
        counts_in_order = [counts[decode_choice(o)] for o in candidates["C"]]
        sigma_result = cu.rsa_sign(self._sign_key, result_message(counts_in_order, ts_close))

        self.bb.post("decryption", {"D": decryption, "I": invalid})
        self.bb.post("result", {
            "T": counts,
            "counts_in_order": counts_in_order,
            "sigma_result": sigma_result,
        })
        return {"T": counts, "D": decryption, "I": invalid, "sigma_result": sigma_result}
