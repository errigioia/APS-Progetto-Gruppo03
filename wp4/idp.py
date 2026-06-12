"""
idp — Identity Provider / IdP.

L'IdP è lo "sportello" che riconosce gli elettori e rilascia il permesso di
votare. Il permesso è un TOKEN: un nonce casuale di 256 bit firmato dall'IdP.

Punto chiave per lo pseudoanonimato: il token NON contiene l'identità. L'IdP sa
"chi sei" ma non "cosa voti"; l'Autorità Elettorale, ricevendo il token, può
verificarne la firma ma non risalire all'elettore (finché IdP e AE non colludono).

Dettagli implementativi:
  * le password sono salvate come hash con salt (PBKDF2-HMAC-SHA256), mai in chiaro;
  * il flag 'voted' viene messo a True PRIMA di consegnare il token: così, anche
    con richieste simultanee, non si possono ottenere due token (anti doppio voto);
  * se il token si perde (es. errore di rete) c'è recover_token() per riaverlo.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

from cryptography import x509

from . import crypto_utils as cu
from .bulletin_board import BulletinBoard
from .pki import CertificateAuthority

# Un token è la coppia (nonce, firma del nonce). Definiamo un alias per leggibilità.
Token = tuple[bytes, bytes]

# Iterazioni di PBKDF2: più sono, più è costoso provare le password a forza bruta.
PBKDF2_ITERATIONS = 200_000


def token_message(nonce: bytes, election_id: str) -> bytes:
    """
    Messaggio che l'IdP firma per creare il token: H(nonce || election_id).
    L'election_id "lega" il token a QUESTA elezione, impedendo di riusare un
    token vecchio in una sessione diversa (anti replay tra sessioni).
    """
    return cu.sha256(nonce + b"|" + election_id.encode())


def _hash_password(password: str, salt: bytes) -> bytes:
    """Hash della password con salt (PBKDF2-HMAC-SHA256)."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)


@dataclass
class _VoterRecord:
    """Una riga del registro R: dati per autenticare un elettore + il suo stato."""
    salt: bytes
    pwd_hash: bytes
    voted: bool = False                          # ha già ricevuto un token?
    issued_token: Token | None = field(default=None, repr=False)  # token emesso


class AuthenticationError(Exception):
    """Autenticazione fallita, oppure elettore non avente diritto / già votante."""


class IdentityProvider:
    def __init__(self, ca: CertificateAuthority, election_id: str) -> None:
        self.election_id = election_id
        self._key = cu.generate_rsa_keypair()  # sk_IdP: firma i token
        self.cert: x509.Certificate = ca.issue_certificate(
            "Identity-Provider", self._key.public_key(), usage="sign"
        )
        self._registry: dict[str, _VoterRecord] = {}  # registro R: id -> record

    @property
    def public_key(self):
        """pk_IdP: la usa l'AE per verificare la firma dei token."""
        return self._key.public_key()

    # ----------------------------------------------------------------- #
    # Caricamento del registro R (fase pre-elettorale)
    # ----------------------------------------------------------------- #
    def load_registry(self, credentials: dict[str, str]) -> None:
        """
        Pre-carica il registro a partire da {voter_id: password}.
        Per ogni elettore generiamo un salt casuale e salviamo l'hash della
        password (mai la password in chiaro). All'inizio voted = False.
        """
        for voter_id, password in credentials.items():
            salt = os.urandom(16)
            self._registry[voter_id] = _VoterRecord(
                salt=salt, pwd_hash=_hash_password(password, salt)
            )

    @property
    def eligible_ids(self) -> list[str]:
        """Elenco degli id aventi diritto (le chiavi del registro)."""
        return list(self._registry.keys())

    # ----------------------------------------------------------------- #
    # Autenticazione e rilascio del token
    # ----------------------------------------------------------------- #
    def _check_credentials(self, voter_id: str, password: str) -> _VoterRecord:
        """Controlla id + password e restituisce il record, o solleva un errore."""
        record = self._registry.get(voter_id)
        if record is None:
            raise AuthenticationError("identità non presente nel registro R")
        if _hash_password(password, record.salt) != record.pwd_hash:
            raise AuthenticationError("credenziali non valide")
        return record

    def authenticate(self, voter_id: str, password: str) -> Token:
        """
        Autentica l'elettore e gli rilascia il token. Passi:
          1. verifica credenziali e che non abbia già votato;
          2. genera il nonce e lo firma -> token;
          3. mette voted=True PRIMA di restituire il token.
        """
        record = self._check_credentials(voter_id, password)
        if record.voted:
            raise AuthenticationError(
                "elettore ha già votato (usare recover_token per il recupero)"
            )

        # Genera il nonce casuale e firmalo: questo è il token.
        nonce = cu.new_nonce()
        sigma_N = cu.rsa_sign(self._key, token_message(nonce, self.election_id))
        token: Token = (nonce, sigma_N)

        # Segna SUBITO l'elettore come "ha votato", prima di consegnare il token:
        # evita che due richieste contemporanee ottengano due token validi.
        record.voted = True
        record.issued_token = token
        return token

    def recover_token(self, voter_id: str, password: str) -> Token:
        """
        Recupero: se l'elettore risulta voted=True ma non ha ricevuto il token
        (es. la rete è caduta), può richiederlo di nuovo su canale autenticato.
        """
        record = self._check_credentials(voter_id, password)
        if not record.voted or not record.issued_token:
            raise AuthenticationError("nessun token da recuperare per questo elettore")
        return record.issued_token

    # ----------------------------------------------------------------- #
    # Chiusura: pubblicazione del numero di token emessi
    # ----------------------------------------------------------------- #
    def publish_token_count(self, bb: BulletinBoard) -> int:
        """
        Pubblica K = numero di elettori che hanno ricevuto un token, firmato:
        sigma_count = Sign(H(K || election_id)).
        Serve al verificatore per il bilancio m <= K <= N_elig.
        """
        k = sum(1 for record in self._registry.values() if record.voted)
        sigma_count = cu.rsa_sign(
            self._key, cu.sha256(f"{k}|{self.election_id}".encode())
        )
        bb.post("token_count", {"K": k, "sigma_count": sigma_count})
        return k
