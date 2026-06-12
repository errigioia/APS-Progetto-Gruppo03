"""
crypto_utils — Primitive crittografiche di base del sistema.

Qui raccogliamo gli "strumenti" crittografici usati da tutte le entità.

  * RSA-2048 con OAEP (SHA-256)  -> cifratura asimmetrica della scheda   
  * RSA con PSS  (SHA-256)       -> firme digitali hash-and-sign          
  * SHA-256                      -> hash, ricevute, foglie del Merkle tree 
  * Merkle tree                  -> integrità del bulletin board           

Idea di fondo: ogni entità del protocollo (IdP, Autorità Elettorale, ecc.) usa
SOLO queste funzioni. In questo modo la crittografia sta tutta in un posto e il
resto del codice si legge come una sequenza di "cifra / firma / verifica".

Nota sulle firme (hash-and-sign). Il WP2 scrive le firme come Sign(H(m)). In
pyca/cryptography lo schema PSS calcola da solo l'hash del messaggio: quindi
firmare 'm' con PSS+SHA-256 equivale a Sign(H(m)).
"""

from __future__ import annotations

import hashlib
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

# --------------------------------------------------------------------------- #
# Parametri di sicurezza 
# --------------------------------------------------------------------------- #
RSA_KEY_SIZE = 2048       # dimensione delle chiavi RSA (parametro di sicurezza n)
PUBLIC_EXPONENT = 65537   # esponente pubblico standard
NONCE_BYTES = 32          # 32 byte = 256 bit (token dell'IdP e nonce personale r)

# Schema di padding per la CIFRATURA (OAEP con SHA-256).
# Lo definiamo una sola volta perché è sempre lo stesso.
_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def _pss() -> padding.PSS:
    """
    Schema di padding per la FIRMA (PSS con SHA-256).
    PSS usa un salt casuale: due firme dello stesso messaggio sono diverse.
    Restituiamo una nuova istanza ad ogni chiamata per chiarezza.
    """
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


# --------------------------------------------------------------------------- #
# Hashing (SHA-256) 
# --------------------------------------------------------------------------- #
def sha256(data: bytes) -> bytes:
    """Hash SHA-256 del dato. Restituisce 32 byte grezzi."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Hash SHA-256 in formato esadecimale (64 caratteri), comodo da stampare."""
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# RSA: generazione chiavi, cifratura OAEP, firma PSS 
# --------------------------------------------------------------------------- #
def generate_rsa_keypair(key_size: int = RSA_KEY_SIZE) -> RSAPrivateKey:
    """
    Genera una coppia di chiavi RSA e restituisce la chiave PRIVATA.
    La chiave pubblica si ottiene con '.public_key()'.
    """
    return rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT, key_size=key_size
    )


def rsa_encrypt(public_key: RSAPublicKey, message: bytes) -> bytes:
    """Cifra 'message' con la chiave pubblica (RSA-OAEP, non deterministica)."""
    return public_key.encrypt(message, _OAEP)


def rsa_decrypt(private_key: RSAPrivateKey, ciphertext: bytes) -> bytes:
    """Decifra 'ciphertext' con la chiave privata (RSA-OAEP)."""
    return private_key.decrypt(ciphertext, _OAEP)


def rsa_sign(private_key: RSAPrivateKey, message: bytes) -> bytes:
    """Firma 'message' con la chiave privata (RSA-PSS, hash-and-sign SHA-256)."""
    return private_key.sign(message, _pss(), hashes.SHA256())


def rsa_verify(public_key: RSAPublicKey, signature: bytes, message: bytes) -> bool:
    """
    Verifica una firma RSA-PSS. Restituisce True/False invece di sollevare
    eccezioni, così nel resto del codice possiamo scrivere semplici 'if'.
    """
    try:
        public_key.verify(signature, message, _pss(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def new_nonce(n_bytes: int = NONCE_BYTES) -> bytes:
    """Genera un valore casuale (nonce) crittograficamente sicuro."""
    return os.urandom(n_bytes)


# --------------------------------------------------------------------------- #
# Merkle tree
# --------------------------------------------------------------------------- #
# Un passo della prova di inclusione: (hash del nodo "fratello", "left"/"right").
# La posizione dice se il fratello va a sinistra o a destra durante il ricalcolo.
ProofStep = tuple[bytes, str]


class MerkleTree:
    """
    Albero di Merkle "append-only".

    A cosa serve: dare un'unica "impronta" (la radice) di tutte le schede
    pubblicate. Se anche una sola scheda cambia, la radice cambia: così
    chiunque può accorgersi di manomissioni.

    La radice viene ricalcolata da zero ad ogni richiesta: il costo è O(n) (lo misuriamo nel benchmark).
    """

    def __init__(self) -> None:
        # Lista delle foglie (gli hash dei dati). È l'unico stato dell'albero.
        self._leaves: list[bytes] = []

    def __len__(self) -> int:
        return len(self._leaves)

    def append(self, data: bytes) -> None:
        """Aggiunge un dato all'albero (ne memorizza l'hash)."""
        self._leaves.append(sha256(data))

    def _build_levels(self) -> list[list[bytes]]:
        """
        Costruisce tutti i livelli dell'albero, dal basso (foglie) verso l'alto.
        Restituisce una lista di livelli: levels[0] = foglie, levels[-1] = radice.
        Se non ci sono foglie, restituisce un livello vuoto.
        """
        if not self._leaves:
            return [[]]

        levels = [list(self._leaves)]
        # Finché il livello corrente ha più di un nodo, costruiamo quello sopra.
        while len(levels[-1]) > 1:
            current = levels[-1]
            parent = []
            for i in range(0, len(current), 2):
                left = current[i]
                # Se manca il nodo destro (numero dispari) si duplica il sinistro.
                right = current[i + 1] if i + 1 < len(current) else left
                parent.append(sha256(left + right))
            levels.append(parent)
        return levels

    def root(self) -> bytes | None:
        """Radice corrente dell'albero (None se non ci sono foglie)."""
        levels = self._build_levels()
        return levels[-1][0] if levels[-1] else None

    def proof(self, data: bytes) -> list[ProofStep] | None:
        """
        Prova di inclusione per 'data': la lista dei nodi "fratelli" da risalire
        dalla foglia fino alla radice. Restituisce None se il dato non è presente.
        """
        leaf = sha256(data)
        levels = self._build_levels()
        if not levels[0]:
            return None
        try:
            index = levels[0].index(leaf)
        except ValueError:
            return None  # il dato non è tra le foglie

        proof: list[ProofStep] = []
        # Saliamo livello per livello (tranne la radice) raccogliendo i fratelli.
        for level in levels[:-1]:
            if index % 2 == 1:
                # Siamo il nodo destro: il fratello è quello a sinistra.
                proof.append((level[index - 1], "left"))
            else:
                # Siamo il nodo sinistro: il fratello è a destra (o noi stessi
                # se siamo l'ultimo nodo di un livello dispari).
                sibling = level[index + 1] if index + 1 < len(level) else level[index]
                proof.append((sibling, "right"))
            index = index // 2  # l'indice del genitore al livello superiore
        return proof

    @staticmethod
    def verify_proof(
        data: bytes, proof: list[ProofStep] | None, root: bytes | None
    ) -> bool:
        """
        Verifica una prova di inclusione: parte dall'hash di 'data', risale
        combinando i fratelli e controlla di ottenere esattamente 'root'.
        """
        if proof is None or root is None:
            return False
        current = sha256(data)
        for sibling, position in proof:
            if position == "left":
                current = sha256(sibling + current)  # il fratello sta a sinistra
            else:
                current = sha256(current + sibling)  # il fratello sta a destra
        return current == root
