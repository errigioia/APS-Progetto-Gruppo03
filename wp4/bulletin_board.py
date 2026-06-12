"""
bulletin_board — Bulletin Board pubblico append-only 

È la "bacheca" pubblica dell'elezione: un registro a cui l'Autorità Elettorale
aggiunge le schede cifrate man mano che arrivano. Due proprietà importanti:

  * append-only: si può solo AGGIUNGERE, mai rimuovere o modificare. Lo imponiamo
    a livello di codice esponendo solo metodi di aggiunta;
  * integrità verificabile: ogni scheda entra in un Merkle tree, la cui radice
    è firmata dall'AE. Se qualcuno alterasse o togliesse una scheda, la radice
    non tornerebbe più.

Oltre alle schede, il bulletin board ospita un'area "pubblica" chiave->valore
con tutti gli artefatti dell'elezione: lista candidati, certificati, CRL,
conteggio dei token, messaggio di chiusura, coppie di decifrazione D, ecc.

Assunzione: il bulletin board è una fonte pubblica UNICA. Un'AE disonesta 
che mostrasse versioni diverse a verificatori diversi non verrebbe rilevata 
da un singolo controllo. È un rischio residuo dichiarato.
"""

from __future__ import annotations

from typing import Any

from .crypto_utils import MerkleTree, ProofStep


def canonical_entry_bytes(entry: dict[str, Any]) -> bytes:
    """
    Trasforma una voce di voto in una sequenza di byte fissa e deterministica.
    Serve sia per costruire il Merkle tree sia per ricalcolarlo in verifica: due
    parti che partono dalla stessa voce devono ottenere gli stessi byte.
    Una voce è BB_entry = (ct, timestamp, H(ct)).
    """
    return entry["ct"] + entry["timestamp"].encode() + entry["h_ct"]


class BulletinBoard:
    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []        # schede di voto (append-only)
        self._tree = MerkleTree()                        # Merkle tree delle schede
        self._signed_roots: list[dict[str, Any]] = []    # storico (root, ts, firma)
        self._public: dict[str, Any] = {}                # artefatti pubblici (k->v)

    # ----------------------------------------------------------------- #
    # Schede di voto (si possono solo aggiungere)
    # ----------------------------------------------------------------- #
    def add_vote_entry(self, entry: dict[str, Any]) -> None:
        """Aggiunge una scheda cifrata e ne inserisce l'hash nel Merkle tree."""
        self._entries.append(entry)
        self._tree.append(canonical_entry_bytes(entry))

    @property
    def entries(self) -> list[dict[str, Any]]:
        """Elenco delle schede. Restituiamo una COPIA: il registro è immutabile."""
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    # ----------------------------------------------------------------- #
    # Merkle root e prove di inclusione
    # ----------------------------------------------------------------- #
    def current_root(self) -> bytes | None:
        """Radice di Merkle attuale (riassume tutte le schede pubblicate)."""
        return self._tree.root()

    def proof_for(self, ct: bytes) -> list[ProofStep] | None:
        """Prova di inclusione di Merkle per la scheda con ciphertext `ct`."""
        for entry in self._entries:
            if entry["ct"] == ct:
                return self._tree.proof(canonical_entry_bytes(entry))
        return None

    def recompute_root(self) -> bytes | None:
        """
        Ricalcola la radice da zero a partire dalle schede pubblicate.
        La usa il verificatore universale per controllare
        che la radice firmata corrisponda davvero al contenuto della bacheca.
        """
        tree = MerkleTree()
        for entry in self._entries:
            tree.append(canonical_entry_bytes(entry))
        return tree.root()

    def add_signed_root(self, root: bytes, timestamp: str, signature: bytes) -> None:
        """Registra una radice firmata dall'AE (storico degli aggiornamenti)."""
        self._signed_roots.append(
            {"root": root, "timestamp": timestamp, "sigma_root": signature}
        )

    @property
    def signed_roots(self) -> list[dict[str, Any]]:
        return list(self._signed_roots)

    def latest_signed_root(self) -> dict[str, Any] | None:
        """L'ultima radice firmata (None se non ce ne sono ancora)."""
        return self._signed_roots[-1] if self._signed_roots else None

    # ----------------------------------------------------------------- #
    # Area pubblica: artefatti dell'elezione (chiave -> valore)
    # ----------------------------------------------------------------- #
    def post(self, key: str, value: Any) -> None:
        """
        Pubblica un artefatto. Anche questa area è append-only: una chiave già
        pubblicata non può essere sovrascritta (l'urna non si "riscrive").
        """
        if key in self._public:
            raise ValueError(f"artefatto '{key}' già pubblicato (append-only)")
        self._public[key] = value

    def get(self, key: str) -> Any:
        """Legge un artefatto pubblico (None se non esiste)."""
        return self._public.get(key)

    def has(self, key: str) -> bool:
        """Vero se l'artefatto è stato pubblicato."""
        return key in self._public

    # ----------------------------------------------------------------- #
    # CRL: unico artefatto aggiornabile (per natura è una lista di revoca)
    # ----------------------------------------------------------------- #
    def update_crl(self, crl: Any) -> None:
        """
        Pubblica o aggiorna la CRL. A differenza degli altri artefatti, la CRL
        può essere sostituita.
        """
        self._public["crl"] = crl
