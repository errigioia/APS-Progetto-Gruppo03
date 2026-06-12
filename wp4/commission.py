"""
commission — Commissione Accademica 

È un attore SOLO pre-elettorale: prepara il "terreno" prima che le urne aprano,
poi esce di scena (non raccoglie né conta i voti). I suoi compiti:

  * definire e firmare la lista ufficiale delle opzioni di voto
    C = {c1, ..., ck, scheda_bianca};
  * firmare il registro degli aventi diritto (ne garantisce l'autenticità);
  * pubblicare N_elig = numero di aventi diritto, firmato. È il tetto massimo
    di token che l'IdP può emettere, usato poi nel "bilancio dei voti".

"""

from __future__ import annotations

from cryptography import x509

from . import crypto_utils as cu
from .bulletin_board import BulletinBoard
from .pki import CertificateAuthority

# Ogni opzione di voto è un numero a lunghezza fissa di 4 byte
CANDIDATE_ID_BYTES = 4
BLANK_ID = 0xFFFFFFFF  # id riservato alla SCHEDA BIANCA, diverso da ogni tesi


def encode_choice(candidate_id: int) -> bytes:
    """Converte l'id di un'opzione (un intero) nei suoi 4 byte."""
    return candidate_id.to_bytes(CANDIDATE_ID_BYTES, "big")


def decode_choice(raw: bytes) -> int:
    """Operazione inversa di encode_choice: dai 4 byte all'intero."""
    return int.from_bytes(raw, "big")


def candidate_list_digest(option_ids: list[bytes]) -> bytes:
    """
    H(C): hash della lista ufficiale delle opzioni. Concateniamo gli id (tutti a
    lunghezza fissa) e ne facciamo l'hash: così la lista ha un'unica "impronta"
    che la Commissione firma e chiunque può ricontrollare.
    """
    return cu.sha256(b"".join(option_ids))


class Commission:
    def __init__(self, ca: CertificateAuthority, election_id: str) -> None:
        self.election_id = election_id
        self._key = cu.generate_rsa_keypair()  # sk della Commissione
        # La CA certifica la chiave pubblica della Commissione (uso: firma).
        self.cert: x509.Certificate = ca.issue_certificate(
            "Commissione-Accademica", self._key.public_key(), usage="sign"
        )

    @property
    def public_key(self):
        return self._key.public_key()

    # ----------------------------------------------------------------- #
    def publish_candidate_list(
        self, bb: BulletinBoard, theses: list[str]
    ) -> dict[str, object]:
        """
        Costruisce la lista C = {tesi..., scheda_bianca}, la firma e la pubblica
        sul bulletin board. Restituisce la struttura pubblicata.
        """
        # Alle tesi assegniamo gli id 1, 2, ..., k; alla scheda bianca BLANK_ID.
        option_ids = [encode_choice(i + 1) for i in range(len(theses))]
        titles = {i + 1: theses[i] for i in range(len(theses))}
        option_ids.append(encode_choice(BLANK_ID))
        titles[BLANK_ID] = "Scheda bianca"

        # Firma sull'hash della lista: lega in modo non falsificabile C alla Commissione.
        sigma_C = cu.rsa_sign(self._key, candidate_list_digest(option_ids))
        published = {
            "C": option_ids,        # opzioni di voto (id in byte)
            "titles": titles,       # id -> titolo leggibile (solo per la GUI)
            "sigma_C": sigma_C,     # firma della lista
            "cert": self.cert,      # certificato della Commissione
        }
        bb.post("candidates", published)
        return published

    def sign_registry(self, eligible_ids: list[str]) -> bytes:
        """
        Firma il registro R degli aventi diritto. Ordiniamo gli id e li uniamo in
        una stringa deterministica, poi firmiamo l'hash: garantisce che il
        registro caricato nell'IdP non sia stato manomesso.
        """
        payload = (self.election_id + "|" + "|".join(sorted(eligible_ids))).encode()
        return cu.rsa_sign(self._key, cu.sha256(payload))

    def publish_eligibility_count(self, bb: BulletinBoard, n_elig: int) -> bytes:
        """
        Pubblica N_elig firmato: sigma_elig = Sign(H(N_elig || election_id)).
        È il limite pubblico al numero di token emettibili, usato nel
        controllo del bilancio: m <= K <= N_elig.
        """
        msg = cu.sha256(f"{n_elig}|{self.election_id}".encode())
        sigma_elig = cu.rsa_sign(self._key, msg)
        bb.post("eligibility", {"N_elig": n_elig, "sigma_elig": sigma_elig})
        return sigma_elig
