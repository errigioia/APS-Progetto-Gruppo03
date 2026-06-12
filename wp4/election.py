"""
election — Orchestrazione dell'elezione.

Questa classe è il "direttore d'orchestra": crea tutte le entità (CA, Commissione,
IdP, AE, Bulletin Board), esegue la fase di setup e offre un'API comoda per le 4
fasi del protocollo. 

Le 4 fasi:
  * setup()           -> crea chiavi/certificati, CRL, lista candidati, registro
  * new_voter()       -> crea un client elettore (fasi di auth e voto le gestisce lui)
  * close_and_tally() -> chiude le urne, pubblica K ed esegue lo scrutinio
"""

from __future__ import annotations

from .authority import ElectionAuthority
from .bulletin_board import BulletinBoard
from .commission import Commission
from .idp import IdentityProvider
from .pki import CertificateAuthority
from .voter import Voter


class Election:
    def __init__(self, election_id: str, theses: list[str]) -> None:
        self.election_id = election_id
        self.theses = theses

        # Bacheca pubblica condivisa da tutte le entità.
        self.bb = BulletinBoard()

        # PKI: la CA dedicata all'elezione è l'ancora di fiducia.
        self.ca = CertificateAuthority("CA-voto")

        # Entità operative (ognuna genera le proprie chiavi e ottiene un certificato).
        self.commission = Commission(self.ca, election_id)
        self.idp = IdentityProvider(self.ca, election_id)
        self.ae = ElectionAuthority(self.ca, self.bb, election_id)

        self._setup_done = False

    @property
    def ca_public(self):
        """pk_CA, distribuita fuori banda agli elettori e ai verificatori."""
        return self.ca.public_key

    # ----------------------------------------------------------------- #
    # Fase di setup 
    # ----------------------------------------------------------------- #
    def setup(self, credentials: dict[str, str]) -> None:
        """
        Prepara l'elezione prima dell'apertura delle urne.
        'credentials' = {voter_id: password} di tutti gli aventi diritto.
        """
        # Identificativo della sessione (serve nelle verifiche indipendenti).
        self.bb.post("election_id", self.election_id)

        # L'IdP condivide fuori banda la propria chiave/cert con l'AE, così l'AE
        # potrà verificare i token senza poter autenticare gli elettori.
        self.ae.register_idp(self.idp.cert, self.idp.public_key)

        # Pubblica i certificati delle entità operative sul bulletin board.
        self.bb.post("idp_cert", self.idp.cert)
        self.bb.post("ae_certs", {"sign": self.ae.cert_sign, "enc": self.ae.cert_enc})

        # CRL iniziale (vuota), firmata dalla CA.
        self.bb.update_crl(self.ca.issue_crl())

        # Lista ufficiale dei candidati, firmata dalla Commissione.
        self.commission.publish_candidate_list(self.bb, self.theses)

        # Registro R: caricato nell'IdP e firmato dalla Commissione.
        self.idp.load_registry(credentials)
        registry_sig = self.commission.sign_registry(self.idp.eligible_ids)
        self.bb.post("registry_signature", registry_sig)

        # N_elig firmato: il tetto pubblico al numero di token emettibili.
        self.commission.publish_eligibility_count(self.bb, len(credentials))

        self._setup_done = True

    def new_voter(self, voter_id: str, password: str) -> Voter:
        """Crea un client elettore (riceve pk_CA fuori banda)."""
        return Voter(voter_id, password, self.election_id, self.ca_public)

    # ----------------------------------------------------------------- #
    # Revoca di un certificato: la CA torna online e aggiorna la CRL 
    # ----------------------------------------------------------------- #
    def revoke(self, cert) -> None:
        """Revoca un certificato e pubblica la CRL aggiornata sul bulletin board."""
        self.bb.update_crl(self.ca.revoke_certificate(cert))

    # ----------------------------------------------------------------- #
    # Chiusura e scrutinio 
    # ----------------------------------------------------------------- #
    def close_and_tally(self) -> dict[str, object]:
        """Chiude le urne, fa pubblicare K all'IdP ed esegue lo scrutinio dell'AE."""
        closure = self.ae.close_election()
        self.idp.publish_token_count(self.bb)
        tally = self.ae.tally()
        return {"closure": closure, "tally": tally}
