"""
pki — Infrastruttura a chiave pubblica (PKI) del sistema.

Serve a rispondere a una domanda: "questa chiave pubblica appartiene davvero a
chi dice di essere?". La risposta arriva dai CERTIFICATI X.509, firmati da una
Certification Authority (CA) di cui tutti si fidano.

Cosa fa questo modulo:
  * crea una CA dedicata all'elezione (CA_voto), con un certificato self-signed
    che funge da "ancora di fiducia";
  * la CA emette i certificati X.509 di IdP, Autorità Elettorale e Commissione;
  * la CA pubblica e aggiorna una CRL (Certificate Revocation List): la lista
    firmata dei certificati revocati;
  * fornisce le funzioni per VERIFICARE un certificato con politica HARD-FAIL:
    se la CRL manca o non è valida, il certificato viene rifiutato.

Modello di fiducia: dopo aver emesso i certificati, la chiave privata
della CA (sk_CA) viene "portata offline". Nella simulazione questo è reso dal
fatto che solo l'oggetto CertificateAuthority la possiede, e la usa unicamente
per emettere o aggiornare la CRL.


"""

from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509.oid import NameOID

from .crypto_utils import generate_rsa_keypair

# Durata di validità di certificati e CRL (giorni). 
VALIDITY_DAYS = 30


def _utcnow() -> dt.datetime:
    """Ora corrente in UTC (i certificati ragionano sempre in UTC)."""
    return dt.datetime.now(dt.timezone.utc)


def _key_usage(purpose: str) -> x509.KeyUsage:
    """
    Costruisce l'estensione X.509 keyUsage, che dichiara lo SCOPO della chiave.
    L'API richiede tutti i flag: qui partiamo da tutto disattivato e accendiamo
    solo quello che serve.
      * "sign"    -> firma digitale  (token, ricevute, root, risultato)
      * "encrypt" -> cifratura       (chiave usata per cifrare le schede)
    """
    flags = dict(
        digital_signature=False, content_commitment=False,
        key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=False, crl_sign=False,
        encipher_only=False, decipher_only=False,
    )
    if purpose == "sign":
        flags["digital_signature"] = True
        flags["content_commitment"] = True  # non ripudio
    elif purpose == "encrypt":
        flags["key_encipherment"] = True
    else:
        raise ValueError(f"scopo non valido: {purpose!r} (atteso 'sign'/'encrypt')")
    return x509.KeyUsage(**flags)


class CertificateAuthority:
    """CA dedicata all'elezione: emette i certificati X.509 e gestisce la CRL."""

    def __init__(self, name: str = "CA-voto") -> None:
        self.name = name
        self._key = generate_rsa_keypair()      # sk_CA: resta confinata nella CA
        self._next_serial = 1000                # contatore dei numeri di serie
        self._revoked: dict[int, dt.datetime] = {}  # serial -> data di revoca

        # Certificato self-signed: la CA firma se stessa. È l'ancora di fiducia,
        # distribuita fuori banda a tutti (subject e issuer coincidono).
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = _utcnow()
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            # "- 1 minuto" assorbe piccoli sfasamenti di orologio.
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=VALIDITY_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(self._key, hashes.SHA256())
        )

    @property
    def public_key(self) -> RSAPublicKey:
        """pk_CA: la chiave pubblica della CA, nota a tutte le entità."""
        return self._key.public_key()

    # ----------------------------------------------------------------- #
    # Emissione dei certificati delle entità
    # ----------------------------------------------------------------- #
    def issue_certificate(
        self, common_name: str, subject_public_key: RSAPublicKey, usage: str
    ) -> x509.Certificate:
        """
        Emette un certificato X.509 per `common_name`, legando la chiave pubblica
        all'identità e firmandolo con sk_CA. `usage` è "sign" oppure "encrypt".
        """
        serial = self._next_serial
        self._next_serial += 1
        now = _utcnow()
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(self.cert.subject)          # emesso dalla nostra CA
            .public_key(subject_public_key)
            .serial_number(serial)
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=VALIDITY_DAYS))
            .add_extension(_key_usage(usage), critical=True)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._key, hashes.SHA256())
        )

    # ----------------------------------------------------------------- #
    # CRL: lista dei certificati revocati, firmata dalla CA
    # ----------------------------------------------------------------- #
    def issue_crl(self) -> x509.CertificateRevocationList:
        """
        Emette la CRL corrente, firmata da sk_CA. All'inizio è vuota (CRL_0);
        ogni revoca la aggiorna.
        """
        now = _utcnow()
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.cert.subject)
            .last_update(now)
            .next_update(now + dt.timedelta(days=VALIDITY_DAYS))
        )
        # Aggiunge una voce per ogni certificato revocato.
        for serial, when in self._revoked.items():
            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(when)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)
        return builder.sign(self._key, hashes.SHA256())

    def revoke_certificate(self, cert: x509.Certificate) -> x509.CertificateRevocationList:
        """Revoca un certificato (la CA torna 'online') e restituisce la nuova CRL."""
        self._revoked[cert.serial_number] = _utcnow()
        return self.issue_crl()


# --------------------------------------------------------------------------- #
# Verifica di certificati e CRL.
# Sono funzioni "libere": chiunque conosca pk_CA può eseguirle.
# --------------------------------------------------------------------------- #
class CertificateRejected(Exception):
    """Sollevata quando un certificato è invalido, scaduto o revocato."""


def _signed_by_ca(tbs_bytes: bytes, signature: bytes, algorithm, ca_public_key) -> bool:
    """
    Controlla che 'signature' sia una firma valida della CA sui byte 'tbs_bytes'
    ("to-be-signed"). I certificati/CRL X.509 sono firmati con PKCS#1 v1.5: è lo
    standard del formato, indipendente dallo schema PSS usato a livello applicativo.
    """
    try:
        ca_public_key.verify(signature, tbs_bytes, padding.PKCS1v15(), algorithm)
        return True
    except InvalidSignature:
        return False


def verify_certificate(cert: x509.Certificate, ca_public_key: RSAPublicKey) -> bool:
    """Vero se il certificato è firmato dalla CA ed è nella finestra di validità."""
    firma_ok = _signed_by_ca(
        cert.tbs_certificate_bytes, cert.signature,
        cert.signature_hash_algorithm, ca_public_key,
    )
    if not firma_ok:
        return False
    now = _utcnow()
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def verify_crl(crl, ca_public_key: RSAPublicKey) -> bool:
    """Vero se la CRL esiste, è firmata dalla CA ed è ancora valida."""
    if crl is None:
        return False
    firma_ok = _signed_by_ca(
        crl.tbs_certlist_bytes, crl.signature,
        crl.signature_hash_algorithm, ca_public_key,
    )
    if not firma_ok:
        return False
    return crl.next_update_utc is None or _utcnow() <= crl.next_update_utc


def check_certificate(cert, crl, ca_public_key: RSAPublicKey) -> None:
    """
    Controllo completo di un certificato con politica HARD-FAIL.
    Solleva CertificateRejected al primo problema:
      1. firma della CA non valida o certificato scaduto;
      2. CRL assente o non verificabile  (qui scatta l'hard-fail);
      3. il numero di serie del certificato compare nella CRL (revocato).
    L'hard-fail evita che un avversario faccia accettare un certificato revocato
    semplicemente impedendo l'accesso alla CRL.
    """
    if not verify_certificate(cert, ca_public_key):
        raise CertificateRejected("certificato non valido o scaduto")
    if not verify_crl(crl, ca_public_key):
        raise CertificateRejected("CRL assente o non verificabile (hard-fail)")
    if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
        raise CertificateRejected(f"certificato revocato (serial={cert.serial_number})")
