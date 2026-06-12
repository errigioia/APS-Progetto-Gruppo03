# WP4 — Implementazione e prestazioni
### Sistema di voto elettronico sicuro — Premio "Tesi dell'Anno" dell'Ateneo

Implementazione in ambiente simulato (stand-alone, in-process) del protocollo
progettato in **WP2**, secondo il modello e le proprietà di sicurezza definiti
in **WP1**. Tutte le entità del sistema (CA, Commissione Accademica, Identity
Provider, Autorità Elettorale, Bulletin Board, Elettori) sono simulate come
oggetti Python distinti che si scambiano messaggi, mantenendo la **separazione
dei ruoli** prevista dal modello.

L'implementazione usa esclusivamente la libreria **`cryptography`** e gli strumenti crittografici già
visti a lezione: RSA-OAEP, firme RSA (hash-and-sign con SHA-256), SHA-256 e
Merkle tree.

---

## Requisiti e installazione

```bash
python3 -m pip install -r requirements.txt   # solo: cryptography
```

Testato con Python 3.13 e `cryptography` 46.

## Esecuzione

```bash
python3 gui.py                   # interfaccia grafica (Tkinter)
python3 demo.py                  # scenario completo narrato + validazioni di sicurezza
python3 benchmark.py             # misure di prestazione (salva results/benchmark.csv)
python3 tests/test_protocol.py   # suite di test (positivi e negativi)
```

### Interfaccia grafica ([gui.py](gui.py))

GUI Tkinter (nessuna dipendenza extra). È solo
uno strato di presentazione sopra il pacchetto `wp4`: non contiene logica
crittografica. Quattro schede guidano l'intero protocollo:

1. **Setup** — configura tesi ed elettorato, inizializza PKI ed entità;
2. **Voto** — autentica un elettore (token IdP), cifra e invia la scheda, ricevuta;
3. **Urna** — bulletin board pubblico: schede cifrate, Merkle root, K;
4. **Scrutinio & Verifica** — chiusura, conteggio, verifica individuale e universale.

---

## Architettura del codice

Scelta progettuale: **simulazione in-process a moduli** (un'unica applicazione
stand-alone, come consentito dalla traccia) con **PKI X.509 e CRL reali**; il
canale TLS è modellato come canale sicuro (assunzione dichiarata).

| File | Entità / ruolo | Riferimento WP2 |
|------|----------------|-----------------|
| [wp4/crypto_utils.py](wp4/crypto_utils.py) | Primitive: RSA-OAEP, RSA-PSS, SHA-256, Merkle tree | 2.1 |
| [wp4/pki.py](wp4/pki.py) | CA dedicata, certificati X.509, CRL, verifica hard-fail | 2.2 |
| [wp4/bulletin_board.py](wp4/bulletin_board.py) | Bulletin board pubblico append-only + Merkle | 2.1, 2.2 |
| [wp4/commission.py](wp4/commission.py) | Commissione Accademica (lista candidati, registro, N_elig) | 2.2, 2.3 |
| [wp4/idp.py](wp4/idp.py) | Identity Provider (autenticazione, token = nonce firmato) | 2.3 |
| [wp4/authority.py](wp4/authority.py) | Autorità Elettorale (voto, ricevuta, scrutinio) | 2.4, 2.5 |
| [wp4/voter.py](wp4/voter.py) | Elettore (votazione + verifica individuale) | 2.4, 2.6.1 |
| [wp4/verifier.py](wp4/verifier.py) | Verifica universale (osservatore esterno) | 2.6.2 |
| [wp4/election.py](wp4/election.py) | Orchestrazione delle 4 fasi (setup/auth/voto/scrutinio) | 2.1 |

---

## Mappatura protocollo → codice

**Fase di setup (2.2).** `Election.setup()` crea la `CertificateAuthority`
self-signed, emette i certificati X.509 con `keyUsage` distinti
(`digitalSignature` per le chiavi di firma di IdP/AE/Commissione,
`keyEncipherment` per la chiave di cifratura `ek_AE`), pubblica la CRL iniziale,
la lista candidati firmata `(C, σ_C)` con scheda bianca `c⊥`, e `N_elig` firmato.
L'AE genera **due coppie RSA distinte** (firma e cifratura).

**Autenticazione (2.3).** `Voter.authenticate()` apre il canale verificando il
certificato dell'IdP con la CRL (hard-fail); `IdentityProvider.authenticate()`
controlla credenziali e flag `voted`, genera il
token `T=(N, σ_N)` con `σ_N = Sign_skIdP(H(N ∥ election_id))` e imposta
`voted=True` **prima** di consegnarlo (anti race-condition). È previsto il
`recover_token()` per il recovery.

**Votazione (2.4).** `Voter.cast_vote()` costruisce `m = c_v ∥ r`, cifra con
`ct = Enc_ekAE(m)` (RSA-OAEP), e invia `M_vote=(N, σ_N, ct)`.
`ElectionAuthority.cast_vote()` esegue: CRL hard-fail sul certificato IdP,
verifica firma del token, controllo unicità del nonce (insieme `U`, con gestione
del re-invio legittimo vs doppio voto), registrazione su bulletin board con
aggiornamento+firma della Merkle root, ed emissione della ricevuta
`ρ = Sign_skAE(H(ct ∥ ts ∥ election_id))`. L'elettore conserva `F=(c_v, r, ct, ρ)`.

**Scrutinio (2.5).** `Election.close_and_tally()` chiude le urne
(`σ_close` sulla root finale), l'IdP pubblica `K` firmato, l'AE decifra le
schede con `dk_AE`, scarta le invalide (lista `I`), pubblica le coppie
`D={(ct, c_v)}`, calcola il vettore `T` e firma `σ_result`.

**Verifica individuale (2.6.1).** `Voter.verify_individual()` = `VerifyVote`:
verifica autenticità della ricevuta, inclusione nel BB tramite Merkle proof e
corrispondenza `c_v` in `D`.

**Verifica universale (2.6.2).** `verifier.verify_election()` = `VerifyElection`:
passi 0–5 + bilancio dei voti `m ≤ K ≤ N_elig`, eseguiti solo su dati pubblici e
`pk_CA`.

---

## Assunzioni e limiti dell'implementazione (coerenti con WP2/WP3)

- **TLS astratto.** I canali sono modellati come sicuri: la simulazione
  stand-alone non instaura socket TLS reali. La libreria garantisce comunque
  l'autenticità delle chiavi pubbliche tramite la PKI X.509 implementata.
- **Non collusione IdP/AE.** Lo pseudoanonimato dipende dall'assunzione che IdP
  e AE non colludano (rischio residuo dichiarato in WP1).
- **Merkle tree ricalcolato ad ogni inserimento** (O(n) per inserimento).
- **Decifrazione non provata in ZK.** Come in WP2 (Compromesso 3), non è fornita
  una prova di correttezza della decifrazione: indicata come estensione futura.
- **Centralizzazione di `dk_AE` e del bulletin board** (Compromessi 4 e 6 del
  WP2): estensioni future = schema a soglia `(t,n)` e registro distribuito (DLT).

---

## Output atteso

- `demo.py` conduce un'elezione di esempio (8 elettori, 3 tesi + scheda bianca),
  mostra il risultato, supera la verifica individuale di tutti gli elettori e la
  verifica universale, e dimostra il blocco di: doppio voto, token contraffatto,
  certificato revocato (hard-fail), con riconoscimento del re-invio legittimo.
- `benchmark.py` riporta costo delle operazioni crittografiche, dimensione dei
  messaggi e latenze di voto/scrutinio/verifica al variare dell'elettorato.
- `tests/test_protocol.py` esegue 9 test (positivi e negativi).
