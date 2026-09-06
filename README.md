# Sistema di Voto Elettronico Universitario

**Project Work — Algoritmi e Protocolli per la Sicurezza**
Docenti: Carlo Mazzocca, Francesco Cauteruccio
Candidati: Radesca Antonio (IE22700221) · Rodia Pasquale (IE22700172)

---

## Descrizione

Implementazione simulata del protocollo crittografico progettato in WP2, come applicazione **a riga di comando** in Python (nessun server, nessun browser). Il sistema replica in un unico processo la separazione logica tra i cinque attori istituzionali definiti in WP1:

- **Root CA / CA Intermedia** — ancora di fiducia, emette i certificati X.509v3 di AA e GU su una gerarchia a due livelli
- **AA** (Autorità di Autenticazione) — anagrafica elettori, rilascia il certificato di voto anonimo `Cert = ⟨NotAfter, σAA⟩`
- **GU** (Gestore dell'Urna) — validazione Zero-Trust delle schede, Bacheca Pubblica come Albero di Merkle, chiusura a soglia, scrutinio
- **CE** (Commissione Elettorale) — genera `⟨pkCE, skCE⟩`, protegge `skCE` con secret sharing (t,n)
- **Elettore / Osservatori** — cabina di voto, verifica individuale e universale, entrambe accessibili senza credenziali

Le primitive crittografiche utilizzate sono **RSA-2048/4096**, **RSA-PSS+SHA-256** (firme, incluse quelle dei certificati X.509), **RSA-OAEP+SHA-256** (cifratura del voto), **SHA-256**, **Albero di Merkle**, **Encrypt-then-MAC** (AES-256-CBC+HMAC-SHA256) e **Shamir Secret Sharing** (t,n) configurabile.

---

## Struttura del Repository

```
aps_evoting_wp4/
├── cli.py                  # Interfaccia interattiva a riga di comando (menu testuale)
├── main.py                 # Simulazione automatica non interattiva, end-to-end
├── benchmark_full.py       # Suite di benchmark (costo, dimensioni, latenza, interazione)
├── esempio_output.txt      # Output di riferimento di main.py
└── core/
    ├── crypto_utils.py     # Libreria crittografica (tutte le primitive di base)
    ├── pki.py               # Root CA, CA Intermedia, emissione/verifica certificati X.509v3
    ├── aa.py                 # Autorità di Autenticazione: anagrafica, Cert con NotAfter
    ├── ce.py                 # Commissione Elettorale: pkCE/skCE, protezione con secret sharing
    ├── gu.py                 # Gestore dell'Urna: Zero-Trust, Merkle, chiusura a soglia, scrutinio
    ├── merkle.py             # Albero di Merkle: root, Proof of Membership, verifica
    └── shamir.py             # Schema (t,n)-Threshold Secret Sharing
```

Non esiste una cartella `templates/`: non essendoci interfaccia web, tutta la presentazione è testuale e vive dentro `cli.py`.

---

## Prerequisiti

- Python **3.9+**

Si consiglia di lavorare in un ambiente virtuale, per non installare le
dipendenze a livello di sistema:

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install cryptography
```

Il benchmark non richiede pacchetti aggiuntivi: riusa la stessa `cryptography` già installata.

---

## Avvio

Con l'ambiente virtuale attivo (vedi sopra):

```bash
python3 cli.py
```

Si apre un menu testuale nel terminale. Nessuna fase di setup automatica all'avvio: è la prima voce di menu (**Amministrazione → Costituisci il sistema elettorale**) a eseguire la Fase 1 — Setup crittografico:

- Generazione della Root CA e della CA Intermedia (RSA-4096), emissione dei certificati X.509v3 di AA e GU
- Generazione di `⟨pkCE, skCE⟩` per la Commissione Elettorale
- Protezione di `skCE` con Encrypt-then-MAC e frammentazione della chiave simmetrica risultante con Shamir (soglia t, n scelti a schermo)
- Generazione dell'anagrafica elettori e delle credenziali dei commissari, mostrate a video

---

## Credenziali di Test

A differenza di un sistema con dati precaricati, qui **non esistono credenziali fisse**: vengono generate casualmente ad ogni esecuzione di "Costituisci il sistema elettorale" e mostrate a schermo (matricole nella forma `IE2270xxxx`, commissari come `Commissario_1`, `Commissario_2`, ...). L'unico valore fisso è il codice di accesso amministrativo:

| Ruolo | Codice |
|-------|--------|
| Amministrazione | `AMM-2026-SVILUPPO` (mostrato in chiaro nel menu stesso) |

---

## Flusso Operativo

### Come Elettore

1. Dal menu principale → **2. Portale Elettore → 1. Accedi con matricola e password**
2. **2. Vota**: il client genera in locale la coppia di chiavi effimere, richiede il Cert all'AA, cifra la preferenza con RSA-OAEP, firma con RSA-PSS e sottomette la scheda al GU
3. Riceve una **Ricevuta** firmata `⟨h, Timestamp, σGU⟩`, verificata localmente prima di essere mostrata
4. Verifica la presenza della propria scheda in qualunque momento da **3. Bacheca pubblica → 1. Verifica individuale**, inserendo `h`

### Come Commissione Elettorale

1. Dal menu principale → **4. Commissione Elettorale → 1. Accedi come commissario** (uno alla volta, con nomi diversi)
2. **2. Conferma la chiusura**: richiede almeno *t* commissari distinti prima che l'urna si chiuda davvero e la bacheca venga pubblicata in via definitiva
3. **3. Carica il rimescolamento**: espone l'array dei soli crittogrammi, ordinato lessicograficamente
4. **4. Fornisci la tua quota**: ripetuto da almeno *t* commissari
5. **5. Ricostruisci skCE e avvia lo scrutinio**: ricostruzione in RAM via Shamir, decifratura, pubblicazione dei soli totali aggregati, distruzione del riferimento alla chiave

Il menu **6. Scenari di minaccia guidati** offre scorciatoie per Tony (doppio voto, sia sequenziale sia in race condition reale con thread paralleli) e per il certificato scaduto (NotAfter); Sam si impersona da **1. Amministrazione → 6. Manomette una scheda**, l'impostore da **5. Console di rete grezza**, senza mai passare dal Portale Elettore.

---

## Benchmark

Per misurare il costo computazionale, la dimensione dei messaggi e la latenza di ogni fase del protocollo:

```bash
python3 benchmark_full.py
```

Stampa a schermo l'avanzamento di ogni misura e salva tutti i numeri in `benchmark_results.json`. Richiede 1-2 minuti; non è basato su un ciclo di misurazione scritto ad hoc (media, min, max, numero di iterazioni per ciascuna operazione, riportati esplicitamente).

### Fasi misurate

| Fase dello script | Cosa misura |
|--------------------|-------------|
| Primitive crittografiche di base | Keygen RSA-2048/4096, firma/verifica PSS, cifratura/decifratura OAEP, SHA-256 |
| PKI | Emissione certificato X.509v3 (CA Intermedia), verifica della catena a due passaggi |
| Shamir | Ricostruzione di `skCE` a soglia minima e a soglie diverse (t=2..9) |
| Merkle | Calcolo della Root e generazione/verifica della Proof of Membership, da 10 a 10.000 foglie |
| Payload | Dimensione di `Mvoto`, della Ricevuta e della Proof of Membership |
| Voto end-to-end | Scomposizione della latenza di un voto completo, fase per fase |
| Scrutinio | Tempo totale al variare del numero di schede (50/200/500) |
| Verifica | Latenza di firma, catena X.509, Proof of Membership, auto-consistenza, coerenza della bacheca (VU.1) |

### Risultati di riferimento (Apple M3, arm64, Python 3.9.6, cryptography 42.x)

| Operazione | Mean |
|------------|------|
| SHA-256 | ≈ 0,002 ms |
| Verifica RSA-PSS | ≈ 0,034 ms |
| Cifratura RSA-OAEP | ≈ 0,025 ms |
| Firma RSA-PSS | ≈ 0,358 ms |
| Decifratura RSA-OAEP | ≈ 0,330 ms |
| Generazione coppia RSA-2048 | ≈ 44 ms |
| Generazione Root CA (RSA-4096) | ≈ 552 ms |
| Emissione certificato X.509v3 (CA Intermedia) | ≈ 46 ms |
| Verifica catena X.509 (Root→Intermedia→cert) | ≈ 0,23 ms |
| Ricostruzione skCE (Shamir, t=3, n=5) | ≈ 40 ms |
| Merkle Root (N=1.000) | ≈ 1,49 ms |
| Verifica Proof of Membership (N=1.000) | ≈ 0,012 ms |
| Scrutinio (50 schede) | ≈ 53 ms |
| Voto end-to-end completo | ≈ 43 ms |
| Auto-consistenza urna (N=100) | ≈ 0,13 ms |
| Coerenza bacheca / VU.1 (N=100) | ≈ 0,25 ms |

---

## Primitive Crittografiche Implementate

| Primitiva | Utilizzo nel protocollo |
|-----------|--------------------------|
| RSA-2048 KeyGen | Chiavi di sessione: elettore (`pktemp`/`sktemp`), AA, GU, CE |
| RSA-4096 KeyGen | Root CA e CA Intermedia |
| RSA-PSS + SHA-256 | `σAA` (Cert), `stemp` (scheda), firma della Ricevuta, firma della Merkle Root, firma dei certificati X.509v3 |
| RSA-OAEP + SHA-256 | Cifratura del voto: `c = RSA-OAEP_pkCE(v)` |
| SHA-256 | Foglie dell'Albero di Merkle, hash della Ricevuta |
| Albero di Merkle | Bacheca Pubblica, Proof of Membership (VI.1), verifica universale (VU.1) |
| Encrypt-then-MAC (AES-256-CBC + HMAC-SHA256) | Protezione di `skCE` prima della frammentazione |
| Shamir (t,n)-Threshold Secret Sharing | Distribuzione e ricostruzione della coppia di chiavi che protegge `skCE` |
| X.509v3 (gerarchia a due livelli) | Catena di fiducia Root CA → CA Intermedia → certificati end-entity di AA/GU |

---

## Note sulle Semplificazioni della Simulazione

- **TLS**: il protocollo (WP2 §2.1.1) assume un canale protetto da TLS per l'autenticazione. La PKI che lo renderebbe possibile è realizzata e verificata per davvero (Root CA, CA Intermedia, catena di fiducia); non viene però instaurato un vero handshake TLS, perché `cli.py`/`main.py` sono un unico processo locale senza comunicazione di rete — non esiste un canale di trasporto da cifrare.
- **Certificati X.509**: a differenza di una simulazione "leggera", qui sono oggetti X.509v3 reali (modulo `cryptography.x509`), con estensioni `BasicConstraints`/`KeyUsage`/`ExtendedKeyUsage` e firma RSA-PSS verificabile crittograficamente, non JSON firmato.
- **Chiusura a soglia**: il documento descrive mTLS e un payload firmato da *t* componenti della CE per il decreto di chiusura. La CLI ottiene la stessa garanzia procedurale (nessun commissario singolo può chiudere l'urna) con sessioni autenticate e un nonce anti-replay, senza mTLS né un vero schema di firma multipla.
- **Stato in memoria**: anagrafica, urna e bacheca sono strutture Python in RAM e si azzerano ad ogni riavvio della CLI.
- **Nessuna interfaccia grafica**: tutta l'interazione è testuale; per riprodurre uno scenario di minaccia si naviga nel menu "giocando" quel ruolo, non premendo un pulsante che esegue uno script preconfezionato.

---

Per uscire dall'ambiente virtuale a fine sessione:

```bash
deactivate
```

