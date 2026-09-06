#!/usr/bin/env python3
"""
Interfaccia interattiva a riga di comando per il sistema di voto
elettronico (WP4).
"""

import getpass
import os
import secrets
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "core"))

from pki import RootCA
from aa import (
    AuthenticationAuthority, AlreadyVotedError, NotEligibleError,
    ExpiredCertificateError, InvalidCertificateSignatureError, Cert,
    DEFAULT_TOKEN_VALIDITY_SECONDS,
)
from ce import ElectionCommission
from gu import (
    BallotBox, InvalidBallotSignatureError, DuplicateBallotError,
    StaleClosureRoundError, DEFAULT_PUBLISH_EVERY_N,
)
from merkle import verify_merkle_proof
from crypto_utils import (
    generate_rsa_keypair, pubkey_to_pem, pem_to_pubkey, oaep_encrypt,
    oaep_decrypt, pss_sign, pss_verify, int_to_bytes8,
)

ADMIN_CODE = "AMM-2026-SVILUPPO"
LISTE = {0: "Scheda Bianca", 1: "Lista A", 2: "Lista B", 3: "Lista C"}


# STATO GLOBALE DELLA SESSIONE CLI
class State:
    def __init__(self):
        self.initialized = False
        self.root_ca = None
        self.aa = None
        self.ce = None
        self.gu = None
        self.students = []
        self.passwords = {}
        self.commissioner_passwords = {}
        self.token_validity_seconds = DEFAULT_TOKEN_VALIDITY_SECONDS
        self.publish_every_n = DEFAULT_PUBLISH_EVERY_N
        self.submitted_shares = {}  # nome commissario -> share fornita per lo scrutinio
        # "sessioni" locali della CLI, un solo utente alla volta, ma si può
        # cambiare identità tra un menu e l'altro nel corso dell'esecuzione
        self.current_student = None
        self.current_commissioner = None


S = State()




# UTILITY DI PRESENTAZIONE
def clear():
    os.system("cls" if os.name == "nt" else "clear")


def header(title):
    print("=" * 74)
    print(title)
    print("=" * 74)


def pause():
    input("\n[Premi INVIO per continuare] ")


def ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    val = input(f"{prompt}{suffix}: ").strip()
    return val if val else default


def ask_int(prompt, default):
    val = ask(prompt, str(default))
    try:
        return int(val)
    except ValueError:
        return default


def require_init():
    if not S.initialized:
        print("\n[!] Il sistema non è stato ancora costituito. Vai su 'Amministrazione' → 'Costituisci il sistema'.")
        pause()
        return False
    return True


def hx(b: bytes) -> str:
    return b.hex()



# 1. PORTALE AMMINISTRAZIONE


def menu_amministrazione():
    while True:
        clear()
        header("AMMINISTRAZIONE — accesso da insider sull'infrastruttura del GU")
        print("[Si consiglia di premere semplicemente INVIO se si vogliono lasciare le impostazioni di default.]")
        print("Codice di servizio dimostrativo:", ADMIN_CODE)
        print()
        print("1. Costituisci il sistema elettorale")
        print("2. Reset completo")
        print("3. Mostra foglio credenziali (elettori + commissari)")
        print("4. Stato dell'urna (vista amministrativa)")
        print("5. Base dati grezza dell'urna")
        print("6. Manomette una scheda (impersona Sam il Gestore Malizioso")
        print("0. Torna al menu principale")
        choice = ask("\nScelta", "0")

        if choice == "1":
            azione_costituisci_sistema()
        elif choice == "2":
            azione_reset()
        elif choice == "3":
            azione_mostra_credenziali()
        elif choice == "4":
            azione_stato_urna()
        elif choice == "5":
            azione_urna_grezza()
        elif choice == "6":
            azione_manomette_scheda()
        elif choice == "0":
            return


def azione_costituisci_sistema():
    clear()
    header("Costituzione del sistema elettorale")
    code = ask("Codice di accesso amministrativo", ADMIN_CODE)
    if code != ADMIN_CODE:
        print("[!] Codice non valido.")
        pause()
        return

    n_students = ask_int("Studenti eleggibili", 12)
    threshold = ask_int("Soglia commissari (t)", 3)
    members = ask_int("Commissari totali (n)", 5)
    token_validity = ask_int("Validità Cert / NotAfter (secondi)", 300)
    publish_every_n = ask_int("Pubblica bacheca ogni N schede", 3)

    if not (2 <= threshold <= members):
        print("[!] Richiesto 2 <= t <= n.")
        pause()
        return

    root_ca = RootCA()
    intermediate_ca = root_ca.create_intermediate()
    aa_sk, aa_pk, aa_cert = intermediate_ca.issue_server_certificate("aa.unisa.it")
    gu_sk, gu_pk, gu_cert = intermediate_ca.issue_server_certificate("gu.unisa.it")
    assert (root_ca.verify_chain(aa_cert, intermediate_ca.certificate)
            and root_ca.verify_chain(gu_cert, intermediate_ca.certificate))

    ce = ElectionCommission(threshold=threshold, n_members=members)
    students = [f"IE2270{1000 + i}" for i in range(n_students)]
    aa = AuthenticationAuthority(aa_sk, aa_pk, aa_cert, eligible_students=students,
                                  token_validity_seconds=token_validity)
    gu = BallotBox(gu_sk, gu_pk, gu_cert, aa_public_key=aa_pk, publish_every_n=publish_every_n,
                   closure_threshold=threshold)

    passwords = {sid: secrets.token_hex(3) for sid in students}
    commissioner_names = list(ce.member_shares.keys())
    commissioner_passwords = {name: secrets.token_hex(3) for name in commissioner_names}

    S.__init__()
    S.initialized = True
    S.root_ca, S.aa, S.ce, S.gu = root_ca, aa, ce, gu
    S.students = students
    S.passwords = passwords
    S.commissioner_passwords = commissioner_passwords
    S.token_validity_seconds = token_validity
    S.publish_every_n = publish_every_n

    print(f"\n[OK] Sistema costituito: {n_students} studenti, soglia ({threshold},{members}), "
          f"Cert validi {token_validity}s, bacheca ogni {publish_every_n} schede.")
    azione_mostra_credenziali(paused=False)
    pause()


def azione_reset():
    code = ask("Codice di accesso amministrativo per confermare il reset", "")
    if code != ADMIN_CODE:
        print("[!] Codice non valido: reset annullato.")
        pause()
        return
    S.__init__()
    print("[OK] Sistema azzerato.")
    pause()


def azione_mostra_credenziali(paused=True):
    if not require_init():
        return
    print("\n--- Foglio credenziali elettori ---")
    for sid, pw in S.passwords.items():
        print(f"  {sid}  ->  {pw}")
    print("\n--- Foglio credenziali Commissione Elettorale ---")
    for name, pw in S.commissioner_passwords.items():
        print(f"  {name}  ->  {pw}")
    if paused:
        pause()


def azione_stato_urna():
    if not require_init():
        return
    aa, gu, ce = S.aa, S.gu, S.ce
    voted = sum(1 for r in aa._db.values() if r["voted"])
    board = gu.published_board
    print(f"\nStudenti: {len(aa._db)} · Votanti: {voted} · Schede in urna: {len(gu)}")
    print(f"Urna: {'chiusa' if gu.closed else 'aperta'} · Bacheca pubblicata: {board.n if board else 0}/{len(gu)}")
    print(f"Auto-consistenza: {gu.verify_ledger_self_consistency()} · "
          f"Coerenza bacheca pubblicata: {gu.verify_published_snapshot()}")
    print(f"Conferme di chiusura: {len(gu.closure_confirmations)}/{gu.closure_threshold} "
          f"({', '.join(gu.closure_confirmations.keys()) or 'nessuna'})")
    print(f"Quote di scrutinio fornite: {len(S.submitted_shares)}/{ce.threshold} "
          f"({', '.join(S.submitted_shares.keys()) or 'nessuna'})")
    pause()


def azione_urna_grezza():
    if not require_init():
        return
    gu = S.gu
    if len(gu) == 0:
        print("\nNessuna scheda registrata.")
        pause()
        return
    print(f"\n{'#':<4}{'h (troncato)':<24}{'c (troncato)':<24}{'pubblicata'}")
    board_n = gu.published_board.n if gu.published_board else 0
    for e in gu.ledger:
        print(f"{e.index:<4}{e.h.hex()[:20]+'…':<24}{e.c.hex()[:20]+'…':<24}{'sì' if e.index < board_n else 'in attesa'}")
    pause()


def azione_manomette_scheda():
    if not require_init():
        return
    gu = S.gu
    if len(gu) == 0:
        print("\nNessuna scheda su cui intervenire.")
        pause()
        return
    idx = ask_int("Indice scheda da manomettere", 0)
    if idx < 0 or idx >= len(gu):
        print("[!] Indice fuori dai limiti.")
        pause()
        return
    original = gu.ledger[idx].c
    tampered = bytes([original[0] ^ 0xFF]) + original[1:]
    gu.tamper_with_entry(idx, tampered)
    print(f"\n[OK] Scheda #{idx} riscritta direttamente sul database (byte 0 invertito).")
    print(f"Auto-consistenza dopo la manomissione: {gu.verify_ledger_self_consistency()} (atteso: False)")
    print(f"Coerenza con la bacheca pubblicata: {gu.verify_published_snapshot()} (atteso: False se già pubblicata)")
    pause()



# 2. PORTALE ELETTORE
def menu_elettore():
    while True:
        clear()
        header("PORTALE ELETTORE")
        if not S.initialized:
            print("Il sistema non è ancora costituito.")
            pause()
            return
        if S.current_student:
            voted = S.aa._db[S.current_student]["voted"]
            print(f"Autenticato come: {S.current_student} (votato: {'sì' if voted else 'no'})")
        else:
            print("Nessuna sessione attiva.")
        print()
        print("1. Accedi con matricola e password")
        print("2. Vota (richiede accesso)")
        print("3. Esci dalla sessione (logout)")
        print("0. Torna al menu principale")
        choice = ask("\nScelta", "0")

        if choice == "1":
            azione_login_elettore()
        elif choice == "2":
            azione_vota()
        elif choice == "3":
            S.current_student = None
            print("[OK] Sessione terminata.")
            pause()
        elif choice == "0":
            return


def azione_login_elettore():
    sid = ask("Matricola")
    pw = getpass.getpass("Password: ") if sys.stdin.isatty() else ask("Password")
    real_pw = S.passwords.get(sid)
    if real_pw is None:
        print("[!] Matricola non riconosciuta dall'anagrafica d'Ateneo.")
    elif pw != real_pw:
        print("[!] Credenziali non valide.")
    else:
        S.current_student = sid
        voted = S.aa._db[sid]["voted"]
        print(f"[OK] Accesso riuscito come {sid}." + (" Hai già votato in questa sessione elettorale." if voted else ""))
    pause()


def azione_vota():
    if not S.current_student:
        print("\n[!] Devi prima accedere (opzione 1).")
        pause()
        return
    if S.gu.closed:
        print("\n[!] Le urne sono chiuse.")
        pause()
        return
    if S.aa._db[S.current_student]["voted"]:
        print("\n[!] Hai già votato: il tuo certificato è già stato consumato.")
        pause()
        return

    t0 = time.perf_counter()
    print("\n[..] Generazione locale delle chiavi effimere <pktemp, sktemp> (CSPRNG)...")
    sktemp, pktemp = generate_rsa_keypair()
    pktemp_pem = pubkey_to_pem(pktemp)

    try:
        print("[..] Richiesta di certificazione ad AA (Cert = <NotAfter, sigma_AA>)...")
        cert = S.aa.authenticate_and_certify(S.current_student, pktemp_pem)
    except AlreadyVotedError as e:
        print(f"[!] Voto rifiutato da AA: {e}")
        pause()
        return
    except NotEligibleError as e:
        print(f"[!] Voto rifiutato da AA: {e}")
        pause()
        return
    print(f"    Cert ottenuto, NotAfter={cert.not_after} (tra {cert.not_after - int(time.time())}s).")

    print("\nPreferenza (Lista Chiusa):")
    for v, label in LISTE.items():
        print(f"  {v}. {label}")
    v = ask_int("Scelta", 0)
    if v not in LISTE:
        del sktemp
        print("\n[!] Scelta non valida. Il certificato di voto era già stato rilasciato e il tuo")
        print("    diritto di voto risulta consumato (l'AA marca lo studente come 'Votante' al")
        print("    momento della richiesta del Cert, non della sottomissione:")
        print("    non potrai votare di nuovo in questa sessione.")
        pause()
        return

    print("[..] Cifratura RSA-OAEP della preferenza con pkCE...")
    c = oaep_encrypt(S.ce.public_key, v.to_bytes(1, "big"))
    print("[..] Firma RSA-PSS della scheda cifrata con sktemp...")
    stemp = pss_sign(sktemp, c)

    try:
        print("[..] Sottomissione al Gestore dell'Urna (validazione Zero-Trust in 3 passi)...")
        receipt = S.gu.submit_ballot(c, stemp, cert.to_bytes(), pktemp_pem)
    except (ExpiredCertificateError, InvalidCertificateSignatureError,
            DuplicateBallotError, InvalidBallotSignatureError, RuntimeError) as e:
        print(f"[!] Scheda rifiutata dal GU: {e}")
        pause()
        return

    # Oblio crittografico: elimina il riferimento a sktemp.
    del sktemp

    dt = (time.perf_counter() - t0) * 1000
    sig_ok = pss_verify(S.gu.public_key, receipt.h + int_to_bytes8(receipt.timestamp), receipt.signature)
    print(f"\n[OK] Voto registrato in {dt:.1f} ms.")
    print(f"     Ricevuta h = {receipt.h.hex()}")
    print(f"     Timestamp = {receipt.timestamp}")
    print(f"     Firma del GU sulla ricevuta verificata localmente: {'VALIDA' if sig_ok else 'NON VALIDA'}")
    print("     Conserva questo valore di h: ti servirà per la verifica dalla Bacheca pubblica.")
    pause()


# 3. BACHECA PUBBLICA (nessun accesso richiesto)
def menu_bacheca():
    while True:
        clear()
        header("BACHECA PUBBLICA — nessun accesso richiesto, dati visibili a chiunque")
        if not S.initialized:
            print("Il sistema non è ancora costituito.")
            pause()
            return
        gu = S.gu
        board = gu.published_board
        print(f"Urna: {'chiusa' if gu.closed else 'aperta'} · Schede: {len(gu)} · "
              f"Bacheca pubblicata: {board.n if board else 0}")
        print()
        print("1. Verifica individuale (Proof of Membership) — inserisci una ricevuta h")
        print("2. Verifica universale — ricalcola la Merkle Root da zero")
        print("3. Verifica auto-consistenza (rileva manomissioni dirette)")
        print("4. Elenca le schede registrate")
        print("0. Torna al menu principale")
        choice = ask("\nScelta", "0")

        if choice == "1":
            azione_verifica_individuale()
        elif choice == "2":
            azione_verifica_universale()
        elif choice == "3":
            azione_verifica_self_consistency()
        elif choice == "4":
            azione_elenca_schede()
        elif choice == "0":
            return


def azione_verifica_individuale():
    h_hex = ask("Ricevuta h (esadecimale)")
    try:
        h = bytes.fromhex(h_hex.strip())
    except ValueError:
        print("[!] Formato non valido.")
        pause()
        return
    try:
        board, index, proof = S.gu.get_membership_proof(h)
    except ValueError as e:
        print(f"[!] {e}")
        pause()
        return
    path_ok = verify_merkle_proof(h, proof, board.root)
    sig_ok = pss_verify(S.gu.public_key, board.root, board.signature)
    print(f"\nIndice nella bacheca: {index} · lunghezza percorso: {len(proof)} passi")
    print(f"Percorso ricalcolato combacia con la Root pubblicata: {'SÌ' if path_ok else 'NO'}")
    print(f"Firma del GU sulla Root verificata: {'VALIDA' if sig_ok else 'NON VALIDA'}")
    print(f"\n{'→ Scheda provatamente inclusa nell’urna pubblicata.' if path_ok and sig_ok else '→ Verifica FALLITA.'}")
    pause()


def azione_verifica_universale():
    board = S.gu.published_board
    if board is None or board.n == 0:
        print("\n[!] Nessuna pubblicazione disponibile ancora.")
        pause()
        return
    from crypto_utils import sha256
    from merkle import merkle_root
    fresh_leaves = [sha256(S.gu.ledger[i].c) for i in range(board.n)]
    recomputed_root = merkle_root(fresh_leaves)
    root_matches = recomputed_root == board.root
    sig_ok = pss_verify(S.gu.public_key, board.root, board.signature)
    print(f"\nRicalcolata la Merkle Root da {len(fresh_leaves)} crittogrammi attualmente memorizzati.")
    print(f"Root ricalcolata: {recomputed_root.hex()}")
    print(f"Root pubblicata:  {board.root.hex()}")
    print(f"Coincidono: {'SÌ' if root_matches else 'NO'} · Firma del GU valida: {'SÌ' if sig_ok else 'NO'}")
    ok = root_matches and sig_ok
    print(f"\n{'→ Urna integra: nessuna scheda coperta da questa pubblicazione è stata alterata.' if ok else '→ ATTENZIONE: la Root ricalcolata NON coincide.'}")
    pause()


def azione_verifica_self_consistency():
    ok = S.gu.verify_ledger_self_consistency()
    print(f"\nAuto-consistenza (h vs SHA-256(c) attuale, per ogni scheda): {'OK' if ok else 'COMPROMESSA'}")
    pause()


def azione_elenca_schede():
    gu = S.gu
    if len(gu) == 0:
        print("\nNessuna scheda registrata.")
        pause()
        return
    board_n = gu.published_board.n if gu.published_board else 0
    print(f"\n{'#':<4}{'h (troncato)':<24}{'pubblicata'}")
    for e in gu.ledger:
        print(f"{e.index:<4}{e.h.hex()[:20]+'…':<24}{'sì' if e.index < board_n else 'in attesa'}")
    pause()




# 4. PORTALE COMMISSIONE ELETTORALE
def menu_commissione():
    while True:
        clear()
        header("COMMISSIONE ELETTORALE")
        if not S.initialized:
            print("Il sistema non è ancora costituito.")
            pause()
            return
        gu, ce = S.gu, S.ce
        print(f"Loggato come: {S.current_commissioner or '(nessuno)'}")
        print(f"Urna: {'chiusa' if gu.closed else 'aperta'} · "
              f"Conferme chiusura: {len(gu.closure_confirmations)}/{gu.closure_threshold} · "
              f"Quote scrutinio: {len(S.submitted_shares)}/{ce.threshold}")
        print()
        print("1. Accedi come commissario")
        print("2. Conferma la chiusura dell'urna")
        print("3. Carica il rimescolamento (array lessicografico dei crittogrammi)")
        print("4. Fornisci la tua quota per lo scrutinio")
        print("5. Ricostruisci skCE e avvia lo scrutinio")
        print("6. Esci dalla sessione (logout)")
        print("0. Torna al menu principale")
        choice = ask("\nScelta", "0")

        if choice == "1":
            azione_login_commissario()
        elif choice == "2":
            azione_conferma_chiusura()
        elif choice == "3":
            azione_rimescolamento()
        elif choice == "4":
            azione_fornisci_quota()
        elif choice == "5":
            azione_scrutinio()
        elif choice == "6":
            S.current_commissioner = None
            print("[OK] Sessione terminata.")
            pause()
        elif choice == "0":
            return


def azione_login_commissario():
    name = ask("Nome commissario (es. Commissario_1)")
    pw = getpass.getpass("Password: ") if sys.stdin.isatty() else ask("Password")
    real_pw = S.commissioner_passwords.get(name)
    if real_pw is None or pw != real_pw:
        print("[!] Credenziali di commissario non valide.")
    else:
        S.current_commissioner = name
        print(f"[OK] Accesso riuscito come {name}.")
    pause()


def azione_conferma_chiusura():
    if not S.current_commissioner:
        print("\n[!] Devi accedere come commissario (opzione 1).")
        pause()
        return
    gu = S.gu
    if gu.closed:
        print("\n[!] Le urne sono già chiuse.")
        pause()
        return
    print(f"\nRound di chiusura corrente: {gu.closure_round_id}")
    try:
        result = gu.confirm_closure(S.current_commissioner, gu.closure_round_id)
    except StaleClosureRoundError as e:
        print(f"[!] {e}")
        pause()
        return
    print(f"[OK] Conferma registrata ({len(result['confirmations'])}/{gu.closure_threshold}): "
          f"{', '.join(result['confirmations'].keys())}")
    if result["closed"]:
        print(f"[OK] Soglia raggiunta: urna chiusa e bacheca pubblicata definitivamente "
              f"(Merkle Root su {gu.published_board.n} schede).")
    pause()


def azione_rimescolamento():
    gu = S.gu
    if not gu.closed:
        print("\n[!] Il rimescolamento è disponibile solo a urne chiuse.")
        pause()
        return
    lex = gu.lexicographic_ciphertexts()
    print(f"\n[OK] {len(lex)} crittogrammi estratti (nessun metadato) e ordinati lessicograficamente.")
    for i, c in enumerate(lex[:5]):
        print(f"  {i}: {c.hex()[:48]}…")
    if len(lex) > 5:
        print(f"  … e altri {len(lex) - 5}")
    pause()


def azione_fornisci_quota():
    if not S.current_commissioner:
        print("\n[!] Devi accedere come commissario (opzione 1).")
        pause()
        return
    if not S.gu.closed:
        print("\n[!] Le urne devono essere chiuse prima di fornire la propria quota.")
        pause()
        return
    S.submitted_shares[S.current_commissioner] = S.ce.get_member_share(S.current_commissioner)
    print(f"\n[OK] Quota fornita. Totale: {len(S.submitted_shares)}/{S.ce.threshold}: "
          f"{', '.join(S.submitted_shares.keys())}")
    pause()


def azione_scrutinio():
    if not S.current_commissioner:
        print("\n[!] Devi accedere come commissario (opzione 1).")
        pause()
        return
    gu, ce = S.gu, S.ce
    if not gu.closed:
        print("\n[!] Le urne devono essere chiuse prima dello scrutinio.")
        pause()
        return
    if len(S.submitted_shares) < ce.threshold:
        print(f"\n[!] Servono almeno {ce.threshold} quote (fornite: {len(S.submitted_shares)}).")
        pause()
        return
    if not gu.verify_published_snapshot():
        print("\n[!] Scrutinio interrotto: la bacheca pubblicata non corrisponde ai crittogrammi "
              "attualmente memorizzati (integrità compromessa).")
        pause()
        return

    shares = list(S.submitted_shares.values())[:ce.threshold]
    print(f"\n[..] Ricostruzione di skCE in RAM isolata da {len(shares)} quote...")
    t0 = time.perf_counter()
    result = gu.tally(ce, shares)
    dt = time.perf_counter() - t0
    print(f"[OK] skCE distrutta dalla memoria subito dopo la decifratura (secure memory zeroing, best-effort).")
    print(f"[OK] Scrutinio completato in {dt:.3f}s su {result['n_ballots']} schede "
          f"({len(result['anomalies'])} anomalie: {result['anomalies']}).")
    print("\nRisultato (SOLO totali aggregati per lista — nessun voto individuale è mai esposto):")
    total = sum(result["counts"].values()) or 1
    for v, n in sorted(result["counts"].items()):
        pct = round(100 * n / total)
        bar = "█" * (pct // 2)
        print(f"  {LISTE.get(v, f'Valore {v}'):<14} {bar:<50} {n} ({pct}%)")
    pause()



# 5. CONSOLE DI RETE GREZZA (nessuna autenticazione — impersona l'attaccante)
def menu_attaccante():
    if not require_init():
        return
    clear()
    header("CONSOLE DI RETE GREZZA — nessuna autenticazione richiesta o disponibile")
    print("Costruisci a mano una richiesta verso il Gestore dell'Urna, senza mai passare")
    print("dal Portale Elettore. Utile per impersonare Alice/l'impostore.\n")

    print("[..] Generazione di una coppia di chiavi (nessuna autenticazione, nessun Cert legittimo)...")
    fake_sk, fake_pk = generate_rsa_keypair()
    fake_pk_pem = pubkey_to_pem(fake_pk)

    print("\nScegli come costruire il Cert:")
    print("1. Auto-firma (non possiedi skAA — verrà rifiutato dal GU)")
    print("2. Incolla un Cert intercettato altrove (esadecimale)")
    choice = ask("Scelta", "1")

    if choice == "2":
        cert_hex = ask("Cert (esadecimale)", "")
        try:
            cert_bytes = bytes.fromhex(cert_hex)
        except ValueError:
            print("[!] Formato non valido.")
            pause()
            return
    else:
        not_after = int(time.time()) + 300
        sigma = pss_sign(fake_sk, fake_pk_pem + int_to_bytes8(not_after))
        cert_bytes = int_to_bytes8(not_after) + sigma
        print(f"[OK] Cert auto-firmato con chiave propria (NotAfter={not_after}). "
              "Non è firmato da skAA: sarà rifiutato.")

    print("\nPreferenza da cifrare:")
    for v, label in LISTE.items():
        print(f"  {v}. {label}")
    v = ask_int("Scelta", 1)
    c = oaep_encrypt(S.ce.public_key, v.to_bytes(1, "big"))
    print(f"[OK] Scheda cifrata con pkCE (pubblica, chiunque può farlo): {c.hex()[:32]}…")

    stemp = pss_sign(fake_sk, c)
    print(f"[OK] Scheda firmata con la chiave propria: {stemp.hex()[:32]}…")

    if ask("\nInviare al Gestore dell'Urna? (s/n)", "s").lower() == "s":
        try:
            receipt = S.gu.submit_ballot(c, stemp, cert_bytes, fake_pk_pem)
            print(f"\n[!!] La richiesta è stata ACCETTATA. Ricevuta: {receipt.h.hex()}")
            print("     Se non te lo aspettavi, verifica il modello di minaccia: potrebbe esserci una vulnerabilità.")
        except (InvalidCertificateSignatureError, ExpiredCertificateError,
                DuplicateBallotError, InvalidBallotSignatureError, RuntimeError) as e:
            print(f"\n[OK] Richiesta RIFIUTATA dal Gestore dell'Urna: {type(e).__name__}: {e}")
    pause()



# 6. SCENARI DI MINACCIA GUIDATI (facoltativo: automatizza la "recita" dei ruoli)
def menu_scenari():
    while True:
        clear()
        header("SCENARI DI MINACCIA GUIDATI (WP3) — dimostrazione rapida")
        print("Le stesse mitigazioni si possono verificare manualmente dai portali sopra:")
        print("qui sotto trovi solo delle scorciatoie per una dimostrazione rapida in sequenza.\n")
        print("1. Tony — secondo voto (stesso studente, due accessi)")
        print("2. Tony — richieste concorrenti reali (due thread paralleli)")
        print("3. Certificato scaduto — NotAfter ")
        print("0. Torna al menu principale")
        choice = ask("\nScelta", "0")

        if choice == "1":
            scenario_tony_ripetuto()
        elif choice == "2":
            scenario_tony_concorrente()
        elif choice == "3":
            scenario_certificato_scaduto()
        elif choice == "0":
            return


def scenario_tony_ripetuto():
    if not require_init():
        return
    voted_students = [sid for sid, r in S.aa._db.items() if r["voted"]]
    if not voted_students:
        print("\n[!] Nessuno studente ha ancora votato: vota prima dal Portale Elettore.")
        pause()
        return
    sid = voted_students[0]
    print(f"\nRiuso le credenziali di {sid} (già votante) per un secondo accesso...")
    S.current_student = sid  # login "silenzioso" per la demo, stesse credenziali reali
    print(f"[OK] Login effettuato di nuovo come {sid}.")
    azione_vota()


def scenario_tony_concorrente():
    if not require_init():
        return
    unvoted = [sid for sid, r in S.aa._db.items() if not r["voted"]]
    if not unvoted:
        print("\n[!] Nessuno studente disponibile per il test.")
        pause()
        return
    sid = unvoted[0]
    print(f"\nLancio due richieste HTTP-equivalenti concorrenti per {sid} (thread paralleli reali)...")

    def attempt():
        try:
            sk, pk = generate_rsa_keypair()
            pem = pubkey_to_pem(pk)
            cert = S.aa.authenticate_and_certify(sid, pem)
            c = oaep_encrypt(S.ce.public_key, (1).to_bytes(1, "big"))
            stemp = pss_sign(sk, c)
            S.gu.submit_ballot(c, stemp, cert.to_bytes(), pem)
            return "OK"
        except (AlreadyVotedError, NotEligibleError, DuplicateBallotError):
            return "RIFIUTATO"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))
    successes = results.count("OK")
    print(f"\nRichieste accettate: {successes}/2 (atteso 1/2).")
    print("[OK] Transazione atomica confermata." if successes == 1 else "[!] Comportamento inatteso!")
    pause()


def scenario_certificato_scaduto():
    if not require_init():
        return
    unvoted = [sid for sid, r in S.aa._db.items() if not r["voted"]]
    if not unvoted:
        print("\n[!] Nessuno studente disponibile per il test (tutti hanno già votato).")
        pause()
        return
    sid = unvoted[0]
    print(f"\nQuesto scenario 'consuma' il diritto di voto di {sid} (come nel mondo reale, "
          f"il certificato viene rilasciato una volta sola).")
    wait_s = ask_int("Validità del Cert per questa demo (secondi)", 3)

    original_validity = S.aa.token_validity_seconds
    S.aa.token_validity_seconds = wait_s
    print(f"\n[..] Validità del Cert impostata temporaneamente a {wait_s}s (era {original_validity}s).")
    print(f"[..] Generazione chiavi effimere e richiesta del Cert reale ad AA per {sid}...")
    sktemp, pktemp = generate_rsa_keypair()
    pktemp_pem = pubkey_to_pem(pktemp)
    try:
        cert = S.aa.authenticate_and_certify(sid, pktemp_pem)
    except (AlreadyVotedError, NotEligibleError) as e:
        print(f"[!] {e}")
        S.aa.token_validity_seconds = original_validity
        pause()
        return
    finally:
        # Ripristina subito la validità normale: non influenza gli altri elettori,
        # il cui Cert (già eventualmente emesso o futuro) resta a original_validity.
        S.aa.token_validity_seconds = original_validity

    print(f"    Cert ottenuto: NotAfter={cert.not_after} (ora={int(time.time())}).")
    wait_actual = max(1, cert.not_after - int(time.time()) + 1)
    print(f"[..] Attendo {wait_actual}s oltre la scadenza — simula un'interruzione/crash "
          f"dell'applicazione prima della sottomissione al GU...")
    time.sleep(wait_actual)

    print("[..] Cifratura e firma della scheda (come se l'app riprendesse dopo l'interruzione)...")
    c = oaep_encrypt(S.ce.public_key, (1).to_bytes(1, "big"))
    stemp = pss_sign(sktemp, c)

    print("[..] Sottomissione al Gestore dell'Urna...")
    try:
        S.gu.submit_ballot(c, stemp, cert.to_bytes(), pktemp_pem)
        print("\n[!!] La scheda con certificato scaduto è stata ACCETTATA: VULNERABILITÀ!")
    except ExpiredCertificateError as e:
        print(f"\n[OK] Scheda rifiutata dal GU per scadenza del certificato: {e}")
        print(f"     {sid} ha comunque 'consumato' il proprio diritto di voto (l'AA marca lo")
        print("     studente come Votante al momento della RICHIESTA del Cert, non della")
        print("     sottomissione — coerente con WP2 §2.1.1 passo 5): non può più votare in")
        print("     questa sessione, esattamente come accadrebbe nel mondo reale se un elettore")
        print("     lasciasse scadere il gettone senza completare l'invio in tempo.")
    pause()


# =============================================================================
# 7. PRESTAZIONI
# =============================================================================

def menu_prestazioni():
    clear()
    header("BENCHMARK DELLE PRESTAZIONI")
    n = ask_int("Iterazioni per operazione", 10)

    def bench(name, fn):
        samples = []
        for _ in range(n):
            t0 = time.perf_counter()
            fn()
            samples.append((time.perf_counter() - t0) * 1000)
        mean = statistics.mean(samples)
        print(f"  {name:<42s}: media {mean:8.3f} ms  (min {min(samples):.3f} / max {max(samples):.3f})")

    sk, pk = generate_rsa_keypair()
    print()
    bench("Generazione coppia RSA-2048", lambda: generate_rsa_keypair())
    bench("Cifratura RSA-OAEP", lambda: oaep_encrypt(pk, b"\x01"))
    ct = oaep_encrypt(pk, b"\x01")
    bench("Decifratura RSA-OAEP", lambda: oaep_decrypt(sk, ct))
    bench("Firma RSA-PSS", lambda: pss_sign(sk, ct))
    sig = pss_sign(sk, ct)
    bench("Verifica RSA-PSS", lambda: pss_verify(pk, ct, sig))

    if S.initialized:
        shares = [S.ce.get_member_share(n_) for n_ in list(S.ce.member_shares.keys())[:S.ce.threshold]]
        bench(f"Ricostruzione skCE (Shamir t={S.ce.threshold})", lambda: S.ce.reconstruct_private_key(shares))

    pktemp_pem = pubkey_to_pem(pk)
    cert_bytes = int_to_bytes8(0) + pss_sign(sk, pktemp_pem + int_to_bytes8(0))
    size = len(ct) + len(sig) + len(cert_bytes) + len(pktemp_pem)
    print(f"\nDimensione di Mvoto = <c, stemp, Cert, pktemp>: {size} byte "
          f"(c={len(ct)}, stemp={len(sig)}, Cert={len(cert_bytes)}, pktemp_PEM={len(pktemp_pem)})")
    pause()



# MENU PRINCIPALE
def menu_principale():
    while True:
        clear()
        header("SISTEMA DI VOTO ELETTRONICO — Consiglio degli Studenti (CLI)")
        stato = "costituito" if S.initialized else "non costituito"
        print(f"Stato sistema: {stato}")
        if S.initialized:
            print(f"Urna: {'chiusa' if S.gu.closed else 'aperta'} · Schede: {len(S.gu)}")
        print()
        print("1. Amministrazione (costituzione del sistema, accesso insider)")
        print("2. Portale Elettore (accesso + voto)")
        print("3. Bacheca pubblica (verifiche, nessun accesso richiesto)")
        print("4. Commissione Elettorale (chiusura, rimescolamento, scrutinio)")
        print("5. Console di rete grezza (nessuna autenticazione — impersona l'attaccante)")
        print("6. Scenari di minaccia guidati (WP3)")
        print("7. Prestazioni")
        print("0. Esci")
        choice = ask("\nScelta", "0")

        if choice == "1":
            menu_amministrazione()
        elif choice == "2":
            menu_elettore()
        elif choice == "3":
            menu_bacheca()
        elif choice == "4":
            menu_commissione()
        elif choice == "5":
            menu_attaccante()
        elif choice == "6":
            menu_scenari()
        elif choice == "7":
            menu_prestazioni()
        elif choice == "0":
            print("\nArrivederci.")
            return


if __name__ == "__main__":
    try:
        menu_principale()
    except (KeyboardInterrupt, EOFError):
        print("\n\nInterrotto dall'utente. Arrivederci.")
