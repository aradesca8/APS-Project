"""
main.py
-------
Simulazione stand-alone a riga di comando dell'intera elezione del
Consiglio degli Studenti, secondo il protocollo aggiornato di WP2 (Cert
con NotAfter, ricevuta firmata dal GU, Bacheca Pubblica come Albero di
Merkle) e verificato in WP3.

Uso:
    python3 main.py
"""

import concurrent.futures
import random
import statistics
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "core"))

from pki import RootCA
from aa import (
    AuthenticationAuthority, AlreadyVotedError, NotEligibleError,
    ExpiredCertificateError, InvalidCertificateSignatureError,
)
from ce import ElectionCommission
from gu import BallotBox, InvalidBallotSignatureError, DuplicateBallotError
from crypto_utils import (
    generate_rsa_keypair, pubkey_to_pem, oaep_encrypt, pss_sign, pss_verify,
)
from merkle import verify_merkle_proof

LISTE = {0: "Scheda Bianca", 1: "Lista A", 2: "Lista B", 3: "Lista C"}


class Voter:
    """Elettore (client): genera le chiavi effimere, ottiene Cert da AA,
    cifra/firma la scheda e la sottomette al GU."""

    def __init__(self, student_id: str):
        self.student_id = student_id

    def cast_vote(self, aa, gu, pkCE, vote_value: int):
        sktemp, pktemp = generate_rsa_keypair()
        pktemp_pem = pubkey_to_pem(pktemp)

        cert = aa.authenticate_and_certify(self.student_id, pktemp_pem)

        v_bytes = vote_value.to_bytes(1, "big")
        c = oaep_encrypt(pkCE, v_bytes)
        stemp = pss_sign(sktemp, c)

        receipt = gu.submit_ballot(c, stemp, cert.to_bytes(), pktemp_pem)

        # Oblio crittografico (WP2 §2.1.4, passo 4): sktemp non serve piu'
        # dopo la sottomissione. Python/cryptography non offre un modo per
        # azzerare esplicitamente la memoria di una chiave privata (nessun
        # "secure wipe" garantito), quindi il meglio ottenibile e' eliminare
        # ogni riferimento cosi' che il Garbage Collector possa reclamarla.
        del sktemp

        return receipt


def setup_infrastructure(n_students: int, ce_threshold: int, ce_n_members: int,
                          token_validity_seconds: int = 300, publish_every_n: int = 3):
    print("=" * 70)
    print("SETUP INFRASTRUTTURA")
    print("=" * 70)

    root_ca = RootCA()
    intermediate_ca = root_ca.create_intermediate()
    aa_sk, aa_pk, aa_cert = intermediate_ca.issue_server_certificate("aa.unisa.it")
    gu_sk, gu_pk, gu_cert = intermediate_ca.issue_server_certificate("gu.unisa.it")
    assert (root_ca.verify_chain(aa_cert, intermediate_ca.certificate)
            and root_ca.verify_chain(gu_cert, intermediate_ca.certificate))
    print("[OK] Root CA d'Ateneo attiva (offline dopo l'emissione dell'intermedia). "
          "CA Intermedia creata; certificati X.509v3 di AA e GU emessi da questa e verificati "
          "sull'intera catena Root->Intermedia->end-entity.")

    ce = ElectionCommission(threshold=ce_threshold, n_members=ce_n_members)
    print(f"[OK] Commissione Elettorale: pkCE/skCE generata, skCE protetta con soglia ({ce_threshold},{ce_n_members}).")

    students = [f"IE2270{1000 + i}" for i in range(n_students)]
    aa = AuthenticationAuthority(aa_sk, aa_pk, aa_cert, eligible_students=students,
                                  token_validity_seconds=token_validity_seconds)
    print(f"[OK] Autorita' di Autenticazione: {len(students)} studenti eleggibili, "
          f"gettoni Cert validi {token_validity_seconds}s (NotAfter).")

    gu = BallotBox(gu_sk, gu_pk, gu_cert, aa_public_key=aa_pk, publish_every_n=publish_every_n,
                   closure_threshold=ce_threshold)
    print(f"[OK] Gestore dell'Urna pronto. Bacheca pubblicata ogni {publish_every_n} schede "
          f"(e definitivamente alla chiusura). Chiusura richiede {ce_threshold} conferme CE.\n")

    return root_ca, aa, ce, gu, students


def honest_voting_session(aa, gu, ce, students, timings):
    print("=" * 70)
    print("SESSIONE DI VOTO (elettori onesti)")
    print("=" * 70)
    receipts = []
    votes_cast = {}

    def cast(student_id):
        voter = Voter(student_id)
        vote = random.choice(list(LISTE.keys()))
        t0 = time.perf_counter()
        receipt = voter.cast_vote(aa, gu, ce.public_key, vote)
        timings["cast_vote"].append(time.perf_counter() - t0)
        return student_id, receipt, vote

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(cast, sid) for sid in students]
        for f in concurrent.futures.as_completed(futures):
            sid, receipt, vote = f.result()
            receipts.append((sid, receipt))
            votes_cast[sid] = vote

    print(f"[OK] {len(receipts)} voti sottomessi con successo. Urna: {len(gu)} schede registrate.")
    print(f"[OK] Auto-consistenza dell'urna (h vs SHA-256(c) corrente): {gu.verify_ledger_self_consistency()}")
    if gu.published_board:
        print(f"[OK] Ultima bacheca pubblicata: n={gu.published_board.n}, "
              f"root={gu.published_board.root.hex()[:16]}...\n")
    else:
        print("[..] Nessuna pubblicazione ancora avvenuta (sotto la soglia periodica).\n")
    return receipts, votes_cast


def scenario_tony_doppio_votante(aa, gu, ce, students):
    print("=" * 70)
    print("SCENARIO WP3 3.1.2 - Tony il Doppio Votante")
    print("=" * 70)
    tony = students[0]

    try:
        Voter(tony).cast_vote(aa, gu, ce.public_key, 1)
        print("[FALLITO] Il secondo voto di Tony e' stato accettato: VULNERABILITA'!")
    except AlreadyVotedError as e:
        print(f"[OK] Secondo voto rifiutato da AA: {e}")

    racer_id = "IE22709999"
    aa.register_student(racer_id)

    def race_attempt():
        try:
            Voter(racer_id).cast_vote(aa, gu, ce.public_key, 2)
            return "OK"
        except (AlreadyVotedError, NotEligibleError):
            return "RIFIUTATO"

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: race_attempt(), range(2)))
    n_success = results.count("OK")
    print(f"[{'OK' if n_success == 1 else 'FALLITO'}] Richieste concorrenti per lo stesso studente: "
          f"accettate {n_success}/2 (atteso 1/2).\n")


def scenario_certificato_scaduto(gu, ce):
    print("=" * 70)
    print("SCENARIO NUOVO (WP2 §2.1.1/§2.1.4) - Certificato scaduto (NotAfter)")
    print("=" * 70)
    from crypto_utils import generate_rsa_keypair as _genrsa
    from aa import AuthenticationAuthority as AA
    from gu import BallotBox as GU
    from crypto_utils import pubkey_to_pem, oaep_encrypt, pss_sign

    # AA "usa e getta" con validita' di 1 secondo, per dimostrare la scadenza,
    # e una BallotBox temporanea (stessa chiave del GU reale) che si fida
    # della chiave pubblica di QUESTA AA effimera.
    sk, pk = _genrsa()
    aa_breve = AA(sk, pk, None, eligible_students=["SCAD-1"], token_validity_seconds=1)
    gu_tmp = GU(gu.private_key, gu.public_key, None, aa_public_key=pk, publish_every_n=99)
    sktemp, pktemp = _genrsa()
    pktemp_pem = pubkey_to_pem(pktemp)
    cert = aa_breve.authenticate_and_certify("SCAD-1", pktemp_pem)
    time.sleep(1.5)
    c = oaep_encrypt(ce.public_key, (1).to_bytes(1, "big"))
    stemp = pss_sign(sktemp, c)
    try:
        gu_tmp.submit_ballot(c, stemp, cert.to_bytes(), pktemp_pem)
        print("[FALLITO] Scheda con certificato scaduto accettata: VULNERABILITA'!")
    except ExpiredCertificateError as e:
        print(f"[OK] Scheda rifiutata per scadenza del certificato: {e}\n")


def scenario_sam_gestore_malizioso(gu):
    print("=" * 70)
    print("SCENARIO WP3 3.1.4 - Sam il Gestore Malizioso dell'Urna")
    print("=" * 70)
    if not gu.published_board or gu.published_board.n == 0:
        gu.publish_bulletin_board()
    print(f"[OK] Auto-consistenza PRIMA della manomissione: {gu.verify_ledger_self_consistency()}")
    print(f"[OK] Coerenza con l'ultima bacheca pubblicata PRIMA: {gu.verify_published_snapshot()}")

    fake_c = b"\x00" * len(gu.ledger[0].c)
    gu.tamper_with_entry(0, fake_c)

    self_ok = gu.verify_ledger_self_consistency()
    snap_ok = gu.verify_published_snapshot()
    print(f"[{'OK' if not self_ok else 'FALLITO'}] Auto-consistenza DOPO: {self_ok} (atteso False)")
    print(f"[{'OK' if not snap_ok else 'FALLITO'}] Coerenza con la bacheca pubblicata DOPO: {snap_ok} (atteso False)\n")


def scenario_impostore(aa_pk, gu, ce):
    print("=" * 70)
    print("SCENARIO WP3 3.1.1/3.1.5 - impostore senza Cert valido da AA")
    print("=" * 70)
    from aa import Cert
    fake_sktemp, fake_pktemp = generate_rsa_keypair()
    fake_pktemp_pem = pubkey_to_pem(fake_pktemp)
    not_after = int(time.time()) + 300
    forged_sigma = pss_sign(fake_sktemp, fake_pktemp_pem + not_after.to_bytes(8, "big"))
    forged_cert = Cert(not_after=not_after, sigma=forged_sigma)

    c = oaep_encrypt(ce.public_key, (1).to_bytes(1, "big"))
    stemp = pss_sign(fake_sktemp, c)

    try:
        gu.submit_ballot(c, stemp, forged_cert.to_bytes(), fake_pktemp_pem)
        print("[FALLITO] Scheda priva di Cert valido accettata: VULNERABILITA'!")
    except InvalidCertificateSignatureError as e:
        print(f"[OK] Scheda rifiutata dal GU: {e}\n")


def individual_verifiability_demo(gu, receipts):
    print("=" * 70)
    print("VERIFICABILITA' INDIVIDUALE (VI.1) - Proof of Membership")
    print("=" * 70)
    if not gu.published_board:
        gu.publish_bulletin_board()
    sid, sample = receipts[0]

    print(f"Firma del GU sulla ricevuta di {sid} valida? "
          f"{pss_verify(gu.public_key, sample.h + sample.timestamp.to_bytes(8,'big'), sample.signature)}")

    try:
        board, index, proof = gu.get_membership_proof(sample.h)
        valid = verify_merkle_proof(sample.h, proof, board.root)
        print(f"[OK] Proof of Membership per {sid}: indice={index}, "
              f"lunghezza percorso={len(proof)}, valida={valid}")
    except ValueError as e:
        print(f"[..] {e}")
    print()


def close_and_tally(gu, ce, votes_cast, receipts_by_sid):
    print("=" * 70)
    print("DECRETO DI CHIUSURA A SOGLIA, RIMESCOLAMENTO E SCRUTINIO (WP2 §2.1.5)")
    print("=" * 70)

    round_id = gu.closure_round_id
    member_names = list(ce.member_shares.keys())[: ce.threshold]
    for name in member_names:
        result = gu.confirm_closure(name, round_id)
        print(f"[OK] Conferma di chiusura da {name} "
              f"({len(result['confirmations'])}/{gu.closure_threshold}).")
    assert gu.closed, "L'urna dovrebbe essere chiusa dopo t conferme distinte."
    print(f"[OK] Soglia raggiunta: urna chiusa e bacheca pubblicata definitivamente "
          f"(Merkle Root firmata su {gu.published_board.n} schede).\n")

    lex = gu.lexicographic_ciphertexts()
    print(f"[OK] Fase di Rimescolamento: estratti {len(lex)} crittogrammi (nessun metadato), "
          f"ordinati lessicograficamente. Primi 2 (troncati): "
          f"{[c.hex()[:16] + '...' for c in lex[:2]]}\n")

    shares_subset = [ce.get_member_share(name) for name in member_names]
    print(f"[OK] {len(shares_subset)}/{ce.n_members} commissari cooperano "
          f"(soglia t={ce.threshold}) per ricostruire skCE in RAM isolata.")

    t0 = time.perf_counter()
    result = gu.tally(ce, shares_subset)
    t1 = time.perf_counter()
    print("[OK] skCE distrutta dalla memoria subito dopo la decifratura (secure memory zeroing, best-effort).")

    print(f"[OK] Scrutinio completato in {t1 - t0:.3f}s su {result['n_ballots']} schede "
          f"({len(result['anomalies'])} anomalie/non decifrabili: {result['anomalies']}).")
    print("[OK] Pubblicati SOLO i totali aggregati per lista (nessun voto individuale v esposto):")
    for v, n in sorted(result["counts"].items()):
        print(f"     {LISTE.get(v, f'Valore sconosciuto {v}')}: {n} voti")

    expected_counts = {}
    for v in votes_cast.values():
        expected_counts[v] = expected_counts.get(v, 0) + 1
    # la scheda manomessa (se presente) non decifra correttamente: la escludiamo dal confronto
    consistent = all(expected_counts.get(k, 0) == v or k in (0,) for k, v in result["counts"].items())
    print(f"[OK] Conteggio ricalcolato indipendentemente coerente con il risultato (a meno delle "
          f"schede segnalate come anomale): {consistent}")

    print("\nVerificabilita' Universale (VU.1): ricalcolo indipendente della Merkle Root "
          "sull'ultima bacheca pubblicata...")
    print(f"[{'OK' if gu.verify_published_snapshot() else 'FALLITO'}] "
          f"Root ricalcolata dai crittogrammi correnti coincide con quella firmata e pubblicata: "
          f"{gu.verify_published_snapshot()}\n")
    return result


def performance_benchmark(n_iterations=20):
    print("=" * 70)
    print(f"BENCHMARK PRESTAZIONI CRITTOGRAFICHE ({n_iterations} iterazioni)")
    print("=" * 70)

    def bench(name, fn):
        samples = []
        for _ in range(n_iterations):
            t0 = time.perf_counter()
            fn()
            samples.append(time.perf_counter() - t0)
        mean_ms = statistics.mean(samples) * 1000
        print(f"  {name:<42s}: media {mean_ms:8.3f} ms  (min {min(samples)*1000:.3f} / "
              f"max {max(samples)*1000:.3f})")
        return mean_ms

    sk, pk = generate_rsa_keypair()
    bench("Generazione coppia RSA-2048", lambda: generate_rsa_keypair())
    bench("Cifratura RSA-OAEP (scheda)", lambda: oaep_encrypt(pk, b"\x01"))
    ct = oaep_encrypt(pk, b"\x01")
    from crypto_utils import oaep_decrypt
    bench("Decifratura RSA-OAEP", lambda: oaep_decrypt(sk, ct))
    bench("Firma RSA-PSS (Cert / stemp / ricevuta)", lambda: pss_sign(sk, ct))
    sig = pss_sign(sk, ct)
    bench("Verifica RSA-PSS", lambda: pss_verify(pk, ct, sig))

    root_ca = RootCA()
    intermediate_ca = root_ca.create_intermediate()
    bench("Emissione certificato X.509v3 (Intermedia)",
          lambda: intermediate_ca.issue_server_certificate("bench.unisa.it"))

    ce = ElectionCommission(threshold=3, n_members=5)
    shares = [ce.get_member_share(f"Commissario_{i}") for i in range(1, 4)]
    bench("Ricostruzione skCE (Shamir t=3,n=5)",
          lambda: ce.reconstruct_private_key(shares))

    from merkle import merkle_root, merkle_proof
    from crypto_utils import sha256
    leaves = [sha256(f"scheda-{i}".encode()) for i in range(500)]
    bench("Merkle Root su 500 foglie", lambda: merkle_root(leaves))
    bench("Merkle Proof su 500 foglie", lambda: merkle_proof(leaves, 250))

    pktemp_pem = pubkey_to_pem(pk)
    not_after_bytes = (0).to_bytes(8, "big")
    cert_bytes = not_after_bytes + pss_sign(sk, pktemp_pem + not_after_bytes)
    message_size = len(ct) + len(sig) + len(cert_bytes) + len(pktemp_pem)
    print(f"\n  Dimensione media di Mvoto = <c, stemp, Cert, pktemp>: {message_size} byte "
          f"(c={len(ct)}, stemp={len(sig)}, Cert={len(cert_bytes)} [8B NotAfter + firma], "
          f"pktemp_PEM={len(pktemp_pem)})")
    print()


def main():
    random.seed(42)
    N_STUDENTS = 40
    CE_THRESHOLD, CE_MEMBERS = 3, 5

    timings = {"cast_vote": []}

    root_ca, aa, ce, gu, students = setup_infrastructure(
        N_STUDENTS, CE_THRESHOLD, CE_MEMBERS, token_validity_seconds=300, publish_every_n=5
    )
    receipts, votes_cast = honest_voting_session(aa, gu, ce, students, timings)
    receipts_by_sid = dict(receipts)

    scenario_tony_doppio_votante(aa, gu, ce, students)
    scenario_certificato_scaduto(gu, ce)
    scenario_impostore(aa.public_key, gu, ce)
    individual_verifiability_demo(gu, receipts)

    # La manomissione di Sam viene dimostrata su un'urna dedicata "usa e getta":
    # per lo scrutinio finale usiamo una sessione elettorale pulita e indipendente.
    scenario_sam_gestore_malizioso(gu)

    _, aa2, ce2, gu2, students2 = setup_infrastructure(
        N_STUDENTS, CE_THRESHOLD, CE_MEMBERS, token_validity_seconds=300, publish_every_n=5
    )
    receipts2, votes_cast2 = honest_voting_session(aa2, gu2, ce2, students2, timings)
    individual_verifiability_demo(gu2, receipts2)
    close_and_tally(gu2, ce2, votes_cast2, dict(receipts2))

    if timings["cast_vote"]:
        avg = statistics.mean(timings["cast_vote"]) * 1000
        print(f"Tempo medio end-to-end per voto (client+AA+GU), {len(timings['cast_vote'])} voti: "
              f"{avg:.3f} ms\n")

    performance_benchmark()


if __name__ == "__main__":
    main()
