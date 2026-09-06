

import json
import statistics
import sys
import time

sys.path.insert(0, "core")

from crypto_utils import (
    generate_rsa_keypair, oaep_encrypt, oaep_decrypt, pss_sign, pss_verify,
    sha256, pubkey_to_pem, int_to_bytes8,
)
from pki import RootCA
from ce import ElectionCommission
from aa import AuthenticationAuthority
from gu import BallotBox
from merkle import merkle_root, merkle_proof, verify_merkle_proof


def bench(fn, n=30):
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)  # ms
    return {
        "mean": statistics.mean(samples),
        "min": min(samples),
        "max": max(samples),
        "stdev": statistics.stdev(samples) if len(samples) > 1 else 0.0,
        "n": n,
    }


results = {}

print("=== Primitive crittografiche di base ===")
sk2048, pk2048 = generate_rsa_keypair()
ct = oaep_encrypt(pk2048, b"\x01")
sig = pss_sign(sk2048, ct)

results["rsa2048_keygen"] = bench(lambda: generate_rsa_keypair(), n=30)
print("RSA-2048 keygen:", results["rsa2048_keygen"]["mean"], "ms")

results["oaep_encrypt"] = bench(lambda: oaep_encrypt(pk2048, b"\x01"), n=100)
print("OAEP encrypt:", results["oaep_encrypt"]["mean"], "ms")

results["oaep_decrypt"] = bench(lambda: oaep_decrypt(sk2048, ct), n=100)
print("OAEP decrypt:", results["oaep_decrypt"]["mean"], "ms")

results["pss_sign"] = bench(lambda: pss_sign(sk2048, ct), n=100)
print("PSS sign:", results["pss_sign"]["mean"], "ms")

results["pss_verify"] = bench(lambda: pss_verify(pk2048, ct, sig), n=100)
print("PSS verify:", results["pss_verify"]["mean"], "ms")

results["sha256"] = bench(lambda: sha256(ct), n=200)
print("SHA-256:", results["sha256"]["mean"], "ms")

print("\n=== PKI (X.509) ===")
root_ca = RootCA()
results["root_ca_keygen"] = {"mean": None}  # generato una volta sola, misurato a parte
t0 = time.perf_counter()
root_ca2 = RootCA()
results["root_ca_keygen"]["mean"] = (time.perf_counter() - t0) * 1000
print("Root CA (4096 bit) keygen+self-sign:", results["root_ca_keygen"]["mean"], "ms")

intermediate_ca = root_ca.create_intermediate()
results["intermediate_issue_cert"] = bench(
    lambda: intermediate_ca.issue_server_certificate("bench.unisa.it"), n=20
)
print("Emissione certificato end-entity (via Intermedia):", results["intermediate_issue_cert"]["mean"], "ms")

print("\n=== Shamir Secret Sharing ===")
ce = ElectionCommission(threshold=3, n_members=5)
shares = [ce.get_member_share(f"Commissario_{i}") for i in range(1, 4)]
results["shamir_reconstruct_t3"] = bench(lambda: ce.reconstruct_private_key(shares), n=20)
print("Ricostruzione skCE (Shamir t=3,n=5):", results["shamir_reconstruct_t3"]["mean"], "ms")

# soglie diverse, per mostrare la scalabilita' rispetto a t
results["shamir_by_threshold"] = {}
for t in [2, 3, 5, 7, 9]:
    ce_t = ElectionCommission(threshold=t, n_members=max(t, 9))
    shares_t = [ce_t.get_member_share(n) for n in list(ce_t.member_shares.keys())[:t]]
    r = bench(lambda: ce_t.reconstruct_private_key(shares_t), n=10)
    results["shamir_by_threshold"][t] = r["mean"]
    print(f"  t={t}: {r['mean']:.3f} ms")

print("\n=== Albero di Merkle: scalabilita' ===")
results["merkle_by_n"] = {}
for n_leaves in [10, 50, 100, 500, 1000, 5000, 10000]:
    leaves = [sha256(f"scheda-{i}".encode()) for i in range(n_leaves)]
    t_root = bench(lambda: merkle_root(leaves), n=10)
    t_proof = bench(lambda: merkle_proof(leaves, n_leaves // 2), n=10)
    root = merkle_root(leaves)
    proof = merkle_proof(leaves, n_leaves // 2)
    t_verify = bench(lambda: verify_merkle_proof(leaves[n_leaves // 2], proof, root), n=20)
    results["merkle_by_n"][n_leaves] = {
        "root_ms": t_root["mean"],
        "proof_gen_ms": t_proof["mean"],
        "proof_verify_ms": t_verify["mean"],
        "proof_len": len(proof),
    }
    print(f"  n={n_leaves}: root={t_root['mean']:.3f}ms proof_gen={t_proof['mean']:.4f}ms "
          f"proof_verify={t_verify['mean']:.4f}ms proof_len={len(proof)}")

print("\n=== Dimensione del payload Mvoto ===")
pktemp_pem = pubkey_to_pem(pk2048)
cert_bytes = int_to_bytes8(0) + pss_sign(sk2048, pktemp_pem + int_to_bytes8(0))
sizes = {
    "c": len(ct),
    "stemp": len(sig),
    "cert": len(cert_bytes),
    "pktemp_pem": len(pktemp_pem),
}
sizes["mvoto_totale"] = sum(sizes.values())
results["message_sizes"] = sizes
print(json.dumps(sizes, indent=2))

receipt_size = 32 + 8 + 256  # h + timestamp + signature
results["receipt_size"] = receipt_size
print("Dimensione Ricevuta:", receipt_size, "byte")

print("\n=== Latenza end-to-end di un voto completo ===")
aa_sk, aa_pk, aa_cert = intermediate_ca.issue_server_certificate("aa.unisa.it")
gu_sk, gu_pk, gu_cert = intermediate_ca.issue_server_certificate("gu.unisa.it")
students = [f"S{i}" for i in range(200)]
aa = AuthenticationAuthority(aa_sk, aa_pk, aa_cert, eligible_students=students)
gu = BallotBox(gu_sk, gu_pk, gu_cert, aa_public_key=aa_pk, publish_every_n=1000, closure_threshold=3)

e2e_steps = {"keygen": [], "cert_request": [], "encrypt": [], "sign": [], "submit": [], "totale": []}
for sid in students[:60]:
    t_start = time.perf_counter()

    t0 = time.perf_counter()
    sktemp, pktemp = generate_rsa_keypair()
    e2e_steps["keygen"].append((time.perf_counter() - t0) * 1000)

    pktemp_pem_i = pubkey_to_pem(pktemp)
    t0 = time.perf_counter()
    cert = aa.authenticate_and_certify(sid, pktemp_pem_i)
    e2e_steps["cert_request"].append((time.perf_counter() - t0) * 1000)

    t0 = time.perf_counter()
    c_i = oaep_encrypt(ce.public_key, (1).to_bytes(1, "big"))
    e2e_steps["encrypt"].append((time.perf_counter() - t0) * 1000)

    t0 = time.perf_counter()
    stemp_i = pss_sign(sktemp, c_i)
    e2e_steps["sign"].append((time.perf_counter() - t0) * 1000)

    t0 = time.perf_counter()
    gu.submit_ballot(c_i, stemp_i, cert.to_bytes(), pktemp_pem_i)
    e2e_steps["submit"].append((time.perf_counter() - t0) * 1000)

    e2e_steps["totale"].append((time.perf_counter() - t_start) * 1000)

results["e2e_vote"] = {k: statistics.mean(v) for k, v in e2e_steps.items()}
print(json.dumps(results["e2e_vote"], indent=2))

print("\n=== Scrutinio: tempo totale al variare del numero di schede ===")
results["tally_by_n"] = {}
for n_ballots in [50, 200, 500]:
    ce_s = ElectionCommission(threshold=3, n_members=5)
    aa_sk_s, aa_pk_s, aa_cert_s = intermediate_ca.issue_server_certificate("aa2.unisa.it")
    gu_sk_s, gu_pk_s, gu_cert_s = intermediate_ca.issue_server_certificate("gu2.unisa.it")
    students_s = [f"T{i}" for i in range(n_ballots)]
    aa_s = AuthenticationAuthority(aa_sk_s, aa_pk_s, aa_cert_s, eligible_students=students_s)
    gu_s = BallotBox(gu_sk_s, gu_pk_s, gu_cert_s, aa_public_key=aa_pk_s,
                      publish_every_n=n_ballots + 1, closure_threshold=3)
    for sid in students_s:
        sk_i, pk_i = generate_rsa_keypair()
        pem_i = pubkey_to_pem(pk_i)
        cert_i = aa_s.authenticate_and_certify(sid, pem_i)
        c_i = oaep_encrypt(ce_s.public_key, (sid.__hash__() % 4).to_bytes(1, "big"))
        stemp_i = pss_sign(sk_i, c_i)
        gu_s.submit_ballot(c_i, stemp_i, cert_i.to_bytes(), pem_i)
    gu_s.close()
    shares_s = [ce_s.get_member_share(n) for n in list(ce_s.member_shares.keys())[:3]]
    t0 = time.perf_counter()
    tally_result = gu_s.tally(ce_s, shares_s)
    dt = (time.perf_counter() - t0) * 1000
    results["tally_by_n"][n_ballots] = dt
    print(f"  n={n_ballots}: {dt:.2f} ms totali ({dt/n_ballots:.3f} ms/scheda)")

print("\n=== Latenza delle operazioni di verifica ===")

print("[..] Verifica della catena X.509 (Root -> Intermedia -> certificato end-entity)...")
_, _, cert_chain = intermediate_ca.issue_server_certificate("verify.bench")
results["x509_verify_chain"] = bench(lambda: root_ca.verify_chain(cert_chain, intermediate_ca.certificate), n=30)
print("  ", results["x509_verify_chain"]["mean"], "ms")

print("[..] Verifica di integrita' su urne di dimensioni diverse (auto-consistenza e VU.1)...")
results["self_consistency_by_n"] = {}
results["published_snapshot_by_n"] = {}
for n_ballots in [100, 500, 2000]:
    ce_v = ElectionCommission(threshold=3, n_members=5)
    aa_sk_v, aa_pk_v, aa_cert_v = intermediate_ca.issue_server_certificate(f"aaV{n_ballots}")
    gu_sk_v, gu_pk_v, gu_cert_v = intermediate_ca.issue_server_certificate(f"guV{n_ballots}")
    students_v = [f"V{n_ballots}_{i}" for i in range(n_ballots)]
    aa_v = AuthenticationAuthority(aa_sk_v, aa_pk_v, aa_cert_v, eligible_students=students_v)
    gu_v = BallotBox(gu_sk_v, gu_pk_v, gu_cert_v, aa_public_key=aa_pk_v,
                      publish_every_n=n_ballots + 1, closure_threshold=3)
    for sid in students_v:
        sk_v, pk_v = generate_rsa_keypair()
        pem_v = pubkey_to_pem(pk_v)
        cert_v = aa_v.authenticate_and_certify(sid, pem_v)
        c_v = oaep_encrypt(ce_v.public_key, (1).to_bytes(1, "big"))
        stemp_v = pss_sign(sk_v, c_v)
        gu_v.submit_ballot(c_v, stemp_v, cert_v.to_bytes(), pem_v)
    gu_v.close()

    t_self = bench(lambda: gu_v.verify_ledger_self_consistency(), n=15)
    t_snap = bench(lambda: gu_v.verify_published_snapshot(), n=15)
    results["self_consistency_by_n"][n_ballots] = t_self["mean"]
    results["published_snapshot_by_n"][n_ballots] = t_snap["mean"]
    print(f"  n={n_ballots}: auto-consistenza={t_self['mean']:.3f}ms  coerenza-bacheca(VU.1)={t_snap['mean']:.3f}ms")

with open("benchmark_results.json", "w") as f:
    json.dump(results, f, indent=2)
print("\nRisultati salvati in benchmark_results.json")
