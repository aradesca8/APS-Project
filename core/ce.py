"""
Commissione Elettorale (CE)
"""

import os
from cryptography.hazmat.primitives import hashes, hmac, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

from crypto_utils import generate_rsa_keypair, privkey_to_der, der_to_privkey
import shamir

#Sollevata se la verifica HMAC su skCE cifrata fallisce (Encrypt-then-MAC).
class TamperedCiphertextError(Exception):
    pass

#funzione per cifrare e autenticare il segreto skCE con Encrypt-then-MAC (AES-256-CBC + HMAC-SHA256)
def _encrypt_then_mac(k_enc: bytes, k_mac: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(k_enc), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    iv_ciphertext = iv + ciphertext
    h = hmac.HMAC(k_mac, hashes.SHA256())
    h.update(iv_ciphertext)
    tag = h.finalize()
    return tag + iv_ciphertext

"""funzione per decifrare e verificare il segreto skCE cifrato con Encrypt-then-MAC (AES-256-CBC + HMAC-SHA256)"""
def _decrypt_then_verify(k_enc: bytes, k_mac: bytes, packet: bytes) -> bytes:
    tag, iv_ciphertext = packet[:32], packet[32:]
    h = hmac.HMAC(k_mac, hashes.SHA256())
    h.update(iv_ciphertext)
    try:
        h.verify(tag)
    except InvalidSignature:
        raise TamperedCiphertextError(
            "Verifica HMAC fallita: skCE cifrata risulta manomessa o le chiavi "
            "ricostruite sono errate."
        )

    iv, ciphertext = iv_ciphertext[:16], iv_ciphertext[16:]
    cipher = Cipher(algorithms.AES(k_enc), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


"""entità che gestisce la chiave ufficiale dell'elezione e la distribuisce ai membri della Commissione Elettorale."""
class ElectionCommission:
    def __init__(self, threshold: int, n_members: int):
        if threshold < 2 or threshold > n_members:
            raise ValueError("Richiesto 2 <= t <= n")
        self.threshold = threshold
        self.n_members = n_members

        #Coppia di chiavi ufficiale dell'elezione <pkCE, skCE>
        self.private_key, self.public_key = generate_rsa_keypair()

        #protezione di skCE con Encrypt-then-MAC (AES-256-CBC + HMAC-SHA256,
        #chiavi separate k_enc/k_mac)
        k_enc = os.urandom(32)
        k_mac = os.urandom(32)
        sk_der = privkey_to_der(self.private_key)
        self.encrypted_sk_ce = _encrypt_then_mac(k_enc, k_mac, sk_der)

        
        combined = k_enc + k_mac
        combined_int = int.from_bytes(combined, "big")
        raw_shares = shamir.split_secret(combined_int, threshold, n_members)
        self.member_shares = {f"Commissario_{x}": (x, y) for x, y in raw_shares}

    """Restituisce lo share di un membro della Commissione."""
    def get_member_share(self, member_name: str):
        return self.member_shares[member_name]

    def reconstruct_private_key(self, shares_subset):
        """
        Ricostruisce skCE a partire da >= t coppie (x, y) fornite da membri
        diversi della Commissione.
        """
        if len(shares_subset) < self.threshold:
            raise ValueError(
                f"Servono almeno {self.threshold} share per ricostruire la chiave "
                f"(ricevute {len(shares_subset)})."
            )
        combined_int = shamir.reconstruct_secret(list(shares_subset)[: self.threshold])
        combined = combined_int.to_bytes(64, "big")
        k_enc, k_mac = combined[:32], combined[32:]

        sk_der = _decrypt_then_verify(k_enc, k_mac, self.encrypted_sk_ce)
        return der_to_privkey(sk_der)
