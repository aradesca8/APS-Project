"""
Wrapper alle primitive crittografiche usate nel protocollo di e-voting (WP2):
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

RSA_KEY_SIZE = 2048 #lunghezza chiave RSA in bit
RSA_PUBLIC_EXPONENT = 65537 #esponente pubblico RSA Fermat

#creazione chiavi dell'elettore
def generate_rsa_keypair(key_size: int = RSA_KEY_SIZE):
    sk = rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=key_size)
    return sk, sk.public_key()



# RSA-OAEP: cifratura/decifratura asimmetrica probabilistica: scheda di voto
def _oaep_padding():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def oaep_encrypt(public_key, plaintext_bytes: bytes) -> bytes:
    return public_key.encrypt(plaintext_bytes, _oaep_padding())


def oaep_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(ciphertext, _oaep_padding())



# RSA-PSS: firma/verifica con padding probabilistico
def _pss_padding_sign():
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=hashes.SHA256().digest_size,
    )


def _pss_padding_verify():
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )

# firma/verifica RSA-PSS su un messaggio arbitrario
def pss_sign(private_key, data: bytes) -> bytes:
    return private_key.sign(data, _pss_padding_sign(), hashes.SHA256())


def pss_verify(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, data, _pss_padding_verify(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False



# Hash / serializzazione, crea un'impronta digitale fissa di 32 byte del dato
def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def sha256_hex(data: bytes) -> str:
    return sha256(data).hex()

#convertitore chiave publica in un formato leggibile standard (PEM) e viceversa
def pubkey_to_pem(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def pem_to_pubkey(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)

"""Serializzazione compatta (DER, PKCS8, non cifrata) usata solo
internamente dalla CE per l'envelope encryption di skCE"""
def privkey_to_der(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def der_to_privkey(der_bytes: bytes):
    return serialization.load_der_private_key(der_bytes, password=None)


# Codifica canonica di interi temporali (NotAfter, Timestamp) 
# usati nelle concatenazioni firmate pktemp||NotAfter e h||Timestamp.


def int_to_bytes8(value: int) -> bytes:
    return int(value).to_bytes(8, "big", signed=False)


def bytes8_to_int(data: bytes) -> int:
    return int.from_bytes(data[:8], "big", signed=False)
