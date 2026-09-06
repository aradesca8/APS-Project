"""
Autorita' di Autenticazione (AA)

Gestisce l'anagrafica degli studenti (eleggibilita', stato "Votante") e
agisce come Mini-CA di sessione: dopo aver autenticato lo studente e
verificato che non abbia gia' votato, firma (RSA-PSS) la chiave pubblica
temporanea pktemp CONCATENATA a un parametro di scadenza NotAfter,
generando un certificato di voto anonimo e a tempo determinato.
"""

import threading
import time
from dataclasses import dataclass

from crypto_utils import pss_sign, pss_verify, int_to_bytes8, bytes8_to_int

DEFAULT_TOKEN_VALIDITY_SECONDS = 300


class AlreadyVotedError(Exception):
    pass


class NotEligibleError(Exception):
    pass


class ExpiredCertificateError(Exception):
    pass


class InvalidCertificateSignatureError(Exception):
    pass


@dataclass
class Cert:
    """rappresenta il certificato fisico (in formato digitale) che viene consegnato allo studente.
    Cert = <NotAfter, sigma_AA> """
    not_after: int
    sigma: bytes

    def to_bytes(self) -> bytes:
        return int_to_bytes8(self.not_after) + self.sigma

    @staticmethod
    def from_bytes(data: bytes) -> "Cert":
        if len(data) < 8:
            raise ValueError("Cert malformato: lunghezza insufficiente per NotAfter.")
        return Cert(not_after=bytes8_to_int(data[:8]), sigma=data[8:])

        """Verifica sigma_AA su (pktemp||NotAfter) e controlla la scadenza.
        Solleva le eccezioni appropriate in caso di esito negativo."""
    def verify(self, aa_public_key, pktemp_pem: bytes, now: float = None) -> None:
        signed_message = pktemp_pem + int_to_bytes8(self.not_after)
        "controllare matematicamente se la firma (self.sigma) corrisponde al messaggio (signed_message)"
        if not pss_verify(aa_public_key, signed_message, self.sigma):
            raise InvalidCertificateSignatureError(
                "Certificato di voto non valido o non emesso dall'Autorita' di Autenticazione."
            )
        now = time.time() if now is None else now
        if now > self.not_after:
            raise ExpiredCertificateError(
                f"Certificato scaduto: NotAfter={self.not_after}, ricevuto a T={int(now)}."
            )

"""entità che controlla il diritto al voto e distribuisce i certificati."""
class AuthenticationAuthority:
    def __init__(self, private_key, public_key, certificate, eligible_students,
                 token_validity_seconds: int = DEFAULT_TOKEN_VALIDITY_SECONDS):
        self.private_key = private_key
        self.public_key = public_key
        self.certificate = certificate
        self.token_validity_seconds = token_validity_seconds
        # Anagrafica: matricola -> stato
        self._db = {sid: {"eligible": True, "voted": False} for sid in eligible_students}
        self._lock = threading.Lock()
        self.issued_certificates = 0

    """Permette di aggiungere manualmente un nuovo studente al database in un secondo momento, se non era nella lista iniziale."""
    def register_student(self, student_id: str):
        self._db.setdefault(student_id, {"eligible": True, "voted": False})

    """Prende la matricola e la chiave anonima che lo studente vuole far firmare, e restituisce un certificato di voto anonimo (Cert) se lo studente è abilitato e non ha già votato."""
    def authenticate_and_certify(self, student_id: str, pktemp_pem: bytes) -> Cert:
        record = self._db.get(student_id)
        if record is None or not record["eligible"]:
            raise NotEligibleError(f"Studente {student_id} non abilitato al voto.")

        # Transazione atomica: check-and-set (mitigazione voto multiplo concorrente)
        with self._lock:
            if record["voted"]:
                raise AlreadyVotedError(f"Studente {student_id} ha gia' ottenuto un certificato di voto.")
            record["voted"] = True  

        not_after = int(time.time()) + self.token_validity_seconds
        signed_message = pktemp_pem + int_to_bytes8(not_after)
        sigma = pss_sign(self.private_key, signed_message)
        self.issued_certificates += 1
        return Cert(not_after=not_after, sigma=sigma)

    def has_voted(self, student_id: str) -> bool:
        record = self._db.get(student_id)
        return bool(record and record["voted"])
