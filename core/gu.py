"""
gu.py
"""

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from crypto_utils import pss_verify, pss_sign, pem_to_pubkey, sha256, sha256_hex, int_to_bytes8
from aa import Cert, ExpiredCertificateError, InvalidCertificateSignatureError
from merkle import merkle_root, merkle_proof, verify_merkle_proof, ProofStep

DEFAULT_PUBLISH_EVERY_N = 3


class InvalidBallotSignatureError(Exception):
    pass


class DuplicateBallotError(Exception):
    pass


class StaleClosureRoundError(Exception):
    """Sollevata se una conferma di chiusura fa riferimento a un round
    (nonce) non piu' valido — mitigazione anti-replay"""
    pass

#strutture dati per rappresentare le schede, le ricevute e la bacheca pubblica
#Rappresenta la Scheda nell'Urna
@dataclass
class BallotEntry:
    index: int
    c: bytes
    stemp: bytes
    cert_bytes: bytes
    pktemp_pem: bytes
    h: bytes            # = SHA-256(c) calcolato al momento della sottomissione
    timestamp: int

    @property
    def receipt_h_hex(self) -> str:
        return self.h.hex()


@dataclass
class Receipt:
    """Ricevuta = <h, Timestamp, Sign_skGU(h||Timestamp)>"""
    h: bytes
    timestamp: int
    signature: bytes

    def to_hex_dict(self) -> dict:
        return {"h_hex": self.h.hex(), "timestamp": self.timestamp, "signature_hex": self.signature.hex()}


@dataclass
class PublishedBoard:
    """Istantanea firmata della Bacheca Pubblica (Merkle Root)"""
    leaves: List[bytes]
    root: bytes
    signature: bytes
    published_at: int
    n: int

#
class BallotBox:
    def __init__(self, private_key, public_key, certificate, aa_public_key,
                 publish_every_n: int = DEFAULT_PUBLISH_EVERY_N,
                 closure_threshold: int = 1):
        self.private_key = private_key   # sk del GU: firma ricevute e Merkle Root
        self.public_key = public_key
        self.certificate = certificate
        self.aa_public_key = aa_public_key
        self.publish_every_n = publish_every_n
        self.closure_threshold = closure_threshold  # t componenti CE per la chiusura, §2.1.5

        self._ledger: List[BallotEntry] = []
        self._used_pktemps = set()
        self._lock = threading.Lock()
        self._last_published_count = 0
        self.published_board: Optional[PublishedBoard] = None
        self.closed = False

        # Decreto di Chiusura a soglia (§2.1.5): il GU genera un nuovo
        # "round" (nonce) di chiusura; ogni conferma di un commissario deve
        # riferirsi al round corrente, cosi' che una conferma catturata non
        # possa essere ripresentata dopo che il round e' stato consumato o
        # rigenerato.
        self._closure_round_id = secrets.token_hex(16)
        self._closure_confirmations: Dict[str, int] = {}  # nome commissario -> timestamp

    # ------------------------------------------------------------------
    # Decreto di Chiusura a soglia (§2.1.5)
    # ------------------------------------------------------------------
    @property
    def closure_round_id(self) -> str:
        return self._closure_round_id

    @property
    def closure_confirmations(self) -> Dict[str, int]:
        return dict(self._closure_confirmations)

    def confirm_closure(self, commissioner_name: str, round_id: str) -> dict:
        """Registra la conferma di chiusura di un componente della CE.
        Richiede che round_id combaci col round corrente (anti-replay: una
        conferma raccolta per un round precedente, o rigenerata dopo un
        reset, non viene piu' accettata). Quando le conferme di almeno
        `closure_threshold` commissari DISTINTI sono state raccolte, l'urna
        viene chiusa automaticamente e la bacheca pubblicata in via
        definitiva."""
        if self.closed:
            raise RuntimeError("Le urne sono gia' chiuse.")
        if round_id != self._closure_round_id:
            raise StaleClosureRoundError(
                "Round di chiusura non valido o scaduto: probabile tentativo di "
                "replay di una conferma precedente. Ricarica lo stato e riprova."
            )
        with self._lock:
            self._closure_confirmations[commissioner_name] = int(time.time())
            confirmed = dict(self._closure_confirmations)
            should_close = len(confirmed) >= self.closure_threshold

        if should_close:
            self.close()

        return {
            "confirmations": confirmed,
            "threshold": self.closure_threshold,
            "closed": self.closed,
        }

  
    """Estrae dall'urna sigillata il solo array dei crittogrammi c
            (nessun pktemp/stemp/Cert/timestamp) e lo ordina secondo l'ordine
            lessicografico dei byte grezzi. Disponibile solo a urne chiuse,
            sul batch coperto dalla pubblicazione definitiva."""
    def lexicographic_ciphertexts(self) -> List[bytes]:
        if not self.closed:
            raise RuntimeError("Il rimescolamento e' disponibile solo a urne chiuse.")
        ciphertexts = [entry.c for entry in self._ledger]
        return sorted(ciphertexts)

   
    # Sottomissione della scheda — validazione Zero-Trust in 3 passi
    def submit_ballot(self, c: bytes, stemp: bytes, cert_bytes: bytes, pktemp_pem: bytes) -> Receipt:
        if self.closed:
            raise RuntimeError("Le urne sono chiuse: non e' piu' possibile votare.")

        #Verifica dell'Autorizzazione e Scadenza
        cert = Cert.from_bytes(cert_bytes)
        cert.verify(self.aa_public_key, pktemp_pem) 

        # Controllo di Unicita' (lettura preliminare; la marcatura atomica avviene sotto lock)
        if pktemp_pem in self._used_pktemps:
            raise DuplicateBallotError("Chiave temporanea gia' utilizzata: scheda duplicata.")

        #Verifica della Firma Effimera (Proof of Possession)
        pktemp = pem_to_pubkey(pktemp_pem)
        if not pss_verify(pktemp, c, stemp):
            raise InvalidBallotSignatureError("Firma sulla scheda cifrata non valida (manomissione?).")

        # Tutti i controlli superati: la pktemp viene "bruciata" e la scheda registrata
        # come un'unica transazione atomica.
        h = sha256(c)
        timestamp = int(time.time())
        with self._lock:
            if pktemp_pem in self._used_pktemps:
                raise DuplicateBallotError("Chiave temporanea gia' utilizzata: scheda duplicata.")
            self._used_pktemps.add(pktemp_pem)
            index = len(self._ledger)
            entry = BallotEntry(index=index, c=c, stemp=stemp, cert_bytes=cert_bytes,
                                 pktemp_pem=pktemp_pem, h=h, timestamp=timestamp)
            self._ledger.append(entry)
            unpublished = len(self._ledger) - self._last_published_count

        # Rilascio della Ricevuta Immediata
        signature = pss_sign(self.private_key, h + int_to_bytes8(timestamp))
        receipt = Receipt(h=h, timestamp=timestamp, signature=signature)

        # Pubblicazione periodica della Bacheca 
        if unpublished >= self.publish_every_n:
            self.publish_bulletin_board()

        return receipt


    
    # Bacheca Pubblica — pubblicazione periodica dell'Albero di Merkle  
    def publish_bulletin_board(self) -> PublishedBoard:
        with self._lock:
            leaves = [e.h for e in self._ledger]
            self._last_published_count = len(leaves)
        root = merkle_root(leaves)
        signature = pss_sign(self.private_key, root)
        board = PublishedBoard(leaves=leaves, root=root, signature=signature,
                                published_at=int(time.time()), n=len(leaves))
        self.published_board = board
        return board

    # Verifica di Appartenenza: proof of membership per una foglia specifica
    def get_membership_proof(self, h: bytes):
        board = self.published_board
        if board is None or board.n == 0:
            raise ValueError("Nessuna pubblicazione disponibile: riprova piu' tardi o a urne chiuse.")
        try:
            index = board.leaves.index(h)
        except ValueError:
            raise ValueError(
                "Ricevuta non presente nell'ultima pubblicazione: potrebbe non "
                "essere ancora stata inclusa (la bacheca si aggiorna periodicamente)."
            )
        proof = merkle_proof(board.leaves, index)
        return board, index, proof


    # Controlli di integrita'
    """Controllo rapido lato server: per ogni scheda, l'hash SHA-256
        del crittogramma attualmente memorizzato deve combaciare con
        l'impronta h registrata al momento della sottomissione. Rileva
        immediatamente qualunque riscrittura diretta di 'c'  sulle schede non ancora ripubblicate."""
    def verify_ledger_self_consistency(self) -> bool:
        for e in self._ledger:
            if sha256(e.c) != e.h:
                return False
        return True


    """Verificabilita' Universale, lato server: ricalcola la
            Merkle Root usando i crittogrammi attualmente memorizzati per gli
            indici coperti dall'ultima pubblicazione, e la confronta con la
            Root firmata pubblicata. Rileva la manomissione di una scheda
            gia' pubblicata anche se un'implementazione mantenesse coerenti
            tra loro 'c' e 'h' in memoria."""
    def verify_published_snapshot(self) -> bool:
        board = self.published_board
        if board is None:
            return True  # nulla e' stato ancora pubblicato: nessuna violazione rilevabile
        fresh_leaves = [sha256(self._ledger[i].c) for i in range(board.n)]
        return merkle_root(fresh_leaves) == board.root


    """Usato SOLO nella console di amministrazione per impersonare
            'Sam il Gestore Malizioso dell'Urna': riscrive
            direttamente il campo c di una scheda gia' registrata, senza
            toccare l'impronta h originariamente calcolata ne' la bacheca
            gia' pubblicata"""
    def tamper_with_entry(self, index: int, new_c: bytes):
        self._ledger[index].c = new_c

   
    # Chiusura urne e scrutinio
    def close(self):
        self.closed = True
        self.publish_bulletin_board() 



    #scrutinio: decifra le schede e conta i voti validi, rilevando eventuali anomalie
    def tally(self, ce, shares_subset) -> Dict:
    
        if not self.closed:
            raise RuntimeError("Le urne devono essere chiuse prima dello scrutinio.")
        from crypto_utils import oaep_decrypt
        sk_ce = ce.reconstruct_private_key(shares_subset)

        counts: Dict[int, int] = {}
        anomalies: List[int] = []
        try:
            for entry in self._ledger:
                try:
                    v = int.from_bytes(oaep_decrypt(sk_ce, entry.c), "big")
                    counts[v] = counts.get(v, 0) + 1
                except Exception:
                    anomalies.append(entry.index)
        finally:
            del sk_ce  # secure memory zeroing (best effort), cfr. §2.1.5

        return {"counts": counts, "anomalies": anomalies, "n_ballots": len(self._ledger)}

    @property
    def ledger(self) -> List[BallotEntry]:
        return self._ledger

    def __len__(self):
        return len(self._ledger)
