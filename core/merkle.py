
from dataclasses import dataclass
from typing import List

from crypto_utils import sha256


@dataclass
class ProofStep:
    sibling: bytes   # hash del nodo fratello
    is_left: bool    # True se il fratello va concatenato PRIMA (a sinistra)


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return sha256(left + right)


def build_levels(leaves: List[bytes]) -> List[List[bytes]]:
    """Ritorna tutti i livelli dell'albero: levels[0] sono le foglie,
    levels[-1] è una lista con il solo elemento radice."""
    if not leaves:
        # Albero vuoto: radice convenzionale = hash della stringa vuota,
        # cosi' che un'urna senza schede abbia comunque una radice definita.
        return [[sha256(b"")]]

    levels = [list(leaves)]
    current = list(leaves)
    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + [current[-1]]  # duplica l'ultimo nodo (dispari)
        next_level = [_hash_pair(current[i], current[i + 1]) for i in range(0, len(current), 2)]
        levels.append(next_level)
        current = next_level
    return levels


def merkle_root(leaves: List[bytes]) -> bytes:
    return build_levels(leaves)[-1][0]

#Calcola la Proof of Membership  per la foglia all'indice dato, dal basso fino alla radice.
def merkle_proof(leaves: List[bytes], index: int) -> List[ProofStep]:
    if index < 0 or index >= len(leaves):
        raise IndexError("Indice di foglia fuori dai limiti dell'urna pubblicata.")

    levels = build_levels(leaves)
    proof: List[ProofStep] = []
    idx = index
    for level in levels[:-1]:  # esclude la radice
        level_padded = level if len(level) % 2 == 0 else level + [level[-1]]
        is_right_node = idx % 2 == 1
        sibling_idx = idx - 1 if is_right_node else idx + 1
        sibling = level_padded[sibling_idx]
        # se il fratello e' a sinistra del nodo corrente, is_left=True
        proof.append(ProofStep(sibling=sibling, is_left=is_right_node))
        idx //= 2
    return proof

#Ricalcola la radice a partire dalla foglia e dal percorso fornito la confronta con la radice pubblicata 
def verify_merkle_proof(leaf: bytes, proof: List[ProofStep], root: bytes) -> bool:
    current = leaf
    for step in proof:
        if step.is_left:
            current = _hash_pair(step.sibling, current)
        else:
            current = _hash_pair(current, step.sibling)
    return current == root
