

import secrets
from typing import List, Tuple

PRIME = (1 << 521) - 1  # M521, numero primo di Mersenne


def _eval_polynomial(coeffs: List[int], x: int, p: int) -> int:
    result = 0
    for coeff in reversed(coeffs):
        result = (result * x + coeff) % p
    return result

#crea i frammenti di segreto per la condivisione di Shamir.
def split_secret(secret_int: int, t: int, n: int, p: int = PRIME) -> List[Tuple[int, int]]:
    if secret_int >= p:
        raise ValueError("Il segreto deve essere minore del modulo primo p")
    if t < 2 or t > n:
        raise ValueError("Richiesto 2 <= t <= n")
    coeffs = [secret_int] + [secrets.randbelow(p) for _ in range(t - 1)]
    shares = [(x, _eval_polynomial(coeffs, x, p)) for x in range(1, n + 1)]
    return shares


def _mod_inverse(a: int, p: int) -> int:
    return pow(a, p - 2, p)  # p primo -> piccolo teorema di Fermat

#ricostruisce il segreto a partire dai frammenti di Shamir.
def reconstruct_secret(shares: List[Tuple[int, int]], p: int = PRIME) -> int:
    secret = 0
    for i, (x_i, y_i) in enumerate(shares):
        num, den = 1, 1
        for j, (x_j, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * (-x_j % p)) % p
            den = (den * (x_i - x_j)) % p
        lagrange_coeff = (num * _mod_inverse(den, p)) % p
        secret = (secret + y_i * lagrange_coeff) % p
    return secret
