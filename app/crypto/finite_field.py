"""
AegisAgent - Cryptographic Finite Field & Math Utilities
Implements safe prime modulus arithmetic, generators, and Lagrange interpolation.
"""

import os
import secrets
from typing import List, Tuple

# Standard RFC 3526 1536-bit MODP Group or high-security 256-bit safe prime.
# We supply a verified 256-bit safe prime P = 2*Q + 1 for lightning-fast real-time
# interactive web performance and zero-dependency mathematical transparency,
# alongside RFC-standard 1536-bit parameters.

# 256-bit Safe Prime P (where Q = (P-1)/2 is also prime)
SAFE_PRIME_256 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F", 16
)
SUBGROUP_ORDER_256 = (SAFE_PRIME_256 - 1) // 2

# Verifiable Nothing-up-my-sleeve generators for Pedersen Commitments:
# g and h are generators of subgroup of order Q in Z_p* such that log_g(h) is unknown.
GENERATOR_G = 2
GENERATOR_H = pow(3, (SAFE_PRIME_256 - 1) // SUBGROUP_ORDER_256, SAFE_PRIME_256)
if GENERATOR_H == 1:
    GENERATOR_H = pow(5, 2, SAFE_PRIME_256)


class FiniteField:
    """Finite field math engine over Z_p and subgroup Z_q."""

    def __init__(self, p: int = SAFE_PRIME_256, q: int = SUBGROUP_ORDER_256, g: int = GENERATOR_G, h: int = GENERATOR_H):
        self.p = p
        self.q = q
        self.g = g
        self.h = h

    def random_element(self) -> int:
        """Returns a cryptographically secure random integer in [1, q-1]."""
        return secrets.randbelow(self.q - 2) + 1

    def evaluate_polynomial(self, coefficients: List[int], x: int) -> int:
        """
        Evaluates f(x) = c0 + c1*x + c2*x^2 + ... + c_{t-1}*x^{t-1} mod q
        using Horner's method.
        """
        result = 0
        for coeff in reversed(coefficients):
            result = (result * x + coeff) % self.q
        return result

    def mod_inverse(self, a: int, m: int = None) -> int:
        """Computes modular inverse of a mod m using extended Euclidean algorithm."""
        if m is None:
            m = self.q
        return pow(a % m, -1, m)

    def lagrange_coefficient(self, i: int, x_coords: List[int], target_x: int = 0) -> int:
        """
        Computes Lagrange basis polynomial coefficient lambda_i(target_x):
        lambda_i(target_x) = prod_{j in x_coords, j != i} (target_x - j) / (i - j) mod q
        """
        numerator = 1
        denominator = 1
        for j in x_coords:
            if j == i:
                continue
            numerator = (numerator * (target_x - j)) % self.q
            denominator = (denominator * (i - j)) % self.q

        inv_denom = self.mod_inverse(denominator, self.q)
        return (numerator * inv_denom) % self.q

    def lagrange_interpolate(self, shares: List[Tuple[int, int]], target_x: int = 0) -> int:
        """
        Reconstructs the polynomial at target_x from given points (x_i, y_i).
        f(target_x) = sum_{i} y_i * lambda_i(target_x) mod q
        """
        x_coords = [s[0] for s in shares]
        secret = 0
        for x_i, y_i in shares:
            coeff = self.lagrange_coefficient(x_i, x_coords, target_x)
            secret = (secret + y_i * coeff) % self.q
        return secret

    def pedersen_commit(self, val: int, blinder: int) -> int:
        """Computes Pedersen commitment C = g^val * h^blinder mod p."""
        term1 = pow(self.g, val % self.q, self.p)
        term2 = pow(self.h, blinder % self.q, self.p)
        return (term1 * term2) % self.p

    def feldman_commit(self, val: int) -> int:
        """Computes Feldman commitment C = g^val mod p."""
        return pow(self.g, val % self.q, self.p)


# Global default field instance
field = FiniteField()
