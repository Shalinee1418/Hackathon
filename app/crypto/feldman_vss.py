"""
AegisAgent - Feldman Verifiable Secret Sharing (VSS) Engine
Implements Feldman's non-interactive VSS scheme with discrete logarithm commitments.
"""

from dataclasses import dataclass, asdict
from typing import List, Tuple, Dict, Any, Optional
from app.crypto.finite_field import FiniteField, field


@dataclass
class FeldmanShare:
    index: int
    secret_share: int
    custodian_name: str
    is_tampered: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "secret_share_hex": hex(self.secret_share),
            "custodian_name": self.custodian_name,
            "is_tampered": self.is_tampered,
        }


class FeldmanVSS:
    """Feldman Verifiable Secret Sharing implementation."""

    def __init__(self, ff: FiniteField = field):
        self.ff = ff

    def split_secret(
        self,
        secret: int,
        threshold: int,
        num_participants: int,
        custodian_names: Optional[List[str]] = None
    ) -> Tuple[List[FeldmanShare], List[int], List[int]]:
        if threshold < 2:
            raise ValueError("Threshold t must be at least 2")
        if threshold > num_participants:
            raise ValueError("Threshold t cannot exceed total participants n")

        secret_coeffs = [secret] + [self.ff.random_element() for _ in range(threshold - 1)]

        # Commitments: C_k = g^{a_k} mod p
        commitments = [self.ff.feldman_commit(a_k) for a_k in secret_coeffs]

        if not custodian_names or len(custodian_names) < num_participants:
            custodian_names = [f"Custodian-{i:02d}" for i in range(1, num_participants + 1)]

        shares = []
        for i in range(1, num_participants + 1):
            s_i = self.ff.evaluate_polynomial(secret_coeffs, i)
            shares.append(FeldmanShare(
                index=i,
                secret_share=s_i,
                custodian_name=custodian_names[i - 1],
                is_tampered=False
            ))

        return shares, commitments, secret_coeffs

    def verify_share(self, share: FeldmanShare, commitments: List[int]) -> Tuple[bool, str, str]:
        i = share.index
        # LHS = g^{s_i} mod p
        lhs = pow(self.ff.g, share.secret_share % self.ff.q, self.ff.p)

        # RHS = prod_{k=0}^{t-1} C_k^{i^k} mod p
        rhs = 1
        curr_power = 1
        for c_k in commitments:
            factor = pow(c_k, curr_power, self.ff.p)
            rhs = (rhs * factor) % self.ff.p
            curr_power = (curr_power * i) % self.ff.q

        is_valid = (lhs == rhs)
        return is_valid, hex(lhs), hex(rhs)

    def reconstruct_secret(self, shares: List[FeldmanShare], commitments: List[int], threshold: int) -> int:
        valid_shares = []
        for s in shares:
            is_valid, _, _ = self.verify_share(s, commitments)
            if is_valid:
                valid_shares.append(s)

        if len(valid_shares) < threshold:
            raise ValueError(f"Feldman VSS failed: insufficient valid shares ({len(valid_shares)}/{threshold})")

        points = [(s.index, s.secret_share) for s in valid_shares[:threshold]]
        return self.ff.lagrange_interpolate(points, target_x=0)


feldman_vss = FeldmanVSS()
