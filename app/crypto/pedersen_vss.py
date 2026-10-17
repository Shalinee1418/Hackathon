"""
AegisAgent - Pedersen Verifiable Secret Sharing (VSS) Engine
Provides information-theoretically hiding and computationally binding secret sharing
with independent mathematical share validation to detect cheating dealers or corrupted nodes.
"""

from dataclasses import dataclass, asdict
from typing import List, Tuple, Dict, Any, Optional
from app.crypto.finite_field import FiniteField, field


@dataclass
class VSSShare:
    index: int                  # Participant ID i (1-indexed)
    secret_share: int          # s_i = f(i) mod q
    blinder_share: int         # r_i = f'(i) mod q
    custodian_name: str        # Friendly name (e.g. Guardian-Alpha)
    is_tampered: bool = False  # Track simulation state

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "secret_share_hex": hex(self.secret_share),
            "blinder_share_hex": hex(self.blinder_share),
            "custodian_name": self.custodian_name,
            "is_tampered": self.is_tampered,
        }


@dataclass
class VSSCommitmentSet:
    commitments: List[int]     # C_0, C_1, ..., C_{t-1} mod p
    threshold: int             # t
    num_participants: int      # n
    prime_p_hex: str
    order_q_hex: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitments_hex": [hex(c) for c in self.commitments],
            "threshold": self.threshold,
            "num_participants": self.num_participants,
            "prime_p_hex": self.prime_p_hex,
            "order_q_hex": self.order_q_hex,
        }


@dataclass
class VerificationResult:
    index: int
    is_valid: bool
    lhs_hex: str               # g^{s_i} * h^{r_i} mod p
    rhs_hex: str               # prod C_k^{i^k} mod p
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PedersenVSS:
    """Pedersen Verifiable Secret Sharing Implementation."""

    def __init__(self, ff: FiniteField = field):
        self.ff = ff

    def split_secret(
        self,
        secret: int,
        threshold: int,
        num_participants: int,
        custodian_names: Optional[List[str]] = None
    ) -> Tuple[List[VSSShare], VSSCommitmentSet, List[int], List[int]]:
        """
        Splits a secret into n shares using a (t, n) Pedersen VSS scheme.
        Returns:
            (shares, commitment_set, secret_poly_coeffs, blinder_poly_coeffs)
        """
        if threshold < 2:
            raise ValueError("Threshold t must be at least 2")
        if threshold > num_participants:
            raise ValueError("Threshold t cannot exceed total participants n")
        if secret >= self.ff.q:
            raise ValueError("Secret exceeds finite field order q")

        # 1. Random secret polynomial f(x) = s + a_1*x + ... + a_{t-1}*x^{t-1} mod q
        secret_coeffs = [secret] + [self.ff.random_element() for _ in range(threshold - 1)]

        # 2. Random blinding polynomial f'(x) = r + b_1*x + ... + b_{t-1}*x^{t-1} mod q
        blinder_coeffs = [self.ff.random_element() for _ in range(threshold)]

        # 3. Pedersen commitments C_k = g^{a_k} * h^{b_k} mod p
        commitments = []
        for k in range(threshold):
            c_k = self.ff.pedersen_commit(secret_coeffs[k], blinder_coeffs[k])
            commitments.append(c_k)

        # 4. Generate participant shares s_i = f(i), r_i = f'(i) for i in [1, n]
        if not custodian_names or len(custodian_names) < num_participants:
            custodian_names = [f"Node-{i:02d}" for i in range(1, num_participants + 1)]

        shares = []
        for i in range(1, num_participants + 1):
            s_i = self.ff.evaluate_polynomial(secret_coeffs, i)
            r_i = self.ff.evaluate_polynomial(blinder_coeffs, i)
            shares.append(VSSShare(
                index=i,
                secret_share=s_i,
                blinder_share=r_i,
                custodian_name=custodian_names[i - 1],
                is_tampered=False
            ))

        commitment_set = VSSCommitmentSet(
            commitments=commitments,
            threshold=threshold,
            num_participants=num_participants,
            prime_p_hex=hex(self.ff.p),
            order_q_hex=hex(self.ff.q)
        )

        return shares, commitment_set, secret_coeffs, blinder_coeffs

    def verify_share(self, share: VSSShare, commitments: List[int]) -> VerificationResult:
        """
        Participant verifies their share using the public commitments:
        Check if g^{s_i} * h^{r_i} == prod_{k=0}^{t-1} (C_k)^{i^k} mod p
        """
        i = share.index
        # Compute Left-Hand Side (LHS) = g^{s_i} * h^{r_i} mod p
        lhs_term1 = pow(self.ff.g, share.secret_share % self.ff.q, self.ff.p)
        lhs_term2 = pow(self.ff.h, share.blinder_share % self.ff.q, self.ff.p)
        lhs = (lhs_term1 * lhs_term2) % self.ff.p

        # Compute Right-Hand Side (RHS) = prod_{k=0}^{t-1} (C_k)^{i^k} mod p
        rhs = 1
        curr_power = 1  # i^0 = 1
        for k, c_k in enumerate(commitments):
            factor = pow(c_k, curr_power, self.ff.p)
            rhs = (rhs * factor) % self.ff.p
            curr_power = (curr_power * i) % self.ff.q

        is_valid = (lhs == rhs)
        explanation = (
            f"Node {share.custodian_name} (index {i}): Share mathematically verified against Pedersen commitments. "
            f"LHS (g^s * h^r) matches RHS (product of C_k^i^k)."
            if is_valid else
            f"FRAUD DETECTED on Node {share.custodian_name} (index {i})! "
            f"LHS != RHS. Share has been tampered with or dealer committed malicious data."
        )

        return VerificationResult(
            index=i,
            is_valid=is_valid,
            lhs_hex=hex(lhs),
            rhs_hex=hex(rhs),
            explanation=explanation
        )

    def reconstruct_secret(
        self,
        shares: List[VSSShare],
        commitments: List[int],
        threshold: int
    ) -> Tuple[int, List[VerificationResult]]:
        """
        Validates each share against commitments before reconstructing the master secret.
        Cheating or corrupted shares are identified and rejected.
        Raises ValueError if fewer than t valid shares are available.
        """
        valid_shares: List[VSSShare] = []
        verifications: List[VerificationResult] = []

        for share in shares:
            res = self.verify_share(share, commitments)
            verifications.append(res)
            if res.is_valid:
                valid_shares.append(share)

        if len(valid_shares) < threshold:
            failed_nodes = [s.custodian_name for s, r in zip(shares, verifications) if not r.is_valid]
            raise ValueError(
                f"Quorum failure: Only {len(valid_shares)}/{threshold} required valid shares verified. "
                f"Tampered nodes detected: {', '.join(failed_nodes) if failed_nodes else 'None'}"
            )

        # Reconstruct using the first t valid shares
        points = [(s.index, s.secret_share) for s in valid_shares[:threshold]]
        reconstructed_secret = self.ff.lagrange_interpolate(points, target_x=0)

        return reconstructed_secret, verifications


# Default VSS instance
pedersen_vss = PedersenVSS()
