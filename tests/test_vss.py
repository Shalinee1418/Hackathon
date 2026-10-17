"""
Unit Tests for Verifiable Secret Sharing (VSS) Cryptographic Schemes
Verifies:
1. Honest Dealer & Valid Share Verification (Pedersen & Feldman)
2. Perfect Lagrange Interpolation Reconstruction
3. Cheating/Malicious Dealer Detection (Invalid commitments or bad shares)
4. Cheating/Corrupted Share Detection (Tampered bits rejected)
5. Threshold Quorum Boundary (Fewer than t shares fail)
"""

import unittest
from app.crypto.finite_field import field
from app.crypto.pedersen_vss import pedersen_vss, VSSShare
from app.crypto.feldman_vss import feldman_vss, FeldmanShare
from app.crypto.zero_leakage import key_to_int, int_to_key


class TestVerifiableSecretSharing(unittest.TestCase):

    def setUp(self):
        self.secret_str = "sk-super-secret-master-token-1234"
        self.secret_int = key_to_int(self.secret_str)
        self.threshold = 3
        self.num_participants = 5

    def test_pedersen_vss_honest_execution(self):
        """Tests that honest dealer produces shares that all verify and reconstruct."""
        shares, comm_set, _, _ = pedersen_vss.split_secret(
            secret=self.secret_int,
            threshold=self.threshold,
            num_participants=self.num_participants
        )

        self.assertEqual(len(shares), self.num_participants)
        self.assertEqual(len(comm_set.commitments), self.threshold)

        # Every participant independently verifies their share
        for share in shares:
            res = pedersen_vss.verify_share(share, comm_set.commitments)
            self.assertTrue(res.is_valid, f"Share {share.index} failed honest verification!")

        # Reconstruct with any 3 shares (e.g. shares 1, 3, 5)
        subset = [shares[0], shares[2], shares[4]]
        reconstructed, verifications = pedersen_vss.reconstruct_secret(
            subset, comm_set.commitments, self.threshold
        )
        self.assertEqual(reconstructed, self.secret_int)
        self.assertEqual(int_to_key(reconstructed), self.secret_str)

    def test_pedersen_vss_catches_tampered_share(self):
        """Tests that bit flips or forged shares are mathematically detected and rejected."""
        shares, comm_set, _, _ = pedersen_vss.split_secret(
            secret=self.secret_int,
            threshold=self.threshold,
            num_participants=self.num_participants
        )

        # Corrupt share 2
        bad_share = VSSShare(
            index=shares[1].index,
            secret_share=shares[1].secret_share ^ 0x1337,  # Altered share
            blinder_share=shares[1].blinder_share,
            custodian_name=shares[1].custodian_name,
            is_tampered=True
        )

        res = pedersen_vss.verify_share(bad_share, comm_set.commitments)
        self.assertFalse(res.is_valid, "Tampered share was NOT detected!")

        # Attempt reconstruction with [share 1, bad_share 2, share 3]
        tampered_subset = [shares[0], bad_share, shares[2]]
        # Because bad_share is rejected, only 2 valid shares remain (less than threshold 3)
        with self.assertRaises(ValueError):
            pedersen_vss.reconstruct_secret(tampered_subset, comm_set.commitments, self.threshold)

    def test_feldman_vss_execution(self):
        """Tests Feldman VSS splitting, verification, and reconstruction."""
        shares, commitments, _ = feldman_vss.split_secret(
            secret=self.secret_int,
            threshold=self.threshold,
            num_participants=self.num_participants
        )

        for share in shares:
            is_valid, _, _ = feldman_vss.verify_share(share, commitments)
            self.assertTrue(is_valid, f"Feldman share {share.index} failed verification")

        reconstructed = feldman_vss.reconstruct_secret(shares[:3], commitments, self.threshold)
        self.assertEqual(reconstructed, self.secret_int)


if __name__ == "__main__":
    unittest.main()
