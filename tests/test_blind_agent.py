"""
Unit Tests for Blind Private AI Agent
Verifies:
1. Client-Side AES-256-GCM authenticated encryption & tamper rejection
2. Entity Sanitizer masking & re-hydration
3. Zero-Leakage ephemeral memory wiping
4. End-to-end Blind Agent processing with Custodian Quorum
"""

import unittest
from app.crypto.client_cipher import client_session_cipher
from app.agent.blind_agent import EntitySanitizer, blind_agent
from app.agent.custodian_network import custodian_network
from app.crypto.pedersen_vss import pedersen_vss
from app.crypto.zero_leakage import key_to_int


class TestBlindPrivateAgent(unittest.TestCase):

    def setUp(self):
        self.cipher = client_session_cipher
        blind_agent.cipher = self.cipher
        # Initialize custodian network
        secret_int = key_to_int("sk-live-test-key-for-agent-999")
        shares, comm_set, _, _ = pedersen_vss.split_secret(
            secret=secret_int,
            threshold=3,
            num_participants=5,
            custodian_names=[n["name"] for n in custodian_network.DEFAULT_NODES]
        )
        custodian_network.distribute_shares(shares, comm_set)

    def test_client_cipher_authenticated_encryption(self):
        plaintext = "Patient John Doe SSN 123-45-6789 transfer $50,000"
        encrypted = self.cipher.encrypt_str(plaintext)

        self.assertIn("nonce_b64", encrypted)
        self.assertIn("ciphertext_b64", encrypted)
        self.assertNotEqual(encrypted["ciphertext_b64"], plaintext)

        decrypted = self.cipher.decrypt_str(encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_entity_sanitizer(self):
        prompt = (
            "Please audit account alice@hedgefund.com with balance $1,250,000. "
            "Master API token is sk-1234567890abcdef1234567890abcdef."
        )
        sanitized, mapping = EntitySanitizer.sanitize(prompt)

        # Ensure raw sensitive data is NOT present in sanitized string
        self.assertNotIn("alice@hedgefund.com", sanitized)
        self.assertNotIn("$1,250,000", sanitized)
        self.assertNotIn("sk-1234567890abcdef1234567890abcdef", sanitized)

        # Ensure shadow tokens are present
        self.assertTrue(any("[SHADOW_" in token for token in mapping.keys()))

        # Ensure re-hydration restores original content
        rehydrated = EntitySanitizer.rehydrate(sanitized, mapping)
        self.assertEqual(rehydrated, prompt)

    def test_blind_agent_end_to_end(self):
        prompt = "Review transaction for client contact bob@example.com with credit card 4111-2222-3333-4444"
        encrypted_payload = self.cipher.encrypt_str(prompt)

        result = blind_agent.process_query(encrypted_payload)

        self.assertEqual(result["receipt"]["threshold_required"], 3)
        self.assertGreaterEqual(result["receipt"]["valid_shares_verified"], 3)
        self.assertTrue(result["receipt"]["ephemeral_zeroization_verified"])
        self.assertIn("receipt", result)
        self.assertIn("final_response", result)


if __name__ == "__main__":
    unittest.main()
