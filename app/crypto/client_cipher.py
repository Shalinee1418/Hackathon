"""
AegisAgent - Client & Agent Cipher Engine
Provides authenticated AES-256-GCM symmetric encryption for client prompts,
agent scratchpad memory, and zero-knowledge communication envelopes.
"""

import os
import base64
import json
import hashlib
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class ClientCipher:
    """AES-256-GCM authenticated cipher engine."""

    def __init__(self, master_secret_bytes: bytes = None):
        if master_secret_bytes:
            # Derive 256-bit symmetric key using HKDF-SHA256
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"AegisAgent_HKDF_Salt_2026",
                info=b"client_prompt_encryption",
            )
            self.key = hkdf.derive(master_secret_bytes)
        else:
            self.key = AESGCM.generate_key(bit_length=256)

        self.aesgcm = AESGCM(self.key)

    @classmethod
    def from_passphrase(cls, passphrase: str, salt: bytes = b"AegisAgent_Client_Salt") -> "ClientCipher":
        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 100_000, 32)
        inst = cls()
        inst.key = key
        inst.aesgcm = AESGCM(key)
        return inst

    def encrypt_str(self, plaintext: str, associated_data: bytes = None) -> Dict[str, str]:
        """
        Encrypts a plaintext string with AES-256-GCM.
        Returns a dict with base64 encoded nonce and ciphertext (which includes auth tag).
        """
        nonce = os.urandom(12)  # 96-bit standard GCM nonce
        ct = self.aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data)
        return {
            "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext_b64": base64.b64encode(ct).decode("utf-8"),
            "algorithm": "AES-256-GCM",
        }

    def decrypt_str(self, payload: Dict[str, str], associated_data: bytes = None) -> str:
        """
        Decrypts an AES-256-GCM payload.
        Verifies authentication tag; raises exception if tampered.
        """
        nonce = base64.b64decode(payload["nonce_b64"])
        ct = base64.b64decode(payload["ciphertext_b64"])
        pt_bytes = self.aesgcm.decrypt(nonce, ct, associated_data)
        return pt_bytes.decode("utf-8")

    def get_key_fingerprint(self) -> str:
        """Returns SHA-256 fingerprint of the encryption key."""
        return hashlib.sha256(self.key).hexdigest()[:16]


# Default client session cipher
client_session_cipher = ClientCipher()
