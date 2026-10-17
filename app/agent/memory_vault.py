"""
AegisAgent - Encrypted Memory Vault & Tamper-Evident Ledger
Stores agent memory records using AES-256-GCM and maintains a cryptographic Merkle hash chain.
"""

import time
import hashlib
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from app.crypto.client_cipher import client_session_cipher


@dataclass
class EncryptedMemoryRecord:
    record_id: str
    timestamp: float
    encrypted_payload: Dict[str, str]
    data_hash: str
    previous_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "ciphertext_preview": self.encrypted_payload["ciphertext_b64"][:20] + "...",
            "nonce_b64": self.encrypted_payload["nonce_b64"],
            "data_hash": self.data_hash,
            "previous_hash": self.previous_hash,
        }


class MemoryVault:
    """Tamper-evident encrypted memory ledger for private agent."""

    def __init__(self, cipher=client_session_cipher):
        self.cipher = cipher
        self.records: List[EncryptedMemoryRecord] = []
        self.latest_merkle_root: str = "GENESIS_ROOT_0000000000000000"

    def store_memory(self, memory_text: str, metadata: Dict[str, Any] = None) -> EncryptedMemoryRecord:
        """Encrypts memory record with AES-256-GCM and links to Merkle chain."""
        timestamp = time.time()
        record_id = f"MEM-{len(self.records) + 1:04d}"

        # Encrypt the memory text
        encrypted_payload = self.cipher.encrypt_str(memory_text)

        # Hash of ciphertext + timestamp
        prev_hash = self.records[-1].data_hash if self.records else "0" * 64
        block_content = f"{record_id}:{timestamp}:{encrypted_payload['ciphertext_b64']}:{prev_hash}"
        data_hash = hashlib.sha256(block_content.encode("utf-8")).hexdigest()

        record = EncryptedMemoryRecord(
            record_id=record_id,
            timestamp=timestamp,
            encrypted_payload=encrypted_payload,
            data_hash=data_hash,
            previous_hash=prev_hash,
        )
        self.records.append(record)
        self._update_merkle_root()
        return record

    def retrieve_memory(self, record_id: str) -> Optional[str]:
        """Decrypts a memory record by ID."""
        for rec in self.records:
            if rec.record_id == record_id:
                return self.cipher.decrypt_str(rec.encrypted_payload)
        return None

    def _update_merkle_root(self):
        combined = "".join(r.data_hash for r in self.records)
        self.latest_merkle_root = hashlib.sha256(combined.encode("utf-8")).hexdigest()

    def get_audit_trail(self) -> Dict[str, Any]:
        return {
            "total_records": len(self.records),
            "merkle_root": self.latest_merkle_root,
            "records": [r.to_dict() for r in self.records],
        }


memory_vault = MemoryVault()
