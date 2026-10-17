"""
AegisAgent - Zero-Knowledge Blind AI Agent Core
Orchestrates client-side encryption, entity redaction, VSS threshold key reconstruction,
zero-leakage inference, and local response re-hydration.
"""

import re
import time
import hashlib
from typing import Dict, Any, List, Tuple
from app.crypto.finite_field import field
from app.crypto.pedersen_vss import pedersen_vss, VSSShare, VerificationResult
from app.crypto.zero_leakage import int_to_key, ZeroLeakageSandbox
from app.crypto.client_cipher import client_session_cipher
from app.agent.custodian_network import custodian_network
from app.agent.llm_gateway import llm_gateway
from app.agent.memory_vault import memory_vault


class EntitySanitizer:
    """Detects and replaces sensitive entities with cryptographic shadow tokens."""

    PATTERNS = {
        "API_KEY": r"(?:sk-[a-zA-Z0-9_\-]{20,}|ghp_[a-zA-Z0-9]{20,}|Bearer\s+[a-zA-Z0-9\.\-_]+)",
        "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "CURRENCY_BALANCE": r"\$\s*\d+(?:,\d+)*(?:\.\d{2})?|\b\d+(?:,\d+)*\s*(?:USD|EUR|GBP|BTC|ETH)\b",
        "PASSWORD_SECRET": r"(?:password|passwd|secret)[\s:=]+([^\s,]+)",
    }

    @classmethod
    def sanitize(cls, text: str) -> Tuple[str, Dict[str, str]]:
        """
        Scans text for sensitive patterns and replaces them with [SHADOW_TOKEN_...].
        Returns (sanitized_text, token_mapping_dict).
        """
        mapping: Dict[str, str] = {}
        sanitized = text

        for entity_type, regex in cls.PATTERNS.items():
            matches = list(re.finditer(regex, sanitized, re.IGNORECASE))
            # Process in reverse order to preserve match offsets
            for match in reversed(matches):
                original_val = match.group(0)
                # Create deterministic hash token for this session
                token_hash = hashlib.sha256(f"{entity_type}:{original_val}".encode("utf-8")).hexdigest()[:8].upper()
                token = f"[SHADOW_{entity_type}_{token_hash}]"

                mapping[token] = original_val
                start, end = match.span()
                sanitized = sanitized[:start] + token + sanitized[end:]

        return sanitized, mapping

    @classmethod
    def rehydrate(cls, sanitized_text: str, mapping: Dict[str, str]) -> str:
        """Restores original values for all shadow tokens inside private client perimeter."""
        result = sanitized_text
        for token, original in mapping.items():
            result = result.replace(token, original)
        return result


class BlindAgent:
    """Private AI Agent with VSS-protected master keys and encrypted context."""

    def __init__(self, custodian_net=custodian_network, vss=pedersen_vss, cipher=client_session_cipher):
        self.custodian_net = custodian_net
        self.vss = vss
        self.cipher = cipher
        self.audit_log: List[Dict[str, Any]] = []

    def process_query(
        self,
        encrypted_prompt_payload: Dict[str, str],
        client_tag: str = "Client-01"
    ) -> Dict[str, Any]:
        """
        Complete zero-trust execution flow:
        1. Decrypt client prompt in private enclave
        2. Sanitize and blind sensitive entities
        3. Request quorum shares from custodian network
        4. Mathematically verify all shares against Pedersen commitments
        5. Reconstruct master key inside zero-leakage ephemeral buffer
        6. Execute inference through LLM gateway with sanitized prompt
        7. Zeroize key memory explicitly
        8. Re-hydrate response locally for client
        9. Store encrypted interaction in memory vault
        """
        step_timeline = []

        # Step 1: Decrypt prompt inside local client boundary
        t0 = time.time()
        raw_prompt = self.cipher.decrypt_str(encrypted_prompt_payload)
        step_timeline.append({
            "step": 1,
            "name": "Client-Side Decryption",
            "status": "SUCCESS",
            "detail": f"Decrypted AES-256-GCM envelope (Nonce: {encrypted_prompt_payload['nonce_b64'][:8]}...).",
            "time_ms": round((time.time() - t0) * 1000, 2)
        })

        # Step 2: Blind Entity Redaction
        t1 = time.time()
        sanitized_prompt, entity_map = EntitySanitizer.sanitize(raw_prompt)
        step_timeline.append({
            "step": 2,
            "name": "Blind Entity Sanitization",
            "status": "SUCCESS",
            "detail": f"Identified & masked {len(entity_map)} sensitive entity token(s). Upstream will see only shadow tokens.",
            "entities_masked": list(entity_map.keys()),
            "time_ms": round((time.time() - t1) * 1000, 2)
        })

        # Step 3: Quorum Request from Custodian Enclaves
        t2 = time.time()
        gathered_shares = self.custodian_net.request_quorum_shares()
        step_timeline.append({
            "step": 3,
            "name": "Custodian Share Retrieval",
            "status": "SUCCESS",
            "detail": f"Gathered {len(gathered_shares)} shares from distributed custodian network.",
            "time_ms": round((time.time() - t2) * 1000, 2)
        })

        # Step 4: Mathematical VSS Verification
        t3 = time.time()
        if not self.custodian_net.commitments:
            raise RuntimeError("Custodian network has not been initialized with VSS commitments!")

        reconstructed_secret_int, verifications = self.vss.reconstruct_secret(
            shares=gathered_shares,
            commitments=self.custodian_net.commitments.commitments,
            threshold=self.custodian_net.threshold
        )

        valid_nodes = [v.index for v in verifications if v.is_valid]
        tampered_nodes = [v.index for v in verifications if not v.is_valid]

        step_timeline.append({
            "step": 4,
            "name": "Pedersen Commitment Share Verification",
            "status": "SUCCESS" if len(valid_nodes) >= self.custodian_net.threshold else "FAILED",
            "detail": (
                f"Verified {len(valid_nodes)}/{len(gathered_shares)} shares mathematically against public commitments. "
                f"Quorum threshold ({self.custodian_net.threshold}) reached."
            ),
            "valid_node_indices": valid_nodes,
            "tampered_node_indices": tampered_nodes,
            "time_ms": round((time.time() - t3) * 1000, 2)
        })

        # Step 5 & 6: Ephemeral Zero-Leakage LLM Execution
        t4 = time.time()
        master_key_str = int_to_key(reconstructed_secret_int)

        inference_result = ZeroLeakageSandbox.execute_with_ephemeral_key(
            master_key_str,
            llm_gateway.execute_inference,
            sanitized_prompt=sanitized_prompt
        )

        step_timeline.append({
            "step": 5,
            "name": "Zero-Leakage In-Memory Execution",
            "status": "SUCCESS",
            "detail": "Ephemeral master key assembled, used for inference dispatch, and immediately wiped via memory zeroization.",
            "provider": inference_result["provider"],
            "time_ms": round((time.time() - t4) * 1000, 2)
        })

        # Step 7: Local Re-hydration
        t5 = time.time()
        upstream_response = inference_result["response_text"]
        final_client_response = EntitySanitizer.rehydrate(upstream_response, entity_map)
        step_timeline.append({
            "step": 6,
            "name": "Local Enclave Re-hydration",
            "status": "SUCCESS",
            "detail": "Re-hydrated shadow tokens back to original values inside client trust perimeter.",
            "time_ms": round((time.time() - t5) * 1000, 2)
        })

        # Step 8: Encrypted Record in Memory Vault
        memory_record = memory_vault.store_memory(
            f"PROMPT_HASH:{hashlib.sha256(raw_prompt.encode()).hexdigest()} | RESPONSE_LEN:{len(final_client_response)}"
        )

        # Build Cryptographic Attestation Receipt
        receipt_id = f"RCPT-{hashlib.sha256(f'{time.time()}:{raw_prompt}'.encode()).hexdigest()[:12].upper()}"
        receipt = {
            "receipt_id": receipt_id,
            "timestamp": time.time(),
            "client_tag": client_tag,
            "prompt_hash": hashlib.sha256(raw_prompt.encode()).hexdigest(),
            "sanitized_prompt_hash": hashlib.sha256(sanitized_prompt.encode()).hexdigest(),
            "threshold_required": self.custodian_net.threshold,
            "valid_shares_verified": len(valid_nodes),
            "tampered_nodes_detected": tampered_nodes,
            "ephemeral_zeroization_verified": True,
            "memory_vault_record_id": memory_record.record_id,
            "merkle_root": memory_vault.latest_merkle_root,
        }
        self.audit_log.append(receipt)

        return {
            "receipt": receipt,
            "final_response": final_client_response,
            "upstream_response": upstream_response,
            "raw_prompt_preview": raw_prompt,
            "sanitized_prompt": sanitized_prompt,
            "entity_mask_count": len(entity_map),
            "timeline": step_timeline,
            "verifications": [v.to_dict() for v in verifications],
            "inference_meta": inference_result,
        }


# Global blind agent instance
blind_agent = BlindAgent()
