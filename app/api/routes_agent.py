"""
AegisAgent - Private Agent API Endpoints
Endpoints for master key VSS sharding, zero-leakage chat inference,
custodian cluster management, and Merkle audit trails.
"""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from app.crypto.finite_field import field
from app.crypto.pedersen_vss import pedersen_vss
from app.crypto.zero_leakage import key_to_int
from app.crypto.client_cipher import client_session_cipher
from app.agent.custodian_network import custodian_network
from app.agent.blind_agent import blind_agent
from app.agent.memory_vault import memory_vault
from app.api.models import AgentSetupKeyRequest, AgentChatRequest, CustodianTamperRequest

router = APIRouter(prefix="/api/agent", tags=["Private AI Agent"])


@router.post("/setup-key")
def setup_master_key_endpoint(req: AgentSetupKeyRequest) -> Dict[str, Any]:
    try:
        secret_int = key_to_int(req.master_key)
        shares, comm_set, _, _ = pedersen_vss.split_secret(
            secret=secret_int,
            threshold=req.threshold,
            num_participants=req.num_nodes,
            custodian_names=[n["name"] for n in custodian_network.DEFAULT_NODES[:req.num_nodes]]
        )

        custodian_network.distribute_shares(shares, comm_set)

        return {
            "status": "SUCCESS",
            "message": f"Master key successfully sharded across {req.num_nodes} custodian nodes using ({req.threshold}, {req.num_nodes}) Pedersen VSS.",
            "threshold": req.threshold,
            "num_nodes": req.num_nodes,
            "commitments_hex": [hex(c) for c in comm_set.commitments],
            "cluster_status": custodian_network.get_cluster_status(),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/chat")
def private_chat_endpoint(req: AgentChatRequest) -> Dict[str, Any]:
    try:
        # If client passed pre-encrypted payload, use it; otherwise encrypt with client cipher
        if req.encrypted_payload:
            payload = req.encrypted_payload
        elif req.prompt:
            payload = client_session_cipher.encrypt_str(req.prompt)
        else:
            raise HTTPException(status_code=400, detail="Either 'prompt' or 'encrypted_payload' must be provided.")

        result = blind_agent.process_query(
            encrypted_prompt_payload=payload,
            client_tag=req.client_tag or "Client-01"
        )
        return {
            "status": "SUCCESS",
            **result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/custodians")
def get_custodians_endpoint() -> Dict[str, Any]:
    return {
        "status": "SUCCESS",
        "cluster": custodian_network.get_cluster_status(),
    }


@router.post("/custodian/tamper")
def tamper_custodian_endpoint(req: CustodianTamperRequest) -> Dict[str, Any]:
    try:
        res = custodian_network.tamper_node(req.node_id)
        return {"status": "SUCCESS", **res}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/custodian/restore")
def restore_custodian_endpoint(req: CustodianTamperRequest) -> Dict[str, Any]:
    try:
        res = custodian_network.restore_node(req.node_id)
        return {"status": "SUCCESS", **res}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/audit-log")
def get_audit_log_endpoint() -> Dict[str, Any]:
    return {
        "status": "SUCCESS",
        "total_receipts": len(blind_agent.audit_log),
        "receipts": blind_agent.audit_log,
        "memory_vault": memory_vault.get_audit_trail(),
    }


@router.get("/cipher-info")
def get_cipher_info_endpoint() -> Dict[str, Any]:
    return {
        "status": "SUCCESS",
        "algorithm": "AES-256-GCM",
        "key_fingerprint": client_session_cipher.get_key_fingerprint(),
        "curve_group": "256-bit Safe Prime MODP",
        "vss_scheme": "Pedersen Information-Theoretic VSS",
    }
