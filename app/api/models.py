"""
AegisAgent - API Request and Response Models
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class VSSSplitRequest(BaseModel):
    secret: str = Field(..., description="Secret string or integer to split")
    threshold: int = Field(3, ge=2, le=10, description="Threshold t")
    num_participants: int = Field(5, ge=2, le=20, description="Total participants n")
    scheme: str = Field("pedersen", description="'pedersen' or 'feldman'")


class VSSVerifyRequest(BaseModel):
    index: int
    secret_share_hex: str
    blinder_share_hex: Optional[str] = None
    commitments_hex: List[str]
    scheme: str = "pedersen"


class VSSReconstructRequest(BaseModel):
    shares: List[Dict[str, Any]]
    commitments_hex: List[str]
    threshold: int
    scheme: str = "pedersen"


class AgentSetupKeyRequest(BaseModel):
    master_key: str = Field(..., description="Master API Key (e.g. sk-live-prod-credential-9876)")
    threshold: int = Field(3, ge=2, le=10)
    num_nodes: int = Field(5, ge=2, le=10)


class AgentChatRequest(BaseModel):
    prompt: Optional[str] = Field(None, description="Plaintext prompt (will be client-side encrypted)")
    encrypted_payload: Optional[Dict[str, str]] = Field(None, description="Pre-encrypted AES-256-GCM payload")
    client_tag: Optional[str] = Field("Client-01", description="Identifier of client enclave")


class CustodianTamperRequest(BaseModel):
    node_id: int = Field(..., description="Node ID to tamper/compromise")
