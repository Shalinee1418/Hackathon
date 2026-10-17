"""
AegisAgent - Custodian Enclave Network
Manages distributed custodian nodes that hold VSS shares of master secrets.
Simulates a multi-node cryptographic trust network with Byzantine fault injection.
"""

import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from app.crypto.pedersen_vss import VSSShare, VSSCommitmentSet, pedersen_vss


@dataclass
class CustodianNode:
    node_id: int
    name: str
    region: str
    status: str            # 'ACTIVE', 'COMPROMISED', 'OFFLINE'
    share: Optional[VSSShare]
    tamper_flag: bool = False
    requests_served: int = 0
    last_verified: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "name": self.name,
            "region": self.region,
            "status": self.status,
            "tamper_flag": self.tamper_flag,
            "requests_served": self.requests_served,
            "last_verified": self.last_verified,
            "has_share": self.share is not None,
            "share_preview": hex(self.share.secret_share)[:14] + "..." if self.share else None,
        }


class CustodianNetwork:
    """Simulates a cluster of independent cryptographic custodian nodes."""

    DEFAULT_NODES = [
        {"id": 1, "name": "Guardian-Alpha", "region": "us-east-enclave"},
        {"id": 2, "name": "Sentinel-Beta", "region": "eu-central-vault"},
        {"id": 3, "name": "Vault-Gamma", "region": "ap-northeast-hsm"},
        {"id": 4, "name": "Cipher-Delta", "region": "sa-east-tee"},
        {"id": 5, "name": "Echo-Epsilon", "region": "ch-secure-bunker"},
    ]

    def __init__(self):
        self.nodes: Dict[int, CustodianNode] = {}
        self.commitments: Optional[VSSCommitmentSet] = None
        self.threshold: int = 3
        self.num_nodes: int = 5
        self._initialize_nodes()

    def _initialize_nodes(self):
        for info in self.DEFAULT_NODES:
            self.nodes[info["id"]] = CustodianNode(
                node_id=info["id"],
                name=info["name"],
                region=info["region"],
                status="ACTIVE",
                share=None,
                tamper_flag=False,
                requests_served=0,
                last_verified=None,
            )

    def distribute_shares(
        self,
        shares: List[VSSShare],
        commitment_set: VSSCommitmentSet
    ):
        """Distributes VSS shares and public commitments across custodian nodes."""
        self.commitments = commitment_set
        self.threshold = commitment_set.threshold
        self.num_nodes = commitment_set.num_participants

        for share in shares:
            if share.index in self.nodes:
                self.nodes[share.index].share = share
                self.nodes[share.index].status = "ACTIVE"
                self.nodes[share.index].tamper_flag = False

    def request_quorum_shares(self) -> List[VSSShare]:
        """
        Gathers shares from all active nodes for threshold reconstruction.
        If a node is compromised, its share is corrupted to test VSS validation.
        """
        gathered: List[VSSShare] = []
        for node in self.nodes.values():
            if node.status == "OFFLINE" or node.share is None:
                continue

            node.requests_served += 1
            node.last_verified = time.time()

            # If node has been tampered, return corrupted share
            if node.tamper_flag or node.status == "COMPROMISED":
                corrupted_share = VSSShare(
                    index=node.share.index,
                    secret_share=(node.share.secret_share ^ 0xDEADBEEF),  # Inverted bits
                    blinder_share=node.share.blinder_share,
                    custodian_name=node.name,
                    is_tampered=True,
                )
                gathered.append(corrupted_share)
            else:
                gathered.append(node.share)

        return gathered

    def tamper_node(self, node_id: int) -> Dict[str, Any]:
        """Simulates an attacker or Byzantine failure corrupting a node's share."""
        if node_id not in self.nodes:
            raise KeyError(f"Node {node_id} not found")
        node = self.nodes[node_id]
        node.tamper_flag = True
        node.status = "COMPROMISED"
        return {
            "node_id": node_id,
            "name": node.name,
            "status": node.status,
            "message": f"Simulated compromise injected into {node.name}. Share bits corrupted.",
        }

    def restore_node(self, node_id: int) -> Dict[str, Any]:
        """Restores a compromised node to legitimate operational state."""
        if node_id not in self.nodes:
            raise KeyError(f"Node {node_id} not found")
        node = self.nodes[node_id]
        node.tamper_flag = False
        node.status = "ACTIVE"
        return {
            "node_id": node_id,
            "name": node.name,
            "status": node.status,
            "message": f"Node {node.name} restored. Share integrity verified.",
        }

    def get_cluster_status(self) -> Dict[str, Any]:
        """Returns full telemetry for all custodian enclaves."""
        return {
            "total_nodes": len(self.nodes),
            "threshold": self.threshold,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "has_commitments": self.commitments is not None,
            "commitments_preview": [hex(c)[:14] + "..." for c in self.commitments.commitments] if self.commitments else [],
        }


# Global custodian network instance
custodian_network = CustodianNetwork()
