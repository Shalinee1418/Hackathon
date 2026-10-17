"""
AegisAgent - VSS API Endpoints
Endpoints for secret splitting, commitment generation, independent share verification,
and Lagrange threshold reconstruction.
"""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
from app.crypto.finite_field import field
from app.crypto.pedersen_vss import pedersen_vss, VSSShare
from app.crypto.feldman_vss import feldman_vss, FeldmanShare
from app.crypto.zero_leakage import key_to_int, int_to_key
from app.api.models import VSSSplitRequest, VSSVerifyRequest, VSSReconstructRequest

router = APIRouter(prefix="/api/vss", tags=["Verifiable Secret Sharing"])


@router.post("/split")
def split_secret_endpoint(req: VSSSplitRequest) -> Dict[str, Any]:
    try:
        # If secret is purely numeric, parse as int; otherwise treat as string key
        if req.secret.isdigit():
            secret_int = int(req.secret) % field.q
        else:
            secret_int = key_to_int(req.secret)

        if req.scheme == "pedersen":
            shares, comm_set, secret_coeffs, blinder_coeffs = pedersen_vss.split_secret(
                secret=secret_int,
                threshold=req.threshold,
                num_participants=req.num_participants
            )
            # Evaluate polynomial points for graph visualization
            curve_points = []
            for step in range(0, (req.num_participants + 1) * 10 + 1):
                x_val = step / 10.0
                # Float interpolation for visual rendering
                y_val = sum(c * (x_val ** k) for k, c in enumerate(secret_coeffs[:req.threshold]))
                curve_points.append({"x": x_val, "y": y_val})

            return {
                "status": "SUCCESS",
                "scheme": "Pedersen VSS",
                "secret_int_hex": hex(secret_int),
                "threshold": req.threshold,
                "num_participants": req.num_participants,
                "commitments_hex": [hex(c) for c in comm_set.commitments],
                "shares": [s.to_dict() for s in shares],
                "secret_polynomial_coeffs_preview": [hex(c)[:10] + "..." for c in secret_coeffs],
                "curve_points": curve_points[:120],
                "prime_p_hex": hex(field.p),
                "order_q_hex": hex(field.q),
            }
        else:
            shares, comms, secret_coeffs = feldman_vss.split_secret(
                secret=secret_int,
                threshold=req.threshold,
                num_participants=req.num_participants
            )
            return {
                "status": "SUCCESS",
                "scheme": "Feldman VSS",
                "secret_int_hex": hex(secret_int),
                "threshold": req.threshold,
                "num_participants": req.num_participants,
                "commitments_hex": [hex(c) for c in comms],
                "shares": [s.to_dict() for s in shares],
                "secret_polynomial_coeffs_preview": [hex(c)[:10] + "..." for c in secret_coeffs],
                "prime_p_hex": hex(field.p),
                "order_q_hex": hex(field.q),
            }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/verify")
def verify_share_endpoint(req: VSSVerifyRequest) -> Dict[str, Any]:
    try:
        commitments = [int(c, 16) if c.startswith("0x") else int(c) for c in req.commitments_hex]
        secret_share = int(req.secret_share_hex, 16) if req.secret_share_hex.startswith("0x") else int(req.secret_share_hex)

        if req.scheme == "pedersen":
            if not req.blinder_share_hex:
                raise HTTPException(status_code=400, detail="blinder_share_hex required for Pedersen VSS")
            blinder_share = int(req.blinder_share_hex, 16) if req.blinder_share_hex.startswith("0x") else int(req.blinder_share_hex)

            share = VSSShare(
                index=req.index,
                secret_share=secret_share,
                blinder_share=blinder_share,
                custodian_name=f"Node-{req.index:02d}"
            )
            res = pedersen_vss.verify_share(share, commitments)
            return {
                "status": "SUCCESS",
                "index": req.index,
                "is_valid": res.is_valid,
                "lhs_hex": res.lhs_hex,
                "rhs_hex": res.rhs_hex,
                "explanation": res.explanation
            }
        else:
            share = FeldmanShare(
                index=req.index,
                secret_share=secret_share,
                custodian_name=f"Node-{req.index:02d}"
            )
            is_valid, lhs, rhs = feldman_vss.verify_share(share, commitments)
            return {
                "status": "SUCCESS",
                "index": req.index,
                "is_valid": is_valid,
                "lhs_hex": lhs,
                "rhs_hex": rhs,
                "explanation": "Valid discrete log commitment" if is_valid else "Commitment mismatch! Fraud detected."
            }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/reconstruct")
def reconstruct_secret_endpoint(req: VSSReconstructRequest) -> Dict[str, Any]:
    try:
        commitments = [int(c, 16) if c.startswith("0x") else int(c) for c in req.commitments_hex]

        if req.scheme == "pedersen":
            shares: List[VSSShare] = []
            for s in req.shares:
                s_int = int(s["secret_share_hex"], 16) if s["secret_share_hex"].startswith("0x") else int(s["secret_share_hex"])
                r_int = int(s["blinder_share_hex"], 16) if s["blinder_share_hex"].startswith("0x") else int(s["blinder_share_hex"])
                shares.append(VSSShare(
                    index=int(s["index"]),
                    secret_share=s_int,
                    blinder_share=r_int,
                    custodian_name=s.get("custodian_name", f"Node-{s['index']}")
                ))

            secret_int, verifications = pedersen_vss.reconstruct_secret(shares, commitments, req.threshold)
            try:
                secret_str = int_to_key(secret_int)
            except Exception:
                secret_str = str(secret_int)

            return {
                "status": "SUCCESS",
                "secret_int_hex": hex(secret_int),
                "secret_str": secret_str,
                "verifications": [v.to_dict() for v in verifications],
                "valid_shares_count": sum(1 for v in verifications if v.is_valid)
            }
        else:
            shares: List[FeldmanShare] = []
            for s in req.shares:
                s_int = int(s["secret_share_hex"], 16) if s["secret_share_hex"].startswith("0x") else int(s["secret_share_hex"])
                shares.append(FeldmanShare(
                    index=int(s["index"]),
                    secret_share=s_int,
                    custodian_name=s.get("custodian_name", f"Node-{s['index']}")
                ))

            secret_int = feldman_vss.reconstruct_secret(shares, commitments, req.threshold)
            try:
                secret_str = int_to_key(secret_int)
            except Exception:
                secret_str = str(secret_int)

            return {
                "status": "SUCCESS",
                "secret_int_hex": hex(secret_int),
                "secret_str": secret_str
            }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
