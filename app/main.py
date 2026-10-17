"""
AegisAgent - Main Application Entrypoint
FastAPI server providing cryptographic VSS validation endpoints,
zero-knowledge private AI agent orchestration, and cyber-cryptographic web UI.
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes_vss import router as vss_router
from app.api.routes_agent import router as agent_router
from app.crypto.finite_field import field
from app.crypto.pedersen_vss import pedersen_vss
from app.crypto.zero_leakage import key_to_int
from app.agent.custodian_network import custodian_network


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize default master key and shard it across the 5 custodian enclaves
    default_master_key = "sk-aegis-master-live-token-42"
    secret_int = key_to_int(default_master_key)
    shares, comm_set, _, _ = pedersen_vss.split_secret(
        secret=secret_int,
        threshold=3,
        num_participants=5,
        custodian_names=[n["name"] for n in custodian_network.DEFAULT_NODES]
    )
    custodian_network.distribute_shares(shares, comm_set)
    print("=================================================================")
    print(" [AegisAgent] Zero-Trust Cryptographic Engine Online")
    print(f" [AegisAgent] Default Master Key sharded across 5 Custodians (3-of-5 threshold)")
    print(f" [AegisAgent] Prime P: {hex(field.p)[:18]}...")
    print(f" [AegisAgent] Subgroup Order Q: {hex(field.q)[:18]}...")
    print("=================================================================")
    yield


app = FastAPI(
    title="AegisAgent - Verifiable Secret Sharing & Blind AI Agent",
    description="A cryptographic framework combining Pedersen/Feldman VSS with zero-leakage private AI agents.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for open accessibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers
app.include_router(vss_router)
app.include_router(agent_router)

# Serve static directory
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def serve_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "AegisAgent API is active. Static frontend files are being generated."}


@app.get("/health")
def health_check():
    return {
        "status": "HEALTHY",
        "service": "AegisAgent",
        "threshold": custodian_network.threshold,
        "active_nodes": len(custodian_network.nodes),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
