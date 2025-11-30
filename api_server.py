"""
FastAPI service for room/admin/WebAuthn handling.
- First registrant for a room becomes admin.
- Issues JWT join tokens used by the WebSocket relay.
- Stores room + credentials in MongoDB.

Env:
  MONGODB_URI (default: mongodb://localhost:27017)
  JWT_SECRET  (default: dev-secret, override for production)
"""

import base64
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fido2 import cbor
from fido2.cose import CoseKey
from fido2.server import Fido2Server, PublicKeyCredentialRpEntity
from fido2.webauthn import (
    AttestationObject,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    AuthenticatorData,
    AuthenticationResponse,
    CollectedClientData,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    AttestedCredentialData,
)
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MONGO_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
DB_NAME = os.getenv("CHAT_DB_NAME", "secure_chat")

client = AsyncIOMotorClient(MONGO_URI)
db = client[DB_NAME]
rooms = db.rooms
creds = db.credentials

rp_name = os.getenv("RP_NAME", "Secure Chat Demo")
rp_env = os.getenv("RP_ID")  # If set, forces a specific RP ID (e.g., your tunnel host)

# In-memory challenge store (demo only)
challenges: Dict[str, Any] = {}


@app.on_event("startup")
async def ensure_indexes():
    await rooms.create_index("room", unique=True)
    await creds.create_index([("room", 1), ("username", 1)])
    await creds.create_index([("room", 1), ("username", 1), ("credential_id", 1)])


def extract_rp_id_from_request(request: Request) -> str:
    if rp_env:
        return rp_env
    origin = request.headers.get("origin") or ""
    host = ""
    if "://" in origin:
        host = origin.split("://", 1)[1].split("/", 1)[0]
    else:
        host = origin
    return host or "localhost"


def get_fido_server(request: Request) -> Fido2Server:
    rp_id = extract_rp_id_from_request(request)
    rp_entity = PublicKeyCredentialRpEntity(id=rp_id, name=rp_name)
    return Fido2Server(rp_entity)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_to_bytes(data: str) -> bytes:
    pad = "=" * ((4 - (len(data) % 4)) % 4)
    return base64.urlsafe_b64decode(data + pad)


class RegisterOptionsIn(BaseModel):
    room: str
    username: str
    mode: Optional[str] = None


class RegisterVerifyIn(BaseModel):
    room: str
    username: str
    rawId: str
    attestationObject: str
    clientDataJSON: str


class AssertOptionsIn(BaseModel):
    room: str
    username: str


class AssertVerifyIn(BaseModel):
    room: str
    username: str
    rawId: str
    authenticatorData: str
    clientDataJSON: str
    signature: str
    credentialId: str


async def find_room(room: str) -> Optional[dict]:
    return await rooms.find_one({"room": room})


async def upsert_room(room: str, admin: str):
    await rooms.update_one(
        {"room": room},
        {"$setOnInsert": {"room": room, "admin": admin, "locked": False, "created_at": datetime.now(timezone.utc)}},
        upsert=True,
    )


async def issue_token(room: str, username: str, is_admin: bool) -> str:
    payload = {
        "room": room,
        "user": username,
        "admin": is_admin,
        "exp": datetime.now(timezone.utc) + timedelta(hours=2),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


@app.post("/register/options")
async def register_options(body: RegisterOptionsIn, request: Request):
    room = body.room.strip()
    username = body.username.strip()
    if not room or not username:
        raise HTTPException(status_code=400, detail="room and username required")

    existing_room = await find_room(room)
    mode = (body.mode or "").lower()
    if mode == "create" and existing_room:
        raise HTTPException(status_code=409, detail="room already exists")
    if mode in {"join-new", "register-new"} and existing_room:
        existing_user = await creds.find_one({"room": room, "username": username})
        if existing_user:
            raise HTTPException(status_code=409, detail="username already exists")

    if not existing_room:
        await upsert_room(room, admin=username)
    room_doc = existing_room or await find_room(room)
    is_admin = room_doc.get("admin") == username if room_doc else True

    user = PublicKeyCredentialUserEntity(
        id=f"{room}:{username}".encode(),
        name=username,
        display_name=username,
    )
    fido_server = get_fido_server(request)
    creation_options, state = fido_server.register_begin(
        user,
        credentials=[],
        user_verification="preferred",
    )

    # Normalize options to a plain dict with base64url fields
    opts: Dict[str, Any] = {}
    if isinstance(creation_options, dict) and "publicKey" in creation_options:
        opts = dict(creation_options["publicKey"])
    else:
        try:
            opts = dict(creation_options["publicKey"])  # type: ignore[index]
        except Exception:
            try:
                opts = dict(getattr(creation_options, "public_key", {}) or {})
            except Exception:
                opts = {}
    rp_id = extract_rp_id_from_request(request)
    opts["rp"] = {"name": rp_name, "id": rp_id}
    opts["user"] = {
        "id": b64u(f"{room}:{username}".encode()),
        "name": username,
        "displayName": username,
    }
    params = opts.get("pubKeyCredParams") or [
        {"type": "public-key", "alg": -7},
        {"type": "public-key", "alg": -257},
    ]
    norm_params = []
    for p in params:
        if not isinstance(p, dict):
            continue
        t = p.get("type")
        if hasattr(t, "value"):
            t = t.value
        norm_params.append({"type": t or "public-key", "alg": p.get("alg")})
    opts["pubKeyCredParams"] = norm_params
    # Ensure challenge is present and base64url
    challenge_b64 = opts.get("challenge") if isinstance(opts.get("challenge"), str) else ""
    raw_chal = None
    if hasattr(creation_options, "public_key") and hasattr(creation_options.public_key, "challenge"):
        raw_chal = creation_options.public_key.challenge
    if raw_chal is None and isinstance(state, dict):
        raw_chal = state.get("challenge")
    if raw_chal is None and isinstance(state, (bytes, bytearray)):
        raw_chal = state
    if not challenge_b64:
        if isinstance(raw_chal, str):
            challenge_b64 = raw_chal
        elif isinstance(raw_chal, (bytes, bytearray)):
            challenge_b64 = b64u(raw_chal)
    opts["challenge"] = challenge_b64

    # Keep FIDO2 internal state for register_complete.
    challenges[f"{room}:{username}:reg"] = state
    return JSONResponse({"publicKey": opts, "admin": is_admin, "challenge": challenge_b64})


@app.post("/register/verify")
async def register_verify(body: RegisterVerifyIn, request: Request):
    key = f"{body.room}:{body.username}:reg"
    if key not in challenges:
        raise HTTPException(status_code=400, detail="challenge missing")
    chall = challenges.pop(key)
    att_obj = AttestationObject(b64u_to_bytes(body.attestationObject))
    client_data = CollectedClientData(b64u_to_bytes(body.clientDataJSON))
    raw_id = b64u_to_bytes(body.rawId)
    att_resp = AuthenticatorAttestationResponse(client_data=client_data, attestation_object=att_obj)
    reg_resp = RegistrationResponse(raw_id=raw_id, response=att_resp)
    fido_server = get_fido_server(request)
    auth_data = fido_server.register_complete(chall, reg_resp)

    await creds.update_one(
        {
            "room": body.room,
            "username": body.username,
            "credential_id": b64u(auth_data.credential_data.credential_id),
        },
        {
            "$set": {
                "room": body.room,
                "username": body.username,
                # Store CBOR-encoded COSE key bytes for future assertions.
                "public_key": b64u(cbor.encode(auth_data.credential_data.public_key)),
                # counter is the signature counter from authenticator data.
                "sign_count": getattr(auth_data, "counter", None),
                "created_at": datetime.now(timezone.utc),
            }
        },
        upsert=True,
    )
    room_doc = await find_room(body.room)
    is_admin = room_doc and room_doc.get("admin") == body.username
    token = await issue_token(body.room, body.username, is_admin=is_admin)
    return {"ok": True, "token": token, "admin": is_admin}


@app.post("/assert/options")
async def assert_options(body: AssertOptionsIn, request: Request):
    room = body.room.strip()
    username = body.username.strip()
    if not room or not username:
        raise HTTPException(status_code=400, detail="room and username required")
    cred_docs = await creds.find({"room": room, "username": username}).to_list(length=5)
    allow = [
        PublicKeyCredentialDescriptor(id=b64u_to_bytes(c["credential_id"]), type="public-key")
        for c in cred_docs
    ]
    fido_server = get_fido_server(request)
    request_options, state = fido_server.authenticate_begin(
        credentials=allow,
        user_verification="preferred",
    )

    # Normalize to dict
    opts: Dict[str, Any] = {}
    if isinstance(request_options, dict) and "publicKey" in request_options:
        opts = dict(request_options["publicKey"])
    else:
        try:
            opts = dict(request_options["public_key"])  # type: ignore[index]
        except Exception:
            opts = {}

    # Ensure challenge is b64url string
    challenge_b64 = opts.get("challenge") if isinstance(opts.get("challenge"), str) else ""
    raw_chal = None
    if hasattr(request_options, "public_key") and hasattr(request_options.public_key, "challenge"):
        raw_chal = request_options.public_key.challenge
    if raw_chal is None and isinstance(state, dict):
        raw_chal = state.get("challenge")
    if raw_chal is None and isinstance(state, (bytes, bytearray)):
        raw_chal = state
    if not challenge_b64:
        if isinstance(raw_chal, str):
            challenge_b64 = raw_chal
        elif isinstance(raw_chal, (bytes, bytearray)):
            challenge_b64 = b64u(raw_chal)
    opts["challenge"] = challenge_b64

    challenges[f"{room}:{username}:assert"] = state
    return {"publicKey": opts, "challenge": challenge_b64}


@app.post("/assert/verify")
async def assert_verify(body: AssertVerifyIn, request: Request):
    key = f"{body.room}:{body.username}:assert"
    if key not in challenges:
        raise HTTPException(status_code=400, detail="challenge missing")
    chall = challenges.pop(key)
    raw_id_bytes = b64u_to_bytes(body.rawId)
    cred_doc = await creds.find_one(
        {"room": body.room, "username": body.username, "credential_id": body.credentialId}
    )
    if not cred_doc:
        # Fallback: lookup by raw_id bytes match (handles padding/encoding differences).
        cred_docs = await creds.find({"room": body.room, "username": body.username}).to_list(length=5)
        for doc in cred_docs:
            try:
                if b64u_to_bytes(doc["credential_id"]) == raw_id_bytes:
                    cred_doc = doc
                    break
            except Exception:
                continue
    if not cred_doc:
        # As a last resort, match any credential in the room by id (helps when username differs across devices).
        cred_docs = await creds.find({"room": body.room}).to_list(length=20)
        for doc in cred_docs:
            try:
                if doc.get("credential_id") == body.credentialId or b64u_to_bytes(doc["credential_id"]) == raw_id_bytes:
                    cred_doc = doc
                    break
            except Exception:
                continue
    if not cred_doc:
        raise HTTPException(status_code=400, detail="credential not found")
    auth_data = AuthenticatorData(b64u_to_bytes(body.authenticatorData))
    client_data = CollectedClientData(b64u_to_bytes(body.clientDataJSON))
    signature = b64u_to_bytes(body.signature)
    raw_id = b64u_to_bytes(body.rawId)
    assertion_resp = AuthenticatorAssertionResponse(
        client_data=client_data,
        authenticator_data=auth_data,
        signature=signature,
        user_handle=None,
    )
    auth_resp = AuthenticationResponse(raw_id=raw_id, response=assertion_resp)
    fido_server = get_fido_server(request)
    stored_cose = cbor.decode(b64u_to_bytes(cred_doc["public_key"]))
    cose_key = CoseKey.parse(stored_cose)
    attested = AttestedCredentialData.create(b"\x00" * 16, raw_id, cose_key)

    # fido2 v1 expects AttestedCredentialData list
    fido_server.authenticate_complete(chall, [attested], auth_resp)
    await creds.update_one(
        {"_id": cred_doc["_id"]},
        {
            "$set": {
                "sign_count": getattr(auth_data, "counter", None),
                "updated_at": datetime.now(timezone.utc),
            }
        },
    )
    room_doc = await find_room(body.room)
    is_admin = room_doc and room_doc.get("admin") == body.username
    token = await issue_token(body.room, body.username, is_admin=is_admin)
    return {"ok": True, "token": token, "admin": is_admin}


class LockIn(BaseModel):
    room: str
    lock: bool
    token: str


def verify_admin(token: str) -> dict:
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return data
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="invalid token")


@app.post("/lock")
async def lock_room(body: LockIn):
    data = verify_admin(body.token)
    if not data.get("admin"):
        raise HTTPException(status_code=403, detail="admin only")
    if data.get("room") != body.room:
        raise HTTPException(status_code=400, detail="token room mismatch")
    await rooms.update_one({"room": body.room}, {"$set": {"locked": bool(body.lock)}}, upsert=True)
    return {"ok": True, "locked": bool(body.lock)}


@app.get("/health")
async def health():
    return {"ok": True, "time": time.time()}


@app.get("/room/{room}")
async def room_info(room: str):
    doc = await find_room(room)
    if not doc:
        return {"room": room, "locked": False}
    return {"room": room, "locked": bool(doc.get("locked")), "admin": doc.get("admin")}


@app.get("/room/{room}/user/{username}")
async def user_in_room(room: str, username: str):
    room_s = room.strip()
    user_s = username.strip()
    if not room_s or not user_s:
        raise HTTPException(status_code=400, detail="room and username required")
    doc = await creds.find_one({"room": room_s, "username": user_s})
    return {"room": room_s, "username": user_s, "exists": bool(doc)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api_server:app", host="0.0.0.0", port=int(os.getenv("API_PORT", "8001")), reload=True)
