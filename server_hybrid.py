"""
Hybrid relay that serves both raw TCP clients and WebSocket clients.
- TCP endpoint: newline-delimited ciphertext tokens (compatible with client.py)
- WebSocket endpoint: text frames carrying one ciphertext token each
- Persists ciphertext tokens per room so reconnecting peers can see recent history.
"""

import asyncio
import logging
import os
import time
import json
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional
from urllib.parse import parse_qs, urlparse

import jwt
from websockets.legacy.server import WebSocketServerProtocol, serve
from motor.motor_asyncio import AsyncIOMotorClient

HOST = os.getenv("CHAT_HOST", "0.0.0.0")
PORT = int(os.getenv("CHAT_PORT", "5555"))  # TCP
WS_HOST = os.getenv("CHAT_WS_HOST", HOST)
WS_PORT = int(os.getenv("CHAT_WS_PORT", "8765"))  # WebSocket

MAX_LINE_LEN = 8192
RATE_WINDOW = 2.0
RATE_MAX_LINES = 60
MONGO_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("CHAT_DB_NAME", "secure_chat")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
HISTORY_LIMIT = int(os.getenv("CHAT_HISTORY_LIMIT", "200"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("server.log", encoding="utf-8"),
    ],
)


@dataclass(eq=False)
class Session:
    kind: str  # "tcp" | "ws"
    addr: str
    send: Callable[[str], Awaitable[None]]
    close: Optional[Callable[[], Awaitable[None]]] = None
    room: Optional[str] = None
    username: Optional[str] = None
    window_start: float = field(default_factory=time.time)
    sent_in_window: int = 0


sessions: set[Session] = set()
sessions_lock = asyncio.Lock()
mongo_client = AsyncIOMotorClient(MONGO_URI)
db = mongo_client[DB_NAME]
rooms = db.rooms
messages = db.messages
creds = db.credentials


async def register_session(session: Session):
    async with sessions_lock:
        sessions.add(session)
    logging.info(f"[+] {session.kind.upper()} client connected: {session.addr}")


async def unregister_session(session: Session):
    async with sessions_lock:
        sessions.discard(session)
    logging.info(f"[-] {session.kind.upper()} client disconnected: {session.addr}")
    if session.close:
        try:
            await session.close()
        except Exception:
            pass


def _rate_limited(session: Session) -> bool:
    now = time.time()
    if now - session.window_start > RATE_WINDOW:
        session.window_start = now
        session.sent_in_window = 0
    session.sent_in_window += 1
    if session.sent_in_window > RATE_MAX_LINES:
        logging.warning(f"[RATE LIMIT] {session.addr} exceeded {RATE_MAX_LINES}/{RATE_WINDOW}s")
        return True
    return False


async def store_message(room: str, token: str):
    try:
        await messages.insert_one({"room": room, "token": token, "ts": time.time()})
        # Trim history to HISTORY_LIMIT oldest-first.
        extras = await messages.find({"room": room}).sort("ts", 1).skip(HISTORY_LIMIT).to_list(length=1000)
        if extras:
            await messages.delete_many({"_id": {"$in": [doc["_id"] for doc in extras]}})
    except Exception as e:
        logging.warning(f"[STORE] failed to persist message for {room}: {e}")


async def fetch_history(room: str):
    try:
        docs = await messages.find({"room": room}).sort("ts", -1).limit(HISTORY_LIMIT).to_list(length=HISTORY_LIMIT)
        docs.reverse()  # send oldest first
        return docs
    except Exception as e:
        logging.warning(f"[HISTORY] failed to fetch history for {room}: {e}")
        return []


async def broadcast_line(line: str, sender: Optional[Session], room: Optional[str] = None):
    async with sessions_lock:
        targets = list(sessions)
    for sess in targets:
        if sess is sender:
            continue
        if room is not None and sess.room not in {None, room}:
            continue
        try:
            await sess.send(line)
        except Exception as e:
            logging.warning(f"[DROP] failed send to {sess.addr}: {e}")
            await unregister_session(sess)


def _addr_str(peer) -> str:
    try:
        host, port = peer
        return f"{host}:{port}"
    except Exception:
        return str(peer)


async def broadcast_presence(room: Optional[str]):
    if not room:
        return
    try:
        cred_docs = await creds.find({"room": room}, {"username": 1}).to_list(length=500)
        registered = sorted({doc.get("username") for doc in cred_docs if doc.get("username")})
    except Exception as e:
        logging.warning(f"[PRESENCE] failed to fetch roster for {room}: {e}")
        registered = []

    async with sessions_lock:
        room_sessions = [s for s in sessions if s.room == room]
    online_users = {s.username for s in room_sessions if s.username}
    all_users = sorted(set(registered) | online_users)
    payload = json.dumps(
        {
            "type": "presence",
            "room": room,
            "users": [{"name": u, "online": u in online_users} for u in all_users],
        }
    )

    for sess in room_sessions:
        try:
            await sess.send(payload)
        except Exception as e:
            logging.warning(f"[PRESENCE] failed send to {sess.addr}: {e}")
            await unregister_session(sess)


async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    addr = _addr_str(peer)

    async def send_line(line: str):
        writer.write((line + "\n").encode("utf-8", errors="ignore"))
        await writer.drain()

    async def close():
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    session = Session(kind="tcp", addr=addr, send=send_line, close=close)
    await register_session(session)

    try:
        while True:
            data = await reader.readline()
            if not data:
                break
            line = data.decode("utf-8", errors="ignore").strip()
            if not line:
                continue
            if len(line) > MAX_LINE_LEN:
                logging.warning(f"[DROP len>{MAX_LINE_LEN}] from {addr}")
                continue
            if _rate_limited(session):
                continue
            await broadcast_line(line, sender=session, room=None)
    except Exception as e:
        logging.error(f"[!] TCP error with {addr}: {e}")
    finally:
        await unregister_session(session)


async def handle_ws(websocket: WebSocketServerProtocol, path: str):
    addr = _addr_str(websocket.remote_address)
    # Parse token from query: /?token=...
    parsed = urlparse(path or "")
    qs = parse_qs(parsed.query)
    token = qs.get("token", [None])[0]
    room = None
    username = None
    is_admin = False
    if not token:
        await websocket.close(code=4001, reason="missing token")
        return
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        room = data.get("room")
        username = data.get("user")
        is_admin = bool(data.get("admin"))
    except jwt.PyJWTError:
        await websocket.close(code=4002, reason="invalid token")
        return

    # Enforce lock: allow admins and previously-registered users to rejoin, block new users.
    room_doc = await rooms.find_one({"room": room}) if room else None
    room_locked = bool(room_doc.get("locked")) if room_doc else False
    user_exists = False
    if room_locked and room and username:
        try:
            user_exists = bool(await creds.find_one({"room": room, "username": username}))
        except Exception as e:
            logging.warning(f"[LOCK CHECK] failed user lookup for {room}/{username}: {e}")
    if room_locked and not (is_admin or user_exists):
        await websocket.close(code=4003, reason="room locked")
        return

    async def send_line(line: str):
        await websocket.send(line)

    async def close():
        try:
            await websocket.close()
        except Exception:
            pass

    session = Session(kind="ws", addr=f"{addr}|{room}|{username}", send=send_line, close=close, room=room, username=username)
    await register_session(session)

    # Send recent history for this room to the newly connected client.
    if room:
        history = await fetch_history(room)
        for doc in history:
            try:
                await send_line(doc["token"])
            except Exception:
                break
        await broadcast_presence(room)

    try:
        async for msg in websocket:
            if isinstance(msg, bytes):
                msg = msg.decode("utf-8", errors="ignore")
            line = msg.strip()
            if not line:
                continue
            if len(line) > MAX_LINE_LEN:
                logging.warning(f"[DROP len>{MAX_LINE_LEN}] from {addr}")
                continue
            if _rate_limited(session):
                continue
            if room:
                await store_message(room, line)
            await broadcast_line(line, sender=session, room=room)
    except Exception:
        pass
    except Exception as e:
        logging.error(f"[!] WS error with {addr}: {e}")
    finally:
        await unregister_session(session)
        if room:
            await broadcast_presence(room)


async def main():
    tcp_server = await asyncio.start_server(handle_tcp, HOST, PORT)
    ws_server = await serve(handle_ws, WS_HOST, WS_PORT)

    tcp_addrs = ", ".join(str(sock.getsockname()) for sock in tcp_server.sockets or [])
    logging.info(f"[+] TCP relay listening on {tcp_addrs}")
    logging.info(f"[+] WS relay listening on {WS_HOST}:{WS_PORT}")
    logging.info("[i] Messages are opaque tokens; server never sees plaintext.")

    try:
        await asyncio.Future()  # run forever
    except asyncio.CancelledError:
        pass
    finally:
        ws_server.close()
        await ws_server.wait_closed()
        tcp_server.close()
        await tcp_server.wait_closed()

        async with sessions_lock:
            leftovers = list(sessions)
        for sess in leftovers:
            await unregister_session(sess)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Shutting down…")
