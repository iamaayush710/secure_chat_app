# secure_chat_app

End-to-end encrypted chat.

## Python clients (desktop)

1. Install deps: `pip install -r requirements.txt`
2. Run the relay (TCP only): `python server.py`
3. Launch GUI client (Tk desktop): `python client.py`

## Hybrid relay (TCP + WebSocket)

To let browsers join the same rooms, start the hybrid relay:

```bash
python server_hybrid.py
# TCP: CHAT_HOST/CHAT_PORT (default 0.0.0.0:5555) for client.py
# WS : CHAT_WS_HOST/CHAT_WS_PORT (default 0.0.0.0:8765) for web clients
```

The relay forwards opaque ciphertext tokens only; it never sees plaintext.

## Web client

1. Serve `web_client.html` locally (e.g., `python -m http.server 8000` in this folder) or open it directly in the browser.
2. Enter your relay host, scheme (`ws://` or `wss://`), WS port (default `8765`), room code, and display name.
3. Connect. The browser client derives the same scrypt → AES-256-GCM key as the desktop client and exchanges ciphertext tokens over WebSocket.

### Exposing to the internet

- Port-forward both the TCP port (if desktop clients connect) and the WebSocket port to your machine, or use a tunnel (e.g., reverse proxy) that supports WebSocket upgrades.
- Prefer HTTPS/WSS via a reverse proxy (nginx/Caddy/Cloudflare Tunnel) so browsers allow the connection and to avoid leaking tokens on the wire.
- Verify the key fingerprint shown in the UI matches across participants.
