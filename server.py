# server.py — secure relay (line-framed)
# - Forwards newline-delimited ciphertext lines to all other clients
# - Never decrypts or inspects payloads
# - Optional demo logging: export CHAT_DEMO=1 to print token prefixes

import os
import socket
import threading
import logging
import time

HOST = os.getenv("CHAT_HOST", "0.0.0.0")
PORT = int(os.getenv("CHAT_PORT", "5555"))

# Security / robustness knobs
MAX_LINE_LEN = 8192          # drop anything longer (protect against floods)
DEMO_LOG = os.getenv("CHAT_DEMO") == "1"  # print 'TOK:' prefixes for class demos
RATE_WINDOW = 2.0            # seconds
RATE_MAX_LINES = 60          # max lines per window per client

# Logging (prints to console and server.log)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("server.log", encoding="utf-8")]
)

clients = set()
clients_lock = threading.Lock()


def broadcast_line(sender_sock: socket.socket, line: str):
    """Send a single newline-terminated line to all other clients."""
    data = (line + "\n").encode("utf-8", errors="ignore")
    with clients_lock:
        targets = list(clients)
    for cli in targets:
        if cli is sender_sock:
            continue
        try:
            cli.sendall(data)
        except OSError:
            # drop dead sockets
            with clients_lock:
                clients.discard(cli)


def handle_client(client_sock: socket.socket, addr):
    logging.info(f"[+] Client connected: {addr}")
    buf = ""  # text buffer for line framing
    # simple per-client rate limiter
    window_start = time.time()
    sent_in_window = 0

    try:
        while True:
            try:
                chunk = client_sock.recv(4096)
            except (ConnectionResetError, ConnectionAbortedError):
                break
            if not chunk:
                break

            # decode as utf-8 text; tokens are base64url so safe
            buf += chunk.decode("utf-8", errors="ignore")

            # process complete lines
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.strip()
                if not line:
                    continue

                # length guard
                if len(line) > MAX_LINE_LEN:
                    logging.warning(f"[DROP len>{MAX_LINE_LEN}] from {addr}")
                    continue

                # very simple rate-limit per client
                now = time.time()
                if now - window_start > RATE_WINDOW:
                    window_start = now
                    sent_in_window = 0
                sent_in_window += 1
                if sent_in_window > RATE_MAX_LINES:
                    logging.warning(f"[RATE LIMIT] {addr} exceeded {RATE_MAX_LINES}/{RATE_WINDOW}s")
                    continue

                # optional demo logging (prefix only; never plaintext)
                if DEMO_LOG:
                    prefix = line[:120]
                    if len(line) > 120:
                        prefix += "…"
                    logging.info(f"TOK: {prefix}")

                # relay to others
                broadcast_line(client_sock, line)

    except Exception as e:
        logging.error(f"[!] Error with {addr}: {e}")

    finally:
        logging.info(f"[-] Client disconnected: {addr}")
        with clients_lock:
            clients.discard(client_sock)
        try:
            client_sock.close()
        except Exception:
            pass


def start_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen()
    logging.info(f"[+] Secure relay listening on {HOST}:{PORT}")
    logging.info("[i] Set CHAT_DEMO=1 to log token prefixes for class demos")

    try:
        while True:
            client_sock, addr = server_sock.accept()
            with clients_lock:
                clients.add(client_sock)
            threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True).start()
    except KeyboardInterrupt:
        logging.info("Shutting down…")
    finally:
        with clients_lock:
            for c in list(clients):
                try:
                    c.close()
                except Exception:
                    pass
            clients.clear()
        try:
            server_sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    start_server()