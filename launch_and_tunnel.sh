#!/usr/bin/env bash
set -euo pipefail

# Launch server_hybrid, local web server for web_client.html, GUI client, then
# tunnel both ports via cloudflared quick tunnels and emit QR codes via qrencode.
# Requires: cloudflared, qrencode, python (with deps installed), internet access.

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="${PROJECT_DIR}/venv/bin/python"
PY_BIN="${VENV_PY}"
if [[ ! -x "${PY_BIN}" ]]; then
  PY_BIN="$(command -v python3 || true)"
fi

CLOUDFLARED="$(command -v cloudflared || true)"
QRENCODE="$(command -v qrencode || true)"

if [[ -z "${CLOUDFLARED}" ]]; then
  echo "[ERR] cloudflared not found. Install it first." >&2
  exit 1
fi
if [[ -z "${QRENCODE}" ]]; then
  echo "[ERR] qrencode not found. Install it (e.g., brew install qrencode)." >&2
  exit 1
fi
if [[ -z "${PY_BIN}" ]]; then
  echo "[ERR] python3 not found." >&2
  exit 1
fi

STATIC_PORT=8000
WS_PORT=${CHAT_WS_PORT:-8765}
TCP_PORT=${CHAT_PORT:-5555}
API_PORT=${API_PORT:-8001}
ROOM_CODE="${ROOM_CODE:-orbit maple glass dial}"
NAME_HINT="${NAME_HINT:-}"

SERVER_LOG="${PROJECT_DIR}/server_hybrid.out.log"
HTTP_LOG="${PROJECT_DIR}/http_server.out.log"
CLIENT_LOG="${PROJECT_DIR}/client.out.log"
API_LOG="${PROJECT_DIR}/api_server.out.log"
STATIC_TUNNEL_LOG="${PROJECT_DIR}/cloudflare_static.log"
WS_TUNNEL_LOG="${PROJECT_DIR}/cloudflare_ws.log"
API_TUNNEL_LOG="${PROJECT_DIR}/cloudflare_api.log"
STATIC_QR="${PROJECT_DIR}/static_url.png"
WS_QR="${PROJECT_DIR}/ws_url.png"
API_QR="${PROJECT_DIR}/api_url.png"

cleanup() {
  [[ -n "${SERVER_PID:-}" ]] && kill ${SERVER_PID} 2>/dev/null || true
  [[ -n "${HTTP_PID:-}" ]] && kill ${HTTP_PID} 2>/dev/null || true
  [[ -n "${CLIENT_PID:-}" ]] && kill ${CLIENT_PID} 2>/dev/null || true
  [[ -n "${API_PID:-}" ]] && kill ${API_PID} 2>/dev/null || true
  [[ -n "${STATIC_TUNNEL_PID:-}" ]] && kill ${STATIC_TUNNEL_PID} 2>/dev/null || true
  [[ -n "${WS_TUNNEL_PID:-}" ]] && kill ${WS_TUNNEL_PID} 2>/dev/null || true
  [[ -n "${API_TUNNEL_PID:-}" ]] && kill ${API_TUNNEL_PID} 2>/dev/null || true
}
trap cleanup EXIT

# Start hybrid relay (TCP + WS)
"${PY_BIN}" "${PROJECT_DIR}/server_hybrid.py" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
echo "[INFO] server_hybrid started (PID ${SERVER_PID}), logs: ${SERVER_LOG}"

# Serve static web client
cd "${PROJECT_DIR}"
"${PY_BIN}" -m http.server ${STATIC_PORT} >"${HTTP_LOG}" 2>&1 &
HTTP_PID=$!
echo "[INFO] web_client served on http://localhost:${STATIC_PORT} (PID ${HTTP_PID}), logs: ${HTTP_LOG}"

## Start FastAPI (WebAuthn/JWT)
"${PY_BIN}" -m uvicorn api_server:app --host 0.0.0.0 --port ${API_PORT} >"${API_LOG}" 2>&1 &
API_PID=$!
echo "[INFO] api_server started on http://localhost:${API_PORT} (PID ${API_PID}), logs: ${API_LOG}"

## Launch desktop client (GUI). Comment out if headless.
#"${PY_BIN}" "${PROJECT_DIR}/client.py" >"${CLIENT_LOG}" 2>&1 &
#CLIENT_PID=$!
#echo "[INFO] client.py launched (PID ${CLIENT_PID}), logs: ${CLIENT_LOG}"

# Helper to start a tunnel and grab the trycloudflare URL.
start_tunnel() {
  local port="$1"; local logfile="$2"; local __pid_var="$3"
  "${CLOUDFLARED}" tunnel --url "http://localhost:${port}" >"${logfile}" 2>&1 &
  local pid=$!
  eval "${__pid_var}=${pid}"
  sleep 5
  local url
  url=$(grep -m1 -o 'https://[^ ]*trycloudflare.com' "${logfile}" || true)
  echo "${url}"
}

# Tunnel static (HTTP)
STATIC_URL=$(start_tunnel "${STATIC_PORT}" "${STATIC_TUNNEL_LOG}" STATIC_TUNNEL_PID)
if [[ -z "${STATIC_URL}" ]]; then
  echo "[ERR] Could not extract static tunnel URL. See ${STATIC_TUNNEL_LOG}" >&2
else
  echo "[INFO] Static tunnel: ${STATIC_URL}"
  STATIC_PAGE_URL="${STATIC_URL}/web_client.html"
  qrencode -o "${STATIC_QR}" "${STATIC_PAGE_URL}"
  echo "[INFO] Static QR saved to ${STATIC_QR}"
fi

# Tunnel WebSocket (WS listener)
WS_URL=$(start_tunnel "${WS_PORT}" "${WS_TUNNEL_LOG}" WS_TUNNEL_PID)
if [[ -z "${WS_URL}" ]]; then
  echo "[ERR] Could not extract WS tunnel URL. See ${WS_TUNNEL_LOG}" >&2
else
  echo "[INFO] WebSocket tunnel: ${WS_URL}"
  WS_HOST="$(echo "${WS_URL}" | sed 's#https://##;s#/$##')"
fi

# Tunnel API (FastAPI for WebAuthn/JWT)
API_URL=$(start_tunnel "${API_PORT}" "${API_TUNNEL_LOG}" API_TUNNEL_PID)
if [[ -z "${API_URL}" ]]; then
  echo "[ERR] Could not extract API tunnel URL. See ${API_TUNNEL_LOG}" >&2
else
  echo "[INFO] API tunnel: ${API_URL}"
  API_HOST="$(echo "${API_URL}" | sed 's#https://##;s#/$##')"
  API_QR_PAYLOAD="$(printf '{\"apiHost\":\"%s\",\"apiPort\":\"443\"}' \"${API_HOST}\")"
  qrencode -o "${API_QR}" "${API_QR_PAYLOAD}"
  echo "[INFO] API QR saved to ${API_QR}"
fi

# Generate join QR with full URLs (WS + API + room code)
if [[ -n "${WS_URL:-}" ]]; then
  EFFECTIVE_API_URL="${API_URL:-${WS_URL}}"
  WS_QR_PAYLOAD="$(
    ROOM_CODE="${ROOM_CODE}" WS_URL="${WS_URL}" API_URL="${EFFECTIVE_API_URL}" NAME_HINT="${NAME_HINT}" python - <<'PY'
import json, os
room = os.environ.get("ROOM_CODE", "")
ws_url = os.environ["WS_URL"].rstrip("/")
api_url = os.environ["API_URL"].rstrip("/")
name = os.environ.get("NAME_HINT", "")

def https_to_wss(url: str) -> str:
    return url.replace("https://", "wss://", 1)

payload = {
    "wsUrl": https_to_wss(ws_url),
    "apiUrl": api_url,
    "room": room,
}
if name:
    payload["name"] = name
print(json.dumps(payload, separators=(",", ":")))
PY
  )"
  qrencode -o "${WS_QR}" "${WS_QR_PAYLOAD}"
  echo "[INFO] Join QR saved to ${WS_QR} (ws+api+room '${ROOM_CODE}'${NAME_HINT:+, name '${NAME_HINT}'})"
fi

echo "" 
echo "[NEXT] Static page: ${STATIC_PAGE_URL:-${STATIC_URL}/web_client.html}"
echo "[NEXT] In the web UI, set Scheme=wss://, Host=${WS_HOST:-$(echo "${WS_URL}" | sed 's#https://##')}, Port=443"
echo "[NEXT] API base: ${API_URL:-http://localhost:${API_PORT}} (host ${API_HOST:-localhost}, port 443 if tunneled)"
echo "[INFO] Press Ctrl+C to stop tunnels/server/client."

# Keep the script alive so tunnels stay up.
wait
