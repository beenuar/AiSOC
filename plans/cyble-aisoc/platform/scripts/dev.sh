#!/usr/bin/env bash
# Run backend + frontend concurrently with cleanup on exit.
set -e

cd "$(dirname "$0")/.."
BACKEND_PORT=${BACKEND_PORT:-8478}
FRONTEND_PORT=${FRONTEND_PORT:-8479}

# Cleanup on Ctrl-C
cleanup() {
  echo ""
  echo "▶ Stopping services..."
  if [[ -n "${BACKEND_PID:-}" ]]; then kill "$BACKEND_PID" 2>/dev/null || true; fi
  if [[ -n "${FRONTEND_PID:-}" ]]; then kill "$FRONTEND_PID" 2>/dev/null || true; fi
  wait 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

# Backend
(
  cd backend
  source .venv/bin/activate
  exec uvicorn app.main:app --host 0.0.0.0 --port "$BACKEND_PORT" --log-level warning
) &
BACKEND_PID=$!

# Frontend
(
  cd frontend
  exec python3 -m http.server "$FRONTEND_PORT" --bind 0.0.0.0 > /dev/null 2>&1
) &
FRONTEND_PID=$!

# Wait for services
sleep 1.5

cat <<EOF

  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║   🛡  Cyble AiSOC running                                  ║
  ║                                                           ║
  ║   Analyst Console:  http://localhost:$FRONTEND_PORT             ║
  ║   API:              http://localhost:$BACKEND_PORT              ║
  ║   API docs:         http://localhost:$BACKEND_PORT/docs         ║
  ║                                                           ║
  ║   In another terminal:                                    ║
  ║     make demo   — auto-run agents on 10 cases             ║
  ║     make stop   — stop everything                         ║
  ║                                                           ║
  ║   Ctrl-C to stop                                          ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝

EOF

# Open in browser if possible
( command -v open >/dev/null && open "http://localhost:$FRONTEND_PORT" ) 2>/dev/null || true

# Block until either child exits
wait -n "$BACKEND_PID" "$FRONTEND_PID"
cleanup
