#!/usr/bin/env bash
# Start OWASP ZAP in headless daemon mode for bb-beast pipeline.
#
# ZAP will:
#   - Listen for API calls on port 8090
#   - Accept proxy connections on port 8090 (route tools through it for passive scan)
#   - Use API key: bb-beast-zap
#
# Usage:
#   ./scripts/start_zap.sh          # start daemon
#   ./scripts/start_zap.sh stop     # kill running daemon
#   ./scripts/start_zap.sh status   # check if running

set -euo pipefail

ZAP_PORT=8090
ZAP_API_KEY="bb-beast-zap"
ZAP_LOG="/tmp/zap-daemon.log"
ZAP_PID_FILE="/tmp/zap-daemon.pid"

# Locate ZAP installation
ZAP_CMD=""
for candidate in \
    "/Applications/OWASP ZAP.app/Contents/Java/zap.sh" \
    "/Applications/ZAP.app/Contents/Java/zap.sh" \
    "$(which zaproxy 2>/dev/null || true)" \
    "$(which zap.sh 2>/dev/null || true)"; do
    if [ -x "$candidate" ]; then
        ZAP_CMD="$candidate"
        break
    fi
done

if [ -z "$ZAP_CMD" ]; then
    echo "ERROR: OWASP ZAP not found."
    echo "Install with: brew install --cask owasp-zap"
    exit 1
fi

case "${1:-start}" in
    stop)
        if [ -f "$ZAP_PID_FILE" ]; then
            PID=$(cat "$ZAP_PID_FILE")
            kill "$PID" 2>/dev/null && echo "ZAP stopped (PID $PID)" || echo "ZAP was not running"
            rm -f "$ZAP_PID_FILE"
        else
            pkill -f "zap.sh" 2>/dev/null && echo "ZAP stopped" || echo "ZAP was not running"
        fi
        ;;
    status)
        if curl -s --max-time 3 "http://localhost:${ZAP_PORT}/JSON/core/view/version/" \
            -H "X-ZAP-API-Key: ${ZAP_API_KEY}" | grep -q version; then
            echo "ZAP is RUNNING on port ${ZAP_PORT}"
        else
            echo "ZAP is NOT running"
        fi
        ;;
    start|*)
        # Check if already running
        if curl -s --max-time 2 "http://localhost:${ZAP_PORT}/JSON/core/view/version/" \
            -H "X-ZAP-API-Key: ${ZAP_API_KEY}" 2>/dev/null | grep -q version; then
            echo "ZAP already running on port ${ZAP_PORT}"
            exit 0
        fi

        echo "Starting ZAP daemon on port ${ZAP_PORT}..."
        echo "API key: ${ZAP_API_KEY}"
        echo "Log: ${ZAP_LOG}"

        "$ZAP_CMD" \
            -daemon \
            -port "${ZAP_PORT}" \
            -config "api.key=${ZAP_API_KEY}" \
            -config "api.addrs.addr.name=.*" \
            -config "api.addrs.addr.regex=true" \
            -config "connection.timeoutInSecs=30" \
            -config "scanner.threadPerHost=5" \
            > "$ZAP_LOG" 2>&1 &

        echo $! > "$ZAP_PID_FILE"
        echo "ZAP starting (PID $!)..."

        # Wait for ZAP to be ready (up to 60s)
        for i in $(seq 1 30); do
            sleep 2
            if curl -s --max-time 2 "http://localhost:${ZAP_PORT}/JSON/core/view/version/" \
                -H "X-ZAP-API-Key: ${ZAP_API_KEY}" 2>/dev/null | grep -q version; then
                echo "ZAP ready on http://localhost:${ZAP_PORT}"
                echo "Proxy: http://127.0.0.1:${ZAP_PORT}"
                echo ""
                echo "To route tools through ZAP for passive scan:"
                echo "  export HTTP_PROXY=http://127.0.0.1:${ZAP_PORT}"
                echo "  export HTTPS_PROXY=http://127.0.0.1:${ZAP_PORT}"
                exit 0
            fi
            echo -n "."
        done

        echo ""
        echo "ERROR: ZAP did not start within 60s. Check log: ${ZAP_LOG}"
        exit 1
        ;;
esac
