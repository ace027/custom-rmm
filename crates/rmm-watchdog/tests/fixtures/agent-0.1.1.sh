#!/bin/sh
# Fixture agent 0.1.1: writes a healthy signal, then idles.
if [ "$1" = --version ]; then echo "rmm-agent 0.1.1"; exit 0; fi
d="$RMM_AGENT_STATE_DIR"
printf '{"version":"0.1.1","pid":%s,"ts":0}\n' "$$" > "$d/health.json.tmp"
mv "$d/health.json.tmp" "$d/health.json"
exec sleep 600
