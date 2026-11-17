#!/bin/bash
# Store one imap-mcp secret as a file (mode 600) in IMAP_MCP_SECRETS
# (default ~/.config/imap-mcp/secrets). Run it YOURSELF in a terminal: the value is typed at a
# hidden prompt and is never echoed, logged, or shown to Claude.
#   ./set-secret.sh icloud-app-password      # paste the Apple app-specific password
#   ./set-secret.sh github-client-secret     # GitHub OAuth App client secret (remote mode)
#   ./set-secret.sh --generate jwt-key       # random signing key (remote mode)
set -euo pipefail
GEN=0; [ "${1:-}" = "--generate" ] && { GEN=1; shift; }
N="${1:?usage: set-secret.sh [--generate] <name>}"
[[ "$N" =~ ^[a-z0-9-]+$ ]] || { echo "name must be [a-z0-9-]" >&2; exit 1; }
D="${IMAP_MCP_SECRETS:-$HOME/.config/imap-mcp/secrets}"
mkdir -p "$D" && chmod 700 "$D"
if [ "$GEN" = 1 ]; then
  V=$(openssl rand -hex 32)
else
  read -rs -p "value for $N: " V; echo
fi
[ -n "$V" ] || { echo "empty — nothing written" >&2; exit 1; }
umask 077; printf '%s' "$V" > "$D/$N.tmp" && mv "$D/$N.tmp" "$D/$N"; unset V
echo "stored $D/$N"
