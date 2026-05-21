#!/usr/bin/env bash
set -euo pipefail

HOST="${CONJUR_HOST:-localhost}"
HTTP_PORT="${CONJUR_HTTP_PORT:-3000}"
HTTPS_PORT="${CONJUR_HTTPS_PORT:-3443}"
HEALTH_PATH="${CONJUR_HEALTH_PATH:-/health}"
DO_CHECK=0

usage() {
  cat <<'EOF'
Usage: dev/conjur_tls_urls.sh [--check] [--help]

Prints Conjur dev URLs for HTTP and HTTPS (TLS proxy).

Options:
  --check   Run curl checks against both URLs (uses -k for HTTPS)
  --help    Show this help message

Environment overrides:
  CONJUR_HOST         Default: localhost
  CONJUR_HTTP_PORT    Default: 3000
  CONJUR_HTTPS_PORT   Default: 3443
  CONJUR_HEALTH_PATH  Default: /health
EOF
}

for arg in "$@"; do
  case "$arg" in
    --check) DO_CHECK=1 ;;
    --help|-h) usage; exit 0 ;;
    *)
      echo "Unknown argument: $arg" >&2
      usage
      exit 2
      ;;
  esac
done

HTTP_URL="http://${HOST}:${HTTP_PORT}"
HTTPS_URL="https://${HOST}:${HTTPS_PORT}"

printf 'Conjur dev endpoints\n'
printf '  HTTP : %s\n' "$HTTP_URL"
printf '  HTTPS: %s\n' "$HTTPS_URL"
printf '\nSample commands\n'
printf '  curl -sS %s%s\n' "$HTTP_URL" "$HEALTH_PATH"
printf '  curl -k -sS %s%s\n' "$HTTPS_URL" "$HEALTH_PATH"

if [[ "$DO_CHECK" -eq 1 ]]; then
  if ! command -v curl >/dev/null 2>&1; then
    echo
    echo "curl not found; skipping checks." >&2
    exit 1
  fi

  echo
  echo "Checking HTTP health..."
  curl -sS "${HTTP_URL}${HEALTH_PATH}" || true

  echo
  echo "Checking HTTPS health (insecure cert trust with -k)..."
  curl -k -sS "${HTTPS_URL}${HEALTH_PATH}" || true
  echo
fi

