#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example."
fi

mkdir -p data workspaces codex-home
if [[ "$(id -u)" -eq 0 ]]; then
  chown -R 1000:1000 data workspaces codex-home 2>/dev/null || true
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo chown -R 1000:1000 data workspaces codex-home 2>/dev/null || true
fi

echo "Next:"
echo "  1. Fill ARK_API_KEY and ARK_MODEL in .env"
echo "  2. Run: docker compose up --build"
