#!/usr/bin/env bash

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${REPO_DIR}/.venv"

cd "${REPO_DIR}"

if [[ ! -d "${VENV_DIR}" ]]; then
  echo "Virtual environment not found at ${VENV_DIR}"
  echo "Create it first with: python3 -m venv .venv"
  exit 1
fi

source "${VENV_DIR}/bin/activate"

if [[ ! -f "${REPO_DIR}/.env" ]]; then
  echo "Warning: .env not found in ${REPO_DIR}"
  echo "You can create it with: cp .env.example .env"
fi

exec streamlit run src/sentinel_local/ui/app.py
