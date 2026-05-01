#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(pwd)"
vertex_credentials_path="$workspace_dir/.credentials/vertex_api.json"
vertex_env_file="$HOME/.config/gh-aw-threat-detection/vertex-env.sh"

install_vertex_env_hook() {
  local shell_rc

  mkdir -p "$(dirname "$vertex_env_file")"
  cat > "$vertex_env_file" <<EOF
export GOOGLE_APPLICATION_CREDENTIALS="$vertex_credentials_path"
export CLAUDE_CODE_USE_VERTEX=1
export CLOUD_ML_REGION=us-east5
export ANTHROPIC_VERTEX_PROJECT_ID=github-next
EOF

  for shell_rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    touch "$shell_rc"
    if ! grep -Fq "$vertex_env_file" "$shell_rc"; then
      printf '\n[ -f "%s" ] && . "%s"\n' "$vertex_env_file" "$vertex_env_file" >> "$shell_rc"
    fi
  done
}

echo "Installing project dependencies..."
make deps

echo "Installing uv..."
curl -LsSf https://astral.sh/uv/install.sh | sh

if ! command -v gcloud >/dev/null 2>&1; then
  echo "Installing Google Cloud CLI for optional Vertex-backed models..."
  sudo apt-get update
  sudo apt-get install -y apt-transport-https ca-certificates gnupg curl
  curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
  echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list >/dev/null
  sudo apt-get update
  sudo apt-get install -y google-cloud-cli
fi

if [ -n "${VERTEX_API_JSON:-}" ]; then
  echo "Configuring Vertex credentials from VERTEX_API_JSON..."
  mkdir -p "$workspace_dir/.credentials"
  printf '%s' "$VERTEX_API_JSON" > "$vertex_credentials_path"
  install_vertex_env_hook
  echo "Vertex environment configured. Open a new shell to pick up exported variables."
else
  echo "VERTEX_API_JSON not set. Skipping Vertex credential configuration."
  echo "You can still use the devcontainer; set VERTEX_API_JSON later if you want Vertex-backed Claude support."
fi
