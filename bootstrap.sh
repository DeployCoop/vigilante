#!/usr/bin/env bash
set -eo pipefail

: "${DEFAULT_INSTALL_DIR:=${HOME}}"
: "${CLUSTER_PROVIDER:=k3d}"       # Options: 'k3d' or 'k3s'
: "${OLLAMA_MODEL:=qwen2.5:3b}"    # Or 'qwen2.5:1.5b' on machines with <= 8 GB RAM

echo "============================================================"
echo " Vigilante + Vigil-SOC Automated Debian Bootstrapper"
echo " Provider: ${CLUSTER_PROVIDER} | Model: ${OLLAMA_MODEL}"
echo "============================================================"

# Step 1: System packages & utilities
echo "--> [1/8] Installing base utilities and TLS prerequisites..."
sudo apt-get update
sudo apt-get install -y \
  ca-certificates \
  curl \
  gnupg \
  rsync \
  git \
  mkcert \
  libnss3-tools \
  nmap \
  jq

# Initialize local trust root for TLS certs
mkcert -install

# Step 2: Node.js 20 & pnpm
echo "--> [2/8] Setting up Node.js 20 & pnpm package manager..."
if ! command -v node >/dev/null 2>&1 || [ "$(node -v | cut -d. -f1 | tr -d 'v')" -lt 18 ]; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi

if ! command -v pnpm >/dev/null 2>&1; then
  sudo npm install -g pnpm
fi

# Step 3: Kubernetes CLI Tools (kubectl & helm)
echo "--> [3/8] Installing Kubernetes CLI tools (kubectl & helm)..."
if ! command -v kubectl >/dev/null 2>&1; then
  KUBECTL_ARCH="$(dpkg --print-architecture)"
  KUBECTL_VER="$(curl -L -s https://dl.k8s.io/release/stable.txt)"
  sudo curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VER}/bin/linux/${KUBECTL_ARCH}/kubectl" -o /usr/local/bin/kubectl
  sudo chmod +x /usr/local/bin/kubectl
fi

if ! command -v helm >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

# Step 4: Kernel Parameters (Required by OpenSearch & inotify watchers)
echo "--> [4/8] Configuring Linux kernel limits (vm.max_map_count for OpenSearch)..."
sudo sysctl -w vm.max_map_count=262144
sudo sysctl -w fs.inotify.max_user_watches=524288
sudo tee /etc/sysctl.d/99-vigilante.conf >/dev/null <<EOF
vm.max_map_count=262144
fs.inotify.max_user_watches=524288
EOF

# Step 5: Cluster Engine (k3d vs k3s)
echo "--> [5/8] Configuring Kubernetes engine (${CLUSTER_PROVIDER})..."
if [ "${CLUSTER_PROVIDER}" = "k3s" ]; then
  if ! command -v k3s >/dev/null 2>&1; then
    curl -sfL https://get.k3s.io | sh -
  fi
  if [ -f /etc/rancher/k3s/k3s.yaml ]; then
    sudo chmod 644 /etc/rancher/k3s/k3s.yaml || true
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
  fi
else
  # Install Docker CE if missing
  if ! command -v docker >/dev/null 2>&1; then
    echo "--> Installing Docker CE..."
    CONFLICTING_PKGS=$(dpkg --get-selections docker.io docker-compose docker-doc docker-buildx podman-docker containerd runc 2>/dev/null | cut -f1 || true)
    if [ -n "${CONFLICTING_PKGS}" ]; then
      sudo apt-get remove -y ${CONFLICTING_PKGS} || true
    fi

    sudo install -m 0755 -d /etc/apt/keyrings
    sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    sudo chmod a+r /etc/apt/keyrings/docker.asc

    CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
    ARCH="$(dpkg --print-architecture)"
    sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: ${CODENAME}
Components: stable
Architectures: ${ARCH}
Signed-By: /etc/apt/keyrings/docker.asc
EOF

    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi

  sudo systemctl enable --now docker
  sudo usermod -aG docker "${USER}" || true

  # Install latest k3d
  if ! command -v k3d >/dev/null 2>&1; then
    echo "--> Installing latest k3d..."
    curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash
  fi
fi

# Step 6: Ollama & LLM Model
echo "--> [6/8] Installing Ollama & pulling model (${OLLAMA_MODEL})..."
if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh
fi
sudo systemctl enable --now ollama || true
ollama pull "${OLLAMA_MODEL}" || echo "Warning: Ollama model pull deferred; ensure ollama service is active."

# Step 7: Local Ingress DNS Mapping
echo "--> [7/8] Configuring local domain names in /etc/hosts..."
if ! grep -q "vigil.vigilante.local" /etc/hosts; then
  echo "127.0.0.1 vigil.vigilante.local opensearch.vigilante.local vigilante.local" | sudo tee -a /etc/hosts
fi

# Step 8: Vigilante CLI & Repository
echo "--> [8/8] Setting up Vigilante workspace & CLI..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"

if [ -n "${SCRIPT_DIR}" ] && [ -f "${SCRIPT_DIR}/bin/vigilante.js" ]; then
  VIGILANTE_DIR="${SCRIPT_DIR}"
else
  mkdir -p "${DEFAULT_INSTALL_DIR}"
  cd "${DEFAULT_INSTALL_DIR}"
  if [ ! -d "vigilante" ]; then
    git clone --filter=blob:none https://github.com/DeployCoop/vigilante.git
  fi
  VIGILANTE_DIR="${DEFAULT_INSTALL_DIR}/vigilante"
fi

cd "${VIGILANTE_DIR}"
pnpm install

# Symlink global CLI binary
sudo ln -sf "${VIGILANTE_DIR}/bin/vigilante.js" /usr/local/bin/vigilante
sudo chmod +x "${VIGILANTE_DIR}/bin/vigilante.js"

echo "============================================================"
echo " Bootstrapping Vigil-SOC Cluster via Vigilante..."
echo "============================================================"
vigilante up --provider "${CLUSTER_PROVIDER}" -m opensearch,vigil-soc

echo ""
echo "✔ Vigil-SOC bootstrap completed successfully!"
echo "  - Ingress Endpoint: https://vigil.vigilante.local"
echo "  - OpenSearch:       https://opensearch.vigilante.local"
echo "  - Web Dashboard:    pnpm --filter @vigilante/web dev (http://localhost:3000)"
echo ""
