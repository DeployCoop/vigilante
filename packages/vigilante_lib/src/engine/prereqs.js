import { execa } from 'execa';
import fsSync from 'node:fs';
import { commandExists } from '../utils/exec.js';

export const REQUIRED_TOOLS = [
  {
    id: 'docker',
    name: 'Docker Engine',
    command: 'docker',
    docUrl: 'https://docs.docker.com/get-docker/',
    installHint: 'Install Docker Engine and ensure the Docker daemon is running (e.g. systemctl start docker).'
  },
  {
    id: 'k3d',
    name: 'k3d (K3s in Docker)',
    command: 'k3d',
    docUrl: 'https://k3d.io/#installation',
    installHint: 'Install k3d via: curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash'
  },
  {
    id: 'k3s',
    name: 'k3s (Lightweight Kubernetes)',
    command: 'k3s',
    docUrl: 'https://k3s.io/',
    installHint: 'Install k3s via: curl -sfL https://get.k3s.io | sh -'
  },
  {
    id: 'mkcert',
    name: 'mkcert (Local CA & TLS)',
    command: 'mkcert',
    docUrl: 'https://github.com/FiloSottile/mkcert#installation',
    installHint: 'Install mkcert (e.g. brew install mkcert / apt install libnss3-tools && brew/apt install mkcert)'
  },
  {
    id: 'kubectl',
    name: 'kubectl (Kubernetes CLI)',
    command: 'kubectl',
    docUrl: 'https://kubernetes.io/docs/tasks/tools/',
    installHint: 'Install kubectl via package manager or official Kubernetes documentation.'
  },
  {
    id: 'helm',
    name: 'Helm 3 (Package Manager)',
    command: 'helm',
    docUrl: 'https://helm.sh/docs/intro/install/',
    installHint: 'Install Helm via: curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash'
  }
];

/**
 * Check if a single prerequisite tool is installed and operational
 */
export async function checkTool(tool) {
  const exists = await commandExists(tool.command);
  if (!exists) {
    return {
      ...tool,
      installed: false,
      ready: false,
      version: null,
      error: `Command '${tool.command}' not found in PATH.`
    };
  }

  try {
    let version = '';
    switch (tool.id) {
      case 'docker': {
        const { stdout: verOut } = await execa('docker', ['--version']);
        version = verOut.trim();

        // Verify Docker daemon is running
        try {
          await execa('docker', ['info']);
        } catch (daemonErr) {
          return {
            ...tool,
            installed: true,
            ready: false,
            version,
            error: 'Docker binary is installed, but the Docker daemon is not responding. Please start Docker.'
          };
        }
        break;
      }
      case 'k3d': {
        const { stdout } = await execa('k3d', ['version']);
        const firstLine = stdout.split('\n')[0].trim();
        version = firstLine.replace('k3d version ', 'v') || stdout.trim();
        break;
      }
      case 'mkcert': {
        const { stdout } = await execa('mkcert', ['-version']);
        version = stdout.trim();
        break;
      }
      case 'kubectl': {
        try {
          const { stdout } = await execa('kubectl', ['version', '--client', '--output=json']);
          const parsed = JSON.parse(stdout);
          version = parsed.clientVersion?.gitVersion || stdout.trim();
        } catch {
          const { stdout } = await execa('kubectl', ['version', '--client']);
          version = stdout.split('\n')[0].trim();
        }
        break;
      }
      case 'helm': {
        const { stdout } = await execa('helm', ['version', '--short']);
        version = stdout.trim();
        break;
      }
      case 'k3s': {
        try {
          const { stdout } = await execa('k3s', ['--version']);
          version = stdout.split('\n')[0].trim();
        } catch {
          if (fsSync.existsSync('/etc/rancher/k3s/k3s.yaml')) {
            version = 'k3s (kubeconfig found)';
          } else {
            throw new Error('k3s binary or /etc/rancher/k3s/k3s.yaml not found.');
          }
        }
        break;
      }
      default:
        version = 'installed';
    }

    return {
      ...tool,
      installed: true,
      ready: true,
      version,
      error: null
    };
  } catch (err) {
    return {
      ...tool,
      installed: true,
      ready: false,
      version: null,
      error: err.message
    };
  }
}

/**
 * Check all prerequisites with optional provider filtering (k3d vs k3s)
 * @param {Object} [options]
 * @param {string} [options.provider='k3d'] - 'k3d' | 'k3s' | 'all'
 */
export async function checkPrereqs(options = {}) {
  const provider = options.provider || 'k3d';
  const toolsToCheck = REQUIRED_TOOLS.filter(tool => {
    if (provider === 'k3s') {
      // For k3s provider, docker and k3d are not required
      return tool.id !== 'docker' && tool.id !== 'k3d';
    }
    if (provider === 'k3d') {
      // For k3d provider, k3s is not required
      return tool.id !== 'k3s';
    }
    return true;
  });

  const results = await Promise.all(toolsToCheck.map(tool => checkTool(tool)));
  const allReady = results.every(r => r.ready);
  const missing = results.filter(r => !r.ready);

  return {
    ready: allReady,
    tools: results,
    missing
  };
}
