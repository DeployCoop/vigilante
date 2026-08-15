import { execa } from 'execa';
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
 * Check all prerequisites
 */
export async function checkPrereqs() {
  const results = await Promise.all(REQUIRED_TOOLS.map(tool => checkTool(tool)));
  const allReady = results.every(r => r.ready);
  const missing = results.filter(r => !r.ready);

  return {
    ready: allReady,
    tools: results,
    missing
  };
}
