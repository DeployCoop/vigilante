import { execa } from 'execa';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs/promises';
import { BaseModule } from '../base.js';
import { execStream } from '../../utils/exec.js';
import { applyK8sTlsSecret } from '../../engine/certs.js';
import { resolveChartValuesArgs } from '../../engine/helm.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class VigilSOCModule extends BaseModule {
  constructor() {
    super({
      id: 'vigil-soc',
      name: 'Vigil AI SOC',
      description: 'Vigil Autonomous AI-Native Security Operations Center Platform',
      category: 'soc',
      version: '1.0.0',
      dependencies: ['opensearch'],
      defaultEnabled: true
    });
    this.namespace = 'vigil-soc';
    this.tlsSecretName = 'vigil-soc-tls';
  }

  /**
   * Install Vigil AI SOC Platform on k3d
   */
  async install({ domain = 'vigilante.local', certPath, keyPath, onLog = null, options = {} }) {
    if (onLog) onLog(`[vigil-soc] Preparing namespace '${this.namespace}'...`);

    // 1. Ensure namespace exists
    await execa('kubectl', [
      'create', 'namespace', this.namespace,
      '--dry-run=client', '-o', 'yaml'
    ], { stdout: 'pipe' }).then(({ stdout }) => {
      return execa('kubectl', ['apply', '-f', '-'], { input: stdout });
    });

    // 2. Inject mkcert TLS secret for Ingress
    if (certPath && keyPath) {
      if (onLog) onLog(`[vigil-soc] Injecting mkcert TLS secret '${this.tlsSecretName}' into namespace '${this.namespace}'...`);
      await applyK8sTlsSecret({
        namespace: this.namespace,
        secretName: this.tlsSecretName,
        certPath,
        keyPath
      });
    }

    // 3. Install Vigil AI-Native SOC Platform (Backend, Daemon, LLM Worker, Agent Worker, Postgres, Redis)
    if (onLog) onLog(`[vigil-soc] Deploying Vigil AI SOC Platform (Ingress: https://vigil.${domain})...`);
    const vigilChartPath = path.join(__dirname, 'charts', 'vigil');
    const vigilDefaultValues = path.join(__dirname, 'values', 'vigil.yaml');
    const vigilValuesArgs = await resolveChartValuesArgs({
      moduleId: this.id,
      chartName: 'vigil',
      defaultValuesPath: vigilDefaultValues,
      customValuesPath: options?.customValuesPath || options?.values,
      customValuesDir: options?.customValuesDir || options?.valuesDir,
      domain,
      tlsSecretName: this.tlsSecretName,
      namespace: this.namespace,
      onLog
    });

    const vigilArgs = [
      'upgrade', '--install', 'vigil', vigilChartPath,
      '--namespace', this.namespace,
      ...vigilValuesArgs
    ];
    await execStream('helm', vigilArgs, { onLog });

    if (onLog) onLog(`[vigil-soc] Successfully deployed Vigil AI SOC! Ingress available at https://vigil.${domain}`);
  }

  /**
   * Uninstall vigil-soc and delete its namespace
   */
  async uninstall({ onLog = null }) {
    if (onLog) onLog('[vigil-soc] Uninstalling Vigil AI SOC Platform...');
    try {
      await execa('helm', ['uninstall', 'vigil', '-n', this.namespace]);
    } catch {
      // Ignore if not present
    }

    if (onLog) onLog(`[vigil-soc] Deleting namespace '${this.namespace}'...`);
    try {
      await execa('kubectl', ['delete', 'namespace', this.namespace, '--timeout=60s']);
    } catch {
      // Ignore if already deleted
    }
  }

  /**
   * Check status of vigil-soc components
   */
  async status({ domain = 'vigilante.local', clusterName = 'vigilante-dev' } = {}) {
    try {
      const { stdout: podsJson } = await execa('kubectl', [
        'get', 'pods',
        '-n', this.namespace,
        '--context', `k3d-${clusterName}`,
        '--request-timeout=3s',
        '-o', 'json'
      ]);
      const parsed = JSON.parse(podsJson);
      const pods = (parsed.items || []).map(p => ({
        name: p.metadata.name,
        phase: p.status.phase,
        ready: p.status.containerStatuses?.every(c => c.ready) || false,
        restarts: p.status.containerStatuses?.reduce((acc, c) => acc + c.restartCount, 0) || 0
      }));

      const isInstalled = pods.length > 0;
      const allReady = isInstalled && pods.every(p => p.ready || p.phase === 'Succeeded');

      return {
        id: this.id,
        name: this.name,
        installed: isInstalled,
        status: allReady ? 'Ready' : isInstalled ? 'Deploying / Degraded' : 'Not Installed',
        pods,
        endpoints: await this.getEndpoints({ domain })
      };
    } catch {
      return {
        id: this.id,
        name: this.name,
        installed: false,
        status: 'Not Installed',
        pods: [],
        endpoints: []
      };
    }
  }

  /**
   * List endpoints for vigil-soc
   */
  async getEndpoints({ domain = 'vigilante.local' }) {
    return [
      {
        name: 'Vigil AI SOC Platform',
        url: `https://vigil.${domain}`,
        description: 'Vigil autonomous AI SOC investigation & case management platform'
      },
      {
        name: 'Vigil Backend API (Internal)',
        url: `http://vigil-backend.${this.namespace}.svc.cluster.local:6987`,
        description: 'Vigil REST API & real-time investigation endpoints'
      }
    ];
  }
}
