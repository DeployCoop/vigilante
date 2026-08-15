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
      name: 'vigil-SOC',
      description: 'OpenSearch SIEM & Network Threat Ingestion Pipeline',
      category: 'siem',
      version: '1.0.0',
      defaultEnabled: true
    });
    this.namespace = 'vigil-soc';
    this.tlsSecretName = 'vigil-soc-tls';
  }

  /**
   * Install OpenSearch SIEM & Security Dashboards on k3d
   */
  async install({ domain = 'vigilante.local', certPath, keyPath, onLog = null, options = {} }) {
    if (onLog) onLog(`[vigil-SOC] Preparing namespace '${this.namespace}'...`);

    // 1. Ensure namespace exists
    await execa('kubectl', [
      'create', 'namespace', this.namespace,
      '--dry-run=client', '-o', 'yaml'
    ], { stdout: 'pipe' }).then(({ stdout }) => {
      return execa('kubectl', ['apply', '-f', '-'], { input: stdout });
    });

    // 2. Inject mkcert TLS secret for Ingress
    if (certPath && keyPath) {
      if (onLog) onLog(`[vigil-SOC] Injecting mkcert TLS secret '${this.tlsSecretName}' into namespace '${this.namespace}'...`);
      await applyK8sTlsSecret({
        namespace: this.namespace,
        secretName: this.tlsSecretName,
        certPath,
        keyPath
      });
    }

    // 3. Add and update OpenSearch Helm repository
    if (onLog) onLog('[vigil-SOC] Configuring OpenSearch Helm repository...');
    await execa('helm', ['repo', 'add', 'opensearch', 'https://opensearch-project.github.io/helm-charts/']);
    await execa('helm', ['repo', 'update', 'opensearch']);
    // 4. Install OpenSearch Single-Node Dev Cluster
    if (onLog) onLog('[vigil-SOC] Deploying OpenSearch SIEM core cluster...');
    const osDefaultValues = path.join(__dirname, 'values', 'opensearch.yaml');
    const osValuesArgs = await resolveChartValuesArgs({
      moduleId: this.id,
      chartName: 'opensearch',
      defaultValuesPath: osDefaultValues,
      customValuesPath: options?.customValuesPath || options?.values,
      customValuesDir: options?.customValuesDir || options?.valuesDir,
      domain,
      tlsSecretName: this.tlsSecretName,
      namespace: this.namespace,
      onLog
    });

    const osArgs = [
      'upgrade', '--install', 'opensearch', 'opensearch/opensearch',
      '--namespace', this.namespace,
      ...osValuesArgs
    ];
    await execStream('helm', osArgs, { onLog });

    // 5. Install OpenSearch Dashboards with Ingress and TLS
    if (onLog) onLog(`[vigil-SOC] Deploying OpenSearch Dashboards (Ingress: https://siem.${domain})...`);
    const dashboardsDefaultValues = path.join(__dirname, 'values', 'opensearch-dashboards.yaml');
    const dashboardsValuesArgs = await resolveChartValuesArgs({
      moduleId: this.id,
      chartName: 'opensearch-dashboards',
      defaultValuesPath: dashboardsDefaultValues,
      customValuesPath: options?.customValuesPath || options?.values,
      customValuesDir: options?.customValuesDir || options?.valuesDir,
      domain,
      tlsSecretName: this.tlsSecretName,
      namespace: this.namespace,
      onLog
    });

    const dashboardsArgs = [
      'upgrade', '--install', 'opensearch-dashboards', 'opensearch/opensearch-dashboards',
      '--namespace', this.namespace,
      ...dashboardsValuesArgs
    ];
    await execStream('helm', dashboardsArgs, { onLog });

    // 6. Apply Network Threat Detection Rules Manifest
    const rulesManifestPath = path.join(__dirname, 'manifests', 'network-threat-pipeline.yaml');
    try {
      await fs.access(rulesManifestPath);
      if (onLog) onLog('[vigil-SOC] Applying SIGMA network threat detection rules ConfigMap...');
      await execa('kubectl', ['apply', '-f', rulesManifestPath, '-n', this.namespace]);
    } catch {
      // Manifest application error is non-fatal
    }

    if (onLog) onLog(`[vigil-SOC] Successfully deployed vigil-SOC SIEM! Ingress available at https://siem.${domain}`);
  }

  /**
   * Uninstall vigil-SOC and delete its namespace
   */
  async uninstall({ onLog = null }) {
    if (onLog) onLog('[vigil-SOC] Uninstalling OpenSearch Dashboards...');
    try {
      await execa('helm', ['uninstall', 'opensearch-dashboards', '-n', this.namespace]);
    } catch {
      // Ignore if not present
    }

    if (onLog) onLog('[vigil-SOC] Uninstalling OpenSearch core cluster...');
    try {
      await execa('helm', ['uninstall', 'opensearch', '-n', this.namespace]);
    } catch {
      // Ignore if not present
    }

    if (onLog) onLog(`[vigil-SOC] Deleting namespace '${this.namespace}'...`);
    try {
      await execa('kubectl', ['delete', 'namespace', this.namespace, '--timeout=60s']);
    } catch {
      // Ignore if already deleted
    }
  }

  /**
   * Check status of vigil-SOC components
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
   * List endpoints for vigil-SOC
   */
  async getEndpoints({ domain = 'vigilante.local' }) {
    return [
      {
        name: 'OpenSearch SIEM Dashboard',
        url: `https://siem.${domain}`,
        description: 'Web console for security event monitoring, MITRE threat mapping & dashboards'
      },
      {
        name: 'OpenSearch REST API (Internal)',
        url: `http://opensearch-cluster-master.${this.namespace}.svc.cluster.local:9200`,
        description: 'SIEM indices and ECS threat event ingestion API'
      }
    ];
  }

  /**
   * Run the network threat simulator to inject test threat events
   */
  async simulateThreats({ onLog = null }) {
    const simulatorManifestPath = path.join(__dirname, 'manifests', 'threat-simulator.yaml');
    if (onLog) onLog('[vigil-SOC] Triggering network threat simulation batch (Port Scan, SSH Brute Force, DNS Tunneling)...');

    // Delete existing simulator job if present
    try {
      await execa('kubectl', ['delete', 'job', 'vigil-threat-injector', '-n', this.namespace, '--ignore-not-found=true']);
    } catch {
      // Ignore
    }

    // Apply simulation job
    await execa('kubectl', ['apply', '-f', simulatorManifestPath, '-n', this.namespace]);
    if (onLog) onLog('[vigil-SOC] Threat simulation Job scheduled! Logs will be visible in OpenSearch SIEM index: vigilante-network-events');
  }
}
