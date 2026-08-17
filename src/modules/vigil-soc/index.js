import { execa } from 'execa';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs/promises';
import { BaseModule } from '../base.js';
import { execStream } from '../../utils/exec.js';
import { applyK8sTlsSecret } from '../../engine/certs.js';
import { ensureNamespace } from '../../engine/k8s.js';
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
   * Install Vigil AI SOC Platform into target namespace
   */
  async install({
    domain = 'vigilante.local',
    certPath,
    keyPath,
    clusterName = 'vigilante-dev',
    namespace = null,
    onLog = null,
    options = {}
  }) {
    const targetNamespace = namespace || options?.namespace || this.namespace;
    const targetTlsSecret = `${targetNamespace}-tls`;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'vigil-soc';
    const releaseName = isStandardNs ? 'vigil' : `${targetNamespace}-vigil`;
    const ingressHost = isStandardNs ? `vigil.${domain}` : `${targetNamespace}-vigil.${domain}`;

    if (onLog) onLog(`[vigil-soc] Preparing namespace '${targetNamespace}' on cluster '${clusterName}'...`);

    // 1. Ensure namespace exists safely
    await ensureNamespace(targetNamespace, { onLog });

    // 2. Inject mkcert TLS secret for Ingress into target namespace
    if (certPath && keyPath) {
      if (onLog) onLog(`[vigil-soc] Injecting mkcert TLS secret '${targetTlsSecret}' into namespace '${targetNamespace}'...`);
      await applyK8sTlsSecret({
        namespace: targetNamespace,
        secretName: targetTlsSecret,
        certPath,
        keyPath
      });
    }

    // 3. Install Vigil AI-Native SOC Platform (Backend, Daemon, LLM Worker, Agent Worker, Postgres, Redis)
    if (onLog) onLog(`[vigil-soc] Deploying Vigil AI SOC '${releaseName}' (Ingress: https://${ingressHost})...`);
    const vigilChartPath = path.join(__dirname, 'charts', 'vigil');
    const vigilDefaultValues = path.join(__dirname, 'values', 'vigil.yaml');
    const vigilValuesArgs = await resolveChartValuesArgs({
      moduleId: this.id,
      chartName: 'vigil',
      defaultValuesPath: vigilDefaultValues,
      customValuesPath: options?.customValuesPath || options?.values,
      customValuesDir: options?.customValuesDir || options?.valuesDir,
      domain,
      tlsSecretName: targetTlsSecret,
      namespace: targetNamespace,
      clusterName,
      onLog
    });

    const vigilArgs = [
      'upgrade', '--install', releaseName, vigilChartPath,
      '--namespace', targetNamespace,
      ...vigilValuesArgs
    ];
    await execStream('helm', vigilArgs, { onLog });

    if (onLog) onLog(`[vigil-soc] Successfully deployed Vigil AI SOC in namespace '${targetNamespace}'! Ingress: https://${ingressHost}`);
  }

  /**
   * Uninstall vigil-soc and delete its namespace
   */
  async uninstall({ clusterName = 'vigilante-dev', namespace = null, onLog = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'vigil-soc';
    const releaseName = isStandardNs ? 'vigil' : `${targetNamespace}-vigil`;

    if (onLog) onLog(`[vigil-soc] Uninstalling Vigil AI SOC from namespace '${targetNamespace}'...`);
    try {
      await execa('helm', ['uninstall', releaseName, '-n', targetNamespace]);
    } catch {
      // Ignore if not present
    }

    if (targetNamespace !== 'default' && targetNamespace !== 'kube-system') {
      if (onLog) onLog(`[vigil-soc] Deleting namespace '${targetNamespace}'...`);
      try {
        await execa('kubectl', ['delete', 'namespace', targetNamespace, '--timeout=60s']);
      } catch {
        // Ignore if already deleted
      }
    }
  }

  /**
   * Check status of vigil-soc components in target namespace
   */
  async status({ domain = 'vigilante.local', clusterName = 'vigilante-dev', namespace = null } = {}) {
    const targetNamespace = namespace || this.namespace;

    try {
      const { stdout: podsJson } = await execa('kubectl', [
        'get', 'pods',
        '-n', targetNamespace,
        '--context', `k3d-${clusterName}`,
        '--request-timeout=3s',
        '-o', 'json'
      ]);
      const parsed = JSON.parse(podsJson);
      const pods = (parsed.items || []).map(p => ({
        name: p.metadata.name,
        namespace: p.metadata.namespace || targetNamespace,
        phase: p.status.phase,
        ready: p.status.containerStatuses?.every(c => c.ready) || false,
        restarts: p.status.containerStatuses?.reduce((acc, c) => acc + c.restartCount, 0) || 0
      }));

      const isInstalled = pods.length > 0;
      const allReady = isInstalled && pods.every(p => p.ready || p.phase === 'Succeeded');

      return {
        id: this.id,
        name: this.name,
        namespace: targetNamespace,
        installed: isInstalled,
        status: allReady ? 'Ready' : isInstalled ? 'Deploying / Degraded' : 'Not Installed',
        pods,
        endpoints: await this.getEndpoints({ domain, namespace: targetNamespace })
      };
    } catch {
      return {
        id: this.id,
        name: this.name,
        namespace: targetNamespace,
        installed: false,
        status: 'Not Installed',
        pods: [],
        endpoints: []
      };
    }
  }

  /**
   * List endpoints for vigil-soc in target namespace
   */
  async getEndpoints({ domain = 'vigilante.local', namespace = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'vigil-soc';
    const webUrl = isStandardNs ? `https://vigil.${domain}` : `https://${targetNamespace}-vigil.${domain}`;

    return [
      {
        name: `Vigil AI SOC Platform (${targetNamespace})`,
        url: webUrl,
        namespace: targetNamespace,
        description: 'Vigil autonomous AI SOC investigation & case management platform'
      },
      {
        name: `Vigil Backend API (Internal, ${targetNamespace})`,
        url: `http://vigil-backend.${targetNamespace}.svc.cluster.local:6987`,
        namespace: targetNamespace,
        description: 'Vigil REST API & real-time investigation endpoints'
      }
    ];
  }

  /**
   * Run network threat simulation against OpenSearch SIEM in target namespace
   */
  async simulateThreats({ clusterName = 'vigilante-dev', namespace = null, onLog = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const { globalModuleRegistry } = await import('../registry.js');
    const osModule = globalModuleRegistry.get('opensearch');
    if (osModule && typeof osModule.simulateThreats === 'function') {
      return osModule.simulateThreats({ clusterName, namespace: targetNamespace, onLog });
    }
    throw new Error('OpenSearch module is required to simulate and ingest threat events.');
  }
}
