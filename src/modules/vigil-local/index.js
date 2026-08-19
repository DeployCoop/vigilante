import { execa } from 'execa';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs/promises';
import { BaseModule } from '../base.js';
import { execStream } from '../../utils/exec.js';
import { applyK8sTlsSecret } from '../../engine/certs.js';
import { ensureNamespace } from '../../engine/k8s.js';
import { resolveChartValuesArgs } from '../../engine/helm.js';
import { loadConfig } from '../../engine/config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const DEFAULT_VIGIL_LOCAL_CHART_PATH = '/home/djehauti/git/vigil/infra/helm/vigil';

export class VigilLocalModule extends BaseModule {
  constructor() {
    super({
      id: 'vigil-local',
      name: 'Vigil AI SOC (Local Source / Dev)',
      description: 'Vigil Autonomous AI-Native SOC Platform installed directly from local checkout at /home/djehauti/git/vigil/infra/helm/vigil',
      category: 'soc',
      version: '0.5.0',
      dependencies: ['opensearch'],
      defaultEnabled: false
    });
    this.namespace = 'vigil-local';
    this.tlsSecretName = 'vigil-local-tls';
  }

  /**
   * Resolve and validate the path to the local Vigil Helm chart
   * @param {Object} [options]
   * @returns {Promise<string>}
   */
  async resolveLocalChartPath(options = {}) {
    const cfg = loadConfig();
    const candidatePath = options?.chartPath ||
      process.env.VIGIL_LOCAL_CHART_PATH ||
      cfg?.modules?.vigilLocal?.chartPath ||
      cfg?.vigilLocalChartPath ||
      DEFAULT_VIGIL_LOCAL_CHART_PATH;

    const resolved = path.resolve(candidatePath);
    const chartYaml = path.join(resolved, 'Chart.yaml');

    try {
      await fs.access(chartYaml);
      return resolved;
    } catch (err) {
      throw new Error(
        `Local Vigil Helm chart not found at '${resolved}'. ` +
        `Please ensure the repository is checked out or configure 'vigilLocalChartPath' in config.yaml.`
      );
    }
  }

  /**
   * Install Vigil AI SOC Platform from local checkout into target namespace
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
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'vigil-local';
    const releaseName = isStandardNs ? 'vigil-local' : `${targetNamespace}-vigil-local`;
    const ingressHost = isStandardNs ? `vigil-local.${domain}` : `${targetNamespace}-vigil-local.${domain}`;

    // 1. Resolve local chart path
    const vigilChartPath = await this.resolveLocalChartPath(options);
    if (onLog) {
      onLog(`[vigil-local] Resolved local Vigil Helm chart: ${vigilChartPath}`);
      onLog(`[vigil-local] Preparing namespace '${targetNamespace}' on cluster '${clusterName}'...`);
    }

    // 2. Ensure namespace exists safely
    await ensureNamespace(targetNamespace, { onLog });

    // 3. Inject mkcert TLS secret for Ingress into target namespace
    if (certPath && keyPath) {
      if (onLog) onLog(`[vigil-local] Injecting mkcert TLS secret '${targetTlsSecret}' into namespace '${targetNamespace}'...`);
      await applyK8sTlsSecret({
        namespace: targetNamespace,
        secretName: targetTlsSecret,
        certPath,
        keyPath
      });
    }

    // 4. Resolve default and custom Helm values
    if (onLog) onLog(`[vigil-local] Deploying local Vigil AI SOC '${releaseName}' (Ingress: https://${ingressHost})...`);
    const defaultValuesPath = path.join(__dirname, 'values', 'vigil.yaml');
    const vigilValuesArgs = await resolveChartValuesArgs({
      moduleId: this.id,
      chartName: 'vigil',
      defaultValuesPath,
      customValuesPath: options?.customValuesPath || options?.values,
      customValuesDir: options?.customValuesDir || options?.valuesDir,
      domain,
      tlsSecretName: targetTlsSecret,
      namespace: targetNamespace,
      clusterName,
      onLog
    });

    // 5. Execute Helm install / upgrade from local chart directory
    const vigilArgs = [
      'upgrade', '--install', releaseName, vigilChartPath,
      '--namespace', targetNamespace,
      ...vigilValuesArgs
    ];
    await execStream('helm', vigilArgs, { onLog });

    if (onLog) onLog(`[vigil-local] Successfully deployed Vigil AI SOC (Local) in namespace '${targetNamespace}'! Ingress: https://${ingressHost}`);
  }

  /**
   * Uninstall vigil-local and delete its namespace
   */
  async uninstall({ clusterName = 'vigilante-dev', namespace = null, onLog = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'vigil-local';
    const releaseName = isStandardNs ? 'vigil-local' : `${targetNamespace}-vigil-local`;

    if (onLog) onLog(`[vigil-local] Uninstalling Vigil AI SOC (Local) from namespace '${targetNamespace}'...`);
    try {
      await execa('helm', ['uninstall', releaseName, '-n', targetNamespace]);
    } catch {
      // Ignore if not present
    }

    if (targetNamespace !== 'default' && targetNamespace !== 'kube-system') {
      if (onLog) onLog(`[vigil-local] Deleting namespace '${targetNamespace}'...`);
      try {
        await execa('kubectl', ['delete', 'namespace', targetNamespace, '--timeout=60s']);
      } catch {
        // Ignore if already deleted
      }
    }
  }

  /**
   * Check status of vigil-local components in target namespace
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
   * List endpoints for vigil-local in target namespace
   */
  async getEndpoints({ domain = 'vigilante.local', namespace = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'vigil-local';
    const webUrl = isStandardNs ? `https://vigil-local.${domain}` : `https://${targetNamespace}-vigil-local.${domain}`;

    return [
      {
        name: `Vigil AI SOC Platform (Local, ${targetNamespace})`,
        url: webUrl,
        namespace: targetNamespace,
        description: 'Vigil autonomous AI SOC investigation platform running from local repository checkout'
      },
      {
        name: `Vigil Backend API (Local, ${targetNamespace})`,
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
