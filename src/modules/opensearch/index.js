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

export class OpenSearchModule extends BaseModule {
  constructor() {
    super({
      id: 'opensearch',
      name: 'OpenSearch SIEM',
      description: 'OpenSearch Analytics Cluster, Security Dashboards & Threat Ingestion Pipeline',
      category: 'siem',
      version: '1.0.0',
      dependencies: [],
      defaultEnabled: true
    });
  }

  /**
   * Install OpenSearch SIEM & Security Dashboards into target namespace
   */
  async install({
    domain = 'vigilante.local',
    certPath = null,
    keyPath = null,
    clusterName = 'vigilante-dev',
    namespace = 'default',
    onLog = null,
    options = {}
  }) {
    const targetNamespace = namespace || options?.namespace || this.namespace;
    const targetTlsSecret = `${targetNamespace}-tls`;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'opensearch';
    const osRelease = isStandardNs ? 'opensearch' : `${targetNamespace}-opensearch`;
    const dashboardsRelease = isStandardNs ? 'opensearch-dashboards' : `${targetNamespace}-opensearch-dashboards`;

    if (onLog) onLog(`[opensearch] Preparing namespace '${targetNamespace}' on cluster '${clusterName}'...`);

    // 1. Ensure namespace exists safely
    await ensureNamespace(targetNamespace, { onLog });

    // 2. Inject mkcert TLS secret for Ingress into target namespace
    if (certPath && keyPath) {
      if (onLog) onLog(`[opensearch] Injecting mkcert TLS secret '${targetTlsSecret}' into namespace '${targetNamespace}'...`);
      await applyK8sTlsSecret({
        namespace: targetNamespace,
        secretName: targetTlsSecret,
        certPath,
        keyPath
      });
    }

    // 3. Add and update OpenSearch Helm repository
    if (onLog) onLog('[opensearch] Configuring OpenSearch Helm repository...');
    await execa('helm', ['repo', 'add', 'opensearch', 'https://opensearch-project.github.io/helm-charts/']);
    await execa('helm', ['repo', 'update', 'opensearch']);

    // 4. Install OpenSearch Single-Node Dev Cluster
    if (onLog) onLog(`[opensearch] Deploying OpenSearch cluster '${osRelease}' in namespace '${targetNamespace}'...`);
    const osDefaultValues = path.join(__dirname, 'values', 'opensearch.yaml');
    const osValuesArgs = await resolveChartValuesArgs({
      moduleId: this.id,
      chartName: 'opensearch',
      defaultValuesPath: osDefaultValues,
      customValuesPath: options?.customValuesPath || options?.values,
      customValuesDir: options?.customValuesDir || options?.valuesDir,
      domain,
      tlsSecretName: targetTlsSecret,
      namespace: targetNamespace,
      clusterName,
      onLog
    });

    const osArgs = [
      'upgrade', '--install', osRelease, 'opensearch/opensearch',
      '--namespace', targetNamespace,
      ...osValuesArgs
    ];
    await execStream('helm', osArgs, { onLog });

    // 5. Install OpenSearch Dashboards with Ingress and TLS
    const dashboardHost = isStandardNs ? `siem.${domain}` : `${targetNamespace}-siem.${domain}`;
    if (onLog) onLog(`[opensearch] Deploying Dashboards '${dashboardsRelease}' (Ingress: https://${dashboardHost})...`);
    const dashboardsDefaultValues = path.join(__dirname, 'values', 'opensearch-dashboards.yaml');
    const dashboardsValuesArgs = await resolveChartValuesArgs({
      moduleId: this.id,
      chartName: 'opensearch-dashboards',
      defaultValuesPath: dashboardsDefaultValues,
      customValuesPath: options?.customValuesPath || options?.values,
      customValuesDir: options?.customValuesDir || options?.valuesDir,
      domain,
      tlsSecretName: targetTlsSecret,
      namespace: targetNamespace,
      clusterName,
      onLog
    });

    const dashboardsArgs = [
      'upgrade', '--install', dashboardsRelease, 'opensearch/opensearch-dashboards',
      '--namespace', targetNamespace,
      ...dashboardsValuesArgs
    ];
    await execStream('helm', dashboardsArgs, { onLog });

    // 6. Apply Network Threat Detection Rules Manifest
    const rulesManifestPath = path.join(__dirname, 'manifests', 'network-threat-pipeline.yaml');
    try {
      await fs.access(rulesManifestPath);
      if (onLog) onLog(`[opensearch] Applying SIGMA network threat detection rules ConfigMap to '${targetNamespace}'...`);
      await execa('kubectl', ['apply', '-f', rulesManifestPath, '-n', targetNamespace]);
    } catch {
      // Manifest application error is non-fatal
    }

    if (onLog) onLog(`[opensearch] Successfully deployed OpenSearch SIEM in namespace '${targetNamespace}'! Ingress: https://${dashboardHost}`);
  }

  /**
   * Uninstall OpenSearch and delete its namespace
   */
  async uninstall({ clusterName = 'vigilante-dev', namespace = null, onLog = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'opensearch';
    const osRelease = isStandardNs ? 'opensearch' : `${targetNamespace}-opensearch`;
    const dashboardsRelease = isStandardNs ? 'opensearch-dashboards' : `${targetNamespace}-opensearch-dashboards`;

    if (onLog) onLog(`[opensearch] Uninstalling OpenSearch Dashboards from namespace '${targetNamespace}'...`);
    try {
      await execa('helm', ['uninstall', dashboardsRelease, '-n', targetNamespace]);
    } catch {
      // Ignore if not present
    }

    if (onLog) onLog(`[opensearch] Uninstalling OpenSearch core cluster from namespace '${targetNamespace}'...`);
    try {
      await execa('helm', ['uninstall', osRelease, '-n', targetNamespace]);
    } catch {
      // Ignore if not present
    }

    if (targetNamespace !== 'default' && targetNamespace !== 'kube-system') {
      if (onLog) onLog(`[opensearch] Deleting namespace '${targetNamespace}'...`);
      try {
        await execa('kubectl', ['delete', 'namespace', targetNamespace, '--timeout=60s']);
      } catch {
        // Ignore if already deleted
      }
    }
  }

  /**
   * Check status of OpenSearch components in target namespace
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
   * List endpoints for OpenSearch in target namespace
   */
  async getEndpoints({ domain = 'vigilante.local', namespace = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'opensearch';
    const webUrl = isStandardNs ? `https://siem.${domain}` : `https://${targetNamespace}-siem.${domain}`;

    return [
      {
        name: `OpenSearch SIEM Dashboard (${targetNamespace})`,
        url: webUrl,
        namespace: targetNamespace,
        description: 'Web console for security event monitoring, MITRE threat mapping & dashboards'
      },
      {
        name: `OpenSearch REST API (Internal, ${targetNamespace})`,
        url: `http://opensearch-cluster-master.${targetNamespace}.svc.cluster.local:9200`,
        namespace: targetNamespace,
        description: 'SIEM indices and ECS threat event ingestion API'
      }
    ];
  }

  /**
   * Run the network threat simulator to inject test threat events into target namespace
   */
  async simulateThreats({ clusterName = 'vigilante-dev', namespace = null, onLog = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const simulatorManifestPath = path.join(__dirname, 'manifests', 'threat-simulator.yaml');
    if (onLog) onLog(`[opensearch] Triggering threat simulation batch in namespace '${targetNamespace}'...`);

    // Delete existing simulator job if present
    try {
      await execa('kubectl', ['delete', 'job', 'opensearch-threat-injector', '-n', targetNamespace, '--ignore-not-found=true']);
    } catch {
      // Ignore
    }

    // Apply simulation job
    await execa('kubectl', ['apply', '-f', simulatorManifestPath, '-n', targetNamespace]);
    if (onLog) onLog(`[opensearch] Threat simulation Job scheduled in '${targetNamespace}'! Ingestion target: vigilante-network-events`);
  }
}
