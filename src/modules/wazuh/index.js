import { execa } from 'execa';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { BaseModule } from '../base.js';
import { execStream } from '../../utils/exec.js';
import { applyK8sTlsSecret } from '../../engine/certs.js';
import { ensureNamespace } from '../../engine/k8s.js';
import { resolveChartValuesArgs } from '../../engine/helm.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class WazuhModule extends BaseModule {
  constructor() {
    super({
      id: 'wazuh',
      name: 'Wazuh XDR/SIEM',
      description: 'Wazuh open-source XDR/SIEM with indexer, manager, and dashboard for a local lab',
      category: 'siem',
      version: '4.14.7',
      dependencies: [],
      defaultEnabled: false
    });
    this.namespace = 'wazuh';
    this.tlsSecretName = 'wazuh-tls';
  }

  /**
   * Install the single-node Wazuh stack into the target namespace.
   */
  async install({
    domain = 'vigilante.local',
    certPath = null,
    keyPath = null,
    clusterName = 'vigilante-dev',
    namespace = null,
    onLog = null,
    options = {}
  } = {}) {
    const targetNamespace = namespace || options?.namespace || this.namespace;
    const targetTlsSecret = `${targetNamespace}-tls`;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'wazuh';
    const releaseName = isStandardNs ? 'wazuh' : `${targetNamespace}-wazuh`;
    const ingressHost = isStandardNs ? `wazuh.${domain}` : `${targetNamespace}-wazuh.${domain}`;

    if (onLog) onLog(`[wazuh] Preparing namespace '${targetNamespace}' on cluster '${clusterName}'...`);

    await ensureNamespace(targetNamespace, { onLog });

    if (certPath && keyPath) {
      if (onLog) onLog(`[wazuh] Injecting mkcert TLS secret '${targetTlsSecret}' into namespace '${targetNamespace}'...`);
      await applyK8sTlsSecret({
        namespace: targetNamespace,
        secretName: targetTlsSecret,
        certPath,
        keyPath
      });
    }

    if (onLog) onLog(`[wazuh] Deploying Wazuh XDR/SIEM '${releaseName}' (Ingress: https://${ingressHost})...`);
    const chartPath = path.join(__dirname, 'charts', 'wazuh');
    const defaultValues = path.join(__dirname, 'values', 'wazuh.yaml');

    const valuesArgs = await resolveChartValuesArgs({
      moduleId: this.id,
      chartName: 'wazuh',
      defaultValuesPath: defaultValues,
      customValuesPath: options?.customValuesPath || options?.values,
      customValuesDir: options?.customValuesDir || options?.valuesDir,
      domain,
      tlsSecretName: targetTlsSecret,
      namespace: targetNamespace,
      clusterName,
      onLog
    });

    const helmArgs = [
      'upgrade', '--install', releaseName, chartPath,
      '--namespace', targetNamespace,
      ...valuesArgs,
      '--set', `ingress.hosts[0].host=${ingressHost}`,
      '--set', `ingress.tls[0].secretName=${targetTlsSecret}`,
      '--set', `ingress.tls[0].hosts[0]=${ingressHost}`
    ];

    await execStream('helm', helmArgs, { onLog });

    if (onLog) {
      onLog(`[wazuh] Successfully deployed Wazuh in namespace '${targetNamespace}'! Ingress: https://${ingressHost}`);
      onLog('[wazuh] Dashboard login (upstream single-node demo): admin / SecretPassword');
    }
  }

  /**
   * Uninstall Wazuh and optionally delete the namespace.
   */
  async uninstall({ clusterName = 'vigilante-dev', namespace = null, onLog = null, deleteNamespace = false } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'wazuh';
    const releaseName = isStandardNs ? 'wazuh' : `${targetNamespace}-wazuh`;

    if (onLog) onLog(`[wazuh] Uninstalling Wazuh XDR/SIEM from namespace '${targetNamespace}'...`);
    try {
      await execa('helm', ['uninstall', releaseName, '-n', targetNamespace]);
    } catch {
      // Ignore if already uninstalled
    }

    try {
      await execa('kubectl', [
        'delete', 'pvc',
        '-n', targetNamespace,
        '-l', 'app.kubernetes.io/name=wazuh',
        '--ignore-not-found=true'
      ]);
    } catch {
      // Ignore if the API is unreachable
    }

    if (deleteNamespace && targetNamespace !== 'default' && targetNamespace !== 'kube-system') {
      if (onLog) onLog(`[wazuh] Deleting namespace '${targetNamespace}'...`);
      try {
        await execa('kubectl', ['delete', 'namespace', targetNamespace, '--timeout=60s']);
      } catch {
        // Ignore if already deleted
      }
    }
  }

  /**
   * Check status of Wazuh components.
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
   * List dashboard, API, indexer, and agent endpoints.
   */
  async getEndpoints({ domain = 'vigilante.local', namespace = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'wazuh';
    const webUrl = isStandardNs ? `https://wazuh.${domain}` : `https://${targetNamespace}-wazuh.${domain}`;
    const indexerHost = `wazuh-indexer.${targetNamespace}.svc.cluster.local`;
    const managerHost = `wazuh-manager.${targetNamespace}.svc.cluster.local`;

    return [
      {
        name: `Wazuh Dashboard (${targetNamespace})`,
        url: webUrl,
        namespace: targetNamespace,
        description: 'Wazuh open-source XDR/SIEM dashboard (lab login admin / SecretPassword)'
      },
      {
        name: `Wazuh Indexer API (Internal, ${targetNamespace})`,
        url: `https://${indexerHost}:9200`,
        namespace: targetNamespace,
        description: 'Wazuh indexer REST API used by the dashboard and manager Filebeat'
      },
      {
        name: `Wazuh Manager API (Internal, ${targetNamespace})`,
        url: `https://${managerHost}:55000`,
        namespace: targetNamespace,
        description: 'Wazuh manager API (lab user wazuh-wui)'
      },
      {
        name: `Wazuh Agent Events (Internal, ${targetNamespace})`,
        url: `${managerHost}:1514`,
        namespace: targetNamespace,
        description: 'Agent event channel (TCP 1514) for enrolling lab agents inside the cluster'
      },
      {
        name: `Wazuh Agent Enrollment (Internal, ${targetNamespace})`,
        url: `${managerHost}:1515`,
        namespace: targetNamespace,
        description: 'Agent registration service (authd, TCP 1515)'
      }
    ];
  }
}
