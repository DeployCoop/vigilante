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

export class SuricataModule extends BaseModule {
  constructor() {
    super({
      id: 'suricata',
      name: 'Suricata Network IDS/IPS & Threat Engine',
      description: 'High-performance real-time network security monitoring, IDS/IPS, and signature threat detection',
      category: 'detection',
      version: '0.1.0',
      dependencies: [],
      defaultEnabled: false
    });
    this.namespace = 'suricata';
    this.tlsSecretName = 'suricata-tls';
  }

  /**
   * Install Suricata into target namespace.
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
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'suricata';
    const releaseName = isStandardNs ? 'suricata' : `${targetNamespace}-suricata`;
    const ingressHost = isStandardNs ? `suricata.${domain}` : `${targetNamespace}-suricata.${domain}`;

    if (onLog) onLog(`[suricata] Preparing namespace '${targetNamespace}' on cluster '${clusterName}'...`);
    await ensureNamespace(targetNamespace, { onLog });

    if (certPath && keyPath) {
      if (onLog) onLog(`[suricata] Injecting TLS secret '${targetTlsSecret}' into namespace '${targetNamespace}'...`);
      await applyK8sTlsSecret({
        namespace: targetNamespace,
        secretName: targetTlsSecret,
        certPath,
        keyPath
      });
    }

    if (onLog) onLog(`[suricata] Deploying Suricata Network IDS '${releaseName}' (Ingress: https://${ingressHost})...`);
    const chartPath = path.join(__dirname, 'charts', 'suricata');
    const defaultValues = path.join(__dirname, 'values', 'suricata.yaml');

    const valuesArgs = await resolveChartValuesArgs({
      moduleId: this.id,
      chartName: 'suricata',
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
      onLog(`[suricata] Successfully deployed Suricata in namespace '${targetNamespace}'! Ingress: https://${ingressHost}`);
    }
  }

  /**
   * Uninstall Suricata.
   */
  async uninstall({ clusterName = 'vigilante-dev', namespace = null, onLog = null, deleteNamespace = false } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'suricata';
    const releaseName = isStandardNs ? 'suricata' : `${targetNamespace}-suricata`;

    if (onLog) onLog(`[suricata] Uninstalling Suricata from namespace '${targetNamespace}'...`);
    try {
      await execa('helm', ['uninstall', releaseName, '-n', targetNamespace]);
    } catch {
      // Ignore if already uninstalled
    }

    if (deleteNamespace && targetNamespace !== 'default' && targetNamespace !== 'kube-system') {
      if (onLog) onLog(`[suricata] Deleting namespace '${targetNamespace}'...`);
      try {
        await execa('kubectl', ['delete', 'namespace', targetNamespace, '--timeout=60s']);
      } catch {
        // Ignore if already deleted
      }
    }
  }

  /**
   * Check status of Suricata.
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
   * List endpoints for Suricata.
   */
  async getEndpoints({ domain = 'vigilante.local', namespace = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'suricata';
    const webUrl = isStandardNs ? `https://suricata.${domain}` : `https://${targetNamespace}-suricata.${domain}`;

    return [
      {
        name: `Suricata Status Ingress (${targetNamespace})`,
        url: webUrl,
        namespace: targetNamespace,
        description: 'Suricata NIDS status endpoint'
      }
    ];
  }
}
