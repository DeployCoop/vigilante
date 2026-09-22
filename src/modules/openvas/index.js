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

export class OpenVASModule extends BaseModule {
  constructor() {
    super({
      id: 'openvas',
      name: 'OpenVAS / Greenbone Community Edition',
      description: 'Greenbone Vulnerability Management (GVM) Suite with OpenVAS Scanner, GSAD Web UI & GMP API',
      category: 'scanner',
      version: '24.10.0',
      dependencies: [],
      defaultEnabled: false
    });
    this.namespace = 'openvas';
    this.tlsSecretName = 'openvas-tls';
  }

  /**
   * Install OpenVAS / Greenbone Community Edition into target namespace
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
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'openvas';
    const releaseName = isStandardNs ? 'openvas' : `${targetNamespace}-openvas`;
    const ingressHost = isStandardNs ? `openvas.${domain}` : `${targetNamespace}-openvas.${domain}`;

    if (onLog) onLog(`[openvas] Preparing namespace '${targetNamespace}' on cluster '${clusterName}'...`);

    // 1. Ensure target namespace exists safely
    await ensureNamespace(targetNamespace, { onLog });

    // 2. Inject TLS secret for Ingress
    if (certPath && keyPath) {
      if (onLog) onLog(`[openvas] Injecting mkcert TLS secret '${targetTlsSecret}' into namespace '${targetNamespace}'...`);
      await applyK8sTlsSecret({
        namespace: targetNamespace,
        secretName: targetTlsSecret,
        certPath,
        keyPath
      });
    }

    // 3. Resolve Helm Chart Values
    if (onLog) onLog(`[openvas] Deploying Greenbone Community Edition '${releaseName}' (Ingress: https://${ingressHost})...`);
    const openvasChartPath = path.join(__dirname, 'charts', 'openvas');
    const openvasDefaultValues = path.join(__dirname, 'values', 'openvas.yaml');

    const openvasValuesArgs = await resolveChartValuesArgs({
      moduleId: this.id,
      chartName: 'openvas',
      defaultValuesPath: openvasDefaultValues,
      customValuesPath: options?.customValuesPath || options?.values,
      customValuesDir: options?.customValuesDir || options?.valuesDir,
      domain,
      tlsSecretName: targetTlsSecret,
      namespace: targetNamespace,
      clusterName,
      onLog
    });

    const helmArgs = [
      'upgrade', '--install', releaseName, openvasChartPath,
      '--namespace', targetNamespace,
      ...openvasValuesArgs
    ];

    await execStream('helm', helmArgs, { onLog });

    if (onLog) {
      onLog(`[openvas] Successfully deployed OpenVAS / Greenbone in namespace '${targetNamespace}'! Ingress: https://${ingressHost}`);
    }
  }

  /**
   * Uninstall OpenVAS and optionally clean up namespace
   */
  async uninstall({ clusterName = 'vigilante-dev', namespace = null, onLog = null, deleteNamespace = false } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'openvas';
    const releaseName = isStandardNs ? 'openvas' : `${targetNamespace}-openvas`;

    if (onLog) onLog(`[openvas] Uninstalling Greenbone Community Edition from namespace '${targetNamespace}'...`);
    try {
      await execa('helm', ['uninstall', releaseName, '-n', targetNamespace]);
    } catch {
      // Ignore if already uninstalled
    }

    if (deleteNamespace && targetNamespace !== 'default' && targetNamespace !== 'kube-system') {
      if (onLog) onLog(`[openvas] Deleting namespace '${targetNamespace}'...`);
      try {
        await execa('kubectl', ['delete', 'namespace', targetNamespace, '--timeout=60s']);
      } catch {
        // Ignore if already deleted
      }
    }
  }

  /**
   * Check status of OpenVAS components
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
   * List endpoints for OpenVAS / Greenbone Community Edition
   */
  async getEndpoints({ domain = 'vigilante.local', namespace = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'openvas';
    const webUrl = isStandardNs ? `https://openvas.${domain}` : `https://${targetNamespace}-openvas.${domain}`;
    const gvmUrl = isStandardNs ? `https://gvm.${domain}` : `https://${targetNamespace}-gvm.${domain}`;

    return [
      {
        name: `Greenbone Security Assistant (GSAD, ${targetNamespace})`,
        url: webUrl,
        namespace: targetNamespace,
        description: 'Greenbone web interface for vulnerability audits, scan management & CVE reports'
      },
      {
        name: `GVM Ingress Alias (${targetNamespace})`,
        url: gvmUrl,
        namespace: targetNamespace,
        description: 'Direct alias for Greenbone Vulnerability Management Web UI'
      },
      {
        name: `OpenVAS Daemon API (Internal, ${targetNamespace})`,
        url: `http://openvas-service.${targetNamespace}.svc.cluster.local:81`,
        namespace: targetNamespace,
        description: 'OpenVAS REST API daemon for vulnerability checks and scanner control'
      },
      {
        name: `GSAD Web Service (Internal, ${targetNamespace})`,
        url: `http://openvas-service.${targetNamespace}.svc.cluster.local:9392`,
        namespace: targetNamespace,
        description: 'Internal HTTP service for GSAD web console'
      }
    ];
  }
}
