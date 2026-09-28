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

export class FlamingoModule extends BaseModule {
  constructor() {
    super({
      id: 'flamingo',
      name: 'Flamingo Credential Harvester',
      description: 'Network credential harvester capturing credentials sprayed across SSH, HTTP/HTTPS, LDAP, DNS, FTP, and SNMP',
      category: 'recon',
      version: '0.1.0',
      dependencies: [],
      defaultEnabled: false
    });
    this.namespace = 'flamingo';
    this.tlsSecretName = 'flamingo-tls';
  }

  /**
   * Install Flamingo credential harvester into target namespace.
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
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'flamingo';
    const releaseName = isStandardNs ? 'flamingo' : `${targetNamespace}-flamingo`;
    const ingressHost = isStandardNs ? `flamingo.${domain}` : `${targetNamespace}-flamingo.${domain}`;

    if (onLog) onLog(`[flamingo] Preparing namespace '${targetNamespace}' on cluster '${clusterName}'...`);

    await ensureNamespace(targetNamespace, { onLog });

    if (certPath && keyPath) {
      if (onLog) onLog(`[flamingo] Injecting mkcert TLS secret '${targetTlsSecret}' into namespace '${targetNamespace}'...`);
      await applyK8sTlsSecret({
        namespace: targetNamespace,
        secretName: targetTlsSecret,
        certPath,
        keyPath
      });
    }

    if (onLog) onLog(`[flamingo] Deploying Flamingo Credential Harvester '${releaseName}' (Ingress: https://${ingressHost})...`);
    const chartPath = path.join(__dirname, 'charts', 'flamingo');
    const defaultValues = path.join(__dirname, 'values', 'flamingo.yaml');

    const valuesArgs = await resolveChartValuesArgs({
      moduleId: this.id,
      chartName: 'flamingo',
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
      onLog(`[flamingo] Successfully deployed Flamingo in namespace '${targetNamespace}'! Ingress: https://${ingressHost}`);
      onLog('[flamingo] Protocol listeners active: SSH (22), HTTP/S (80/443), LDAP/S (389/636), DNS (53), FTP (21), SNMP (161)');
    }
  }

  /**
   * Uninstall Flamingo and optionally delete the namespace.
   */
  async uninstall({ clusterName = 'vigilante-dev', namespace = null, onLog = null, deleteNamespace = false } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'flamingo';
    const releaseName = isStandardNs ? 'flamingo' : `${targetNamespace}-flamingo`;

    if (onLog) onLog(`[flamingo] Uninstalling Flamingo Credential Harvester from namespace '${targetNamespace}'...`);
    try {
      await execa('helm', ['uninstall', releaseName, '-n', targetNamespace]);
    } catch {
      // Ignore if already uninstalled
    }

    try {
      await execa('kubectl', [
        'delete', 'pvc',
        '-n', targetNamespace,
        '-l', 'app.kubernetes.io/name=flamingo',
        '--ignore-not-found=true'
      ]);
    } catch {
      // Ignore if the API is unreachable
    }

    if (deleteNamespace && targetNamespace !== 'default' && targetNamespace !== 'kube-system') {
      if (onLog) onLog(`[flamingo] Deleting namespace '${targetNamespace}'...`);
      try {
        await execa('kubectl', ['delete', 'namespace', targetNamespace, '--timeout=60s']);
      } catch {
        // Ignore if already deleted
      }
    }
  }

  /**
   * Check status of Flamingo components.
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
   * List listener endpoints and web ingress for Flamingo.
   */
  async getEndpoints({ domain = 'vigilante.local', namespace = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'flamingo';
    const webUrl = isStandardNs ? `https://flamingo.${domain}` : `https://${targetNamespace}-flamingo.${domain}`;
    const serviceHost = `flamingo.${targetNamespace}.svc.cluster.local`;

    return [
      {
        name: `Flamingo Web / HTTP Ingress (${targetNamespace})`,
        url: webUrl,
        namespace: targetNamespace,
        description: 'Flamingo HTTP/HTTPS credential harvester ingress endpoint'
      },
      {
        name: `Flamingo SSH Listener (Internal, ${targetNamespace})`,
        url: `${serviceHost}:22`,
        namespace: targetNamespace,
        description: 'Internal SSH credential harvester (TCP 22)'
      },
      {
        name: `Flamingo LDAP Listener (Internal, ${targetNamespace})`,
        url: `${serviceHost}:389`,
        namespace: targetNamespace,
        description: 'Internal LDAP/LDAPS credential harvester (TCP 389/636)'
      },
      {
        name: `Flamingo DNS Listener (Internal, ${targetNamespace})`,
        url: `${serviceHost}:53`,
        namespace: targetNamespace,
        description: 'Internal DNS credential & query harvester (UDP/TCP 53)'
      },
      {
        name: `Flamingo FTP Listener (Internal, ${targetNamespace})`,
        url: `${serviceHost}:21`,
        namespace: targetNamespace,
        description: 'Internal FTP credential harvester (TCP 21)'
      },
      {
        name: `Flamingo SNMP Listener (Internal, ${targetNamespace})`,
        url: `${serviceHost}:161`,
        namespace: targetNamespace,
        description: 'Internal SNMP community string harvester (UDP 161)'
      }
    ];
  }
}
