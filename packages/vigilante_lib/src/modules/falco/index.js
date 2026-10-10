import { execa } from 'execa';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { BaseModule } from '../base.js';
import { execStream } from '../../utils/exec.js';
import { applyK8sTlsSecret } from '../../engine/certs.js';
import { ensureNamespace } from '../../engine/k8s.js';
import { resolveChartValuesArgs } from '../../engine/helm.js';

import {
  BUILTIN_FALCO_RULES,
  validateFalcoRule,
  simulateFalcoEvent,
  aggregateFalcoMetrics,
  evaluateFalcoSoarAction,
  renderFalcoRulesYaml
} from '../../engine/falco.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class FalcoModule extends BaseModule {
  constructor() {
    super({
      id: 'falco',
      name: 'Falco eBPF Runtime Threat Sensor',
      description: 'Cloud-native runtime threat detection and behavioral alerting powered by eBPF and Falcosidekick',
      category: 'detection',
      version: '0.1.0',
      dependencies: [],
      defaultEnabled: false
    });
    this.namespace = 'falco';
    this.tlsSecretName = 'falco-tls';
  }

  /**
   * Return built-in and active Falco detection rules
   */
  getRules() {
    return BUILTIN_FALCO_RULES;
  }

  /**
   * Validate a Falco rule definition
   */
  validateRule(ruleDef) {
    return validateFalcoRule(ruleDef);
  }

  /**
   * Simulate a Falco detection event for a given scenario
   */
  simulateEvent(scenarioId = 'shell-spawn', overrides = {}) {
    return simulateFalcoEvent(scenarioId, overrides);
  }

  /**
   * Compute aggregated metrics over Falco events
   */
  getMetrics(events = []) {
    return aggregateFalcoMetrics(events);
  }

  /**
   * Evaluate automated SOAR actions for a Falco detection
   */
  evaluateSoar(event) {
    return evaluateFalcoSoarAction(event);
  }

  /**
   * Return eBPF driver configuration and capabilities
   */
  getDriverInfo() {
    return {
      kind: 'modern_ebpf',
      driver: 'falco_modern_ebpf',
      description: 'Kernel-space ring-buffer probes without out-of-tree kernel modules',
      probeSource: 'CO-RE (Compile Once - Run Everywhere) BTF vmlinux',
      bufferCpus: 2,
      syscallCategories: ['process', 'filesystem', 'network', 'k8s_audit', 'kernel']
    };
  }

  /**
   * Install Falco into target namespace.
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
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'falco';
    const releaseName = isStandardNs ? 'falco' : `${targetNamespace}-falco`;
    const ingressHost = isStandardNs ? `falco.${domain}` : `${targetNamespace}-falco.${domain}`;

    if (onLog) onLog(`[falco] Preparing namespace '${targetNamespace}' on cluster '${clusterName}'...`);
    await ensureNamespace(targetNamespace, { onLog });

    if (certPath && keyPath) {
      if (onLog) onLog(`[falco] Injecting mkcert TLS secret '${targetTlsSecret}' into namespace '${targetNamespace}'...`);
      await applyK8sTlsSecret({
        namespace: targetNamespace,
        secretName: targetTlsSecret,
        certPath,
        keyPath
      });
    }

    if (onLog) onLog(`[falco] Deploying Falco eBPF sensor '${releaseName}' (UI Ingress: https://${ingressHost})...`);
    const chartPath = path.join(__dirname, 'charts', 'falco');
    const defaultValues = path.join(__dirname, 'values', 'falco.yaml');

    const valuesArgs = await resolveChartValuesArgs({
      moduleId: this.id,
      chartName: 'falco',
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
      'upgrade', '--install', '--wait', releaseName, chartPath,
      '--namespace', targetNamespace,
      ...valuesArgs,
      '--set', `ingress.hosts[0].host=${ingressHost}`,
      '--set', `ingress.tls[0].secretName=${targetTlsSecret}`,
      '--set', `ingress.tls[0].hosts[0]=${ingressHost}`
    ];

    await execStream('helm', helmArgs, { onLog });

    if (onLog) {
      onLog(`[falco] Successfully deployed Falco in namespace '${targetNamespace}'! Ingress: https://${ingressHost}`);
    }
  }

  /**
   * Uninstall Falco.
   */
  async uninstall({ clusterName = 'vigilante-dev', namespace = null, onLog = null, deleteNamespace = false } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'falco';
    const releaseName = isStandardNs ? 'falco' : `${targetNamespace}-falco`;

    if (onLog) onLog(`[falco] Uninstalling Falco from namespace '${targetNamespace}'...`);
    try {
      await execa('helm', ['uninstall', releaseName, '-n', targetNamespace]);
    } catch {
      // Ignore if already uninstalled
    }

    if (deleteNamespace && targetNamespace !== 'default' && targetNamespace !== 'kube-system') {
      if (onLog) onLog(`[falco] Deleting namespace '${targetNamespace}'...`);
      try {
        await execa('kubectl', ['delete', 'namespace', targetNamespace, '--timeout=60s']);
      } catch {
        // Ignore if already deleted
      }
    }
  }

  /**
   * Check status of Falco.
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
   * List listener endpoints and web ingress for Falco.
   */
  async getEndpoints({ domain = 'vigilante.local', namespace = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'falco';
    const webUrl = isStandardNs ? `https://falco.${domain}` : `https://${targetNamespace}-falco.${domain}`;

    return [
      {
        name: `Falcosidekick UI (${targetNamespace})`,
        url: webUrl,
        namespace: targetNamespace,
        description: 'Falcosidekick runtime alert visualization dashboard'
      },
      {
        name: `Falcosidekick Event Endpoint (Internal, ${targetNamespace})`,
        url: `falco.${targetNamespace}.svc.cluster.local:2801`,
        namespace: targetNamespace,
        description: 'Internal HTTP event sink for Falco security events'
      }
    ];
  }
}
