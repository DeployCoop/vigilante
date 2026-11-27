import { execa } from 'execa';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { BaseModule } from '../base.js';
import { execStream } from '../../utils/exec.js';
import { applyK8sTlsSecret } from '../../engine/certs.js';
import { ensureNamespace, getClusterContextArgs, getKubeExecutionEnv } from '../../engine/k8s.js';
import { resolveChartValuesArgs } from '../../engine/helm.js';
import {
  REDAIRANGE_SCENARIOS,
  listRedAiRangeScenarios,
  evaluateAiAttackTelemetry,
  validateStackComposeYaml
} from '../../engine/redairange.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class RedAiRangeModule extends BaseModule {
  constructor() {
    super({
      id: 'redairange',
      name: 'RedAiRange (AI Red Teaming Cyber Range)',
      description: 'Containerized AI/ML red teaming, adversarial security lab, and AI-CTF range backed by an isolated Docker-in-Docker (DinD) sidecar',
      category: 'ai-redteam',
      version: '0.1.0',
      dependencies: [],
      defaultEnabled: false
    });
    this.namespace = 'redairange';
    this.tlsSecretName = 'redairange-tls';
  }

  /**
   * Return isolated DinD runtime architecture & security guardrail metadata.
   */
  getRuntimeInfo() {
    return {
      mode: 'k8s-isolated-dind',
      hostDockerSocketMounted: false,
      socketTransport: 'unix:///var/run/dind/docker.sock',
      appImage: 'erdemozgen/redairange:1',
      dindImage: 'docker:27-dind',
      uiPort: 5002,
      stacksDir: '/opt/stacks',
      scenarioPorts: [11000, 11001, 11002, 11003, 11004, 11005, 11006],
      supportedProviders: ['k3d', 'k3s'],
      license: 'MIT',
      upstreamRepo: 'https://github.com/ErdemOzgen/RedAiRange'
    };
  }

  getScenarios(filters = {}) {
    return listRedAiRangeScenarios(filters);
  }

  validateCompose(rawYaml) {
    return validateStackComposeYaml(rawYaml);
  }

  evaluateTelemetry(scenarioId) {
    return evaluateAiAttackTelemetry(scenarioId);
  }

  /**
   * Install RedAiRange + isolated DinD sidecar into target Kubernetes namespace (k3d or k3s).
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
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'redairange';
    const releaseName = isStandardNs ? 'redairange' : `${targetNamespace}-redairange`;
    const ingressHost = isStandardNs ? `redairange.${domain}` : `${targetNamespace}-redairange.${domain}`;

    if (onLog) {
      onLog(`[redairange] Preparing namespace '${targetNamespace}' on cluster '${clusterName}' (isolated DinD sidecar, zero host docker.sock)...`);
    }
    await ensureNamespace(targetNamespace, { onLog });

    if (certPath && keyPath) {
      if (onLog) {
        onLog(`[redairange] Injecting mkcert TLS secret '${targetTlsSecret}' into namespace '${targetNamespace}'...`);
      }
      await applyK8sTlsSecret({
        namespace: targetNamespace,
        secretName: targetTlsSecret,
        certPath,
        keyPath
      });
    }

    if (onLog) {
      onLog(`[redairange] Deploying RedAiRange '${releaseName}' (Ingress: https://${ingressHost})...`);
    }

    const chartPath = path.join(__dirname, 'charts', 'redairange');
    const defaultValues = path.join(__dirname, 'values', 'redairange.yaml');

    const valuesArgs = await resolveChartValuesArgs({
      moduleId: this.id,
      chartName: 'redairange',
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
      'upgrade', '--install', '--wait', '--timeout', options?.timeout || '10m',
      releaseName, chartPath,
      '--namespace', targetNamespace,
      ...valuesArgs,
      '--set', `ingress.hosts[0].host=${ingressHost}`,
      '--set', `ingress.tls[0].secretName=${targetTlsSecret}`,
      '--set', `ingress.tls[0].hosts[0]=${ingressHost}`
    ];

    await execStream('helm', helmArgs, { onLog, env: getKubeExecutionEnv() });

    if (onLog) {
      onLog(`[redairange] Successfully deployed RedAiRange in namespace '${targetNamespace}'! Ingress: https://${ingressHost}`);
      onLog(`[redairange] Seeded ${REDAIRANGE_SCENARIOS.length} starter AI red-teaming scenarios in isolated DinD stack volume (/opt/stacks).`);
    }
  }

  /**
   * Uninstall RedAiRange and clean up isolated DinD resources & PVCs.
   */
  async uninstall({
    clusterName = 'vigilante-dev',
    namespace = null,
    onLog = null,
    deleteNamespace = false,
    provider = null
  } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'redairange';
    const releaseName = isStandardNs ? 'redairange' : `${targetNamespace}-redairange`;
    const kubeEnv = getKubeExecutionEnv();
    const ctxArgs = await getClusterContextArgs(clusterName, provider);

    if (onLog) onLog(`[redairange] Uninstalling RedAiRange from namespace '${targetNamespace}'...`);
    try {
      await execa('helm', ['uninstall', releaseName, '-n', targetNamespace], { env: kubeEnv });
    } catch {
      // Ignore if already uninstalled
    }

    try {
      await execa(
        'kubectl',
        [
          'delete', 'pvc',
          '-n', targetNamespace,
          '-l', 'app.kubernetes.io/name=redairange',
          '--ignore-not-found=true',
          ...ctxArgs
        ],
        { env: kubeEnv }
      );
    } catch {
      // Ignore if cluster unreachable
    }

    if (deleteNamespace && targetNamespace !== 'default' && targetNamespace !== 'kube-system') {
      if (onLog) onLog(`[redairange] Deleting namespace '${targetNamespace}'...`);
      try {
        await execa(
          'kubectl',
          ['delete', 'namespace', targetNamespace, '--timeout=60s', ...ctxArgs],
          { env: kubeEnv }
        );
      } catch {
        // Ignore if already deleted
      }
    }
  }

  /**
   * Check deployment status of RedAiRange (supports both k3d and k3s contexts).
   */
  async status({ domain = 'vigilante.local', clusterName = 'vigilante-dev', namespace = null, provider = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const kubeEnv = getKubeExecutionEnv();
    const ctxArgs = await getClusterContextArgs(clusterName, provider);

    try {
      const { stdout: podsJson } = await execa(
        'kubectl',
        [
          'get', 'pods',
          '-n', targetNamespace,
          '-l', 'app.kubernetes.io/name=redairange',
          '--request-timeout=3s',
          '-o', 'json',
          ...ctxArgs
        ],
        { env: kubeEnv }
      );

      const parsed = JSON.parse(podsJson);
      const pods = (parsed.items || []).map((p) => ({
        name: p.metadata.name,
        namespace: p.metadata.namespace || targetNamespace,
        phase: p.status.phase,
        ready: p.status.containerStatuses?.every((c) => c.ready) || false,
        containers: (p.status.containerStatuses || []).map((c) => ({
          name: c.name,
          ready: c.ready,
          restarts: c.restartCount
        })),
        restarts: p.status.containerStatuses?.reduce((acc, c) => acc + c.restartCount, 0) || 0
      }));

      const isInstalled = pods.length > 0;
      const allReady = isInstalled && pods.every((p) => p.ready || p.phase === 'Succeeded');

      return {
        id: this.id,
        name: this.name,
        namespace: targetNamespace,
        installed: isInstalled,
        status: allReady ? 'Ready' : isInstalled ? 'Deploying / Degraded' : 'Not Installed',
        pods,
        runtime: this.getRuntimeInfo(),
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
        runtime: this.getRuntimeInfo(),
        endpoints: []
      };
    }
  }

  /**
   * List accessible web dashboard and internal scenario endpoints for RedAiRange.
   */
  async getEndpoints({ domain = 'vigilante.local', namespace = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'redairange';
    const webUrl = isStandardNs ? `https://redairange.${domain}` : `https://${targetNamespace}-redairange.${domain}`;
    const serviceHost = `redairange.${targetNamespace}.svc.cluster.local`;

    return [
      {
        name: `RedAiRange Web Console (${targetNamespace})`,
        url: webUrl,
        namespace: targetNamespace,
        description: 'RedAiRange AI red-teaming stack orchestrator, console & session recorder (port 5002)'
      },
      {
        name: `RedAiRange Internal Service (${targetNamespace})`,
        url: `http://${serviceHost}:5002`,
        namespace: targetNamespace,
        description: 'Cluster-internal HTTP/WebSocket endpoint for RedAiRange dashboard'
      },
      {
        name: `Adversarial Playground / Jupyter Gateway (${targetNamespace})`,
        url: `http://${serviceHost}:11000`,
        namespace: targetNamespace,
        description: 'Internal gateway for spawned Jupyter & AI scenario target ports (11000-11006)'
      }
    ];
  }
}
