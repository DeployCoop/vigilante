import { execa } from 'execa';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { BaseModule } from '../base.js';
import { execStream } from '../../utils/exec.js';
import { applyK8sTlsSecret } from '../../engine/certs.js';
import { ensureNamespace, getClusterContextArgs, getKubeExecutionEnv } from '../../engine/k8s.js';
import { resolveChartValuesArgs } from '../../engine/helm.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SECRET_NAME = 'opencti-credentials';

/**
 * Resolve the four OpenCTI credentials for an install.
 *
 * Precedence: explicit options win; otherwise reuse the existing
 * `opencti-credentials` Secret when it is complete; otherwise generate
 * fresh values. An existing but incomplete Secret fails closed instead of
 * silently rotating credentials (a re-install must not lock the operator
 * out of the platform). Generated credentials are reported once via onLog
 * — the admin token is what the engine/CLI/MCP use as $OPENCTI_TOKEN.
 */
async function resolveOpenCtiCredentials({ namespace, clusterName, provider, options = {}, onLog = null }) {
  const provided = {
    adminPassword: options.adminPassword || null,
    adminToken: options.adminToken || null,
    rabbitmqPassword: options.rabbitmqPassword || null,
    minioPassword: options.minioPassword || null
  };
  if (Object.values(provided).every(Boolean)) {
    return { ...provided, generated: false };
  }

  const kubeEnv = getKubeExecutionEnv();
  const ctxArgs = await getClusterContextArgs(clusterName, provider);
  try {
    const { stdout } = await execa(
      'kubectl',
      ['get', 'secret', SECRET_NAME, '-n', namespace, '-o', 'json', ...ctxArgs],
      { env: kubeEnv }
    );
    const data = JSON.parse(stdout).data || {};
    const fromSecret = (key) => (data[key] ? Buffer.from(data[key], 'base64').toString('utf8') : null);
    const reused = {
      adminPassword: provided.adminPassword || fromSecret('OPENCTI_ADMIN_PASSWORD'),
      adminToken: provided.adminToken || fromSecret('OPENCTI_ADMIN_TOKEN'),
      rabbitmqPassword: provided.rabbitmqPassword || fromSecret('RABBITMQ_PASSWORD'),
      minioPassword: provided.minioPassword || fromSecret('MINIO_ROOT_PASSWORD')
    };
    if (Object.values(reused).every(Boolean)) {
      if (onLog) onLog(`[opencti] Reusing existing credentials from Secret '${SECRET_NAME}' in namespace '${namespace}'.`);
      return { ...reused, generated: false };
    }
    throw new Error(
      `OpenCTI Secret '${SECRET_NAME}' in namespace '${namespace}' exists but is missing credentials; ` +
      'delete it or pass adminPassword, adminToken, rabbitmqPassword, and minioPassword via options to regenerate'
    );
  } catch (err) {
    const msg = `${err?.stderr || ''} ${err?.message || ''}`;
    if (/NotFound|not found|does not exist/i.test(msg)) {
      const generated = {
        adminPassword: provided.adminPassword || crypto.randomBytes(18).toString('base64url'),
        adminToken: provided.adminToken || crypto.randomUUID(),
        rabbitmqPassword: provided.rabbitmqPassword || crypto.randomBytes(18).toString('base64url'),
        minioPassword: provided.minioPassword || crypto.randomBytes(18).toString('base64url')
      };
      if (onLog) {
        onLog('[opencti] Generated fresh credentials (shown once — store them now):');
        onLog('[opencti]   Admin email:    admin@vigilante.local');
        onLog(`[opencti]   Admin password: ${generated.adminPassword}`);
        onLog(`[opencti]   Admin token:    ${generated.adminToken}  (use as $OPENCTI_TOKEN)`);
      }
      return { ...generated, generated: true };
    }
    throw err;
  }
}

export class OpenCtiModule extends BaseModule {
  constructor() {
    super({
      id: 'opencti',
      name: 'OpenCTI Threat Intelligence Platform',
      description: 'Open Cyber Threat Intelligence Platform (STIX 2.1-native): indicator/observable knowledge base with a GraphQL API, backed by the OpenSearch module plus bundled Redis, RabbitMQ, and S3 storage',
      category: 'cti',
      version: '0.1.0',
      dependencies: ['opensearch'],
      defaultEnabled: false
    });
    this.namespace = 'opencti';
    this.tlsSecretName = 'opencti-tls';
  }

  /**
   * Return deployment architecture & image metadata.
   */
  getRuntimeInfo() {
    return {
      mode: 'k8s-helm',
      platformImage: 'opencti/platform:7.261127.0',
      workerImage: 'opencti/worker:7.261127.0',
      redisImage: 'redis:8.10.1',
      rabbitmqImage: 'rabbitmq:4.3-management',
      s3Image: 'pgsty/silo:latest',
      platformPort: 8080,
      searchEngine: 'opensearch (module dependency; engine_client=opensearch)',
      searchUrl: 'http://opensearch-cluster-master.default.svc.cluster.local:9200',
      supportedProviders: ['k3d', 'k3s'],
      upstreamRepo: 'https://github.com/opencti-platform/opencti'
    };
  }

  /**
   * Install OpenCTI + worker + Redis + RabbitMQ + S3 into the target namespace.
   * Requires the opensearch module first (declared dependency).
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
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'opencti';
    const releaseName = isStandardNs ? 'opencti' : `${targetNamespace}-opencti`;
    const ingressHost = isStandardNs ? `opencti.${domain}` : `${targetNamespace}-opencti.${domain}`;

    if (onLog) {
      onLog(`[opencti] Preparing namespace '${targetNamespace}' on cluster '${clusterName}' (platform + worker + Redis + RabbitMQ + S3)...`);
    }
    await ensureNamespace(targetNamespace, { onLog });

    if (certPath && keyPath) {
      if (onLog) {
        onLog(`[opencti] Injecting mkcert TLS secret '${targetTlsSecret}' into namespace '${targetNamespace}'...`);
      }
      await applyK8sTlsSecret({
        namespace: targetNamespace,
        secretName: targetTlsSecret,
        certPath,
        keyPath
      });
    }

    const credentials = await resolveOpenCtiCredentials({ namespace: targetNamespace, clusterName, provider: options?.provider || null, options, onLog });

    if (onLog) {
      onLog(`[opencti] Deploying OpenCTI '${releaseName}' (Ingress: https://${ingressHost})...`);
    }

    const chartPath = path.join(__dirname, 'charts', 'opencti');
    const defaultValues = path.join(__dirname, 'values', 'opencti.yaml');

    const valuesArgs = await resolveChartValuesArgs({
      moduleId: this.id,
      chartName: 'opencti',
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
      'upgrade', '--install', '--wait', '--timeout', options?.timeout || '15m',
      releaseName, chartPath,
      '--namespace', targetNamespace,
      ...valuesArgs,
      '--set', `ingress.hosts[0].host=${ingressHost}`,
      '--set', `ingress.tls[0].secretName=${targetTlsSecret}`,
      '--set', `ingress.tls[0].hosts[0]=${ingressHost}`,
      '--set', `secrets.adminPassword=${credentials.adminPassword}`,
      '--set', `secrets.adminToken=${credentials.adminToken}`,
      '--set', `secrets.rabbitmqPassword=${credentials.rabbitmqPassword}`,
      '--set', `secrets.minioPassword=${credentials.minioPassword}`
    ];

    await execStream('helm', helmArgs, { onLog, env: getKubeExecutionEnv() });

    if (onLog) {
      onLog(`[opencti] Successfully deployed OpenCTI in namespace '${targetNamespace}'! Ingress: https://${ingressHost}`);
      onLog('[opencti] The admin token printed above is the $OPENCTI_TOKEN for `vigilante opencti` / the MCP tools / the web portal.');
    }
  }

  /**
   * Uninstall OpenCTI and clean up its PVCs.
   */
  async uninstall({
    clusterName = 'vigilante-dev',
    namespace = null,
    onLog = null,
    deleteNamespace = false,
    provider = null
  } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'opencti';
    const releaseName = isStandardNs ? 'opencti' : `${targetNamespace}-opencti`;
    const kubeEnv = getKubeExecutionEnv();
    const ctxArgs = await getClusterContextArgs(clusterName, provider);

    if (onLog) onLog(`[opencti] Uninstalling OpenCTI from namespace '${targetNamespace}'...`);
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
          '-l', 'app.kubernetes.io/name=opencti',
          '--ignore-not-found=true',
          ...ctxArgs
        ],
        { env: kubeEnv }
      );
    } catch {
      // Ignore if cluster unreachable
    }

    if (deleteNamespace && targetNamespace !== 'default' && targetNamespace !== 'kube-system') {
      if (onLog) onLog(`[opencti] Deleting namespace '${targetNamespace}'...`);
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
   * Check deployment status of OpenCTI (supports both k3d and k3s contexts).
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
          '-l', 'app.kubernetes.io/name=opencti',
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
   * List accessible web dashboard and internal API endpoints for OpenCTI.
   */
  async getEndpoints({ domain = 'vigilante.local', namespace = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'opencti';
    const webUrl = isStandardNs ? `https://opencti.${domain}` : `https://${targetNamespace}-opencti.${domain}`;
    const serviceHost = `opencti-platform.${targetNamespace}.svc.cluster.local`;

    return [
      {
        name: `OpenCTI Web Console (${targetNamespace})`,
        url: webUrl,
        namespace: targetNamespace,
        description: 'OpenCTI threat intelligence platform UI (port 8080)'
      },
      {
        name: `OpenCTI GraphQL API (${targetNamespace})`,
        url: `${webUrl}/graphql`,
        namespace: targetNamespace,
        description: 'OpenCTI GraphQL endpoint — the engine, CLI, and MCP tools talk to this URL with $OPENCTI_TOKEN'
      },
      {
        name: `OpenCTI Internal Service (${targetNamespace})`,
        url: `http://${serviceHost}:8080`,
        namespace: targetNamespace,
        description: 'Cluster-internal platform endpoint for the worker and connectors'
      }
    ];
  }
}
