import { execa } from 'execa';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs/promises';
import { BaseModule } from '../base.js';
import { applyK8sTlsSecret } from '../../engine/certs.js';
import { ensureNamespace } from '../../engine/k8s.js';
import { resolveChartValuesArgs, renderTemplate } from '../../engine/helm.js';
import { logger } from '../../utils/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class KCTFModule extends BaseModule {
  constructor() {
    super({
      id: 'kctf',
      name: 'kCTF (Capture The Flag Platform)',
      description: 'Google kCTF Challenge Infrastructure & Isolation Platform with nsjail, PoW & Ingress',
      category: 'ctf',
      version: '1.0.0',
      dependencies: [],
      defaultEnabled: false
    });
    this.namespace = 'kctf';
    this.tlsSecretName = 'kctf-tls';
  }

  /**
   * Install kCTF CRD, Controller, Web Portal & Starter Challenges into target namespace
   */
  async install({
    domain = 'vigilante.local',
    certPath = null,
    keyPath = null,
    clusterName = 'vigilante-dev',
    namespace = null,
    onLog = null,
    options = {}
  }) {
    const targetNamespace = namespace || options?.namespace || this.namespace;
    const targetTlsSecret = `${targetNamespace}-tls`;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'kctf';
    const ingressHost = isStandardNs ? `kctf.${domain}` : `${targetNamespace}-kctf.${domain}`;
    const ctfHost = isStandardNs ? `ctf.${domain}` : `${targetNamespace}-ctf.${domain}`;

    if (onLog) {
      onLog(`[kctf] Preparing kCTF environment in namespace '${targetNamespace}' on cluster '${clusterName}'...`);
    }

    // 1. Ensure target namespace exists safely
    await ensureNamespace(targetNamespace, { onLog });

    // 2. Inject TLS certificate for Ingress
    if (certPath && keyPath) {
      if (onLog) onLog(`[kctf] Injecting mkcert TLS secret '${targetTlsSecret}' into namespace '${targetNamespace}'...`);
      await applyK8sTlsSecret({
        namespace: targetNamespace,
        secretName: targetTlsSecret,
        certPath,
        keyPath
      });
    }

    // 3. Apply challenges.kctf.dev CustomResourceDefinition
    const crdPath = path.join(__dirname, 'manifests', '00-crd-challenges.yaml');
    try {
      await fs.access(crdPath);
      if (onLog) onLog('[kctf] Applying kctf.dev/v1 Challenge CustomResourceDefinition (CRD)...');
      await execa('kubectl', ['apply', '-f', crdPath, '--context', `k3d-${clusterName}`]);
    } catch (err) {
      if (onLog) onLog(`[kctf] Warning: Could not apply CRD: ${err.message}`);
    }

    // 4. Apply RBAC Manifest (with parameterized namespace)
    const rbacPath = path.join(__dirname, 'manifests', '01-rbac.yaml');
    try {
      const rawRbac = await fs.readFile(rbacPath, 'utf8');
      const renderedRbac = rawRbac.replace(/namespace: kctf/g, `namespace: ${targetNamespace}`);
      if (onLog) onLog(`[kctf] Applying Controller RBAC in namespace '${targetNamespace}'...`);
      await execa('kubectl', ['apply', '--context', `k3d-${clusterName}`, '-f', '-'], {
        input: renderedRbac
      });
    } catch (err) {
      if (onLog) onLog(`[kctf] Warning: Could not apply RBAC: ${err.message}`);
    }

    // 5. Apply Portal, Deployment, Service & Ingress Manifest
    const portalPath = path.join(__dirname, 'manifests', '02-kctf-portal.yaml');
    try {
      const rawPortal = await fs.readFile(portalPath, 'utf8');
      const renderedPortal = renderTemplate(rawPortal, {
        domain,
        tlsSecretName: targetTlsSecret,
        namespace: targetNamespace,
        clusterName
      }).replace(/namespace: kctf/g, `namespace: ${targetNamespace}`);

      if (onLog) onLog(`[kctf] Deploying kCTF Challenge Explorer & Web Portal (Ingress: https://${ingressHost})...`);
      await execa('kubectl', ['apply', '--context', `k3d-${clusterName}`, '-n', targetNamespace, '-f', '-'], {
        input: renderedPortal
      });
    } catch (err) {
      if (onLog) onLog(`[kctf] Warning: Could not deploy portal: ${err.message}`);
    }

    // 6. Deploy Starter Challenges (Web & Pwn sandbox)
    const challengesPath = path.join(__dirname, 'manifests', '03-sample-challenges.yaml');
    try {
      const rawChallenges = await fs.readFile(challengesPath, 'utf8');
      const renderedChallenges = rawChallenges.replace(/namespace: kctf/g, `namespace: ${targetNamespace}`);
      if (onLog) onLog(`[kctf] Deploying built-in starter CTF challenges (web-flag-leak, pwn-nsjail-echo)...`);
      await execa('kubectl', ['apply', '--context', `k3d-${clusterName}`, '-n', targetNamespace, '-f', '-'], {
        input: renderedChallenges
      });
    } catch (err) {
      if (onLog) onLog(`[kctf] Note: Starter challenges skipped or already present: ${err.message}`);
    }

    if (onLog) {
      onLog(`[kctf] Successfully deployed kCTF Platform in namespace '${targetNamespace}'! Web: https://${ingressHost} | Event: https://${ctfHost}`);
    }
  }

  /**
   * Uninstall kCTF and optionally clean up namespace
   */
  async uninstall({ clusterName = 'vigilante-dev', namespace = null, onLog = null, deleteNamespace = false } = {}) {
    const targetNamespace = namespace || this.namespace;

    if (onLog) onLog(`[kctf] Uninstalling kCTF Platform from namespace '${targetNamespace}'...`);

    const manifests = [
      path.join(__dirname, 'manifests', '03-sample-challenges.yaml'),
      path.join(__dirname, 'manifests', '02-kctf-portal.yaml'),
      path.join(__dirname, 'manifests', '01-rbac.yaml')
    ];

    for (const mPath of manifests) {
      try {
        await execa('kubectl', ['delete', '-f', mPath, '-n', targetNamespace, '--context', `k3d-${clusterName}`, '--ignore-not-found=true']);
      } catch {
        // Ignore deletion errors
      }
    }

    if (deleteNamespace && targetNamespace !== 'default' && targetNamespace !== 'kube-system') {
      if (onLog) onLog(`[kctf] Deleting namespace '${targetNamespace}'...`);
      try {
        await execa('kubectl', ['delete', 'namespace', targetNamespace, '--timeout=60s', '--context', `k3d-${clusterName}`]);
      } catch {
        // Ignore
      }
    }
  }

  /**
   * Check status of kCTF components and active challenges
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

      // Query challenges
      let challenges = [];
      try {
        const { stdout: chalJson } = await execa('kubectl', [
          'get', 'challenges.kctf.dev',
          '-n', targetNamespace,
          '--context', `k3d-${clusterName}`,
          '--request-timeout=3s',
          '-o', 'json'
        ]);
        const parsedChals = JSON.parse(chalJson);
        challenges = (parsedChals.items || []).map(c => ({
          name: c.metadata.name,
          category: c.spec?.category || 'misc',
          deployed: c.spec?.deployed ?? true,
          pow: c.spec?.powDifficultySeconds || 0,
          ports: c.spec?.network?.ports || []
        }));
      } catch {
        // CRD not applied yet
      }

      const isInstalled = pods.length > 0;
      const allReady = isInstalled && pods.every(p => p.ready || p.phase === 'Succeeded');

      return {
        id: this.id,
        name: this.name,
        namespace: targetNamespace,
        installed: isInstalled,
        status: allReady ? 'Ready' : isInstalled ? 'Deploying / Running' : 'Not Installed',
        pods,
        challenges,
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
        challenges: [],
        endpoints: []
      };
    }
  }

  /**
   * List accessible web and challenge endpoints for kCTF
   */
  async getEndpoints({ domain = 'vigilante.local', namespace = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'kctf';
    const webUrl = isStandardNs ? `https://kctf.${domain}` : `https://${targetNamespace}-kctf.${domain}`;
    const ctfUrl = isStandardNs ? `https://ctf.${domain}` : `https://${targetNamespace}-ctf.${domain}`;

    return [
      {
        name: `kCTF Challenge Explorer & Web Portal (${targetNamespace})`,
        url: webUrl,
        namespace: targetNamespace,
        description: 'Web dashboard listing active challenges, port bindings, categories, and connection guides'
      },
      {
        name: `kCTF Event Ingress Endpoint (${targetNamespace})`,
        url: ctfUrl,
        namespace: targetNamespace,
        description: 'Direct competitor ingress hostname for CTF challenge routing and reverse proxy'
      },
      {
        name: `kCTF Pwn Sandbox (pwn-nsjail-echo)`,
        url: `nc ${domain} 31337`,
        namespace: targetNamespace,
        description: 'Sample sandboxed TCP binary running isolated via nsjail container'
      }
    ];
  }

  /**
   * Helper to retrieve all active challenges as structured objects
   */
  async listChallenges({ clusterName = 'vigilante-dev', namespace = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    try {
      const { stdout } = await execa('kubectl', [
        'get', 'challenges.kctf.dev',
        '-n', targetNamespace,
        '--context', `k3d-${clusterName}`,
        '-o', 'json'
      ]);
      const data = JSON.parse(stdout);
      return (data.items || []).map(item => ({
        name: item.metadata.name,
        category: item.spec?.category || 'misc',
        deployed: item.spec?.deployed ?? true,
        powDifficultySeconds: item.spec?.powDifficultySeconds || 0,
        ports: item.spec?.network?.ports || [],
        createdAt: item.metadata.creationTimestamp
      }));
    } catch {
      return [];
    }
  }
}
