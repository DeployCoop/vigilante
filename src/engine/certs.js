import { execa } from 'execa';
import fs from 'node:fs/promises';
import path from 'node:path';
import { getInstanceCertsDir, ensureVigilanteConfig } from './config.js';
import { ensureInstanceDirs } from './instances.js';
import { ensureNamespace, safeKubectlApply } from './k8s.js';
import { logger } from '../utils/logger.js';

/**
 * Resolve target certificate directory from options or instance name
 * @param {string|Object} [options]
 * @returns {string}
 */
function resolveCertDir(options) {
  if (typeof options === 'string' && options.trim()) {
    return options.trim();
  }
  if (options && typeof options === 'object') {
    if (options.certDir) return options.certDir;
    const instance = options.instanceName || options.clusterName || 'vigilante-dev';
    return getInstanceCertsDir(instance);
  }
  return getInstanceCertsDir('vigilante-dev');
}

/**
 * Setup local certificates with mkcert in the instance certificates directory
 * @param {string} [domain='vigilante.local'] - Base domain
 * @param {string|Object} [options] - Custom directory or { certDir, instanceName, clusterName }
 */
export async function setupCertificates(domain = 'vigilante.local', options = null) {
  await ensureVigilanteConfig();
  const certDir = resolveCertDir(options);
  await fs.mkdir(certDir, { recursive: true });

  const certPath = path.join(certDir, `${domain}.pem`);
  const keyPath = path.join(certDir, `${domain}-key.pem`);

  logger.info('CERTS:SETUP', `Generating certificates for *.${domain} in ${certDir}`);

  // 1. Ensure mkcert local CA is installed
  await execa('mkcert', ['-install']);

  // 2. Fetch CA root path
  let caRoot = '';
  try {
    const { stdout } = await execa('mkcert', ['-CAROOT']);
    caRoot = stdout.trim();
  } catch {
    // Non-fatal if CAROOT output fails
  }

  // 3. Generate wildcard certs for base domain and subdomains
  await execa('mkcert', [
    '-cert-file', certPath,
    '-key-file', keyPath,
    domain,
    `*.${domain}`,
    'localhost',
    '127.0.0.1'
  ]);

  return {
    certPath,
    keyPath,
    certDir,
    domain,
    caRoot
  };
}

/**
 * Check if certificates exist and are present on disk
 * @param {string} [domain='vigilante.local']
 * @param {string|Object} [options]
 */
export async function checkCertificates(domain = 'vigilante.local', options = null) {
  const certDir = resolveCertDir(options);
  const certPath = path.join(certDir, `${domain}.pem`);
  const keyPath = path.join(certDir, `${domain}-key.pem`);

  try {
    await fs.access(certPath);
    await fs.access(keyPath);
    return {
      exists: true,
      certPath,
      keyPath,
      certDir
    };
  } catch {
    return {
      exists: false,
      certPath,
      keyPath,
      certDir
    };
  }
}

/**
 * Inject TLS certificate as Kubernetes Secret
 */
export async function applyK8sTlsSecret({
  namespace = 'default',
  secretName = 'vigilante-tls',
  certPath,
  keyPath,
  onLog = null
}) {
  // 1. Ensure namespace exists safely
  await ensureNamespace(namespace, { onLog });

  // 2. Create or update secret
  const { stdout: secretYaml } = await execa('kubectl', [
    'create', 'secret', 'tls', secretName,
    `--cert=${certPath}`,
    `--key=${keyPath}`,
    '-n', namespace,
    '--dry-run=client', '-o', 'yaml'
  ]);

  await safeKubectlApply(secretYaml, { onLog });

  return {
    namespace,
    secretName
  };
}
