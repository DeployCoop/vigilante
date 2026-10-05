/**
 * Autonomous Deception Technology & Honeynet Mesh ("Canary Kube")
 * Deploys decoy ServiceAccounts, canary Secrets, and honeypot network services.
 * Detects unauthorized interactions and triggers immediate SOAR active containment.
 */

import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { dump as yamlDump } from 'js-yaml';
import { getVigilanteCanaryDir, getVigilanteEvidenceDir } from './config.js';
import { logger } from '../utils/logger.js';
import { saveEvidenceFile } from './evidence.js';
import { isolatePod, blockIp } from './soar.js';

const CANARY_REGISTRY_FILE = 'canary_registry.json';

/**
 * Get path to canary registry file
 */
function getRegistryPath() {
  return path.join(getVigilanteCanaryDir(), CANARY_REGISTRY_FILE);
}

/**
 * Load all registered canaries
 * @returns {Promise<Array<Object>>}
 */
export async function listActiveCanaries() {
  const regPath = getRegistryPath();
  try {
    const data = await fs.readFile(regPath, 'utf8');
    return JSON.parse(data);
  } catch {
    return [];
  }
}

/**
 * Save canary entry to registry
 * @param {Object} canaryEntry 
 */
async function registerCanary(canaryEntry) {
  const canaries = await listActiveCanaries();
  const existingIdx = canaries.findIndex(c => c.id === canaryEntry.id);
  if (existingIdx >= 0) {
    canaries[existingIdx] = canaryEntry;
  } else {
    canaries.push(canaryEntry);
  }
  const regPath = getRegistryPath();
  await fs.mkdir(path.dirname(regPath), { recursive: true });
  await fs.writeFile(regPath, JSON.stringify(canaries, null, 2), 'utf8');
}

/**
 * Generate a decoy Kubernetes ServiceAccount with tantalizing RBAC permissions on paper
 * @param {string} [name='cluster-admin-backup']
 * @param {string} [namespace='kube-system']
 * @returns {Object} { id, yaml, manifest, canary }
 */
export function generateCanaryServiceAccount(name = 'cluster-admin-backup', namespace = 'kube-system') {
  const canaryId = `canary-sa-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;
  const tokenSignature = `canary_tok_${crypto.randomBytes(16).toString('hex')}`;

  const manifest = [
    {
      apiVersion: 'v1',
      kind: 'ServiceAccount',
      metadata: {
        name,
        namespace,
        labels: {
          'app.kubernetes.io/managed-by': 'vigilante-deception',
          'vigilante.io/canary': 'true',
          'vigilante.io/canary-id': canaryId
        },
        annotations: {
          'vigilante.io/canary-token': tokenSignature,
          'vigilante.io/created-at': new Date().toISOString()
        }
      }
    },
    {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRoleBinding',
      metadata: {
        name: `vigilante-canary-binding-${name}`,
        labels: {
          'vigilante.io/canary': 'true',
          'vigilante.io/canary-id': canaryId
        }
      },
      subjects: [
        {
          kind: 'ServiceAccount',
          name,
          namespace
        }
      ],
      roleRef: {
        kind: 'ClusterRole',
        name: 'cluster-admin',
        apiGroup: 'rbac.authorization.k8s.io'
      }
    }
  ];

  const yamlContent = manifest.map(doc => yamlDump(doc)).join('---\n');
  const canaryRecord = {
    id: canaryId,
    type: 'SERVICE_ACCOUNT',
    name,
    namespace,
    tokenSignature,
    status: 'ACTIVE',
    createdAt: new Date().toISOString(),
    tripped: false
  };

  return {
    id: canaryId,
    yaml: yamlContent,
    manifest,
    canary: canaryRecord
  };
}

/**
 * Generate a canary Secret containing deceptive credentials (AWS, DB, JWT, Kubeconfig)
 * @param {string} [name='aws-prod-secrets']
 * @param {string} [namespace='default']
 * @param {string} [tokenType='aws_key']
 * @returns {Object} { id, yaml, manifest, canary }
 */
export function generateCanarySecret(name = 'aws-prod-secrets', namespace = 'default', tokenType = 'aws_key') {
  const canaryId = `canary-sec-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;
  const tokenHash = `canary_${crypto.randomBytes(12).toString('hex')}`;

  let secretData = {};
  if (tokenType === 'aws_key') {
    secretData = {
      AWS_ACCESS_KEY_ID: Buffer.from(`AKIA${crypto.randomBytes(8).toString('hex').toUpperCase()}`).toString('base64'),
      AWS_SECRET_ACCESS_KEY: Buffer.from(`sec_${tokenHash}_${crypto.randomBytes(16).toString('hex')}`).toString('base64'),
      AWS_DEFAULT_REGION: Buffer.from('us-east-1').toString('base64')
    };
  } else if (tokenType === 'db_password') {
    secretData = {
      DATABASE_URL: Buffer.from(`postgresql://postgres_admin:db_${tokenHash}_pass@postgres-primary.internal:5432/finance`).toString('base64'),
      POSTGRES_PASSWORD: Buffer.from(`db_${tokenHash}_pass`).toString('base64')
    };
  } else {
    secretData = {
      API_SECRET_KEY: Buffer.from(`jwt_${tokenHash}_key`).toString('base64'),
      TOKEN_BEARER: Buffer.from(`vgt_${tokenHash}`).toString('base64')
    };
  }

  const manifest = {
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: {
      name,
      namespace,
      labels: {
        'app.kubernetes.io/managed-by': 'vigilante-deception',
        'vigilante.io/canary': 'true',
        'vigilante.io/canary-id': canaryId,
        'vigilante.io/token-type': tokenType
      },
      annotations: {
        'vigilante.io/canary-token': tokenHash,
        'vigilante.io/created-at': new Date().toISOString()
      }
    },
    type: 'Opaque',
    data: secretData
  };

  const yamlContent = yamlDump(manifest);
  const canaryRecord = {
    id: canaryId,
    type: 'SECRET',
    name,
    namespace,
    tokenType,
    tokenSignature: tokenHash,
    status: 'ACTIVE',
    createdAt: new Date().toISOString(),
    tripped: false
  };

  return {
    id: canaryId,
    yaml: yamlContent,
    manifest,
    canary: canaryRecord
  };
}

/**
 * Generate Deployment manifest for decoy network honeypots (SMB, SSH, Redis)
 * @param {string} [serviceType='smb']
 * @param {Object} [options={}]
 * @returns {Object} { id, yaml, manifest, canary }
 */
export function generateDecoyDeploymentYaml(serviceType = 'smb', options = {}) {
  const namespace = options.namespace || 'default';
  const name = options.name || `decoy-${serviceType}`;
  const canaryId = `canary-decoy-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;

  let containerPort = 445;
  let servicePort = 445;
  let image = 'alpine:latest';
  let command = ['sh', '-c', 'while true; do nc -lvp 445; sleep 1; done'];

  if (serviceType === 'ssh') {
    containerPort = 2222;
    servicePort = 22;
    command = ['sh', '-c', 'while true; do nc -lvp 2222; sleep 1; done'];
  } else if (serviceType === 'redis') {
    containerPort = 6379;
    servicePort = 6379;
    command = ['sh', '-c', 'while true; do nc -lvp 6379; sleep 1; done'];
  } else if (serviceType === 'mssql') {
    containerPort = 1433;
    servicePort = 1433;
    command = ['sh', '-c', 'while true; do nc -lvp 1433; sleep 1; done'];
  }

  const deployment = {
    apiVersion: 'apps/v1',
    kind: 'Deployment',
    metadata: {
      name,
      namespace,
      labels: {
        'app.kubernetes.io/name': name,
        'app.kubernetes.io/component': 'honeypot-decoy',
        'vigilante.io/canary': 'true',
        'vigilante.io/canary-id': canaryId,
        'vigilante.io/service-type': serviceType
      }
    },
    spec: {
      replicas: 1,
      selector: {
        matchLabels: {
          'app.kubernetes.io/name': name
        }
      },
      template: {
        metadata: {
          labels: {
            'app.kubernetes.io/name': name,
            'vigilante.io/canary': 'true',
            'vigilante.io/canary-id': canaryId
          }
        },
        spec: {
          containers: [
            {
              name: 'decoy-listener',
              image,
              command,
              ports: [{ containerPort, name: `${serviceType}-port` }],
              resources: {
                limits: { cpu: '50m', memory: '32Mi' },
                requests: { cpu: '10m', memory: '16Mi' }
              }
            }
          ]
        }
      }
    }
  };

  const service = {
    apiVersion: 'v1',
    kind: 'Service',
    metadata: {
      name,
      namespace,
      labels: {
        'app.kubernetes.io/name': name,
        'vigilante.io/canary': 'true',
        'vigilante.io/canary-id': canaryId
      }
    },
    spec: {
      selector: {
        'app.kubernetes.io/name': name
      },
      ports: [
        {
          name: serviceType,
          port: servicePort,
          targetPort: containerPort
        }
      ]
    }
  };

  const yamlContent = [deployment, service].map(d => yamlDump(d)).join('---\n');
  const canaryRecord = {
    id: canaryId,
    type: 'DECOY_SERVICE',
    name,
    namespace,
    serviceType,
    port: servicePort,
    status: 'ACTIVE',
    createdAt: new Date().toISOString(),
    tripped: false
  };

  return {
    id: canaryId,
    yaml: yamlContent,
    manifest: [deployment, service],
    canary: canaryRecord
  };
}

/**
 * Detect if any canary token or honeypot was interacted with
 * @param {Array<Object>} events Raw K8s audit logs, Falco alerts, or network flow records
 * @param {Array<Object>} [registeredCanaries]
 * @returns {Array<Object>} List of matched canary trip events
 */
export function detectCanaryTripped(events = [], registeredCanaries = []) {
  const canaries = registeredCanaries.length > 0 ? registeredCanaries : [];
  const tripped = [];

  for (const event of events) {
    const raw = typeof event === 'string' ? event : JSON.stringify(event);

    for (const canary of canaries) {
      let isMatch = false;
      let matchedIndicator = '';

      if (canary.tokenSignature && raw.includes(canary.tokenSignature)) {
        isMatch = true;
        matchedIndicator = `token:${canary.tokenSignature}`;
      } else if (canary.name && raw.includes(canary.name) && (canary.type === 'SERVICE_ACCOUNT' || canary.type === 'DECOY_SERVICE')) {
        isMatch = true;
        matchedIndicator = `name:${canary.name}`;
      }

      if (isMatch) {
        tripped.push({
          tripId: `trip-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`,
          canaryId: canary.id,
          canaryType: canary.type,
          canaryName: canary.name,
          namespace: canary.namespace,
          matchedIndicator,
          sourcePod: event.pod || event.sourcePod || event.pod_name || 'unknown-workload',
          sourceIp: event.srcIp || event.sourceIp || event.ip || '10.42.0.99',
          timestamp: new Date().toISOString(),
          severity: 'CRITICAL',
          rawEventSnippet: raw.substring(0, 300)
        });
      }
    }
  }

  return tripped;
}

/**
 * Trigger immediate alarm on canary trip and invoke Pillar 1 SOAR active containment
 * @param {Object} canaryTrip 
 * @param {Object} [options={}]
 * @returns {Promise<Object>} Alarm and containment outcome
 */
export async function triggerCanaryAlarm(canaryTrip, options = {}) {
  const autoIsolate = options.autoIsolate !== false;
  logger.warn('CANARY', `🚨 CANARY HONEYPOT TRIPPED! Canary: ${canaryTrip.canaryName} (${canaryTrip.canaryType}) by ${canaryTrip.sourcePod} [${canaryTrip.sourceIp}]`);

  const alarmRecord = {
    alarmId: `alarm-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`,
    tripId: canaryTrip.tripId,
    canaryId: canaryTrip.canaryId,
    canaryName: canaryTrip.canaryName,
    sourcePod: canaryTrip.sourcePod,
    sourceNamespace: canaryTrip.namespace || 'default',
    sourceIp: canaryTrip.sourceIp,
    timestamp: new Date().toISOString(),
    verdict: 'HIGH_FIDELITY_INTRUSION_DETECTED',
    soarAction: null
  };

  // If autoIsolate is enabled and we have a valid pod name, isolate pod via SOAR
  if (autoIsolate && canaryTrip.sourcePod && canaryTrip.sourcePod !== 'unknown-workload') {
    try {
      const containment = await isolatePod(canaryTrip.sourcePod, canaryTrip.namespace || 'default', {
        reason: `Canary honeypot trip on ${canaryTrip.canaryName}`,
        source: 'canary-kube'
      });
      alarmRecord.soarAction = {
        action: 'ISOLATE_POD',
        containmentId: containment.containmentId,
        status: 'CONTAINED'
      };
      logger.info('CANARY', `SOAR pod containment activated: ${containment.containmentId}`);
    } catch (err) {
      alarmRecord.soarAction = {
        action: 'ISOLATE_POD',
        status: 'FAILED',
        error: err.message
      };
    }
  } else if (autoIsolate && canaryTrip.sourceIp) {
    try {
      const block = await blockIp(canaryTrip.sourceIp, { reason: `Canary trip on ${canaryTrip.canaryName}` });
      alarmRecord.soarAction = {
        action: 'BLOCK_IP',
        containmentId: block.containmentId,
        status: 'BLOCKED'
      };
    } catch (err) {
      alarmRecord.soarAction = { action: 'BLOCK_IP', status: 'FAILED', error: err.message };
    }
  }

  // Update registry tripped status
  const canaries = await listActiveCanaries();
  const c = canaries.find(item => item.id === canaryTrip.canaryId);
  if (c) {
    c.tripped = true;
    c.lastTrippedAt = alarmRecord.timestamp;
    c.lastTrippedBy = `${canaryTrip.sourcePod}@${canaryTrip.sourceIp}`;
    const regPath = getRegistryPath();
    await fs.writeFile(regPath, JSON.stringify(canaries, null, 2), 'utf8');
  }

  // Persist incident evidence
  const evidenceDir = path.join(getVigilanteCanaryDir(), 'alarms');
  await fs.mkdir(evidenceDir, { recursive: true });
  const alarmFile = path.join(evidenceDir, `${alarmRecord.alarmId}.json`);
  await fs.writeFile(alarmFile, JSON.stringify(alarmRecord, null, 2), 'utf8');

  return alarmRecord;
}

/**
 * Register a newly generated canary into persistent storage
 * @param {Object} canary 
 */
export async function registerCanaryAsset(canary) {
  await registerCanary(canary);
  return canary;
}

/**
 * Generate cloud-native honeytokens (AWS STS, GitHub PAT, Slack Webhook, Kubeconfig)
 * @param {'aws'|'github'|'slack'|'kubeconfig'} tokenType
 * @param {Object} [options={}]
 * @returns {Promise<Object>} Generated honeytoken definition
 */
export async function generateCloudHoneytoken(tokenType = 'aws', options = {}) {
  const canaryId = `canary-cloud-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;
  const label = options.label || `canary-${tokenType}`;
  let tokenData = {};

  if (tokenType === 'aws') {
    const accessKeyId = `AKIA${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
    const secretAccessKey = crypto.randomBytes(20).toString('base64');
    tokenData = {
      type: 'aws',
      accessKeyId,
      secretAccessKey,
      canaryId,
      envSnippet: `AWS_ACCESS_KEY_ID=${accessKeyId}\nAWS_SECRET_ACCESS_KEY=${secretAccessKey}\nAWS_DEFAULT_REGION=us-east-1`
    };
  } else if (tokenType === 'github') {
    const token = `ghp_${crypto.randomBytes(18).toString('hex')}`;
    tokenData = {
      type: 'github',
      token,
      canaryId,
      envSnippet: `GITHUB_TOKEN=${token}`
    };
  } else if (tokenType === 'slack') {
    const webhookUrl = `https://hooks.slack.com/services/T00000000/B00000000/${crypto.randomBytes(12).toString('hex')}?cid=${canaryId}`;
    tokenData = {
      type: 'slack',
      webhookUrl,
      canaryId,
      envSnippet: `SLACK_WEBHOOK_URL=${webhookUrl}`
    };
  } else if (tokenType === 'kubeconfig') {
    tokenData = {
      type: 'kubeconfig',
      clusterEndpoint: `https://canary-api.vigilante.local:6443?cid=${canaryId}`,
      canaryId,
      clientCert: `LS0tLS1CRUdJTi...${canaryId}`
    };
  }

  const asset = {
    id: canaryId,
    name: label,
    type: `cloud-${tokenType}`,
    tokenData,
    createdAt: new Date().toISOString(),
    tripped: false
  };

  await registerCanaryAsset(asset);
  logger.info('CANARY', `Generated Cloud Honeytoken [${tokenType}]: ${canaryId}`);
  return asset;
}

/**
 * Plant decoy breadcrumbs into an environment or mock configuration text
 * @param {'env'|'configmap'|'markdown'} targetFormat
 * @param {Object} honeytoken
 * @returns {string} Planted configuration content
 */
export function plantDecoyBreadcrumbs(targetFormat = 'env', honeytoken = {}) {
  const snippet = honeytoken.tokenData?.envSnippet || `CANARY_TOKEN=${honeytoken.id}`;

  if (targetFormat === 'configmap') {
    return [
      `apiVersion: v1`,
      `kind: ConfigMap`,
      `metadata:`,
      `  name: app-credentials-backup`,
      `  namespace: default`,
      `data:`,
      ...snippet.split('\n').map(l => `  ${l.replace('=', ': ')}`)
    ].join('\n');
  }

  if (targetFormat === 'markdown') {
    return [
      `# Project Internal Credentials (Do Not Share)`,
      `\`\`\`bash`,
      snippet,
      `\`\`\``
    ].join('\n');
  }

  return snippet;
}

/**
 * Start an in-process HTTP webhook trap listener to catch incoming canary callbacks
 * @param {Object} [options={}]
 * @returns {Promise<{ server: import('node:http').Server, port: number, close: Function }>}
 */
export async function startCanaryWebhookListener(options = {}) {
  const http = await import('node:http');
  const port = options.port || 0; // 0 chooses a random available port

  return new Promise((resolve, reject) => {
    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
      const cid = url.searchParams.get('cid') || url.pathname.replace(/^\/canary\/?/, '').trim();
      const clientIp = req.socket.remoteAddress || '127.0.0.1';

      if (cid) {
        logger.warn('CANARY', `Incoming trap callback tripped on canaryId: ${cid} from ${clientIp}`);
        try {
          await triggerCanaryAlarm({
            tripId: `trip-cb-${Date.now().toString(36)}`,
            canaryId: cid,
            canaryName: `Canary Trap (${cid})`,
            canaryType: 'webhook',
            sourcePod: 'external-intruder',
            sourceIp: clientIp,
            namespace: 'perimeter'
          }, options.autoIsolate !== false);
        } catch (err) {
          logger.error('CANARY', `Failed to trigger alarm for callback: ${err.message}`);
        }
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', received: true }));
    });

    server.on('error', reject);
    server.listen(port, () => {
      const actualPort = server.address().port;
      logger.info('CANARY', `Canary webhook listener listening on port ${actualPort}`);
      resolve({
        server,
        port: actualPort,
        close: () => new Promise(r => server.close(r))
      });
    });
  });
}

