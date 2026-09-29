/**
 * VIGILANTE Dynamic Ephemeral Honeynet & Breadcrumb Mesh Engine
 * Deploys low-interaction decoy services (SSH, Redis, HTTP),
 * plants enticing breadcrumbs (AWS keys, Kubeconfig, bash history),
 * and captures high-fidelity intrusion attempts with zero false positives.
 */

import net from 'node:net';
import http from 'node:http';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { logger } from '../utils/logger.js';

export const DECOY_TYPES = {
  SSH: 'SSH',
  REDIS: 'REDIS',
  HTTP: 'HTTP',
  K8S_API: 'K8S_API'
};

/**
 * Start a standalone ephemeral decoy service on a specified port
 * @param {string} serviceType 'SSH', 'REDIS', or 'HTTP'
 * @param {number} [port=0] 0 for dynamic random port allocation
 * @param {Object} [options={}]
 * @returns {Promise<Object>} Running decoy instance
 */
export async function startDecoyService(serviceType, port = 0, options = {}) {
  const onAlert = options.onAlert || (() => {});
  const type = (serviceType || '').toUpperCase();

  let server;
  let allocatedPort = port;

  if (type === DECOY_TYPES.SSH) {
    server = net.createServer((socket) => {
      const clientIp = socket.remoteAddress || '127.0.0.1';
      const clientPort = socket.remotePort || 0;

      // Send OpenSSH banner
      socket.write('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n');

      socket.once('data', (data) => {
        const payloadStr = data.toString('utf8').trim();
        const alert = {
          id: `honey-alert-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
          serviceType: 'SSH',
          timestamp: new Date().toISOString(),
          clientIp,
          clientPort,
          payload: payloadStr,
          payloadHex: data.toString('hex').substring(0, 64),
          severity: 'CRITICAL',
          mitreTechnique: 'T1110.001',
          description: `Unauthorized SSH connection and handshake attempt from ${clientIp}:${clientPort}`
        };
        onAlert(alert);
        socket.destroy();
      });
    });
  } else if (type === DECOY_TYPES.REDIS) {
    server = net.createServer((socket) => {
      const clientIp = socket.remoteAddress || '127.0.0.1';
      const clientPort = socket.remotePort || 0;

      socket.on('data', (data) => {
        const cmd = data.toString('utf8').trim();
        const alert = {
          id: `honey-alert-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
          serviceType: 'REDIS',
          timestamp: new Date().toISOString(),
          clientIp,
          clientPort,
          command: cmd,
          severity: 'CRITICAL',
          mitreTechnique: 'T1059',
          description: `Unauthorized Redis command execution from ${clientIp}: ${cmd}`
        };
        onAlert(alert);

        // Respond with standard Redis RESP protocol response
        if (cmd.toUpperCase().includes('PING')) {
          socket.write('+PONG\r\n');
        } else if (cmd.toUpperCase().includes('INFO')) {
          socket.write('$19\r\nredis_version:6.2.6\r\n');
        } else {
          socket.write('-ERR unknown command or authorization failed\r\n');
        }
      });
    });
  } else {
    // Default: HTTP Decoy
    server = http.createServer((req, res) => {
      const clientIp = req.socket.remoteAddress || '127.0.0.1';
      const url = req.url || '/';
      const method = req.method || 'GET';

      const alert = {
        id: `honey-alert-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        serviceType: 'HTTP',
        timestamp: new Date().toISOString(),
        clientIp,
        method,
        url,
        userAgent: req.headers['user-agent'] || 'unknown',
        severity: 'CRITICAL',
        mitreTechnique: 'T1190',
        description: `Honeypot HTTP probe ${method} ${url} from ${clientIp}`
      };
      onAlert(alert);

      // Return deceptive payload
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'ok',
        version: 'v2.4.0',
        portal: 'Internal Kubernetes Admin Console',
        warning: 'Authorized access only'
      }));
    });
  }

  await new Promise((resolve, reject) => {
    server.listen(port, () => {
      allocatedPort = server.address().port;
      resolve();
    });
    server.on('error', reject);
  });

  return {
    id: `decoy-${type.toLowerCase()}-${allocatedPort}`,
    type,
    port: allocatedPort,
    server,
    stop: () => new Promise(res => server.close(res))
  };
}

/**
 * Coordinate and launch a full Honeynet mesh of ephemeral decoys
 * @param {Object} [config={}]
 * @returns {Promise<Object>} Honeynet mesh instance
 */
export async function createHoneynetMesh(config = {}) {
  const meshId = `mesh-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
  const alerts = [];

  const onAlert = (alert) => {
    alerts.push(alert);
    if (typeof config.onAlert === 'function') {
      config.onAlert(alert);
    }
  };

  const decoysToStart = config.services || ['SSH', 'REDIS', 'HTTP'];
  const runningDecoys = [];

  for (const s of decoysToStart) {
    try {
      const decoy = await startDecoyService(s, 0, { onAlert });
      runningDecoys.push(decoy);
    } catch (err) {
      logger.warn(`Honeynet: could not start decoy ${s}: ${err.message}`);
    }
  }

  return {
    meshId,
    status: 'ACTIVE',
    startTime: new Date().toISOString(),
    decoys: runningDecoys,
    alerts,
    getAlerts: () => [...alerts],
    teardown: async () => {
      for (const d of runningDecoys) {
        try {
          await d.stop();
        } catch {}
      }
    }
  };
}

/**
 * Plant alluring breadcrumbs into a target filesystem directory
 * @param {string} targetDir Directory to drop breadcrumb files
 * @param {Array<string>} [types=['aws', 'kube', 'history']]
 * @returns {Promise<Array<Object>>} Planted breadcrumbs metadata
 */
export async function plantBreadcrumbs(targetDir, types = ['aws', 'kube', 'history']) {
  if (!targetDir) throw new Error('Target directory required for breadcrumbs');
  await fs.mkdir(targetDir, { recursive: true });

  const planted = [];

  // 1. AWS Credentials Honeytoken
  if (types.includes('aws')) {
    const awsDir = path.join(targetDir, '.aws');
    await fs.mkdir(awsDir, { recursive: true });
    const awsKey = `AKIAVIGILANTE${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const awsSecret = crypto.randomBytes(20).toString('hex');
    const awsContent = `[default]\naws_access_key_id = ${awsKey}\naws_secret_access_key = ${awsSecret}\nregion = us-east-1\n`;
    const awsPath = path.join(awsDir, 'credentials');
    await fs.writeFile(awsPath, awsContent, 'utf8');
    planted.push({
      type: 'AWS_CREDENTIALS',
      path: awsPath,
      token: awsKey,
      mitreTechnique: 'T1552.001',
      description: `Canary AWS Access Key planted in ${awsPath}`
    });
  }

  // 2. Kubernetes Config Honeytoken
  if (types.includes('kube')) {
    const kubeDir = path.join(targetDir, '.kube');
    await fs.mkdir(kubeDir, { recursive: true });
    const kubeToken = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.honeycanary.${crypto.randomBytes(8).toString('hex')}`;
    const kubeContent = `apiVersion: v1\nclusters:\n- cluster:\n    server: https://10.96.0.1:443\n  name: production-core\nusers:\n- name: cluster-admin\n  user:\n    token: ${kubeToken}\n`;
    const kubePath = path.join(kubeDir, 'config');
    await fs.writeFile(kubePath, kubeContent, 'utf8');
    planted.push({
      type: 'KUBECONFIG_TOKEN',
      path: kubePath,
      token: kubeToken,
      mitreTechnique: 'T1552.007',
      description: `Canary Kubeconfig cluster token planted in ${kubePath}`
    });
  }

  // 3. Bash History Breadcrumb
  if (types.includes('history')) {
    const histPath = path.join(targetDir, '.bash_history');
    const histContent = `ssh admin@10.0.99.15 -p 2222\ncurl -u admin:SuperSecretAdminPass2026! http://internal-vault:8088/admin\nkubectl get secrets --all-namespaces\n`;
    await fs.writeFile(histPath, histContent, 'utf8');
    planted.push({
      type: 'BASH_HISTORY_LURE',
      path: histPath,
      mitreTechnique: 'T1552.003',
      description: `Enticing command lure planted in ${histPath}`
    });
  }

  return planted;
}
