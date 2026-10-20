import { NextRequest, NextResponse } from 'next/server';
import fs from 'node:fs/promises';
import path from 'node:path';
import { resolveCtfFlagSecret } from 'vigilante_lib/engine/config.js';
import { listK3dClusters, detectK3sAvailability } from 'vigilante_lib/engine/cluster.js';
import { listActiveSandboxes } from 'vigilante_lib/engine/kctf.js';
import { authorizeRequest } from '@/lib/authz';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:read');
  if (denied) return denied;

  try {
    // 1. CTF Secret Check
    const secret = resolveCtfFlagSecret();
    const hasSecret = Boolean(secret);

    // 2. Cluster Connectivity Check (k3d or k3s)
    let k3dClusters = [];
    let k3sStatus = { available: false, serviceActive: false, kubectlK3sConnected: false };
    try {
      k3dClusters = await listK3dClusters();
    } catch {
      // k3d binary or docker might not be running
    }
    try {
      k3sStatus = await detectK3sAvailability();
    } catch {
      // host k3s not available
    }

    const clusterRunning = k3dClusters.length > 0 || k3sStatus.serviceActive || k3sStatus.kubectlK3sConnected;
    const clusterSummary = k3dClusters.length > 0
      ? `k3d clusters online (${k3dClusters.map((c: any) => c.name).join(', ')})`
      : k3sStatus.kubectlK3sConnected
      ? 'Native host k3s cluster reachable'
      : 'No active Kubernetes cluster detected (emulation/mock mode enabled)';

    // 3. Sandboxes Quota Check
    const sandboxes = await listActiveSandboxes();
    const activeCount = sandboxes.filter((s: any) => s.status === 'ACTIVE').length;
    const quotaRemaining = Math.max(0, 3 - activeCount);

    // 4. Local CTF Workspace Check
    const workspaceDir = path.resolve(process.cwd(), 'ctf-workspace');
    let workspaceReady = false;
    let challengeDirs: string[] = [];

    try {
      const stat = await fs.stat(workspaceDir);
      if (stat.isDirectory()) {
        workspaceReady = true;
        const entries = await fs.readdir(workspaceDir, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isDirectory()) {
            const catPath = path.join(workspaceDir, entry.name);
            const subEntries = await fs.readdir(catPath, { withFileTypes: true }).catch(() => []);
            for (const sub of subEntries) {
              if (sub.isDirectory()) {
                challengeDirs.push(`${entry.name}/${sub.name}`);
              }
            }
          }
        }
      }
    } catch {
      workspaceReady = false;
    }

    const checks = [
      {
        id: 'secret',
        name: 'CTF Flag HMAC Secret',
        passed: hasSecret,
        status: hasSecret ? 'READY' : 'WARNING',
        detail: hasSecret ? 'Configured (VIGILANTE_CTF_SECRET)' : 'Missing: Using ephemeral fallback. Set VIGILANTE_CTF_SECRET in environment or config.yaml.',
        remediation: 'export VIGILANTE_CTF_SECRET="your-high-entropy-secret"'
      },
      {
        id: 'cluster',
        name: 'Kubernetes Cluster Runtime',
        passed: clusterRunning,
        status: clusterRunning ? 'READY' : 'STANDBY',
        detail: clusterSummary,
        remediation: 'vigilante up --dev   # or vigilante up --k3s'
      },
      {
        id: 'sandboxes',
        name: 'Sandbox Concurrency Quota',
        passed: quotaRemaining > 0,
        status: quotaRemaining > 0 ? 'READY' : 'FULL',
        detail: `${activeCount}/3 active sandboxes deployed (${quotaRemaining} available slots)`,
        remediation: 'Reap or terminate expired pods in /ctf to free sandbox slots.'
      },
      {
        id: 'workspace',
        name: 'Local Contestant Workspace',
        passed: workspaceReady,
        status: workspaceReady ? 'READY' : 'NOT_FOUND',
        detail: workspaceReady
          ? `./ctf-workspace initialized with ${challengeDirs.length} challenge tree(s)`
          : 'Workspace directory ./ctf-workspace does not exist yet. Run scaffolding from the manual.',
        remediation: 'Click "1-Click Scaffold Workspace" below or run: vigilante ctf workspace init'
      }
    ];

    const allPassed = checks.every(c => c.passed);

    return NextResponse.json({
      success: true,
      ready: allPassed,
      timestamp: new Date().toISOString(),
      checks,
      sandboxes: {
        active: activeCount,
        max: 3,
        quotaRemaining
      },
      workspace: {
        path: './ctf-workspace',
        ready: workspaceReady,
        challengeCount: challengeDirs.length,
        challenges: challengeDirs
      }
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
