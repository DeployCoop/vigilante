import { NextResponse } from 'next/server';
import {
  listActiveCanaries,
  triggerCanaryAlarm,
  generateDecoyDeploymentYaml,
  generateCanarySecret,
  generateCanaryServiceAccount
} from 'vigilante_lib/engine/deception.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const denied = await authorizeRequest(req, 'telemetry:read');
  if (denied) return denied;

  try {
    const canaries = await listActiveCanaries();
    return NextResponse.json({
      success: true,
      canaries
    });
  } catch (err: unknown) {
    return NextResponse.json(
      {
        success: false,
        error: errorMessage(err),
        canaries: []
      },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  const denied = await authorizeRequest(request, 'simulations:run');
  if (denied) return denied;

  try {
    const body = await request.json();

    const { action = 'deploy', canaryId, type = 'smb', name, namespace = 'default' } = body;

    if (action === 'alarm') {
      if (!canaryId) {
        return NextResponse.json({ success: false, error: 'canaryId is required for alarm' }, { status: 400 });
      }
      const alarmResult = await triggerCanaryAlarm(canaryId, {
        attackerIp: '198.51.100.77',
        triggerAction: 'Simulated Tripwire Access',
        autoContain: true
      });
      return NextResponse.json({ success: true, alarmResult });
    }

    // Deploy or generate canary manifests
    let result: string | null = null;
    if (type === 'sa' || type === 'serviceaccount') {
      result = generateCanaryServiceAccount(name || 'cluster-admin-backup', namespace);
    } else if (type === 'secret' || type === 'token') {
      result = generateCanarySecret(name || 'production-db-credentials', namespace);
    } else {
      result = generateDecoyDeploymentYaml(type, { name, namespace });
    }

    return NextResponse.json({
      success: true,
      manifest: result
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
