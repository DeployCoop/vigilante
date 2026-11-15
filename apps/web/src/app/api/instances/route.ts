import { NextResponse } from 'next/server';
import {
  listInstances,
  deleteInstance,
  saveInstanceMetadata
} from 'vigilante_lib/engine/instances.js';
import { loadConfig } from 'vigilante_lib/engine/config.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const denied = await authorizeRequest(req, 'cluster:read');
  if (denied) return denied;

  try {
    const instances = await listInstances();
    const config = loadConfig();
    const activeCluster = config.defaults?.clusterName || 'vigilante-dev';

    return NextResponse.json({
      success: true,
      activeCluster,
      instances
    });
  } catch (err: unknown) {
    return NextResponse.json(
      {
        success: false,
        error: errorMessage(err),
        instances: []
      },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  const denied = await authorizeRequest(request, 'cluster:write');
  if (denied) return denied;

  try {
    const body = await request.json();
    const { instanceName, domain = 'vigilante.local', ip = '127.0.0.1', provider = 'k3d' } = body;

    if (!instanceName) {
      return NextResponse.json({ success: false, error: 'instanceName is required' }, { status: 400 });
    }

    const saved = await saveInstanceMetadata(instanceName, {
      clusterName: instanceName,
      domain,
      ip,
      provider,
      createdAt: new Date().toISOString()
    });

    return NextResponse.json({
      success: true,
      saved
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}

export async function DELETE(request: Request) {
  const denied = await authorizeRequest(request, 'cluster:write');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(request.url);

    const instanceName = searchParams.get('instanceName');
    const deleteCluster = searchParams.get('deleteCluster') === 'true';

    if (!instanceName) {
      return NextResponse.json({ success: false, error: 'instanceName is required' }, { status: 400 });
    }

    await deleteInstance(instanceName, { deleteCluster });
    return NextResponse.json({ success: true, deleted: instanceName });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
