import { NextResponse } from 'next/server';
import {
  listInstances,
  deleteInstance,
  saveInstanceMetadata
} from 'vigilante_lib/engine/instances.js';
import { loadConfig } from 'vigilante_lib/engine/config.js';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const instances = await listInstances();
    const config = loadConfig();
    const activeCluster = config.defaults?.clusterName || 'vigilante-dev';

    return NextResponse.json({
      success: true,
      activeCluster,
      instances
    });
  } catch (err: any) {
    return NextResponse.json(
      {
        success: false,
        error: err.message,
        instances: []
      },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { instanceName, domain = 'vigilante.local', ip = '127.0.0.1' } = body;

    if (!instanceName) {
      return NextResponse.json({ success: false, error: 'instanceName is required' }, { status: 400 });
    }

    const saved = await saveInstanceMetadata(instanceName, {
      clusterName: instanceName,
      domain,
      ip,
      createdAt: new Date().toISOString()
    });

    return NextResponse.json({
      success: true,
      saved
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}

export async function DELETE(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const instanceName = searchParams.get('instanceName');
    const deleteCluster = searchParams.get('deleteCluster') === 'true';

    if (!instanceName) {
      return NextResponse.json({ success: false, error: 'instanceName is required' }, { status: 400 });
    }

    await deleteInstance(instanceName, { deleteCluster });
    return NextResponse.json({ success: true, deleted: instanceName });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
