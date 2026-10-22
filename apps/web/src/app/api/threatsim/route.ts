import { NextResponse } from 'next/server';
import {
  listAvailablePlaybooks,
  loadPlaybook,
  executeThreatPlaybook
} from 'vigilante_lib/engine/threats.js';
import { loadConfig } from 'vigilante_lib/engine/config.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const denied = await authorizeRequest(req, 'telemetry:read');
  if (denied) return denied;

  try {
    const playbooks = await listAvailablePlaybooks();
    const config = loadConfig();
    const domain = config.defaults?.domain || 'vigilante.local';

    return NextResponse.json({
      success: true,
      domain,
      playbooks
    });
  } catch (err: unknown) {
    return NextResponse.json(
      {
        success: false,
        error: errorMessage(err),
        playbooks: []
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

    const { playbookId, namespace = 'opensearch' } = body;

    if (!playbookId) {
      return NextResponse.json({ success: false, error: 'playbookId is required' }, { status: 400 });
    }

    const playbook = await loadPlaybook(playbookId);
    if (!playbook) {
      return NextResponse.json({ success: false, error: `Playbook ${playbookId} not found` }, { status: 404 });
    }

    const logs: string[] = [];
    const execution = await executeThreatPlaybook({
      playbook,
      namespace,
      onLog: (line: string) => {
        logs.push(line);
      }
    });

    return NextResponse.json({
      success: true,
      execution,
      logs
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
