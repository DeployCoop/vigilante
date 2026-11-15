import { NextResponse } from 'next/server';
import { getPodsWide } from 'vigilante_lib/engine/pods.js';
import { loadConfig } from 'vigilante_lib/engine/config.js';
import { resolveKubeContext } from 'vigilante_lib/engine/cluster.js';
import { execa } from 'execa';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const namespace = searchParams.get('namespace') || null;

  const denied = await authorizeRequest(request, 'cluster:read', namespace ? { namespace } : undefined);
  if (denied) return denied;

  try {
    const podName = searchParams.get('pod');

    const action = searchParams.get('action'); // 'describe' | 'logs'
    const container = searchParams.get('container') || undefined;

    const config = loadConfig();
    const clusterName = config.defaults?.clusterName || 'vigilante-dev';

    // If specific pod action requested (logs or describe)
    if (podName && namespace && action) {
      const targetCtx = await resolveKubeContext(clusterName, config.defaults?.clusterProvider);
      const ctxArgs = targetCtx ? ['--context', targetCtx] : [];

      if (action === 'logs') {
        const args = ['logs', podName, '-n', namespace, '--tail=150', ...ctxArgs];
        if (container) args.push('-c', container);
        const { stdout, stderr } = await execa('kubectl', args).catch((err: unknown) => ({
          stdout: '',
          stderr: errorMessage(err)
        }));
        return NextResponse.json({
          success: true,
          output: stdout || stderr || '(No logs returned)'
        });
      }

      if (action === 'describe') {
        const args = ['describe', 'pod', podName, '-n', namespace, ...ctxArgs];
        const { stdout, stderr } = await execa('kubectl', args).catch((err: unknown) => ({
          stdout: '',
          stderr: errorMessage(err)
        }));
        return NextResponse.json({
          success: true,
          output: stdout || stderr || '(Describe output unavailable)'
        });
      }
    }

    // Default: fetch list of pods
    const pods = await getPodsWide({
      clusterName,
      namespace: namespace === 'all' ? null : namespace
    });

    const namespaces = Array.from(new Set(pods.map((p) => p.namespace))).sort();

    return NextResponse.json({
      success: true,
      clusterName,
      namespaces,
      pods
    });
  } catch (err: unknown) {
    return NextResponse.json(
      {
        success: false,
        error: errorMessage(err),
        pods: [],
        namespaces: []
      },
      { status: 500 }
    );
  }
}
