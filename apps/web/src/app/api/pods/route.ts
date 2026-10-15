import { NextResponse } from 'next/server';
import { getPodsWide } from 'vigilante_lib/engine/pods.js';
import { loadConfig } from 'vigilante_lib/engine/config.js';
import { execa } from 'execa';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const namespace = searchParams.get('namespace') || null;
    const podName = searchParams.get('pod');
    const action = searchParams.get('action'); // 'describe' | 'logs'
    const container = searchParams.get('container') || undefined;

    const config = loadConfig();
    const clusterName = config.defaults?.clusterName || 'vigilante-dev';

    // If specific pod action requested (logs or describe)
    if (podName && namespace && action) {
      if (action === 'logs') {
        const args = ['logs', podName, '-n', namespace, '--tail=150', '--context', `k3d-${clusterName}`];
        if (container) args.push('-c', container);
        const { stdout, stderr } = await execa('kubectl', args).catch((err: any) => ({
          stdout: '',
          stderr: err.message
        }));
        return NextResponse.json({
          success: true,
          output: stdout || stderr || '(No logs returned)'
        });
      }

      if (action === 'describe') {
        const args = ['describe', 'pod', podName, '-n', namespace, '--context', `k3d-${clusterName}`];
        const { stdout, stderr } = await execa('kubectl', args).catch((err: any) => ({
          stdout: '',
          stderr: err.message
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

    const namespaces = Array.from(new Set(pods.map((p: any) => p.namespace))).sort();

    return NextResponse.json({
      success: true,
      clusterName,
      namespaces,
      pods
    });
  } catch (err: any) {
    return NextResponse.json(
      {
        success: false,
        error: err.message,
        pods: [],
        namespaces: []
      },
      { status: 500 }
    );
  }
}
