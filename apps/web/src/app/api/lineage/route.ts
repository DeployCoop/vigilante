import { NextResponse } from 'next/server';
import {
  buildProcessLineageTree,
  detectAnomalousProcessLineage,
  renderAsciiProcessTree
} from 'vigilante_lib/engine/lineage.js';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const sampleEvents = [
      { pid: 1, ppid: 0, comm: 'systemd', user: 'root', podName: 'host' },
      { pid: 100, ppid: 1, comm: 'containerd', user: 'root', podName: 'host' },
      { pid: 200, ppid: 100, comm: 'nginx', args: ['-g', 'daemon off;'], user: 'www-data', podName: 'ingress-nginx-4b7' },
      { pid: 250, ppid: 200, comm: '/bin/sh', args: ['-i'], user: 'www-data', podName: 'ingress-nginx-4b7' },
      { pid: 310, ppid: 250, comm: 'curl', args: ['-s', 'http://169.254.169.254/latest/meta-data/'], user: 'www-data', podName: 'ingress-nginx-4b7' },
      { pid: 320, ppid: 250, comm: 'cat', args: ['/var/run/secrets/kubernetes.io/serviceaccount/token'], user: 'www-data', podName: 'ingress-nginx-4b7' },
      { pid: 400, ppid: 100, comm: 'kubelet', user: 'root', podName: 'host' }
    ];

    const tree = buildProcessLineageTree(sampleEvents);
    const anomalies = detectAnomalousProcessLineage(tree);
    const ascii = tree.roots && tree.roots.length > 0 ? renderAsciiProcessTree(tree.roots[0]) : '';

    return NextResponse.json({
      success: true,
      tree,
      anomalies,
      ascii
    });
  } catch (err: any) {
    return NextResponse.json(
      {
        success: false,
        error: err.message
      },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { events = [] } = body;

    const tree = buildProcessLineageTree(events);
    const anomalies = detectAnomalousProcessLineage(tree);
    const ascii = tree.roots && tree.roots.length > 0 ? renderAsciiProcessTree(tree.roots[0]) : '';

    return NextResponse.json({
      success: true,
      tree,
      anomalies,
      ascii
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
