import { NextRequest } from 'next/server';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    start(controller) {
      // Send initial connection packet
      controller.enqueue(encoder.encode(`event: connected\ndata: ${JSON.stringify({ status: 'connected', time: new Date().toISOString() })}\n\n`));

      const samples = [
        {
          source: 'falco',
          severity: 'CRITICAL',
          rule: 'Terminal Shell Spawned in Container',
          container: 'web-sqli-portal-pod',
          message: 'Bash process spawned by unprivileged user (UID 1000) under /var/www/html',
          time: new Date().toISOString()
        },
        {
          source: 'suricata',
          severity: 'HIGH',
          rule: 'ET EXPLOIT Possible SQL Injection UNION SELECT in URI',
          srcIp: '198.51.100.42',
          destIp: '10.0.1.5',
          message: 'GET /api/search?q=%27%20UNION%20SELECT%201,flag,3%20FROM%20secrets--',
          time: new Date().toISOString()
        },
        {
          source: 'zeek',
          severity: 'MEDIUM',
          rule: 'DNS Tunneling / High Entropy Subdomain Queries',
          srcIp: '10.0.1.12',
          destIp: '8.8.8.8',
          message: 'Query: 6162633132332e657866696c.attacker.c2 (Entropy: 4.82 bits/byte)',
          time: new Date().toISOString()
        },
        {
          source: 'falco',
          severity: 'HIGH',
          rule: 'Read Sensitive File Untrusted (/etc/shadow)',
          container: 'kctf-pwn-nsjail-pod',
          message: 'Attempt to open /etc/shadow in read-only mode by process "exploit_runner"',
          time: new Date().toISOString()
        }
      ];

      let idx = 0;
      const interval = setInterval(() => {
        const item = samples[idx % samples.length];
        const eventData = {
          ...item,
          id: `evt-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
          time: new Date().toISOString()
        };
        try {
          controller.enqueue(encoder.encode(`event: telemetry\ndata: ${JSON.stringify(eventData)}\n\n`));
          idx++;
        } catch {
          clearInterval(interval);
        }
      }, 3500);

      req.signal.addEventListener('abort', () => {
        clearInterval(interval);
        controller.close();
      });
    }
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive'
    }
  });
}
