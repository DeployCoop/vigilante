import { NextResponse } from 'next/server';
import {
  listCarvedFiles,
  carveFilesFromPayload,
  reconstructTcpStreams,
  generateFlowLadder
} from 'vigilante_lib/engine/forensics.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const denied = await authorizeRequest(req, 'forensics:read');
  if (denied) return denied;

  try {
    const files = await listCarvedFiles();

    
    // Generate sample reconstructed streams if none present for interactive inspection
    const samplePackets = [
      { srcIp: '10.42.0.15', srcPort: 49152, dstIp: '10.42.1.22', dstPort: 80, flags: ['SYN'], length: 0 },
      { srcIp: '10.42.1.22', srcPort: 80, dstIp: '10.42.0.15', dstPort: 49152, flags: ['SYN', 'ACK'], length: 0 },
      { srcIp: '10.42.0.15', srcPort: 49152, dstIp: '10.42.1.22', dstPort: 80, flags: ['ACK'], length: 0 },
      { srcIp: '10.42.0.15', srcPort: 49152, dstIp: '10.42.1.22', dstPort: 80, flags: ['PSH', 'ACK'], length: 240 },
      { srcIp: '10.42.1.22', srcPort: 80, dstIp: '10.42.0.15', dstPort: 49152, flags: ['ACK'], length: 0 },
      { srcIp: '10.42.1.22', srcPort: 80, dstIp: '10.42.0.15', dstPort: 49152, flags: ['PSH', 'ACK'], length: 1460 }
    ];

    const streams = reconstructTcpStreams(samplePackets);
    const ladder = streams.length > 0 ? generateFlowLadder(streams[0]) : '';

    return NextResponse.json({
      success: true,
      files,
      streams,
      ladder
    });
  } catch (err: unknown) {
    return NextResponse.json(
      {
        success: false,
        error: errorMessage(err),
        files: []
      },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  const denied = await authorizeRequest(request, 'forensics:run');
  if (denied) return denied;

  try {
    const body = await request.json();

    const { payload } = body;

    if (!payload) {
      return NextResponse.json({ success: false, error: 'Payload data is required' }, { status: 400 });
    }

    const carved = await carveFilesFromPayload(payload);
    return NextResponse.json({
      success: true,
      carved
    });
  } catch (err: unknown) {
    return NextResponse.json(
      {
        success: false,
        error: errorMessage(err)
      },
      { status: 500 }
    );
  }
}
