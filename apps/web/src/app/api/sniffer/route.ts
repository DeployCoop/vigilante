import { NextResponse } from 'next/server';
import {
  dissectFullPacket,
  filterPacket,
  formatHexDump,
  generateSyntheticPacketStream,
  exportToPcap
} from 'vigilante_lib/engine/sniffer.js';
import path from 'node:path';
import os from 'node:os';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  const denied = await authorizeRequest(request, 'telemetry:read');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(request.url);

    const filter = searchParams.get('filter') || '';
    const count = parseInt(searchParams.get('count') || '15', 10);

    const buffers = generateSyntheticPacketStream(count);
    const rawPackets = buffers.map((buf: Buffer, idx: number) => {
      const pkt = dissectFullPacket(buf, idx + 1);
      const hexDump = formatHexDump(buf);
      
      // Clean up Buffers for JSON serialization
      return {
        id: pkt.id,
        index: pkt.id,
        timestamp: pkt.timestamp,
        src: pkt.src,
        dst: pkt.dst,
        protocol: pkt.protocol,
        length: pkt.length,
        info: pkt.info,
        ethernet: {
          srcMac: pkt.ethernet?.srcMac,
          dstMac: pkt.ethernet?.dstMac,
          typeName: pkt.ethernet?.typeName
        },
        ip: pkt.ip ? {
          srcIp: pkt.ip.srcIp,
          dstIp: pkt.ip.dstIp,
          protocolName: pkt.ip.protocolName,
          ttl: pkt.ip.ttl
        } : null,
        tcp: pkt.tcp ? {
          srcPort: pkt.tcp.srcPort,
          dstPort: pkt.tcp.dstPort,
          flags: pkt.tcp.flags,
          seqNumber: pkt.tcp.seqNumber,
          ackNumber: pkt.tcp.ackNumber
        } : null,
        udp: pkt.udp ? {
          srcPort: pkt.udp.srcPort,
          dstPort: pkt.udp.dstPort,
          length: pkt.udp.length
        } : null,
        dns: pkt.dns,
        tls: pkt.tls,
        hexDump
      };
    });

    const filtered = filter ? rawPackets.filter((p) => filterPacket(p, filter)) : rawPackets;

    return NextResponse.json({
      success: true,
      packets: filtered,
      totalCount: rawPackets.length
    });
  } catch (err: unknown) {
    return NextResponse.json(
      {
        success: false,
        error: errorMessage(err),
        packets: []
      },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  const denied = await authorizeRequest(request, 'telemetry:write');
  if (denied) return denied;

  try {
    const body = await request.json();

    const { count = 20 } = body;

    const buffers = generateSyntheticPacketStream(count);
    const packets = buffers.map((buf: Buffer, i: number) => dissectFullPacket(buf, i + 1));
    const pcapPath = path.join(os.tmpdir(), `vigilante-capture-${Date.now()}.pcap`);
    const bytes = await exportToPcap(packets, pcapPath);

    return NextResponse.json({
      success: true,
      pcapPath,
      bytesWritten: bytes,
      packetCount: packets.length
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
