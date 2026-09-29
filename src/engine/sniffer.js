/**
 * VIGILANTE Terminal Live Packet Sniffer & Protocol Dissector Engine
 * Pure Node.js zero-dependency network packet dissection,
 * Ethernet/IPv4/TCP/UDP/DNS/TLS layer decoding, BPF-style filtering,
 * hex dump formatting, and PCAP file exporter.
 */

import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { logger } from '../utils/logger.js';

export const ETHER_TYPES = {
  IPV4: 0x0800,
  ARP: 0x0806,
  IPV6: 0x86dd
};

export const IP_PROTOCOLS = {
  ICMP: 1,
  TCP: 6,
  UDP: 17
};

/**
 * Format MAC address from 6-byte buffer
 */
function formatMac(buf, offset = 0) {
  const parts = [];
  for (let i = 0; i < 6; i++) {
    parts.push(buf[offset + i].toString(16).padStart(2, '0'));
  }
  return parts.join(':');
}

/**
 * Dissect Ethernet II Frame
 * @param {Buffer} buf
 * @returns {Object}
 */
export function dissectEthernetFrame(buf) {
  if (!buf || buf.length < 14) return null;

  const dstMac = formatMac(buf, 0);
  const srcMac = formatMac(buf, 6);
  const etherType = buf.readUInt16BE(12);
  const payload = buf.subarray(14);

  let typeName = 'UNKNOWN';
  if (etherType === ETHER_TYPES.IPV4) typeName = 'IPv4';
  else if (etherType === ETHER_TYPES.IPV6) typeName = 'IPv6';
  else if (etherType === ETHER_TYPES.ARP) typeName = 'ARP';

  return {
    srcMac,
    dstMac,
    etherType,
    typeName,
    payload
  };
}

/**
 * Dissect IPv4 Packet
 * @param {Buffer} buf
 * @returns {Object}
 */
export function dissectIpPacket(buf) {
  if (!buf || buf.length < 20) return null;

  const version = buf[0] >> 4;
  if (version !== 4) return null;

  const ihl = (buf[0] & 0x0f) * 4;
  const totalLength = buf.readUInt16BE(2);
  const ttl = buf[8];
  const protocol = buf[9];

  const srcIp = `${buf[12]}.${buf[13]}.${buf[14]}.${buf[15]}`;
  const dstIp = `${buf[16]}.${buf[17]}.${buf[18]}.${buf[19]}`;
  const payload = buf.subarray(ihl);

  let protoName = 'UNKNOWN';
  if (protocol === IP_PROTOCOLS.TCP) protoName = 'TCP';
  else if (protocol === IP_PROTOCOLS.UDP) protoName = 'UDP';
  else if (protocol === IP_PROTOCOLS.ICMP) protoName = 'ICMP';

  return {
    version: 4,
    ihl,
    totalLength,
    ttl,
    protocol,
    protoName,
    srcIp,
    dstIp,
    payload
  };
}

/**
 * Dissect TCP Segment
 * @param {Buffer} buf
 * @returns {Object}
 */
export function dissectTcpSegment(buf) {
  if (!buf || buf.length < 20) return null;

  const srcPort = buf.readUInt16BE(0);
  const dstPort = buf.readUInt16BE(2);
  const seqNum = buf.readUInt32BE(4);
  const ackNum = buf.readUInt32BE(8);
  const dataOffset = (buf[12] >> 4) * 4;
  const flagsByte = buf[13];

  const flags = {
    FIN: (flagsByte & 0x01) !== 0,
    SYN: (flagsByte & 0x02) !== 0,
    RST: (flagsByte & 0x04) !== 0,
    PSH: (flagsByte & 0x08) !== 0,
    ACK: (flagsByte & 0x10) !== 0,
    URG: (flagsByte & 0x20) !== 0
  };

  const activeFlags = Object.keys(flags).filter(k => flags[k]).join(',');
  const windowSize = buf.readUInt16BE(14);
  const payload = buf.subarray(dataOffset);

  return {
    srcPort,
    dstPort,
    seqNum,
    ackNum,
    dataOffset,
    flags,
    activeFlags,
    windowSize,
    payload
  };
}

/**
 * Dissect UDP Datagram
 * @param {Buffer} buf
 * @returns {Object}
 */
export function dissectUdpDatagram(buf) {
  if (!buf || buf.length < 8) return null;

  const srcPort = buf.readUInt16BE(0);
  const dstPort = buf.readUInt16BE(2);
  const length = buf.readUInt16BE(4);
  const payload = buf.subarray(8, Math.min(buf.length, length));

  return {
    srcPort,
    dstPort,
    length,
    payload
  };
}

/**
 * Dissect DNS Payload
 * @param {Buffer} buf
 * @returns {Object}
 */
export function dissectDnsPayload(buf) {
  if (!buf || buf.length < 12) return null;

  const id = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  const isResponse = (flags >> 15) === 1;
  const qdCount = buf.readUInt16BE(4);
  const anCount = buf.readUInt16BE(6);

  // Parse first Question QNAME
  let qname = '';
  let offset = 12;
  while (offset < buf.length) {
    const len = buf[offset];
    if (len === 0) {
      offset += 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      // Compression pointer
      offset += 2;
      break;
    }
    offset += 1;
    if (offset + len <= buf.length) {
      const label = buf.subarray(offset, offset + len).toString('ascii');
      qname = qname ? `${qname}.${label}` : label;
      offset += len;
    } else {
      break;
    }
  }

  let qtype = 1; // A record default
  if (offset + 2 <= buf.length) {
    qtype = buf.readUInt16BE(offset);
  }

  let qtypeName = 'A';
  if (qtype === 28) qtypeName = 'AAAA';
  else if (qtype === 15) qtypeName = 'MX';
  else if (qtype === 16) qtypeName = 'TXT';
  else if (qtype === 5) qtypeName = 'CNAME';

  return {
    id,
    isResponse,
    qdCount,
    anCount,
    queryName: qname || 'unknown.domain',
    queryType: qtypeName
  };
}

/**
 * Dissect TLS Client Hello and Handshake
 * @param {Buffer} buf
 * @returns {Object}
 */
export function dissectTlsPayload(buf) {
  if (!buf || buf.length < 5) return null;

  const contentType = buf[0];
  if (contentType !== 22) return null; // 22 = Handshake

  const version = buf.readUInt16BE(1);
  const length = buf.readUInt16BE(3);

  if (buf.length < 9) return null;
  const handshakeType = buf[5]; // 1 = Client Hello

  let sni = null;
  if (handshakeType === 1 && buf.length > 43) {
    // Scan for SNI extension (extension type 0x0000)
    for (let i = 43; i < buf.length - 8; i++) {
      if (buf[i] === 0x00 && buf[i + 1] === 0x00) {
        const extLen = buf.readUInt16BE(i + 2);
        if (extLen >= 5 && i + 4 + extLen <= buf.length) {
          const listLen = buf.readUInt16BE(i + 4);
          if (listLen + 2 === extLen && buf[i + 6] === 0x00) {
            const nameLen = buf.readUInt16BE(i + 7);
            if (nameLen + 3 === listLen && i + 9 + nameLen <= buf.length) {
              sni = buf.subarray(i + 9, i + 9 + nameLen).toString('utf8');
              break;
            }
          }
        }
      }
    }
  }

  return {
    contentType: 'Handshake',
    handshakeType: handshakeType === 1 ? 'Client Hello' : 'Server Hello / Other',
    tlsVersion: version === 0x0303 ? 'TLS 1.2' : version === 0x0304 ? 'TLS 1.3' : 'TLS',
    sni
  };
}

/**
 * Dissect a complete raw network packet through all protocol layers
 * @param {Buffer} rawBuf
 * @param {number} [packetIndex=1]
 * @returns {Object} Fully decoded packet
 */
export function dissectFullPacket(rawBuf, packetIndex = 1) {
  const buf = Buffer.isBuffer(rawBuf) ? rawBuf : Buffer.from(rawBuf);
  const timestamp = Date.now();

  const eth = dissectEthernetFrame(buf);
  let ip = null;
  let transport = null;
  let app = null;
  let protocol = 'ETHERNET';
  let src = eth?.srcMac || 'unknown';
  let dst = eth?.dstMac || 'unknown';
  let summary = `Frame length ${buf.length} bytes`;

  if (eth && eth.etherType === ETHER_TYPES.IPV4 && eth.payload) {
    ip = dissectIpPacket(eth.payload);
    if (ip) {
      src = ip.srcIp;
      dst = ip.dstIp;
      protocol = ip.protoName;

      if (ip.protocol === IP_PROTOCOLS.TCP && ip.payload) {
        transport = dissectTcpSegment(ip.payload);
        if (transport) {
          src = `${ip.srcIp}:${transport.srcPort}`;
          dst = `${ip.dstIp}:${transport.dstPort}`;
          summary = `TCP ${transport.activeFlags || 'NO_FLAGS'} Seq=${transport.seqNum} Ack=${transport.ackNum} Win=${transport.windowSize}`;

          // Check TLS
          if (transport.payload && transport.payload.length > 5 && transport.payload[0] === 22) {
            app = dissectTlsPayload(transport.payload);
            if (app) {
              protocol = 'TLS';
              summary = `${app.handshakeType} ${app.sni ? `SNI=${app.sni}` : ''} (${app.tlsVersion})`.trim();
            }
          } else if (transport.payload && transport.payload.length > 4) {
            const firstChars = transport.payload.subarray(0, 8).toString('ascii');
            if (firstChars.startsWith('GET') || firstChars.startsWith('POST') || firstChars.startsWith('HTTP')) {
              protocol = 'HTTP';
              summary = firstChars.split('\r\n')[0].substring(0, 48);
            }
          }
        }
      } else if (ip.protocol === IP_PROTOCOLS.UDP && ip.payload) {
        transport = dissectUdpDatagram(ip.payload);
        if (transport) {
          src = `${ip.srcIp}:${transport.srcPort}`;
          dst = `${ip.dstIp}:${transport.dstPort}`;
          summary = `UDP Len=${transport.length}`;

          // Check DNS (standard port 53)
          if (transport.srcPort === 53 || transport.dstPort === 53) {
            app = dissectDnsPayload(transport.payload);
            if (app) {
              protocol = 'DNS';
              summary = `Standard query ${app.isResponse ? 'response' : ''} ${app.queryType} ${app.queryName}`;
            }
          }
        }
      }
    }
  }

  return {
    index: packetIndex,
    timestamp,
    length: buf.length,
    protocol,
    src,
    dst,
    summary,
    layers: {
      ethernet: eth,
      ip,
      transport,
      app
    },
    rawBuffer: buf
  };
}

/**
 * Filter packet against boolean expression (e.g. 'tcp', 'dns', 'port 443', 'ip.src == 10.0.0.1')
 * @param {Object} packet
 * @param {string} filterExpr
 * @returns {boolean}
 */
export function filterPacket(packet, filterExpr = '') {
  const f = (filterExpr || '').trim().toLowerCase();
  if (!f) return true;

  if (f === 'tcp') return packet.protocol === 'TCP' || packet.layers.ip?.protoName === 'TCP';
  if (f === 'udp') return packet.protocol === 'UDP' || packet.layers.ip?.protoName === 'UDP';
  if (f === 'dns') return packet.protocol === 'DNS';
  if (f === 'tls') return packet.protocol === 'TLS';
  if (f === 'http') return packet.protocol === 'HTTP';

  if (f.startsWith('port ')) {
    const port = f.replace('port ', '').trim();
    return packet.src.includes(`:${port}`) || packet.dst.includes(`:${port}`);
  }

  if (f.startsWith('host ')) {
    const host = f.replace('host ', '').trim();
    return packet.src.includes(host) || packet.dst.includes(host);
  }

  return packet.summary.toLowerCase().includes(f) || 
         packet.src.toLowerCase().includes(f) || 
         packet.dst.toLowerCase().includes(f);
}

/**
 * Format binary buffer into classic Wireshark-style Hex + ASCII representation
 * @param {Buffer} buf
 * @param {number} [maxBytes=128]
 * @returns {string} Formatted hex string
 */
export function formatHexDump(buf, maxBytes = 128) {
  if (!buf) return '';
  const slice = buf.subarray(0, maxBytes);
  const lines = [];

  for (let i = 0; i < slice.length; i += 16) {
    const chunk = slice.subarray(i, i + 16);
    const hex = [];
    const ascii = [];

    for (let j = 0; j < 16; j++) {
      if (j < chunk.length) {
        const b = chunk[j];
        hex.push(b.toString(16).padStart(2, '0'));
        ascii.push(b >= 32 && b <= 126 ? String.fromCharCode(b) : '.');
      } else {
        hex.push('  ');
        ascii.push(' ');
      }
    }

    const offsetStr = i.toString(16).padStart(4, '0');
    const hexStr1 = hex.slice(0, 8).join(' ');
    const hexStr2 = hex.slice(8, 16).join(' ');
    lines.push(`${offsetStr}   ${hexStr1}  ${hexStr2}   |${ascii.join('')}|`);
  }

  if (buf.length > maxBytes) {
    lines.push(`... [${buf.length - maxBytes} additional bytes omitted]`);
  }

  return lines.join('\n');
}

/**
 * Export packets to standard Global PCAP format
 * @param {Array<Object>} packets Decoded packet objects
 * @param {string} filePath
 * @returns {Promise<number>} Bytes written
 */
export async function exportToPcap(packets = [], filePath) {
  if (!filePath) throw new Error('Target filePath required for PCAP export');

  const globalHeader = Buffer.alloc(24);
  globalHeader.writeUInt32BE(0xa1b2c3d4, 0); // Magic number
  globalHeader.writeUInt16BE(2, 4);          // Version major (2)
  globalHeader.writeUInt16BE(4, 6);          // Version minor (4)
  globalHeader.writeInt32BE(0, 8);           // Timezone offset
  globalHeader.writeUInt32BE(0, 12);         // Timestamp accuracy
  globalHeader.writeUInt32BE(65535, 16);     // Snaplen
  globalHeader.writeUInt32BE(1, 20);         // Linktype: 1 = Ethernet

  const chunks = [globalHeader];

  for (const pkt of packets) {
    const raw = pkt.rawBuffer || Buffer.alloc(14);
    const pcapPktHeader = Buffer.alloc(16);
    const sec = Math.floor(pkt.timestamp / 1000);
    const usec = (pkt.timestamp % 1000) * 1000;

    pcapPktHeader.writeUInt32BE(sec, 0);
    pcapPktHeader.writeUInt32BE(usec, 4);
    pcapPktHeader.writeUInt32BE(raw.length, 8);  // Captured length
    pcapPktHeader.writeUInt32BE(raw.length, 12); // Original length

    chunks.push(pcapPktHeader);
    chunks.push(raw);
  }

  const finalBuf = Buffer.concat(chunks);
  await fs.writeFile(filePath, finalBuf);
  return finalBuf.length;
}

/**
 * Generate synthetic network packets for testing & unprivileged environments
 * @param {number} [count=5]
 * @returns {Array<Buffer>}
 */
export function generateSyntheticPacketStream(count = 5) {
  const packets = [];

  // Packet 1: DNS Query for api.c2-exfil.com
  const dnsBuf = Buffer.concat([
    // Ethernet Header (14 bytes)
    Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00]),
    // IPv4 Header (20 bytes: src 10.0.0.5, dst 8.8.8.8, proto 17 UDP)
    Buffer.from([
      0x45, 0x00, 0x00, 0x3c, 0x12, 0x34, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 5, 8, 8, 8, 8
    ]),
    // UDP Header (8 bytes: src port 54321, dst port 53, len 40)
    Buffer.from([0xd4, 0x31, 0x00, 0x35, 0x00, 0x28, 0x00, 0x00]),
    // DNS Payload (Transaction ID 0x1337, Query: api.c2-exfil.com)
    Buffer.from([
      0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x03, 0x61, 0x70, 0x69, 0x08, 0x63, 0x32, 0x2d, 0x65, 0x78, 0x66, 0x69, 0x6c, 0x03, 0x63, 0x6f, 0x6d, 0x00,
      0x00, 0x01, 0x00, 0x01
    ])
  ]);
  packets.push(dnsBuf);

  // Packet 2: TCP SYN to Port 443
  const tcpSynBuf = Buffer.concat([
    Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00]),
    Buffer.from([
      0x45, 0x00, 0x00, 0x28, 0x22, 0x22, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
      10, 0, 0, 5, 198, 51, 100, 42
    ]),
    // TCP Header (20 bytes: src 45678, dst 443, flags SYN 0x02)
    Buffer.from([
      0xb2, 0x6e, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x50, 0x02, 0x72, 0x10, 0x00, 0x00, 0x00, 0x00
    ])
  ]);
  packets.push(tcpSynBuf);

  // Packet 3: TLS Client Hello with SNI: evil-c2.net
  const tlsBuf = Buffer.concat([
    Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00]),
    Buffer.from([
      0x45, 0x00, 0x00, 0x55, 0x33, 0x33, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
      10, 0, 0, 5, 198, 51, 100, 42
    ]),
    Buffer.from([
      0xb2, 0x6e, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
      0x50, 0x18, 0x72, 0x10, 0x00, 0x00, 0x00, 0x00
    ]),
    // TLS Record Header (Type 22 Handshake, TLS 1.2 0x0303)
    Buffer.from([0x16, 0x03, 0x03, 0x00, 0x23]),
    // Handshake: Client Hello (Type 1)
    Buffer.from([0x01, 0x00, 0x00, 0x1f, 0x03, 0x03]),
    Buffer.alloc(32, 0xaa), // Random
    Buffer.from([0x00]),    // Session ID len
    Buffer.from([0x00, 0x02, 0x13, 0x01]), // Cipher Suites
    Buffer.from([0x01, 0x00]), // Compression
    // Extension: Server Name Indication (0x0000)
    Buffer.from([
      0x00, 0x00, 0x00, 0x10,
      0x00, 0x0e, 0x00, 0x00, 0x0b,
      0x65, 0x76, 0x69, 0x6c, 0x2d, 0x63, 0x32, 0x2e, 0x6e, 0x65, 0x74
    ])
  ]);
  packets.push(tlsBuf);

  return packets.slice(0, count);
}
