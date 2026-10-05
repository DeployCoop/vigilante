import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import { logger } from '../utils/logger.js';

export const SLA_STATUS = {
  UP: 'UP',
  FAULTY: 'FAULTY',
  DOWN: 'DOWN'
};

export const AD_TICK_PHASES = {
  IDLE: 'IDLE',
  TICK_PREPARE: 'TICK_PREPARE',
  FLAG_INJECT: 'FLAG_INJECT',
  SLA_CHECK: 'SLA_CHECK',
  POINT_CALCULATION: 'POINT_CALCULATION',
  TICK_COMPLETE: 'TICK_COMPLETE'
};

/**
 * Generate a deterministic tick-scoped flag for an Attack-Defense service
 */
export function generateAdTickFlag({
  teamId,
  serviceId,
  tick,
  secretKey = 'vigilante-ad-secret'
}) {
  const hmac = crypto.createHmac('sha256', secretKey);
  hmac.update(`${teamId}:${serviceId}:${tick}`);
  const token = hmac.digest('hex').slice(0, 16);
  return `VIGILANTE{ad__${serviceId}__${teamId}__t${tick}__${token}}`;
}

/**
 * Parse an Attack-Defense flag into its components
 */
export function parseAdFlag(flagString) {
  if (!flagString || typeof flagString !== 'string') return null;
  const match = flagString.trim().match(/^VIGILANTE\{ad__(.+)__(.+)__t(\d+)__([a-f0-9]+)\}$/);
  if (!match) return null;
  return {
    serviceId: match[1],
    teamId: match[2],
    tick: parseInt(match[3], 10),
    token: match[4]
  };
}

/**
 * Autonomous Attack-Defense Tournament Runner & SLA Engine
 */
export class AttackDefenseRunner {
  constructor({
    tournamentEngine,
    tickDurationSeconds = 120,
    slaTimeoutMs = 1500,
    defensePointsPerTick = 100,
    attackPointsPerCapture = 150,
    slaPenaltyDown = 50,
    slaPenaltyFaulty = 25,
    flagGraceTicks = 1,
    mockProbes = true
  } = {}) {
    if (!tournamentEngine) {
      throw new Error('TournamentEngine instance is required by AttackDefenseRunner');
    }

    this.tournament = tournamentEngine;
    this.tickDurationSeconds = tickDurationSeconds;
    this.slaTimeoutMs = slaTimeoutMs;
    this.defensePointsPerTick = defensePointsPerTick;
    this.attackPointsPerCapture = attackPointsPerCapture;
    this.slaPenaltyDown = slaPenaltyDown;
    this.slaPenaltyFaulty = slaPenaltyFaulty;
    this.flagGraceTicks = flagGraceTicks;
    this.mockProbes = mockProbes;

    this.isRunning = false;
    this.timer = null;
    this.currentPhase = AD_TICK_PHASES.IDLE;

    // Services registered for AD
    this.services = [
      {
        id: 'ad-service-vault',
        name: 'Secure Vault Storage',
        port: 9200,
        protocol: 'HTTP',
        healthEndpoint: '/health',
        apiEndpoint: '/api/secrets'
      }
    ];

    // Injected flags map: key: `${serviceId}:${teamId}:${tick}` -> { flag, injectedAt, captures: [] }
    this.injectedFlags = new Map();

    // Round submission history: set of `${attackerTeamId}:${victimTeamId}:${serviceId}:${tick}`
    this.processedCaptures = new Set();

    // Tick round records
    this.rounds = [];

    // Mock probe overrides for unit testing: map of `${teamId}:${serviceId}` -> { status, latencyMs }
    this.mockProbeOverrides = new Map();

    // Event listeners
    this.eventListeners = [];
  }

  /**
   * Subscribe to runner events (TICK_START, SLA_RESULT, CAPTURE, TICK_COMPLETE)
   */
  onEvent(callback) {
    if (typeof callback === 'function') {
      this.eventListeners.push(callback);
    }
  }

  /**
   * Broadcast an event to subscribers
   */
  broadcast(eventType, payload) {
    const event = {
      type: eventType,
      timestamp: new Date().toISOString(),
      ...payload
    };
    for (const listener of this.eventListeners) {
      try {
        listener(event);
      } catch (err) {
        logger.error('AD_RUNNER:EVENT', `Error in listener: ${err.message}`);
      }
    }
  }

  /**
   * Add a vulnerable service to the Attack-Defense roster
   */
  addService({ id, name, port = 9200, protocol = 'HTTP', healthEndpoint = '/health', apiEndpoint = '/api/secrets' }) {
    if (!id || !name) throw new Error('Service id and name are required');
    this.services.push({ id, name, port, protocol, healthEndpoint, apiEndpoint });
  }

  /**
   * Set mock probe status override for unit testing
   */
  setMockProbeResult(teamId, serviceId, { status = SLA_STATUS.UP, latencyMs = 85 } = {}) {
    this.mockProbeOverrides.set(`${teamId}:${serviceId}`, { status, latencyMs });
  }

  /**
   * Start autonomous tick scheduling
   */
  start() {
    if (this.isRunning) return;
    this.isRunning = true;
    logger.info('AD_RUNNER', `Started Attack-Defense autonomous runner (Tick: ${this.tickDurationSeconds}s)`);
    this.stepTick(); // Run initial tick immediately
    this.timer = setInterval(() => this.stepTick(), this.tickDurationSeconds * 1000);
  }

  /**
   * Stop autonomous tick scheduling
   */
  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.isRunning = false;
    this.currentPhase = AD_TICK_PHASES.IDLE;
    logger.info('AD_RUNNER', 'Stopped Attack-Defense autonomous runner');
  }

  /**
   * Execute a single tick sequentially through all phases
   */
  async stepTick() {
    const currentTick = (this.tournament.adState.currentTick || 0) + 1;
    this.tournament.adState.currentTick = currentTick;

    const tickRecord = {
      tick: currentTick,
      startedAt: new Date().toISOString(),
      services: {}, // teamId -> serviceId -> { slaStatus, latencyMs, capturedCount, defensePoints, attackPoints, penalty }
      captures: [],
      completedAt: null
    };

    // --------------------------------------------------------------------------
    // Phase 1: TICK_PREPARE
    // --------------------------------------------------------------------------
    this.currentPhase = AD_TICK_PHASES.TICK_PREPARE;
    this.broadcast('TICK_START', { tick: currentTick });

    // --------------------------------------------------------------------------
    // Phase 2: FLAG_INJECT (Generate and deposit tick flags)
    // --------------------------------------------------------------------------
    this.currentPhase = AD_TICK_PHASES.FLAG_INJECT;
    const teams = Array.from(this.tournament.teams.values());

    for (const team of teams) {
      tickRecord.services[team.id] = {};
      for (const svc of this.services) {
        const flag = generateAdTickFlag({
          teamId: team.id,
          serviceId: svc.id,
          tick: currentTick,
          secretKey: this.tournament.secretKey
        });

        const key = `${svc.id}:${team.id}:${currentTick}`;
        this.injectedFlags.set(key, {
          flag,
          teamId: team.id,
          serviceId: svc.id,
          tick: currentTick,
          injectedAt: Date.now(),
          capturedBy: []
        });

        tickRecord.services[team.id][svc.id] = {
          flag,
          slaStatus: SLA_STATUS.UP,
          latencyMs: 0,
          capturedBy: [],
          defensePoints: 0,
          attackPoints: 0,
          penalty: 0
        };
      }
    }

    // --------------------------------------------------------------------------
    // Phase 3: SLA_CHECK (Execute autonomous health checks)
    // --------------------------------------------------------------------------
    this.currentPhase = AD_TICK_PHASES.SLA_CHECK;
    for (const team of teams) {
      for (const svc of this.services) {
        const probeResult = await this.probeServiceSla({ team, service: svc });
        tickRecord.services[team.id][svc.id].slaStatus = probeResult.status;
        tickRecord.services[team.id][svc.id].latencyMs = probeResult.latencyMs;

        this.broadcast('SLA_PROBE_COMPLETE', {
          tick: currentTick,
          teamId: team.id,
          teamName: team.name,
          serviceId: svc.id,
          status: probeResult.status,
          latencyMs: probeResult.latencyMs
        });
      }
    }

    // --------------------------------------------------------------------------
    // Phase 4: POINT_CALCULATION (Defense, Attack & SLA scoring)
    // --------------------------------------------------------------------------
    this.currentPhase = AD_TICK_PHASES.POINT_CALCULATION;
    for (const team of teams) {
      for (const svc of this.services) {
        const sRecord = tickRecord.services[team.id][svc.id];
        const isUp = sRecord.slaStatus === SLA_STATUS.UP;
        const isFaulty = sRecord.slaStatus === SLA_STATUS.FAULTY;
        const isDown = sRecord.slaStatus === SLA_STATUS.DOWN;
        const wasCaptured = sRecord.capturedBy.length > 0;

        // Defense points: Awarded if service passed SLA AND was not captured
        if (isUp && !wasCaptured) {
          sRecord.defensePoints = this.defensePointsPerTick;
          team.adDefenseScore += this.defensePointsPerTick;
          team.score += this.defensePointsPerTick;
        }

        // SLA penalties
        if (isDown) {
          sRecord.penalty = this.slaPenaltyDown;
          team.adSlaScore -= this.slaPenaltyDown;
          team.score = Math.max(0, team.score - this.slaPenaltyDown);
        } else if (isFaulty) {
          sRecord.penalty = this.slaPenaltyFaulty;
          team.adSlaScore -= this.slaPenaltyFaulty;
          team.score = Math.max(0, team.score - this.slaPenaltyFaulty);
        }
      }
    }

    // --------------------------------------------------------------------------
    // Phase 5: TICK_COMPLETE
    // --------------------------------------------------------------------------
    this.currentPhase = AD_TICK_PHASES.TICK_COMPLETE;
    tickRecord.completedAt = new Date().toISOString();
    this.rounds.push(tickRecord);
    this.tournament.adState.tickHistory.push(tickRecord);

    this.broadcast('AD_TICK_COMPLETE', {
      tick: currentTick,
      summary: tickRecord
    });

    logger.info('AD_RUNNER', `Tick #${currentTick} finished. Processed ${teams.length} teams.`);
    return tickRecord;
  }

  /**
   * Probe an Attack-Defense service for SLA health
   */
  async probeServiceSla({ team, service }) {
    const overrideKey = `${team.id}:${service.id}`;
    if (this.mockProbeOverrides.has(overrideKey)) {
      return this.mockProbeOverrides.get(overrideKey);
    }

    if (this.mockProbes) {
      // Default mock probe: returns UP with fast simulated latency
      return { status: SLA_STATUS.UP, latencyMs: Math.floor(Math.random() * 40) + 15 };
    }

    return probeServiceSla({
      host: '127.0.0.1',
      port: service.port,
      serviceType: service.protocol || 'HTTP',
      path: service.healthEndpoint || '/',
      timeoutMs: this.slaTimeoutMs
    });
  }

  /**
   * Submit an Attack flag captured from a rival team's service
   */
  submitAttackFlag({ attackerTeamId, flag }) {
    const parsed = parseAdFlag(flag);
    if (!parsed) {
      return { success: false, reason: 'Malformed Attack-Defense flag format' };
    }

    const { serviceId, teamId: victimTeamId, tick: flagTick } = parsed;

    // 1. Verify attacker team exists
    const attackerTeam = this.tournament.teams.get(attackerTeamId);
    if (!attackerTeam) {
      return { success: false, reason: 'Invalid attacker team identifier' };
    }

    // 2. Prevent self-capture
    if (attackerTeamId === victimTeamId) {
      return { success: false, reason: 'Cannot submit flag stolen from your own team' };
    }

    // 3. Verify victim team exists
    const victimTeam = this.tournament.teams.get(victimTeamId);
    if (!victimTeam) {
      return { success: false, reason: 'Victim team does not exist' };
    }

    // 4. Verify flag validity window (creation tick or creation tick + grace)
    const currentTick = this.tournament.adState.currentTick || 1;
    const oldestAllowedTick = currentTick - this.flagGraceTicks;

    if (flagTick < oldestAllowedTick) {
      return { success: false, reason: `Flag expired (Issued in tick ${flagTick}, current tick ${currentTick})` };
    }

    if (flagTick > currentTick) {
      return { success: false, reason: 'Flag is from a future tick' };
    }

    // 5. Verify authentic flag cryptographic signature
    const expectedFlag = generateAdTickFlag({
      teamId: victimTeamId,
      serviceId,
      tick: flagTick,
      secretKey: this.tournament.secretKey
    });

    if (flag.trim() !== expectedFlag) {
      return { success: false, reason: 'Invalid flag signature' };
    }

    // 6. Check duplicate capture: same attacker, victim, service, and tick
    const captureKey = `${attackerTeamId}:${victimTeamId}:${serviceId}:${flagTick}`;
    if (this.processedCaptures.has(captureKey)) {
      return { success: false, reason: 'You have already submitted this flag for this round' };
    }

    // 7. Record capture & award attack points
    this.processedCaptures.add(captureKey);

    const flagRecord = this.injectedFlags.get(`${serviceId}:${victimTeamId}:${flagTick}`);
    if (flagRecord) {
      flagRecord.capturedBy.push(attackerTeamId);
    }

    attackerTeam.adAttackScore += this.attackPointsPerCapture;
    attackerTeam.score += this.attackPointsPerCapture;

    const captureEvent = {
      attackerTeamId,
      attackerTeamName: attackerTeam.name,
      victimTeamId,
      victimTeamName: victimTeam.name,
      serviceId,
      tick: flagTick,
      awardedPoints: this.attackPointsPerCapture,
      timestamp: new Date().toISOString()
    };

    const curRound = this.rounds[this.rounds.length - 1];
    if (curRound) {
      curRound.captures.push(captureEvent);
      if (curRound.services[victimTeamId]?.[serviceId]) {
        curRound.services[victimTeamId][serviceId].capturedBy.push(attackerTeam.name);
      }
    }

    this.broadcast('FLAG_CAPTURED', captureEvent);
    logger.info('AD_RUNNER', `Team '${attackerTeam.name}' attacked '${victimTeam.name}' on '${serviceId}' (+${this.attackPointsPerCapture} pts)`);

    return {
      success: true,
      awardedPoints: this.attackPointsPerCapture,
      attackerTeam: attackerTeam.name,
      victimTeam: victimTeam.name,
      service: serviceId,
      tick: flagTick
    };
  }

  /**
   * Generates a simulated network PCAP trace of adversary traffic targeting a team
   */
  generateAdTrafficPcap({ teamId, tick = null }) {
    const targetTick = tick || this.tournament.adState.currentTick || 1;
    const team = this.tournament.teams.get(teamId);
    const teamName = team ? team.name : teamId;

    // Header buffer for PCAP (Global Header: Magic 0xa1b2c3d4, version 2.4, standard 65535 snaplen)
    const pcapHeader = Buffer.from([
      0xd4, 0xc3, 0xb2, 0xa1, // magic number
      0x02, 0x00,             // major version 2
      0x04, 0x00,             // minor version 4
      0x00, 0x00, 0x00, 0x00, // thiszone GMT
      0x00, 0x00, 0x00, 0x00, // sigfigs
      0xff, 0xff, 0x00, 0x00, // snaplen 65535
      0x01, 0x00, 0x00, 0x00  // network: LINKTYPE_ETHERNET (1)
    ]);

    // Simulated payload string showing adversary exploit attempt and payload
    const mockExploitPayload = Buffer.from(
      `POST /api/secrets HTTP/1.1\r\n` +
      `Host: ${teamId}.ad.vigilante.local\r\n` +
      `User-Agent: Adversary-Exploiter/1.0 (Round ${targetTick})\r\n` +
      `Content-Type: application/json\r\n\r\n` +
      `{"action":"dump_vault","token":"' OR '1'='1"}\r\n`
    );

    const packetLength = mockExploitPayload.length;
    const packetHeader = Buffer.alloc(16);
    const nowSec = Math.floor(Date.now() / 1000);
    packetHeader.writeUInt32LE(nowSec, 0);       // timestamp seconds
    packetHeader.writeUInt32LE(123456, 4);       // timestamp microseconds
    packetHeader.writeUInt32LE(packetLength, 8); // captured length
    packetHeader.writeUInt32LE(packetLength, 12);// untruncated length

    const pcapBuffer = Buffer.concat([pcapHeader, packetHeader, mockExploitPayload]);

    return {
      teamId,
      teamName,
      tick: targetTick,
      byteLength: pcapBuffer.length,
      packetsCount: 1,
      buffer: pcapBuffer,
      contentType: 'application/vnd.tcpdump.pcap',
      filename: `${teamId}_round_${targetTick}_traffic.pcap`
    };
  }
}

/**
 * Direct SLA probe against an HTTP or TCP endpoint
 */
export async function probeServiceSla({
  host = '127.0.0.1',
  port,
  serviceType = 'HTTP',
  path = '/health',
  timeoutMs = 1500
} = {}) {
  const start = Date.now();

  if (serviceType && serviceType.toUpperCase() === 'TCP') {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let timer = setTimeout(() => {
        socket.destroy();
        resolve({ status: SLA_STATUS.DOWN, latencyMs: timeoutMs, target: `${host}:${port}` });
      }, timeoutMs);

      socket.connect(port, host, () => {
        clearTimeout(timer);
        const latencyMs = Date.now() - start;
        socket.destroy();
        resolve({ status: SLA_STATUS.UP, latencyMs, target: `${host}:${port}` });
      });

      socket.on('error', () => {
        clearTimeout(timer);
        resolve({ status: SLA_STATUS.DOWN, latencyMs: Date.now() - start, target: `${host}:${port}` });
      });
    });
  }

  // HTTP probe
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      resolve({ status: SLA_STATUS.DOWN, latencyMs: timeoutMs, target: `http://${host}:${port}${path}` });
    }, timeoutMs);

    const req = http.get(`http://${host}:${port}${path}`, (res) => {
      clearTimeout(timer);
      const latencyMs = Date.now() - start;
      const status = res.statusCode >= 200 && res.statusCode < 300 ? SLA_STATUS.UP : SLA_STATUS.FAULTY;
      resolve({ status, statusCode: res.statusCode, latencyMs, target: `http://${host}:${port}${path}` });
    });

    req.on('error', () => {
      clearTimeout(timer);
      resolve({ status: SLA_STATUS.DOWN, latencyMs: Date.now() - start, target: `http://${host}:${port}${path}` });
    });

    req.setTimeout(timeoutMs, () => {
      req.destroy();
      resolve({ status: SLA_STATUS.DOWN, latencyMs: timeoutMs, target: `http://${host}:${port}${path}` });
    });
  });
}

