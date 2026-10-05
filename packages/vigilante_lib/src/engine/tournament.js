import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { logger } from '../utils/logger.js';
import { getVigilanteConfigDir } from './config.js';

export const TOURNAMENT_MODES = {
  JEOPARDY: 'jeopardy',
  ATTACK_DEFENSE: 'attack-defense',
  KOTH: 'koth'
};

export const TOURNAMENT_STATES = {
  DRAFT: 'DRAFT',
  REGISTRATION: 'REGISTRATION',
  COUNTDOWN: 'COUNTDOWN',
  ACTIVE: 'ACTIVE',
  FROZEN: 'FROZEN',
  PAUSED: 'PAUSED',
  ENDED: 'ENDED',
  ARCHIVED: 'ARCHIVED'
};

export const FIRST_BLOOD_BONUSES = [
  { rank: 1, multiplier: 0.10, label: 'First Blood (1st)', badge: '🩸' },
  { rank: 2, multiplier: 0.05, label: 'Second Blood (2nd)', badge: '🥈' },
  { rank: 3, multiplier: 0.02, label: 'Third Blood (3rd)', badge: '🥉' }
];

/**
 * Calculates dynamic decay points for a Jeopardy challenge based on total solves
 */
export function calculateDynamicPoints({
  initialPoints = 500,
  minimumPoints = 100,
  decaySolves = 30,
  solveCount = 0
} = {}) {
  if (solveCount <= 1) return initialPoints;
  if (solveCount >= decaySolves) return minimumPoints;

  const pointRange = minimumPoints - initialPoints;
  const decaySquare = decaySolves * decaySolves;
  const currentSolvesSquare = (solveCount - 1) * (solveCount - 1);
  const calculated = Math.floor((pointRange / decaySquare) * currentSolvesSquare + initialPoints);

  return Math.max(minimumPoints, calculated);
}

/**
 * Generates an HMAC-derived per-team dynamic flag to prevent flag sharing
 */
export function generateTeamDynamicFlag({
  teamId,
  challengeId,
  secretKey = 'vigilante-ctf-secret'
}) {
  const hmac = crypto.createHmac('sha256', secretKey);
  hmac.update(`${teamId}:${challengeId}`);
  const digest = hmac.digest('hex').slice(0, 16);
  return `VIGILANTE{${challengeId}_${teamId}_${digest}}`;
}

/**
 * Core Tournament Engine class managing Jeopardy, Attack-Defense, and King of the Hill
 */
export class TournamentEngine {
  constructor({
    id = 'vigilante-cup-2026',
    title = 'Vigilante Cyber Defense CTF Tournament',
    modes = [TOURNAMENT_MODES.JEOPARDY, TOURNAMENT_MODES.ATTACK_DEFENSE, TOURNAMENT_MODES.KOTH],
    activeMode = TOURNAMENT_MODES.JEOPARDY,
    initialPoints = 500,
    minimumPoints = 100,
    decaySolves = 30,
    secretKey = crypto.randomBytes(32).toString('hex')
  } = {}) {
    this.id = id;
    this.title = title;
    this.modes = modes;
    this.activeMode = activeMode;
    this.state = TOURNAMENT_STATES.DRAFT;
    this.initialPoints = initialPoints;
    this.minimumPoints = minimumPoints;
    this.decaySolves = decaySolves;
    this.secretKey = secretKey;

    // Timestamps
    this.createdAt = new Date().toISOString();
    this.startTime = null;
    this.freezeTime = null;
    this.endTime = null;

    // State collections
    this.teams = new Map();
    this.challenges = new Map();
    this.solves = [];
    this.submissions = [];
    this.announcements = [];
    this.alerts = [];

    // Attack-Defense state
    this.adState = {
      currentTick: 0,
      tickDurationSeconds: 120,
      services: [], // [{ id, name, port, defaultFlag }]
      tickHistory: []
    };

    // King of the Hill state
    this.kothState = {
      hills: [
        {
          id: 'citadel-01',
          name: 'The Citadel Core Hill',
          port: 32001,
          category: 'pwn',
          currentKing: null,
          kingSinceTick: null,
          totalReignTicks: {},
          pointsPerTick: 25,
          dethroneBonus: 50
        }
      ],
      currentTick: 0,
      tickDurationSeconds: 30,
      history: []
    };

    // Live Event Bus listeners
    this.eventListeners = [];
  }

  /**
   * Subscribe to tournament events (SOLVE, FIRST_BLOOD, KOTH, TICK, HINT, etc.)
   */
  onEvent(callback) {
    if (typeof callback === 'function') {
      this.eventListeners.push(callback);
    }
  }

  /**
   * Broadcast an event to all subscribers
   */
  broadcastEvent(eventType, payload) {
    const event = {
      type: eventType,
      timestamp: new Date().toISOString(),
      ...payload
    };
    for (const listener of this.eventListeners) {
      try {
        listener(event);
      } catch (err) {
        logger.error('TOURNAMENT:EVENT', `Error in event listener: ${err.message}`);
      }
    }
  }

  /**
   * Register a new team with unique API token and dynamic credentials
   */
  registerTeam({ name, email = null, members = [] }) {
    if (!name || typeof name !== 'string') {
      throw new Error('Valid team name is required');
    }

    const cleanName = name.trim();
    for (const team of this.teams.values()) {
      if (team.name.toLowerCase() === cleanName.toLowerCase()) {
        throw new Error(`Team '${cleanName}' is already registered`);
      }
    }

    const teamId = 'team_' + crypto.randomBytes(4).toString('hex');
    const teamToken = 'tk_' + crypto.randomBytes(16).toString('hex');

    const newTeam = {
      id: teamId,
      name: cleanName,
      email,
      members,
      token: teamToken,
      score: 0,
      jeopardyScore: 0,
      adAttackScore: 0,
      adDefenseScore: 0,
      adSlaScore: 0,
      kothScore: 0,
      lastSolveTimestamp: 0,
      solves: [], // challenge IDs
      submissionsCount: 0,
      instanceCount: 0,
      registeredAt: new Date().toISOString()
    };

    this.teams.set(teamId, newTeam);
    return newTeam;
  }

  /**
   * Get team by ID or token
   */
  getTeam(identifier) {
    if (this.teams.has(identifier)) return this.teams.get(identifier);
    for (const team of this.teams.values()) {
      if (team.token === identifier) return team;
    }
    return null;
  }

  /**
   * Add a challenge to the tournament catalog
   */
  addChallenge({
    id,
    name,
    category = 'web',
    difficulty = 'Easy',
    port = 8080,
    protocol = 'TCP',
    defaultFlag = null,
    isDynamicFlag = true,
    description = '',
    hints = [],
    wave = 1
  }) {
    if (!id || !name) {
      throw new Error('Challenge id and name required');
    }

    const challenge = {
      id,
      name,
      category,
      difficulty,
      port,
      protocol,
      defaultFlag: defaultFlag || `VIGILANTE{${id}_solve}`,
      isDynamicFlag,
      description,
      hints,
      wave,
      released: wave === 1,
      solvesCount: 0,
      currentPoints: this.initialPoints,
      firstBlood: null,
      solves: []
    };

    this.challenges.set(id, challenge);
    return challenge;
  }

  /**
   * Start the tournament
   */
  start({ durationHours = 4, freezeHoursBeforeEnd = 1 } = {}) {
    const now = Date.now();
    this.startTime = now;
    this.endTime = now + durationHours * 3600 * 1000;
    this.freezeTime = this.endTime - freezeHoursBeforeEnd * 3600 * 1000;
    this.state = TOURNAMENT_STATES.ACTIVE;

    this.addAnnouncement({
      title: 'Tournament Started!',
      content: `The tournament is now LIVE! Duration: ${durationHours}h. Good luck competitors.`
    });
  }

  /**
   * Pause the tournament
   */
  pause(reason = 'Administrative Hold') {
    this.state = TOURNAMENT_STATES.PAUSED;
    this.addAnnouncement({
      title: 'Tournament Paused',
      content: `Tournament is temporarily paused: ${reason}`
    });
  }

  /**
   * Resume tournament
   */
  resume() {
    this.state = TOURNAMENT_STATES.ACTIVE;
    this.addAnnouncement({
      title: 'Tournament Resumed',
      content: 'The tournament has resumed. Continue hacking!'
    });
  }

  /**
   * Add announcement
   */
  addAnnouncement({ title, content }) {
    const announcement = {
      id: 'ann_' + Date.now(),
      title,
      content,
      timestamp: new Date().toISOString()
    };
    this.announcements.unshift(announcement);
    return announcement;
  }

  /**
   * Validate and submit a flag from a team
   */
  submitFlag({ teamId, challengeId, flag }) {
    if (this.state !== TOURNAMENT_STATES.ACTIVE && this.state !== TOURNAMENT_STATES.FROZEN) {
      return { success: false, reason: `Tournament is not active (Status: ${this.state})` };
    }

    const team = this.teams.get(teamId);
    if (!team) return { success: false, reason: 'Invalid team identifier' };

    const challenge = this.challenges.get(challengeId);
    if (!challenge) return { success: false, reason: 'Challenge not found' };

    const now = Date.now();
    const cleanFlag = (flag || '').trim();

    // Check duplicate solve
    if (team.solves.includes(challengeId)) {
      return { success: false, reason: 'Challenge already solved by your team' };
    }

    // Rate limiting: max 5 submissions per minute
    const recentSubmissions = this.submissions.filter(
      s => s.teamId === teamId && s.challengeId === challengeId && now - s.timestamp < 60000
    );
    if (recentSubmissions.length >= 5) {
      return { success: false, reason: 'Rate limit exceeded: Please wait before submitting again' };
    }

    team.submissionsCount += 1;

    // Check if team submitted ANOTHER team's dynamic flag (Collusion detection)
    if (challenge.isDynamicFlag) {
      for (const [otherTeamId, otherTeam] of this.teams.entries()) {
        if (otherTeamId === teamId) continue;
        const otherFlag = generateTeamDynamicFlag({
          teamId: otherTeamId,
          challengeId,
          secretKey: this.secretKey
        });
        if (cleanFlag === otherFlag) {
          const alert = {
            id: 'alt_' + Date.now(),
            type: 'COLLUSION_DETECTED',
            severity: 'CRITICAL',
            message: `Flag sharing detected! Team '${team.name}' submitted dynamic flag belonging to Team '${otherTeam.name}' on challenge '${challenge.id}'!`,
            teams: [teamId, otherTeamId],
            challengeId,
            timestamp: new Date().toISOString()
          };
          this.alerts.unshift(alert);
          logger.error('TOURNAMENT:ANTI_CHEAT', alert.message);
          return {
            success: false,
            reason: 'Flag rejected: Security anomaly detected and logged for arbitration'
          };
        }
      }
    }

    // Expected flag check
    const expectedFlag = challenge.isDynamicFlag
      ? generateTeamDynamicFlag({ teamId, challengeId, secretKey: this.secretKey })
      : challenge.defaultFlag;

    const isCorrect = cleanFlag === expectedFlag || cleanFlag === challenge.defaultFlag;

    const submissionRecord = {
      teamId,
      challengeId,
      flag: cleanFlag,
      isCorrect,
      timestamp: now
    };
    this.submissions.push(submissionRecord);

    if (!isCorrect) {
      return { success: false, reason: 'Incorrect flag submitted' };
    }

    // Calculate score & decay
    challenge.solvesCount += 1;
    const basePoints = calculateDynamicPoints({
      initialPoints: this.initialPoints,
      minimumPoints: this.minimumPoints,
      decaySolves: this.decaySolves,
      solveCount: challenge.solvesCount
    });

    challenge.currentPoints = basePoints;

    // First blood check
    let firstBloodBonus = 0;
    let bloodBadge = null;
    if (challenge.solvesCount === 1) {
      firstBloodBonus = Math.floor(basePoints * FIRST_BLOOD_BONUSES[0].multiplier);
      bloodBadge = FIRST_BLOOD_BONUSES[0].badge;
      challenge.firstBlood = team.name;
    } else if (challenge.solvesCount === 2) {
      firstBloodBonus = Math.floor(basePoints * FIRST_BLOOD_BONUSES[1].multiplier);
      bloodBadge = FIRST_BLOOD_BONUSES[1].badge;
    } else if (challenge.solvesCount === 3) {
      firstBloodBonus = Math.floor(basePoints * FIRST_BLOOD_BONUSES[2].multiplier);
      bloodBadge = FIRST_BLOOD_BONUSES[2].badge;
    }

    const earnedPoints = basePoints + firstBloodBonus;

    team.solves.push(challengeId);
    team.jeopardyScore += earnedPoints;
    team.score += earnedPoints;
    team.lastSolveTimestamp = now;

    const solveEvent = {
      teamId,
      teamName: team.name,
      challengeId,
      challengeName: challenge.name,
      category: challenge.category,
      points: earnedPoints,
      basePoints,
      firstBloodBonus,
      bloodBadge,
      timestamp: now,
      isFrozen: this.state === TOURNAMENT_STATES.FROZEN
    };
    this.solves.push(solveEvent);
    challenge.solves.push(solveEvent);

    this.broadcastEvent('SOLVE_EVENT', solveEvent);
    if (firstBloodBonus > 0) {
      this.broadcastEvent('FIRST_BLOOD', {
        ...solveEvent,
        rank: challenge.solvesCount
      });
    }

    return {
      success: true,
      points: earnedPoints,
      basePoints,
      firstBloodBonus,
      bloodBadge,
      totalScore: team.score,
      solvesCount: challenge.solvesCount
    };
  }

  /**
   * Run one Attack-Defense tick (SLA evaluation, attack flag checks, defense awards)
   */
  runAttackDefenseTick({ slaResults = {} } = {}) {
    this.adState.currentTick += 1;
    const tick = this.adState.currentTick;
    const tickData = {
      tick,
      timestamp: new Date().toISOString(),
      events: []
    };

    const defenseAwardPerService = 10;
    const slaAwardPerService = 5;

    for (const [teamId, team] of this.teams.entries()) {
      let teamTickDef = 0;
      let teamTickSla = 0;

      for (const service of this.adState.services) {
        const teamSlaPass = slaResults[`${teamId}_${service.id}`] ?? true;

        if (teamSlaPass) {
          teamTickSla += slaAwardPerService;
          teamTickDef += defenseAwardPerService;
        }
      }

      team.adDefenseScore += teamTickDef;
      team.adSlaScore += teamTickSla;
      team.score += teamTickDef + teamTickSla;

      tickData.events.push({
        teamId,
        teamName: team.name,
        defenseEarned: teamTickDef,
        slaEarned: teamTickSla
      });
    }

    this.adState.tickHistory.push(tickData);
    return tickData;
  }

  /**
   * Claim Hill in King of the Hill (KotH) mode
   */
  claimHill({ hillId = 'citadel-01', teamId, proofToken }) {
    const hill = this.kothState.hills.find(h => h.id === hillId);
    if (!hill) throw new Error(`Hill '${hillId}' not found`);

    const team = this.teams.get(teamId);
    if (!team) throw new Error(`Team '${teamId}' not registered`);

    const prevKing = hill.currentKing;
    if (prevKing === teamId) {
      return { success: true, message: 'You already hold the crown!' };
    }

    let bonus = 0;
    if (prevKing !== null) {
      bonus = hill.dethroneBonus;
      team.kothScore += bonus;
      team.score += bonus;
    }

    hill.currentKing = teamId;
    hill.kingSinceTick = this.kothState.currentTick;

    const claimEvent = {
      hillId,
      newKing: team.name,
      newKingId: teamId,
      previousKing: prevKing ? this.teams.get(prevKing)?.name : null,
      dethroneBonus: bonus,
      tick: this.kothState.currentTick,
      timestamp: new Date().toISOString()
    };

    this.kothState.history.unshift(claimEvent);
    this.broadcastEvent('KOTH_CROWN_CHANGE', claimEvent);
    this.addAnnouncement({
      title: `👑 New King of the Hill on ${hill.name}!`,
      content: `Team '${team.name}' has claimed the crown from ${claimEvent.previousKing || 'the void'}! (+${bonus} pts)`
    });

    return {
      success: true,
      hillId,
      king: team.name,
      dethroneBonus: bonus
    };
  }

  /**
   * Run one King of the Hill tick: awards points to reigning king
   */
  runKothTick() {
    this.kothState.currentTick += 1;
    const tick = this.kothState.currentTick;
    const awards = [];

    for (const hill of this.kothState.hills) {
      if (hill.currentKing) {
        const kingTeam = this.teams.get(hill.currentKing);
        if (kingTeam) {
          kingTeam.kothScore += hill.pointsPerTick;
          kingTeam.score += hill.pointsPerTick;
          hill.totalReignTicks[hill.currentKing] = (hill.totalReignTicks[hill.currentKing] || 0) + 1;

          awards.push({
            hillId: hill.id,
            hillName: hill.name,
            kingId: kingTeam.id,
            kingName: kingTeam.name,
            points: hill.pointsPerTick,
            totalReign: hill.totalReignTicks[hill.currentKing]
          });
        }
      }
    }

    return { tick, awards };
  }

  /**
   * Returns current sorted leaderboard with tie-breaking logic
   */
  getLeaderboard({ revealFrozen = false } = {}) {
    const list = Array.from(this.teams.values()).map(t => ({
      id: t.id,
      name: t.name,
      totalScore: t.score,
      jeopardyScore: t.jeopardyScore,
      adAttackScore: t.adAttackScore,
      adDefenseScore: t.adDefenseScore,
      adSlaScore: t.adSlaScore,
      kothScore: t.kothScore,
      solvesCount: t.solves.length,
      lastSolveTimestamp: t.lastSolveTimestamp
    }));

    // Tie-breaking: Higher score first, earlier lastSolveTimestamp wins ties
    list.sort((a, b) => {
      if (b.totalScore !== a.totalScore) return b.totalScore - a.totalScore;
      return a.lastSolveTimestamp - b.lastSolveTimestamp;
    });

    return list.map((t, idx) => ({ rank: idx + 1, ...t }));
  }

  /**
   * Unlock a progressive Socratic hint for a challenge and apply configured penalty
   */
  unlockHint({ teamId, challengeId, tier = 1 }) {
    const team = this.teams.get(teamId);
    if (!team) throw new Error('Invalid team identifier');

    const challenge = this.challenges.get(challengeId);
    if (!challenge) throw new Error('Challenge not found');

    team.unlockedHints = team.unlockedHints || [];
    const existing = team.unlockedHints.find(h => h.challengeId === challengeId && h.tier === tier);
    if (existing) {
      return { success: true, alreadyUnlocked: true, ...existing };
    }

    // Penalty percentages: Tier 1 = 0%, Tier 2 = 10%, Tier 3 = 25%
    const penaltyRate = tier === 3 ? 0.25 : tier === 2 ? 0.10 : 0.00;
    const basePoints = challenge.currentPoints || this.initialPoints;
    const penaltyPoints = Math.floor(basePoints * penaltyRate);

    team.score = Math.max(0, team.score - penaltyPoints);
    if (team.jeopardyScore !== undefined) {
      team.jeopardyScore = Math.max(0, team.jeopardyScore - penaltyPoints);
    }

    const hintRecord = {
      teamId,
      teamName: team.name,
      challengeId,
      challengeName: challenge.name,
      tier,
      penaltyPoints,
      unlockedAt: new Date().toISOString()
    };

    team.unlockedHints.push(hintRecord);
    this.broadcastEvent('HINT_UNLOCKED', hintRecord);

    logger.info('TOURNAMENT:HINT', `Team '${team.name}' unlocked Tier ${tier} hint on '${challengeId}' (-${penaltyPoints} pts)`);
    return {
      success: true,
      alreadyUnlocked: false,
      ...hintRecord,
      remainingScore: team.score
    };
  }

  /**
   * Get time series score progression points for dynamic graphing
   */
  getScoreProgressionData() {
    const start = this.startTime || Date.now() - 3600000;
    const series = {};

    for (const team of this.teams.values()) {
      series[team.id] = {
        teamId: team.id,
        teamName: team.name,
        points: [{ elapsedMinutes: 0, score: 0 }]
      };
    }

    // Sort all solves chronologically
    const sortedSolves = [...this.solves].sort((a, b) => a.timestamp - b.timestamp);
    const runningScores = {};

    for (const solve of sortedSolves) {
      const elapsedMinutes = Math.max(0, Math.round((solve.timestamp - start) / 60000));
      runningScores[solve.teamId] = (runningScores[solve.teamId] || 0) + solve.points;

      if (series[solve.teamId]) {
        series[solve.teamId].points.push({
          elapsedMinutes,
          score: runningScores[solve.teamId],
          challengeId: solve.challengeId,
          badge: solve.bloodBadge
        });
      }
    }

    // Add current final score point
    const currentElapsed = Math.max(1, Math.round((Date.now() - start) / 60000));
    for (const team of this.teams.values()) {
      const lastPt = series[team.id].points[series[team.id].points.length - 1];
      if (lastPt.elapsedMinutes !== currentElapsed) {
        series[team.id].points.push({
          elapsedMinutes: currentElapsed,
          score: team.score
        });
      }
    }

    return Object.values(series);
  }

  /**
   * Render dynamic SVG polyline line chart showing score progression over tournament elapsed time
   */
  renderScoreCurvesSvg({ width = 700, height = 260 } = {}) {
    const seriesList = this.getScoreProgressionData();
    const margin = { top: 20, right: 120, bottom: 30, left: 50 };
    const chartW = width - margin.left - margin.right;
    const chartH = height - margin.top - margin.bottom;

    let maxScore = 100;
    let maxTime = 10;

    for (const s of seriesList) {
      for (const pt of s.points) {
        if (pt.score > maxScore) maxScore = pt.score;
        if (pt.elapsedMinutes > maxTime) maxTime = pt.elapsedMinutes;
      }
    }

    const COLORS = ['#00e5ff', '#ff007f', '#00ff66', '#ffb700', '#9d00ff', '#ffffff'];

    const linesSvg = [];
    seriesList.forEach((s, idx) => {
      const color = COLORS[idx % COLORS.length];
      const coords = s.points.map(pt => {
        const x = margin.left + Math.round((pt.elapsedMinutes / maxTime) * chartW);
        const y = margin.top + chartH - Math.round((pt.score / maxScore) * chartH);
        return `${x},${y}`;
      });

      const polyline = `<polyline fill="none" stroke="${color}" stroke-width="2.5" points="${coords.join(' ')}" />`;
      const lastPt = s.points[s.points.length - 1];
      const lastX = margin.left + Math.round((lastPt.elapsedMinutes / maxTime) * chartW) + 6;
      const lastY = margin.top + chartH - Math.round((lastPt.score / maxScore) * chartH) + 4;
      const label = `<text x="${lastX}" y="${lastY}" fill="${color}" font-family="monospace" font-size="10" font-weight="bold">${s.teamName} (${lastPt.score})</text>`;

      linesSvg.push(polyline);
      linesSvg.push(label);
    });

    return `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" style="background:#0a0c10; border-radius:6px;">
  <!-- Grid lines -->
  <line x1="${margin.left}" y1="${margin.top + chartH}" x2="${margin.left + chartW}" y2="${margin.top + chartH}" stroke="#22272e" stroke-width="1"/>
  <line x1="${margin.left}" y1="${margin.top}" x2="${margin.left}" y2="${margin.top + chartH}" stroke="#22272e" stroke-width="1"/>
  <!-- Axes labels -->
  <text x="${margin.left}" y="${margin.top - 6}" fill="#768390" font-family="monospace" font-size="10">POINTS (${maxScore})</text>
  <text x="${margin.left + chartW}" y="${margin.top + chartH + 20}" fill="#768390" font-family="monospace" font-size="10">TIME (${maxTime}m)</text>
  <!-- Curves -->
  ${linesSvg.join('\n  ')}
</svg>`.trim();
  }

  /**
   * Get 2D solve matrix (Teams x Challenges)
   */
  getSolveMatrix() {
    const chals = Array.from(this.challenges.values());
    const matrix = [];

    for (const team of this.teams.values()) {
      const row = {
        teamId: team.id,
        teamName: team.name,
        score: team.score,
        challenges: {}
      };

      for (const chal of chals) {
        const solve = this.solves.find(s => s.teamId === team.id && s.challengeId === chal.id);
        if (solve) {
          row.challenges[chal.id] = {
            solved: true,
            badge: solve.bloodBadge || '✔',
            points: solve.points,
            solveTime: solve.timestamp
          };
        } else {
          row.challenges[chal.id] = {
            solved: false,
            badge: null
          };
        }
      }

      matrix.push(row);
    }

    matrix.sort((a, b) => b.score - a.score);
    return {
      challenges: chals.map(c => ({ id: c.id, name: c.name, category: c.category, points: c.currentPoints })),
      matrix
    };
  }

  /**
   * Export complete tournament state to JSON
   */
  exportState() {
    return {
      id: this.id,
      title: this.title,
      modes: this.modes,
      activeMode: this.activeMode,
      state: this.state,
      initialPoints: this.initialPoints,
      minimumPoints: this.minimumPoints,
      decaySolves: this.decaySolves,
      createdAt: this.createdAt,
      startTime: this.startTime,
      freezeTime: this.freezeTime,
      endTime: this.endTime,
      teams: Array.from(this.teams.values()),
      challenges: Array.from(this.challenges.values()),
      solves: this.solves,
      announcements: this.announcements,
      alerts: this.alerts,
      adState: this.adState,
      kothState: this.kothState
    };
  }
}
