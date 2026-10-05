/**
 * VIGILANTE Autonomous Adversarial Swarm Duel ("Cyber Range") Engine
 * Multi-agent autonomous turn-based battle simulator:
 * Red Team Swarm (Recon, Exploit, PrivEsc, Lateral, Exfil) vs.
 * Blue Team Swarm (Sensor, Triage, Containment, Patch).
 * Evaluates Mean Time to Detect (MTTD), MTTR, blast containment, and victor.
 */

import { logger } from '../utils/logger.js';

/**
 * Duel Victory Conditions
 */
export const DUEL_OUTCOMES = {
  BLUE_TEAM_VICTORY_CONTAINED: 'BLUE_TEAM_VICTORY_CONTAINED',
  RED_TEAM_VICTORY_EXFILTRATED: 'RED_TEAM_VICTORY_EXFILTRATED',
  STALEMATE_TIMEOUT: 'STALEMATE_TIMEOUT'
};

/**
 * MITRE ATT&CK Attack Phases for Red Team
 */
export const ATTACK_PHASES = [
  { phase: 'RECONNAISSANCE', agent: 'ReconAgent', technique: 'T1595', desc: 'Port discovery & service enumeration' },
  { phase: 'INITIAL_ACCESS', agent: 'ExploitAgent', technique: 'T1190', desc: 'Exploit public-facing web service' },
  { phase: 'PRIVILEGE_ESCALATION', agent: 'PrivEscAgent', technique: 'T1068', desc: 'Exploit container runtime / sudo' },
  { phase: 'LATERAL_MOVEMENT', agent: 'LateralAgent', technique: 'T1021', desc: 'Internal network pivot to crown jewel' },
  { phase: 'EXFILTRATION', agent: 'ExfilAgent', technique: 'T1048', desc: 'Exfiltrate sensitive data via C2 channel' }
];

/**
 * Blue Team Defensive Counter-Capabilities
 */
export const DEFENSE_ACTIONS = [
  { name: 'PASSIVE_MONITORING', agent: 'SensorAgent', efficacy: 0.4, desc: 'eBPF syscall & packet inspection' },
  { name: 'TACTICAL_TRIAGE', agent: 'TriageAgent', efficacy: 0.6, desc: 'Correlate alerts into attack chain' },
  { name: 'EBPF_LSM_BLOCK', agent: 'ContainmentAgent', efficacy: 0.85, desc: 'Drop network traffic & kill rogue PIDs' },
  { name: 'CREDENTIAL_REVOCATION', agent: 'PatchAgent', efficacy: 0.9, desc: 'Rotate stolen tokens and close ingress' }
];

/**
 * Initialize a new Autonomous Swarm Duel state
 * @param {Object} [config={}]
 * @returns {Object} Duel state
 */
export function createSwarmDuel(config = {}) {
  const maxRounds = config.maxRounds || 5;
  const crownJewel = config.crownJewel || 'production-vault-db';
  const stealthMode = config.stealthMode || false;

  return {
    duelId: `duel-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
    startTime: new Date().toISOString(),
    status: 'ACTIVE',
    round: 0,
    maxRounds,
    crownJewel,
    stealthMode,
    currentPhaseIndex: 0,
    outcome: null,
    isContained: false,
    isExfiltrated: false,
    firstDetectedRound: null,
    containedRound: null,
    scores: {
      redTeam: 0,
      blueTeam: 0
    },
    roundsLog: []
  };
}

/**
 * Execute a single turn/round in the swarm duel
 * @param {Object} duelState
 * @param {Object} [options={}]
 * @returns {Object} Round result
 */
export function executeDuelRound(duelState, options = {}) {
  if (duelState.status !== 'ACTIVE') return duelState;

  duelState.round += 1;
  const roundNum = duelState.round;
  const phaseInfo = ATTACK_PHASES[duelState.currentPhaseIndex] || ATTACK_PHASES[ATTACK_PHASES.length - 1];

  // 1. Red Team Action
  const redNoiseFactor = duelState.stealthMode ? 0.3 : 0.7;
  const redSuccessChance = options.forceRedSuccess !== undefined ? options.forceRedSuccess : (0.75 + (duelState.stealthMode ? 0.1 : 0));
  const redSucceeded = Math.random() <= redSuccessChance;

  const redAction = {
    agent: phaseInfo.agent,
    phase: phaseInfo.phase,
    technique: phaseInfo.technique,
    description: phaseInfo.desc,
    success: redSucceeded,
    noise: redNoiseFactor
  };

  if (redSucceeded) {
    duelState.scores.redTeam += 20;
    // Progress to next attack phase if not already at final phase
    if (duelState.currentPhaseIndex < ATTACK_PHASES.length - 1) {
      duelState.currentPhaseIndex += 1;
    } else {
      // Exfiltration phase completed
      duelState.isExfiltrated = true;
    }
  }

  // 2. Blue Team Action
  const detectionChance = Math.min(0.95, redNoiseFactor + (roundNum * 0.15));
  const detected = options.forceBlueDetect !== undefined ? options.forceBlueDetect : (Math.random() <= detectionChance);

  let blueAction;
  if (detected) {
    if (duelState.firstDetectedRound === null) {
      duelState.firstDetectedRound = roundNum;
    }

    // Determine defense response
    if (roundNum >= 3 || phaseInfo.phase === 'LATERAL_MOVEMENT' || phaseInfo.phase === 'EXFILTRATION') {
      // Deploy high-impact active containment
      blueAction = {
        agent: 'ContainmentAgent',
        action: 'EBPF_LSM_BLOCK',
        success: true,
        description: 'Synthesized eBPF LSM drop rule and isolated workload network namespace'
      };
      duelState.isContained = true;
      duelState.containedRound = roundNum;
      duelState.scores.blueTeam += 35;
    } else {
      // Triage & Passive monitoring
      blueAction = {
        agent: 'TriageAgent',
        action: 'TACTICAL_TRIAGE',
        success: true,
        description: `Correlated ${phaseInfo.technique} telemetry alerts into active incident DAG`
      };
      duelState.scores.blueTeam += 15;
    }
  } else {
    blueAction = {
      agent: 'SensorAgent',
      action: 'PASSIVE_MONITORING',
      success: false,
      description: 'Sensor telemetry analyzed, adversary action evaded detection threshold'
    };
  }

  const roundRecord = {
    round: roundNum,
    redAction,
    blueAction,
    scores: { ...duelState.scores }
  };

  duelState.roundsLog.push(roundRecord);

  // 3. Evaluate terminal conditions
  if (duelState.isContained && !duelState.isExfiltrated) {
    duelState.status = 'COMPLETED';
    duelState.outcome = DUEL_OUTCOMES.BLUE_TEAM_VICTORY_CONTAINED;
  } else if (duelState.isExfiltrated && !duelState.isContained) {
    duelState.status = 'COMPLETED';
    duelState.outcome = DUEL_OUTCOMES.RED_TEAM_VICTORY_EXFILTRATED;
  } else if (roundNum >= duelState.maxRounds) {
    duelState.status = 'COMPLETED';
    if (duelState.scores.blueTeam > duelState.scores.redTeam) {
      duelState.outcome = DUEL_OUTCOMES.BLUE_TEAM_VICTORY_CONTAINED;
    } else if (duelState.scores.redTeam > duelState.scores.blueTeam) {
      duelState.outcome = DUEL_OUTCOMES.RED_TEAM_VICTORY_EXFILTRATED;
    } else {
      duelState.outcome = DUEL_OUTCOMES.STALEMATE_TIMEOUT;
    }
  }

  return roundRecord;
}

/**
 * Run a full multi-round Swarm Duel simulation to completion
 * @param {Object} [options={}]
 * @returns {Object} Final duel state and performance evaluation
 */
export function runFullDuelSimulation(options = {}) {
  const duelState = createSwarmDuel(options);

  while (duelState.status === 'ACTIVE') {
    executeDuelRound(duelState, options);
  }

  const metrics = evaluateDuelMetrics(duelState);

  return {
    duelState,
    metrics,
    transcript: generateDuelTranscript(duelState)
  };
}

/**
 * Evaluate performance metrics from a completed duel
 * @param {Object} duelState
 * @returns {Object} Structured metrics
 */
export function evaluateDuelMetrics(duelState) {
  const totalRounds = duelState.round;
  const mttd = duelState.firstDetectedRound !== null ? duelState.firstDetectedRound : totalRounds;
  const mttr = duelState.containedRound !== null 
    ? Math.max(1, duelState.containedRound - (duelState.firstDetectedRound || 1)) 
    : totalRounds;

  const containmentRatio = duelState.isContained ? 1.0 : 0.0;
  const compromisePct = Number(((duelState.currentPhaseIndex / (ATTACK_PHASES.length - 1)) * 100).toFixed(0));

  return {
    duelId: duelState.duelId,
    outcome: duelState.outcome,
    totalRounds,
    mttdRounds: mttd,
    mttrRounds: mttr,
    containmentRatio,
    compromisePercentage: compromisePct,
    redScore: duelState.scores.redTeam,
    blueScore: duelState.scores.blueTeam,
    winner: duelState.outcome === DUEL_OUTCOMES.BLUE_TEAM_VICTORY_CONTAINED ? 'BLUE_TEAM' :
            duelState.outcome === DUEL_OUTCOMES.RED_TEAM_VICTORY_EXFILTRATED ? 'RED_TEAM' : 'DRAW'
  };
}

/**
 * Generate human-readable battle transcript
 * @param {Object} duelState
 * @returns {string} Formatted ASCII transcript
 */
export function generateDuelTranscript(duelState) {
  const lines = [];
  lines.push('╔══════════════════════════════════════════════════════════════════════════════╗');
  lines.push('║             ⚔️  VIGILANTE AUTONOMOUS SWARM DUEL CYBER RANGE BATTLE            ║');
  lines.push('╚══════════════════════════════════════════════════════════════════════════════╝');
  lines.push(`Duel ID: ${duelState.duelId} | Outcome: ${duelState.outcome || 'IN_PROGRESS'}`);
  lines.push(`Crown Jewel Target: ${duelState.crownJewel} | Max Rounds: ${duelState.maxRounds}`);
  lines.push('─'.repeat(78));

  for (const r of duelState.roundsLog) {
    lines.push(`\n▶ ROUND ${r.round}:`);
    lines.push(`  🔴 [RED SWARM] ${r.redAction.agent} (${r.redAction.phase}): ${r.redAction.description}`);
    lines.push(`     Result: ${r.redAction.success ? '✔ SUCCESS' : '✖ BLOCKED'} | Technique: ${r.redAction.technique}`);
    lines.push(`  🔵 [BLUE SWARM] ${r.blueAction.agent}: ${r.blueAction.description}`);
    lines.push(`     Action: ${r.blueAction.action} (${r.blueAction.success ? 'DETECTED' : 'EVADED'})`);
    lines.push(`  Score Tracker: Red ${r.scores.redTeam} pts vs. Blue ${r.scores.blueTeam} pts`);
  }

  lines.push('\n' + '─'.repeat(78));
  lines.push(`FINAL OUTCOME: ${duelState.outcome}`);
  lines.push(`Final Scores: Red Team ${duelState.scores.redTeam} | Blue Team ${duelState.scores.blueTeam}`);

  return lines.join('\n');
}
