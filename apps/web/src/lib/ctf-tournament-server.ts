import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { TournamentEngine, TOURNAMENT_STATES } from 'vigilante_lib/engine/tournament.js';
import { CHALLENGE_TEMPLATES } from 'vigilante_lib/engine/kctf.js';
import { buildAiCtfChallengeCatalog } from 'vigilante_lib/engine/redairange.js';
import { getVigilanteConfigDir, resolveCtfFlagSecret } from 'vigilante_lib/engine/config.js';
import { errorMessage } from '@/lib/envelope';

/**
 * Challenge template as consumed by the web CTF routes: the kCTF template
 * set (packages/vigilante_lib/src/engine/kctf.js) plus the RedAiRange
 * AI-CTF catalog (buildAiCtfChallengeCatalog in redairange.js). The catalog
 * entries carry source/owaspLlm/mitreAtlas; the kCTF templates carry
 * defaultFlag. Both shapes share the core fields below.
 */
export interface ChallengeTemplateView {
  id: string;
  name: string;
  category: string;
  difficulty: string;
  port: number;
  protocol: string;
  serviceType: string;
  description: string;
  hints?: string[];
  defaultFlag?: string;
  source?: string;
  owaspLlm?: string[];
  mitreAtlas?: string[];
}

let cachedEngine: TournamentEngine | null = null;

function getTournamentStateFile(): string {
  return path.join(getVigilanteConfigDir(), 'ctf-tournament.json');
}

export async function getTournamentEngine(): Promise<TournamentEngine> {
  const secretKey = resolveCtfFlagSecret();
  if (cachedEngine) {
    cachedEngine.secretKey = secretKey;
    return cachedEngine;
  }

  const engine = new TournamentEngine({
    id: 'vigilante-kctf-arena',
    title: 'Vigilante kCTF Cyber Range Tournament',
    secretKey
  });

  // Seed default challenge templates (kCTF + RedAiRange AI-CTF bridge)
  const allTemplates: ChallengeTemplateView[] = [
    ...CHALLENGE_TEMPLATES,
    ...buildAiCtfChallengeCatalog()
  ];
  for (const chal of allTemplates) {
    try {
      engine.addChallenge({
        id: chal.id,
        name: chal.name,
        category: chal.category,
        difficulty: chal.difficulty,
        port: chal.port,
        protocol: chal.protocol,
        defaultFlag: chal.defaultFlag || null,
        isDynamicFlag: true,
        description: chal.description,
        hints: chal.hints || [],
        wave: 1
      });
    } catch {
      // Challenge may already be registered
    }
  }

  // Ensure tournament is active so submissions are processed
  engine.state = TOURNAMENT_STATES.ACTIVE;
  if (!engine.startTime) {
    engine.startTime = Date.now() - 3600000; // 1 hour ago
  }

  // Restore state from disk if exists
  const stateFile = getTournamentStateFile();
  try {
    if (fsSync.existsSync(stateFile)) {
      const raw = await fs.readFile(stateFile, 'utf8');
      const saved = JSON.parse(raw);
      if (saved && Array.isArray(saved.teams)) {
        for (const t of saved.teams) {
          engine.teams.set(t.id, t);
        }
      }
      if (saved && Array.isArray(saved.solves)) {
        engine.solves = saved.solves;
      }
      if (saved && Array.isArray(saved.announcements)) {
        engine.announcements = saved.announcements;
      }
      if (saved && Array.isArray(saved.alerts)) {
        engine.alerts = saved.alerts;
      }
      if (saved && saved.challenges) {
        for (const sc of saved.challenges) {
          const c = engine.challenges.get(sc.id);
          if (c) {
            c.solvesCount = sc.solvesCount || 0;
            c.currentPoints = sc.currentPoints || c.currentPoints;
            c.firstBlood = sc.firstBlood || null;
            c.solves = sc.solves || [];
          }
        }
      }
    }
  } catch (err: unknown) {
    console.warn('[tournament] Could not restore saved state:', errorMessage(err));
  }

  cachedEngine = engine;
  return engine;
}

export async function persistTournamentState(engine: TournamentEngine): Promise<void> {
  try {
    const file = getTournamentStateFile();
    await fs.mkdir(path.dirname(file), { recursive: true });
    const tmp = `${file}.tmp`;
    const state = engine.exportState();
    await fs.writeFile(tmp, JSON.stringify(state, null, 2), 'utf8');
    await fs.rename(tmp, file);
  } catch (err: unknown) {
    console.warn('[tournament] Could not persist state:', errorMessage(err));
  }
}
