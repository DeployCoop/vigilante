import { createMongoAbility, type MongoAbility, type RawRuleOf } from '@casl/ability';

export type ClientAbility = MongoAbility<
  [string, string | Record<string, unknown>]
>;

export interface MePrincipal {
  id: string;
  name: string;
  kind: string;
  role: string;
}

export interface MeResponse {
  success?: boolean;
  authzEnabled: boolean;
  principal: MePrincipal | null;
  localBoard?: boolean;
  rules: Array<Record<string, unknown>>;
  reason?: string;
}

export type AbilityStatus =
  | 'loading'
  | 'disabled'
  | 'ready'
  | 'local-board'
  | 'unauthenticated'
  | 'unknown-principal';

export const PERMISSION_SUBJECT: Record<string, string> = {
  'cluster:read': 'Cluster',
  'cluster:write': 'Cluster',
  'modules:read': 'Module',
  'modules:deploy': 'Module',
  'scans:read': 'Scan',
  'scans:run': 'Scan',
  'telemetry:read': 'Telemetry',
  'telemetry:write': 'Telemetry',
  'forensics:read': 'Forensics',
  'forensics:run': 'Forensics',
  'simulations:run': 'Simulation',
  'ctf:read': 'Ctf',
  'ctf:manage': 'Ctf',
  'users:manage_permissions': 'User'
};

export interface AuthzTarget {
  moduleId?: string;
  namespace?: string;
  clusterName?: string;
  [key: string]: unknown;
}

export function subjectFor(permission: string, target?: AuthzTarget): Record<string, unknown> | string {
  const subjectName = PERMISSION_SUBJECT[permission] || 'all';
  if (!target || Object.keys(target).length === 0) {
    return subjectName;
  }
  return { ...target, __caslSubjectType__: subjectName };
}

export function permissiveAbility(): ClientAbility {
  return createMongoAbility([{ action: 'manage', subject: 'all' }]);
}

export function emptyAbility(): ClientAbility {
  return createMongoAbility([]);
}

export function abilityFromRules(rules: Array<Record<string, unknown>>): ClientAbility {
  return createMongoAbility(rules as unknown as Array<RawRuleOf<ClientAbility>>);
}

export function abilityFromMe(
  me: MeResponse | null,
  httpStatus: number
): { status: AbilityStatus; ability: ClientAbility } {
  if (me && me.authzEnabled === false) {
    return { status: me.localBoard ? 'local-board' : 'disabled', ability: permissiveAbility() };
  }
  if (me && me.localBoard && !me.principal) {
    return { status: 'local-board', ability: permissiveAbility() };
  }
  if (me && me.principal) {
    return { status: 'ready', ability: abilityFromRules(me.rules ?? []) };
  }
  if (httpStatus === 401) {
    return {
      status: me?.reason === 'deny_unknown_principal' ? 'unknown-principal' : 'unauthenticated',
      ability: emptyAbility()
    };
  }
  return { status: 'unauthenticated', ability: emptyAbility() };
}

/**
 * Exchange token or password for httpOnly session cookie
 */
export async function exchangeTokenForSession(secret: string): Promise<boolean> {
  try {
    const res = await fetch('/api/authz/session', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: secret })
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * End current session and clear cookie
 */
export async function endSession(): Promise<void> {
  try {
    await fetch('/api/authz/session', { method: 'DELETE' });
  } catch {
    // ignore
  }
}
