import {
  PERMISSIONS,
  ROLES,
  loadAuthzStore,
  saveAuthzStore,
  initOwner,
  addPrincipal,
  removePrincipal,
  rotatePrincipalToken,
  decide,
  resolvePrincipalByToken,
  MIN_PASSWORD_LENGTH
} from '../engine/authz.js';
import { getVigilanteAuthzFile } from '../engine/config.js';

export const AUTHZ_USAGE = `Usage: vigilante authz <command> [options]

Commands:
  init [--name <name>] [--password <password>] [--token <token>]
                                  Create the store and its first owner principal
  add <name> [options]            Add a principal (token printed once)
    --role <role>                 ${ROLES.join(' | ')} (default: viewer)
    --kind <kind>                 human | service (default: human)
    --oidc-subject <sub>          Map an OIDC identity instead of issuing a token
    --grant <permission>          Extra permission grant (repeatable)
    --scope-module <moduleId>     Scope grant to a specific module
    --scope-namespace <ns>        Scope grant to a specific namespace
    --scope-cluster <name>        Scope grant to a specific cluster
  list                            List principals (never prints secrets)
  revoke <principal-id>           Remove a principal
  rotate <principal-id>           Issue a replacement token or password (printed once)
    --password <password>         Set a specific password instead of generated token
  check <token> <permission>      Dry-run a permission check, prints the decision reason
    --module <moduleId>           Target module
    --namespace <ns>              Target namespace
    --cluster <name>              Target cluster
    --source loopback|any         Caller source (default: any)
    --auth-method <method>        session | token | oidc | any (default: token)
`;

export async function runAuthzCli(args = []) {
  const sub = args[0];
  const rest = args.slice(1);

  if (!sub || sub === '--help' || sub === '-h') {
    console.log(AUTHZ_USAGE);
    return 0;
  }

  // Parse simple flags
  const flags = {};
  const positional = [];
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = rest[i + 1];
      if (next && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }

  const filePath = getVigilanteAuthzFile();

  if (sub === 'init') {
    try {
      const name = flags.name || positional[0] || 'Owner';
      const password = flags.password;
      const token = flags.token;

      const res = await initOwner({ name, password, token }, filePath);
      console.log(`\n🛡️  VIGILANTE AUTHZ INITIALIZED`);
      console.log('='.repeat(65));
      console.log(`Principal ID: ${res.principal.id}`);
      console.log(`Name:         ${res.principal.name}`);
      console.log(`Role:         ${res.principal.role}`);
      console.log(`Store:        ${filePath}\n`);
      console.log(
        res.isCustomPassword
          ? `Owner password set for ${res.principal.name}.`
          : `Owner token (shown once — store it now, it cannot be recovered):\n  ${res.secret}`
      );
      console.log('\nUse this token/password to log in or authenticate API requests.\n');
      return 0;
    } catch (err) {
      console.error(`✖ Error initializing authz: ${err.message}`);
      return 1;
    }
  }

  if (sub === 'list') {
    const loaded = loadAuthzStore(filePath);
    if (loaded.state === 'disabled') {
      console.log('Authorization is disabled (VIGILANTE_AUTHZ=off).');
      return 0;
    }
    if (loaded.state === 'invalid') {
      console.error(`✖ Authorization store at ${filePath} is invalid: ${loaded.error}`);
      return 1;
    }
    const store = loaded.store || { principals: [] };
    console.log(`\n👥 VIGILANTE PRINCIPALS (${store.principals.length})`);
    console.log('='.repeat(70));
    if (store.principals.length === 0) {
      console.log('No principals found. Run `vigilante authz init` to create the initial owner.');
      return 0;
    }
    store.principals.forEach((p, idx) => {
      const status = p.disabled ? '🔴 DISABLED' : '🟢 ACTIVE';
      console.log(`[${idx + 1}] ${p.name} (${p.id}) [${p.role.toUpperCase()}] ${status}`);
      console.log(`    Kind: ${p.kind} | Has Token: ${Boolean(p.tokenHash)} | OIDC: ${p.oidcSubject || 'None'}`);
      if (p.grants && p.grants.length > 0) {
        console.log(`    Grants (${p.grants.length}): ${p.grants.map(g => g.permission).join(', ')}`);
      }
      if (p.revocations && p.revocations.length > 0) {
        console.log(`    Revocations: ${p.revocations.join(', ')}`);
      }
      console.log();
    });
    return 0;
  }

  if (sub === 'add') {
    const name = positional[0] || flags.name;
    if (!name) {
      console.error('✖ Error: Principal name is required (`vigilante authz add <name>`)');
      return 1;
    }
    const role = flags.role || 'viewer';
    const kind = flags.kind || 'human';
    const oidcSubject = flags['oidc-subject'] || flags.oidc;

    const grants = [];
    if (flags.grant) {
      const grantList = Array.isArray(flags.grant) ? flags.grant : [flags.grant];
      for (const g of grantList) {
        const scope = {};
        if (flags['scope-module']) scope.moduleId = flags['scope-module'];
        if (flags['scope-namespace']) scope.namespace = flags['scope-namespace'];
        if (flags['scope-cluster']) scope.clusterName = flags['scope-cluster'];
        grants.push({
          permission: g,
          scope: Object.keys(scope).length ? scope : undefined
        });
      }
    }

    try {
      const res = await addPrincipal({ name, kind, role, oidcSubject, grants }, filePath);
      console.log(`\n✔ Principal created: ${res.principal.name} (${res.principal.id})`);
      console.log(`Role: ${res.principal.role} | Kind: ${res.principal.kind}`);
      if (res.token) {
        console.log(`\nToken (shown once — store it now, it cannot be recovered):\n  ${res.token}\n`);
      }
      return 0;
    } catch (err) {
      console.error(`✖ Error adding principal: ${err.message}`);
      return 1;
    }
  }

  if (sub === 'revoke') {
    const id = positional[0];
    if (!id) {
      console.error('✖ Error: Principal ID is required (`vigilante authz revoke <principal-id>`)');
      return 1;
    }
    try {
      await removePrincipal(id, filePath);
      console.log(`✔ Principal '${id}' removed from authorization store.`);
      return 0;
    } catch (err) {
      console.error(`✖ Error removing principal: ${err.message}`);
      return 1;
    }
  }

  if (sub === 'rotate') {
    const id = positional[0];
    if (!id) {
      console.error('✖ Error: Principal ID is required (`vigilante authz rotate <principal-id>`)');
      return 1;
    }
    try {
      const res = await rotatePrincipalToken(id, { password: flags.password }, filePath);
      console.log(`✔ Credential rotated for principal '${id}'.`);
      console.log(
        res.isCustomPassword
          ? `New custom password configured.`
          : `New token (shown once — store it now):\n  ${res.secret}\n`
      );
      return 0;
    } catch (err) {
      console.error(`✖ Error rotating credential: ${err.message}`);
      return 1;
    }
  }

  if (sub === 'check') {
    const secret = positional[0];
    const permission = positional[1];
    if (!secret || !permission) {
      console.error('✖ Error: Token and permission are required (`vigilante authz check <token> <permission>`)');
      return 1;
    }
    const loaded = loadAuthzStore(filePath);
    const principal = resolvePrincipalByToken(loaded.store, secret);
    const target = {};
    if (flags.module) target.moduleId = flags.module;
    if (flags.namespace) target.namespace = flags.namespace;
    if (flags.cluster) target.clusterName = flags.cluster;

    const opts = {
      source: flags.source || 'any',
      authMethod: flags['auth-method'] || 'token'
    };

    const decision = decide(loaded, principal, permission, target, opts);
    console.log(`\nDecision: ${decision.allowed ? '✅ ALLOWED' : '❌ DENIED'}`);
    console.log(`Reason:   ${decision.reason}`);
    console.log(`Principal: ${principal ? `${principal.name} (${principal.id})` : 'unauthenticated'}\n`);
    return decision.allowed ? 0 : 1;
  }

  console.error(`Unknown authz command '${sub}'. Run \`vigilante authz --help\` for usage.`);
  return 1;
}
