import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  PERMISSIONS,
  ROLES,
  ROLE_PERMISSIONS,
  generateToken,
  hashToken,
  hashPassword,
  verifyPasswordOrToken,
  loadAuthzStore,
  saveAuthzStore,
  initOwner,
  addPrincipal,
  updatePrincipal,
  removePrincipal,
  rotatePrincipalToken,
  createSession,
  resolvePrincipalBySession,
  revokeSession,
  assertNotLastOwner,
  decide,
  invalidateAuthzCache,
  AuthzInvariantError
} from '../src/engine/authz.js';


test('authz token generation and hashing', () => {
  const token = generateToken();
  assert.ok(token.startsWith('vig_'), 'Token starts with vig_');
  const hashed = hashToken(token);
  assert.ok(hashed.startsWith('sha256:'), 'Hash starts with sha256:');
  assert.ok(verifyPasswordOrToken(token, hashed), 'Valid token verifies');
  assert.ok(!verifyPasswordOrToken('vig_wrongtoken', hashed), 'Invalid token fails');
});

test('authz scrypt password hashing', () => {
  const pw = 'superSecretPassword123!';
  const hashed = hashPassword(pw);
  assert.ok(hashed.startsWith('scrypt:'), 'Hash starts with scrypt:');
  assert.ok(verifyPasswordOrToken(pw, hashed), 'Valid password verifies');
  assert.ok(!verifyPasswordOrToken('wrongPassword123!', hashed), 'Wrong password fails');
});

test('authz lifecycle, invariants, and decisions in isolated store', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-authz-test-'));
  const testFile = path.join(tmpDir, 'authz.yaml');

  try {
    // 1. Initial state (empty store)
    const initial = loadAuthzStore(testFile);
    assert.equal(initial.state, 'ready');
    assert.equal(initial.store.principals.length, 0);

    // Loopback decision on empty store allows local board
    const localDecision = decide(initial, null, 'cluster:read', {}, { isLoopback: true, source: 'loopback' });
    assert.equal(localDecision.allowed, true);
    assert.equal(localDecision.reason, 'allow_local_board');

    // Non-loopback decision on empty store is denied
    const remoteDecision = decide(initial, null, 'cluster:read', {}, { isLoopback: false, source: 'any' });
    assert.equal(remoteDecision.allowed, false);
    assert.equal(remoteDecision.reason, 'deny_unauthenticated');

    // 2. Init owner
    const initRes = await initOwner({ name: 'Alice Owner' }, testFile);
    assert.equal(initRes.principal.role, 'owner');
    assert.ok(initRes.secret.startsWith('vig_'));

    const loadedAfterInit = loadAuthzStore(testFile);
    assert.equal(loadedAfterInit.store.principals.length, 1);
    const owner = loadedAfterInit.store.principals[0];

    // Cannot init again
    await assert.rejects(
      () => initOwner({ name: 'Bob' }, testFile),
      AuthzInvariantError
    );

    // Cannot delete or disable the last owner
    assert.throws(
      () => assertNotLastOwner(loadedAfterInit.store, owner.id, 'delete'),
      AuthzInvariantError
    );
    await assert.rejects(
      () => removePrincipal(owner.id, testFile),
      AuthzInvariantError
    );
    await assert.rejects(
      () => updatePrincipal(owner.id, { disabled: true }, testFile),
      AuthzInvariantError
    );

    // Owner has all permissions
    const ownerDec = decide(loadedAfterInit, owner, 'users:manage_permissions');
    assert.equal(ownerDec.allowed, true);
    assert.equal(ownerDec.reason, 'allow_owner');

    // 3. Add operator principal
    const opRes = await addPrincipal(
      {
        name: 'Bob Operator',
        role: 'operator',
        kind: 'human'
      },
      testFile
    );
    assert.equal(opRes.principal.role, 'operator');

    let loaded = loadAuthzStore(testFile);
    const bob = loaded.store.principals.find(p => p.id === opRes.principal.id);

    // Operator can deploy modules but cannot manage permissions
    const bobCanDeploy = decide(loaded, bob, 'modules:deploy');
    assert.equal(bobCanDeploy.allowed, true);
    assert.equal(bobCanDeploy.reason, 'allow_role_default');

    const bobCannotManage = decide(loaded, bob, 'users:manage_permissions');
    assert.equal(bobCannotManage.allowed, false);
    assert.equal(bobCannotManage.reason, 'deny_missing_grant');

    // 4. Scoped grants on a viewer
    const viewerRes = await addPrincipal(
      {
        name: 'Charlie Viewer',
        role: 'viewer',
        grants: [
          {
            permission: 'modules:deploy',
            scope: { moduleId: 'wazuh', namespace: 'security' }
          }
        ]
      },
      testFile
    );

    loaded = loadAuthzStore(testFile);
    const charlie = loaded.store.principals.find(p => p.id === viewerRes.principal.id);

    // Scoped grant matches target
    const charlieMatch = decide(loaded, charlie, 'modules:deploy', { moduleId: 'wazuh', namespace: 'security' });
    assert.equal(charlieMatch.allowed, true);
    assert.equal(charlieMatch.reason, 'allow_explicit_grant');

    // Scoped grant fails on different module
    const charlieMismatch = decide(loaded, charlie, 'modules:deploy', { moduleId: 'openvas', namespace: 'security' });
    assert.equal(charlieMismatch.allowed, false);
    assert.equal(charlieMismatch.reason, 'deny_missing_grant');

    // 5. Explicit revocation
    await updatePrincipal(
      charlie.id,
      { revocations: ['cluster:read'] },
      testFile
    );
    loaded = loadAuthzStore(testFile);
    const charlieUpdated = loaded.store.principals.find(p => p.id === charlie.id);
    const charlieRevoked = decide(loaded, charlieUpdated, 'cluster:read');
    assert.equal(charlieRevoked.allowed, false);
    assert.equal(charlieRevoked.reason, 'deny_revoked');

    // 6. Sessions
    const sess = await createSession(owner.id, testFile);
    assert.ok(sess.sessionToken.startsWith('vig_sess_'));
    loaded = loadAuthzStore(testFile);
    const resolvedSess = resolvePrincipalBySession(loaded.store, sess.sessionToken);
    assert.equal(resolvedSess.principal.id, owner.id);
    assert.equal(resolvedSess.expired, false);

    // Revoke session
    await revokeSession(sess.sessionToken, testFile);
    loaded = loadAuthzStore(testFile);
    const resolvedRevoked = resolvePrincipalBySession(loaded.store, sess.sessionToken);
    assert.equal(resolvedRevoked.principal, null);

    // 7. Fail-closed on invalid store
    await fs.writeFile(testFile, 'not: [valid: yaml: {{}}', 'utf8');
    invalidateAuthzCache();
    const invalidStore = loadAuthzStore(testFile);
    assert.equal(invalidStore.state, 'invalid');
    const invalidDec = decide(invalidStore, owner, 'cluster:read', {}, { isLoopback: true });
    assert.equal(invalidDec.allowed, false);
    assert.equal(invalidDec.reason, 'deny_invalid_store');


  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});
