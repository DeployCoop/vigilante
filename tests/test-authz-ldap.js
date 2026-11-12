import assert from 'node:assert';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import {
  escapeLdapFilter,
  escapeLdapDnValue,
  resolveVigilanteLdapConfig,
  mapLdapGroupsToRole,
  authenticateLdapUser,
  getVigilanteLdapStatus
} from '../packages/vigilante_lib/src/engine/authz-ldap.js';
import {
  loadAuthzStore,
  initOwner,
  syncLdapPrincipal,
  findPrincipalByLdapUid,
  buildAbilityFor,
  decide
} from '../packages/vigilante_lib/src/engine/authz.js';

// Minimal BER helpers for the in-memory mock LDAPv3 server
function berLen(len) {
  if (len < 0x80) return Buffer.from([len]);
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function berEl(tag, payload) {
  const b = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  return Buffer.concat([Buffer.from([tag]), berLen(b.length), b]);
}
function berInt(v) {
  return berEl(0x02, Buffer.from([v & 0xff]));
}
function berEnum(v) {
  return berEl(0x0a, Buffer.from([v & 0xff]));
}
function berStr(s) {
  return berEl(0x04, Buffer.from(String(s ?? ''), 'utf8'));
}
function berSeq(items) {
  return berEl(0x30, Buffer.concat(items));
}
function readBerEl(buf, offset = 0) {
  if (offset >= buf.length) return null;
  const tag = buf[offset];
  const first = buf[offset + 1];
  if (first === undefined) return null;
  let len = 0;
  let lenBytes = 1;
  if ((first & 0x80) === 0) {
    len = first;
  } else {
    const count = first & 0x7f;
    if (offset + 2 + count > buf.length) return null;
    for (let i = 0; i < count; i++) {
      len = (len << 8) | buf[offset + 2 + i];
    }
    lenBytes = 1 + count;
  }
  const start = offset + 1 + lenBytes;
  const end = start + len;
  if (end > buf.length) return null;
  return { tag, value: buf.subarray(start, end), next: end };
}
function readBerChildren(buf) {
  const out = [];
  let off = 0;
  while (off < buf.length) {
    const el = readBerEl(buf, off);
    if (!el) break;
    out.push(el);
    off = el.next;
  }
  return out;
}

function createMockLdapServer() {
  const users = {
    'soc-owner': {
      dn: 'uid=soc-owner,ou=users,dc=axonwall,dc=local',
      password: 'owner-secret-password',
      cn: 'SOC Chief Owner',
      mail: 'owner@axonwall.local',
      groups: ['axonwall-admin', 'vigilante-admin']
    },
    'soc-analyst': {
      dn: 'uid=soc-analyst,ou=users,dc=axonwall,dc=local',
      password: 'analyst-secret-password',
      cn: 'SOC Threat Hunter',
      mail: 'analyst@axonwall.local',
      groups: ['vigilante-operator']
    },
    'locked-user': {
      dn: 'uid=locked-user,ou=users,dc=axonwall,dc=local',
      password: 'locked-password',
      cn: 'Locked Analyst',
      locked: '20261101000000Z',
      groups: ['vigilante-readonly']
    },
    'nogroup-user': {
      dn: 'uid=nogroup-user,ou=users,dc=axonwall,dc=local',
      password: 'nogroup-secret',
      cn: 'No Group User',
      mail: 'nogroup@axonwall.local',
      groups: ['unmapped-group']
    },
    dup: {
      dn: 'uid=dup,ou=users,dc=axonwall,dc=local',
      password: 'dup-secret',
      cn: 'Dup Short',
      groups: ['vigilante-readonly']
    },
    'dup-user': {
      dn: 'uid=dup-user,ou=users,dc=axonwall,dc=local',
      password: 'dup-user-secret',
      cn: 'Dup User',
      groups: ['vigilante-readonly']
    },
    'group-error-user': {
      dn: 'uid=group-error-user,ou=users,dc=axonwall,dc=local',
      password: 'group-error-secret',
      cn: 'Group Error User',
      groups: ['vigilante-readonly']
    },
    'user-error-user': {
      dn: 'uid=user-error-user,ou=users,dc=axonwall,dc=local',
      password: 'user-error-secret',
      cn: 'User Error User',
      groups: ['vigilante-readonly']
    }
  };

  const server = net.createServer(socket => {
    let buf = Buffer.alloc(0);
    socket.on('data', chunk => {
      buf = Buffer.concat([buf, chunk]);
      while (buf.length > 0) {
        const msg = readBerEl(buf, 0);
        if (!msg) break;
        buf = buf.subarray(msg.next);
        const parts = readBerChildren(msg.value);
        if (parts.length < 2) continue;
        const msgId = parts[0].value[0];
        const op = parts[1];

        if (op.tag === 0x60) {
          // BindRequest
          const bParts = readBerChildren(op.value);
          const bindDN = bParts[1].value.toString('utf8');
          const bindPw = bParts[2].value.toString('utf8');

          let ok = false;
          if (bindDN === 'cn=svc-vigilante,ou=services,dc=axonwall,dc=local' && bindPw === 'svc-pass-123') {
            ok = true;
          } else {
            for (const u of Object.values(users)) {
              if (u.dn === bindDN && u.password === bindPw && !u.locked) {
                ok = true;
                break;
              }
            }
          }

          const bindRes = berEl(
            0x61,
            Buffer.concat([berEnum(ok ? 0 : 49), berStr(''), berStr(ok ? '' : 'Invalid credentials')])
          );
          socket.write(berSeq([berInt(msgId), bindRes]));
        } else if (op.tag === 0x63) {
          // SearchRequest
          const sParts = readBerChildren(op.value);
          const baseObject = sParts[0].value.toString('utf8');
          const rawFilterBytes = sParts[6].value.toString('utf8');

          // Error-injection triggers for the fail-closed tests: a search
          // that fails at the directory must never be read as "no match".
          let searchResultCode = 0;
          if (baseObject.startsWith('ou=users') && rawFilterBytes.includes('user-error-user')) {
            searchResultCode = 32;
          } else if (baseObject.startsWith('ou=groups') && rawFilterBytes.includes('group-error-user')) {
            searchResultCode = 32;
          }

          if (searchResultCode === 0 && baseObject.startsWith('ou=users')) {
            for (const [uid, u] of Object.entries(users)) {
              if (rawFilterBytes.includes(uid)) {
                const attrList = [
                  berSeq([berStr('uid'), berEl(0x31, berStr(uid))]),
                  berSeq([berStr('cn'), berEl(0x31, berStr(u.cn))])
                ];
                if (u.mail) {
                  attrList.push(berSeq([berStr('mail'), berEl(0x31, berStr(u.mail))]));
                }
                if (u.locked) {
                  attrList.push(berSeq([berStr('pwdAccountLockedTime'), berEl(0x31, berStr(u.locked))]));
                }
                const entry = berEl(0x64, Buffer.concat([berStr(u.dn), berSeq(attrList)]));
                socket.write(berSeq([berInt(msgId), entry]));
              }
            }
          } else if (searchResultCode === 0 && baseObject.startsWith('ou=groups')) {
            for (const [uid, u] of Object.entries(users)) {
              if (rawFilterBytes.includes(uid)) {
                for (const g of u.groups) {
                  const gEntry = berEl(
                    0x64,
                    Buffer.concat([
                      berStr(`cn=${g},ou=groups,dc=axonwall,dc=local`),
                      berSeq([berSeq([berStr('cn'), berEl(0x31, berStr(g))])])
                    ])
                  );
                  socket.write(berSeq([berInt(msgId), gEntry]));
                }
              }
            }
          }

          const done = berEl(0x65, Buffer.concat([berEnum(searchResultCode), berStr(''), berStr('')]));
          socket.write(berSeq([berInt(msgId), done]));
        }
      }
    });
  });

  return server;
}

async function runTests() {
  console.log('🧪 Testing Vigilante OpenLDAP Authentication & CASL Principal Sync...');

  // Test 1: RFC 4515 & RFC 4514 Escaping
  const escapedFilter = escapeLdapFilter('admin*)(|(uid=*))\\test\0');
  assert.strictEqual(escapedFilter, 'admin\\2a\\29\\28|\\28uid=\\2a\\29\\29\\5ctest\\00');
  const escapedDn = escapeLdapDnValue(' #lead,plus+quote"slash\\trail ');
  assert(escapedDn.startsWith('\\ #lead\\,plus\\+quote\\"slash\\\\trail\\ '));
  console.log('✔ Test 1 passed: RFC 4515 filter escaping and RFC 4514 DN escaping verified.');

  // Test 2: Group-to-Role Precedence
  assert.strictEqual(mapLdapGroupsToRole(['vigilante-readonly', 'axonwall-admin']), 'owner');
  assert.strictEqual(mapLdapGroupsToRole(['vigilante-readonly', 'vigilante-admin']), 'admin');
  assert.strictEqual(mapLdapGroupsToRole(['vigilante-readonly', 'vigilante-operator']), 'operator');
  assert.strictEqual(mapLdapGroupsToRole(['vigilante-readonly']), 'viewer');
  assert.strictEqual(mapLdapGroupsToRole([], undefined, 'viewer'), 'viewer');
  console.log('✔ Test 2 passed: POSIX group to Vigilante CASL role precedence verified.');

  // Test 3: Axonwall Plugin Binding JSON Discovery & Mock LDAPv3 Server Authentication
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-ldap-test-'));
  const server = createMockLdapServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  try {
    const pluginJsonPath = path.join(tmpDir, 'vigilante.json');
    await fs.writeFile(
      pluginJsonPath,
      JSON.stringify({
        pluginId: 'core-vigilante',
        enabled: true,
        url: `ldap://127.0.0.1:${port}`,
        baseDN: 'dc=axonwall,dc=local',
        bindDN: 'cn=svc-vigilante,ou=services,dc=axonwall,dc=local',
        bindPassword: 'svc-pass-123',
        userSearchBase: 'ou=users,dc=axonwall,dc=local',
        userSearchFilter: '(uid={username})',
        groupSearchBase: 'ou=groups,dc=axonwall,dc=local',
        groupSearchFilter: '(|(memberUid={username})(member={userDn}))',
        roleGroups: {
          admin: ['axonwall-admin', 'vigilante-admin'],
          operator: ['axonwall-operator', 'vigilante-operator'],
          readonly: ['axonwall-readonly', 'vigilante-readonly']
        }
      }),
      'utf8'
    );

    const cfg = resolveVigilanteLdapConfig({ pluginConfigPath: pluginJsonPath });
    assert.strictEqual(cfg.enabled, true);
    assert.strictEqual(cfg.source, 'axonwall-plugin');
    assert.strictEqual(cfg.uri, `ldap://127.0.0.1:${port}`);

    const st = await getVigilanteLdapStatus({ pluginConfigPath: pluginJsonPath });
    assert.strictEqual(st.reachable, true);

    // Authenticate SOC Owner
    const ownerRes = await authenticateLdapUser('soc-owner', 'owner-secret-password', {
      pluginConfigPath: pluginJsonPath
    });
    assert.strictEqual(ownerRes.ok, true);
    assert.strictEqual(ownerRes.role, 'owner');
    assert.strictEqual(ownerRes.displayName, 'SOC Chief Owner');
    assert(ownerRes.groups.includes('axonwall-admin'));

    // Authenticate SOC Analyst (operator)
    const analystRes = await authenticateLdapUser('soc-analyst', 'analyst-secret-password', {
      pluginConfigPath: pluginJsonPath
    });
    assert.strictEqual(analystRes.ok, true);
    assert.strictEqual(analystRes.role, 'operator');

    // Reject wrong password
    const badPwRes = await authenticateLdapUser('soc-analyst', 'wrong-password', {
      pluginConfigPath: pluginJsonPath
    });
    assert.strictEqual(badPwRes.ok, false);
    assert.strictEqual(badPwRes.code, 'INVALID_CREDENTIALS');

    // Reject locked account
    const lockedRes = await authenticateLdapUser('locked-user', 'locked-password', {
      pluginConfigPath: pluginJsonPath
    });
    assert.strictEqual(lockedRes.ok, false);
    assert.strictEqual(lockedRes.code, 'ACCOUNT_LOCKED');
    console.log('✔ Test 3 passed: Live RFC 4511 LDAPv3 two-phase bind, group lookup, and lockout enforcement verified.');

    // Test 4: JIT Principal Sync into authz.yaml & CASL evaluation
    const authzPath = path.join(tmpDir, 'authz.yaml');
    await initOwner({ name: 'Local Break-Glass Owner', password: 'super-secure-password-123' }, authzPath);

    const syncedAnalyst = await syncLdapPrincipal(analystRes, { autoProvision: true }, authzPath);
    assert(syncedAnalyst && syncedAnalyst.ldapUid === 'soc-analyst');
    assert.strictEqual(syncedAnalyst.role, 'operator');

    const loaded = loadAuthzStore(authzPath, { forceReload: true });
    const found = findPrincipalByLdapUid(loaded.store, 'soc-analyst');
    assert(found && found.id === syncedAnalyst.id);

    const ability = buildAbilityFor(found);
    assert.strictEqual(ability.can('deploy', 'Module'), true);
    assert.strictEqual(ability.can('manage_permissions', 'User'), false);

    const decision = decide(loaded, found, 'forensics:run', {}, { authMethod: 'ldap' });
    assert.strictEqual(decision.allowed, true);
    console.log('✔ Test 4 passed: JIT principal provisioning into authz.yaml and CASL permission checks verified.');
  } finally {
    server.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  }

  // Test 5: LDAPS TLS verification defaults on; explicit opt-out honored.
  // (No TLS server needed here: the live cert-rejection behavior is
  // covered by the mock-directory probe; this pins the config contract.)
  {
    const secure = resolveVigilanteLdapConfig({ enabled: true, uri: 'ldaps://127.0.0.1:636' });
    assert.strictEqual(secure.tlsRejectUnauthorized, true, 'LDAPS must verify certificates by default');
    assert.strictEqual(secure.tlsCaFile, null);
    const insecure = resolveVigilanteLdapConfig({
      enabled: true,
      uri: 'ldaps://127.0.0.1:636',
      tlsRejectUnauthorized: false,
      tlsCaFile: '/tmp/ca.pem'
    });
    assert.strictEqual(insecure.tlsRejectUnauthorized, false, 'Explicit opt-out must be honored');
    assert.strictEqual(insecure.tlsCaFile, '/tmp/ca.pem');
    console.log('✔ Test 5 passed: LDAPS TLS verification on by default, opt-out and CA file honored.');
  }

  // Test 6: Fail-closed LDAP lookups — no silent viewer fallback, no
  // first-entry-wins, no swallowed search errors (hunt A2/A3).
  {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-ldap-test-'));
    const server = createMockLdapServer();
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    try {
      const pluginJsonPath = path.join(tmpDir, 'vigilante.json');
      await fs.writeFile(
        pluginJsonPath,
        JSON.stringify({
          pluginId: 'core-vigilante',
          enabled: true,
          url: `ldap://127.0.0.1:${port}`,
          baseDN: 'dc=axonwall,dc=local',
          bindDN: 'cn=svc-vigilante,ou=services,dc=axonwall,dc=local',
          bindPassword: 'svc-pass-123',
          userSearchBase: 'ou=users,dc=axonwall,dc=local',
          userSearchFilter: '(uid={username})',
          groupSearchBase: 'ou=groups,dc=axonwall,dc=local',
          groupSearchFilter: '(|(memberUid={username})(member={userDn}))',
          roleGroups: {
            admin: ['axonwall-admin', 'vigilante-admin'],
            operator: ['axonwall-operator', 'vigilante-operator'],
            readonly: ['axonwall-readonly', 'vigilante-readonly']
          }
        }),
        'utf8'
      );
      const opts = { pluginConfigPath: pluginJsonPath };

      // Config contract: no implicit default role. An explicitly
      // configured default is still honored.
      const cfg = resolveVigilanteLdapConfig({ enabled: true, uri: 'ldap://127.0.0.1:1' });
      assert.strictEqual(cfg.defaultRole, null, 'Unmapped LDAP users must be denied, not defaulted to viewer');
      assert.strictEqual(mapLdapGroupsToRole([], undefined), null);
      assert.strictEqual(mapLdapGroupsToRole([], undefined, 'viewer'), 'viewer');

      // Happy path still works through the new checks.
      const analystRes = await authenticateLdapUser('soc-analyst', 'analyst-secret-password', opts);
      assert.strictEqual(analystRes.ok, true);
      assert.strictEqual(analystRes.role, 'operator');

      // Zero mapped groups -> NO_MAPPED_ROLE, not viewer.
      const noGroupRes = await authenticateLdapUser('nogroup-user', 'nogroup-secret', opts);
      assert.strictEqual(noGroupRes.ok, false);
      assert.strictEqual(noGroupRes.code, 'NO_MAPPED_ROLE');

      // Duplicate directory entries -> ambiguous, never first-wins.
      const dupRes = await authenticateLdapUser('dup-user', 'dup-user-secret', opts);
      assert.strictEqual(dupRes.ok, false);
      assert.strictEqual(dupRes.code, 'LDAP_AMBIGUOUS_USER');

      // Group search failure -> fail closed, not silent viewer.
      const groupErrRes = await authenticateLdapUser('group-error-user', 'group-error-secret', opts);
      assert.strictEqual(groupErrRes.ok, false);
      assert.strictEqual(groupErrRes.code, 'LDAP_GROUP_LOOKUP_FAILED');

      // User search failure -> fail closed, not "user not found".
      const userErrRes = await authenticateLdapUser('user-error-user', 'user-error-secret', opts);
      assert.strictEqual(userErrRes.ok, false);
      assert.strictEqual(userErrRes.code, 'LDAP_USER_LOOKUP_FAILED');

      console.log('✔ Test 6 passed: fail-closed LDAP lookups (no viewer fallback, no first-entry-wins, search errors denied).');
    } finally {
      server.close();
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  }

  console.log('🎉 ALL VIGILANTE OPENLDAP AUTHZ TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Vigilante OpenLDAP test failed:', err);
  process.exit(1);
});
