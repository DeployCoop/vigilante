import fsSync from 'node:fs';
import net from 'node:net';
import tls from 'node:tls';
import { load as yamlLoad } from 'js-yaml';
import { getVigilanteAuthzFile, getVigilanteConfigFile } from './config.js';

export const DEFAULT_AXONWALL_PLUGIN_PATHS = [
  '/etc/axonwall/ldap-plugins/vigilante.json',
  '/etc/axonwall/ldap-plugins/core-vigilante.json',
  '/etc/axonwall/vigilante/ldap.json',
  '/var/lib/axonwall/vigilante/ldap.json'
];

export const DEFAULT_ROLE_MAPPING = {
  ownerGroups: ['axonwall-admin'],
  adminGroups: ['vigilante-admin'],
  operatorGroups: ['axonwall-operator', 'vigilante-operator'],
  viewerGroups: ['axonwall-readonly', 'vigilante-readonly']
};

/**
 * RFC 4515 Section 3: Escape special characters in LDAP search filter assertion values.
 * @param {string} value
 * @returns {string}
 */
export function escapeLdapFilter(value) {
  return String(value ?? '').replace(/[\0*()\\]/g, ch => {
    const hex = ch.charCodeAt(0).toString(16).padStart(2, '0');
    return `\\${hex}`;
  });
}

/**
 * RFC 4514: Escape special characters in LDAP Relative Distinguished Name (RDN) values.
 * @param {string} value
 * @returns {string}
 */
export function escapeLdapDnValue(value) {
  const s = String(value ?? '');
  if (!s) return '';
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const code = ch.charCodeAt(0);
    if (code === 0) {
      out += '\\00';
    } else if (i === 0 && (ch === ' ' || ch === '#')) {
      out += `\\${ch}`;
    } else if (i === s.length - 1 && ch === ' ') {
      out += '\\ ';
    } else if (['"', '+', ',', ';', '<', '>', '\\'].includes(ch)) {
      out += `\\${ch}`;
    } else {
      out += ch;
    }
  }
  return out;
}

function splitCsv(val) {
  if (!val) return [];
  if (Array.isArray(val)) return val.map(x => String(x).trim()).filter(Boolean);
  return String(val)
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
}

/**
 * Resolve Vigilante LDAP configuration from:
 * 1. Explicit overrides
 * 2. Axonwall plugin binding JSON (/etc/axonwall/ldap-plugins/vigilante.json, /etc/axonwall/vigilante/ldap.json, etc.)
 * 3. Vigilante config.yaml / authz.yaml (ldap section)
 * 4. VIGILANTE_LDAP_* environment variables
 *
 * @param {Object} [overrides]
 */
export function resolveVigilanteLdapConfig(overrides = {}) {
  let fileBinding = null;
  let discoveredPath = null;

  const candidatePaths = [
    overrides.pluginConfigPath,
    process.env.VIGILANTE_LDAP_CONFIG_PATH,
    process.env.VIGILANTE_LDAP_PLUGIN_CONFIG_PATH,
    ...DEFAULT_AXONWALL_PLUGIN_PATHS
  ].filter(Boolean);

  for (const p of candidatePaths) {
    try {
      if (fsSync.existsSync(p)) {
        const raw = fsSync.readFileSync(p, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') {
          fileBinding = parsed;
          discoveredPath = p;
          break;
        }
      }
    } catch {
      // Ignore unreadable or malformed file and try next candidate
    }
  }

  let yamlLdap = null;
  const yamlCandidates = [
    overrides.configFilePath || getVigilanteConfigFile(),
    overrides.authzFilePath || getVigilanteAuthzFile()
  ].filter(Boolean);

  for (const yp of yamlCandidates) {
    try {
      if (fsSync.existsSync(yp)) {
        const raw = fsSync.readFileSync(yp, 'utf8');
        const parsed = yamlLoad(raw);
        if (parsed && typeof parsed === 'object' && parsed.ldap && typeof parsed.ldap === 'object') {
          yamlLdap = { ...(yamlLdap || {}), ...parsed.ldap };
          if (!discoveredPath) discoveredPath = yp;
        }
      }
    } catch {
      // Ignore unreadable YAML
    }
  }

  const envEnabled = process.env.VIGILANTE_LDAP_ENABLED;
  const envUri = process.env.VIGILANTE_LDAP_URI || process.env.VIGILANTE_LDAP_URL;
  const envBaseDN = process.env.VIGILANTE_LDAP_BASE_DN;
  const envBindDN = process.env.VIGILANTE_LDAP_BIND_DN;
  const envBindPassword = process.env.VIGILANTE_LDAP_BIND_PASSWORD;

  const baseDN =
    overrides.baseDN ||
    envBaseDN ||
    fileBinding?.baseDn ||
    fileBinding?.baseDN ||
    yamlLdap?.baseDN ||
    yamlLdap?.baseDn ||
    'dc=axonwall,dc=local';

  const uri =
    overrides.uri ||
    envUri ||
    fileBinding?.url ||
    fileBinding?.uri ||
    yamlLdap?.uri ||
    yamlLdap?.url ||
    'ldap://127.0.0.1:389';

  const enabled =
    overrides.enabled !== undefined
      ? Boolean(overrides.enabled)
      : envEnabled !== undefined
      ? envEnabled === 'true' || envEnabled === '1'
      : yamlLdap?.enabled !== undefined
      ? Boolean(yamlLdap.enabled)
      : fileBinding?.enabled !== undefined
      ? Boolean(fileBinding.enabled)
      : Boolean(fileBinding || envUri || envBaseDN);

  const bindDN =
    overrides.bindDN !== undefined
      ? overrides.bindDN
      : envBindDN ||
        fileBinding?.bindDn ||
        fileBinding?.bindDN ||
        yamlLdap?.bindDN ||
        yamlLdap?.bindDn ||
        '';

  const bindPassword =
    overrides.bindPassword !== undefined
      ? overrides.bindPassword
      : envBindPassword ||
        fileBinding?.bindPassword ||
        yamlLdap?.bindPassword ||
        '';

  const userSearchBase =
    overrides.userSearchBase ||
    process.env.VIGILANTE_LDAP_USER_SEARCH_BASE ||
    fileBinding?.userSearchBase ||
    yamlLdap?.userSearchBase ||
    `ou=users,${baseDN}`;

  const userSearchFilter =
    overrides.userSearchFilter ||
    process.env.VIGILANTE_LDAP_USER_SEARCH_FILTER ||
    fileBinding?.userSearchFilter ||
    yamlLdap?.userSearchFilter ||
    '(uid={username})';

  const groupSearchBase =
    overrides.groupSearchBase ||
    process.env.VIGILANTE_LDAP_GROUP_SEARCH_BASE ||
    fileBinding?.groupSearchBase ||
    yamlLdap?.groupSearchBase ||
    `ou=groups,${baseDN}`;

  const groupSearchFilter =
    overrides.groupSearchFilter ||
    process.env.VIGILANTE_LDAP_GROUP_SEARCH_FILTER ||
    fileBinding?.groupSearchFilter ||
    yamlLdap?.groupSearchFilter ||
    '(|(memberUid={username})(member={userDn}))';

  const bindingRoleGroups = fileBinding?.roleGroups || {};
  const yamlRoleMapping = yamlLdap?.roleMapping || {};
  const overrideMapping = overrides.roleMapping || {};

  const ownerGroups = Array.from(
    new Set([
      ...DEFAULT_ROLE_MAPPING.ownerGroups,
      ...splitCsv(process.env.VIGILANTE_LDAP_OWNER_GROUPS),
      ...splitCsv(yamlRoleMapping.ownerGroups),
      ...splitCsv(overrideMapping.ownerGroups)
    ])
  );

  const adminGroups = Array.from(
    new Set([
      ...DEFAULT_ROLE_MAPPING.adminGroups,
      ...splitCsv(bindingRoleGroups.admin).filter(g => !ownerGroups.includes(g)),
      ...splitCsv(process.env.VIGILANTE_LDAP_ADMIN_GROUPS),
      ...splitCsv(yamlRoleMapping.adminGroups),
      ...splitCsv(overrideMapping.adminGroups)
    ])
  );

  const operatorGroups = Array.from(
    new Set([
      ...DEFAULT_ROLE_MAPPING.operatorGroups,
      ...splitCsv(bindingRoleGroups.operator),
      ...splitCsv(process.env.VIGILANTE_LDAP_OPERATOR_GROUPS),
      ...splitCsv(yamlRoleMapping.operatorGroups),
      ...splitCsv(overrideMapping.operatorGroups)
    ])
  );

  const viewerGroups = Array.from(
    new Set([
      ...DEFAULT_ROLE_MAPPING.viewerGroups,
      ...splitCsv(bindingRoleGroups.readonly),
      ...splitCsv(process.env.VIGILANTE_LDAP_VIEWER_GROUPS || process.env.VIGILANTE_LDAP_READONLY_GROUPS),
      ...splitCsv(yamlRoleMapping.viewerGroups),
      ...splitCsv(overrideMapping.viewerGroups)
    ])
  );

  const autoProvisionPrincipals =
    overrides.autoProvisionPrincipals !== undefined
      ? Boolean(overrides.autoProvisionPrincipals)
      : process.env.VIGILANTE_LDAP_AUTO_PROVISION !== undefined
      ? process.env.VIGILANTE_LDAP_AUTO_PROVISION !== 'false' && process.env.VIGILANTE_LDAP_AUTO_PROVISION !== '0'
      : yamlLdap?.autoProvisionPrincipals !== undefined
      ? Boolean(yamlLdap.autoProvisionPrincipals)
      : true;

  const allowLocalBreakGlass =
    overrides.allowLocalBreakGlass !== undefined
      ? Boolean(overrides.allowLocalBreakGlass)
      : process.env.VIGILANTE_LDAP_ALLOW_BREAK_GLASS !== undefined
      ? process.env.VIGILANTE_LDAP_ALLOW_BREAK_GLASS !== 'false' && process.env.VIGILANTE_LDAP_ALLOW_BREAK_GLASS !== '0'
      : yamlLdap?.allowLocalBreakGlass !== undefined
      ? Boolean(yamlLdap.allowLocalBreakGlass)
      : true;

  const defaultRole =
    overrides.defaultRole ||
    process.env.VIGILANTE_LDAP_DEFAULT_ROLE ||
    yamlLdap?.defaultRole ||
    'viewer';

  const timeoutMs = Number(
    overrides.timeoutMs || process.env.VIGILANTE_LDAP_TIMEOUT_MS || yamlLdap?.timeoutMs || 5000
  );

  const source = overrides.uri
    ? 'override'
    : envUri || envBaseDN || envEnabled !== undefined
    ? 'env'
    : fileBinding
    ? 'axonwall-plugin'
    : yamlLdap
    ? 'config-yaml'
    : 'default';

  return {
    enabled,
    uri,
    baseDN,
    bindDN,
    bindPassword,
    userSearchBase,
    userSearchFilter,
    groupSearchBase,
    groupSearchFilter,
    autoProvisionPrincipals,
    allowLocalBreakGlass,
    defaultRole,
    timeoutMs,
    roleMapping: {
      ownerGroups,
      adminGroups,
      operatorGroups,
      viewerGroups
    },
    source,
    discoveredPath
  };
}

/**
 * Map a list of LDAP group CNs to the highest-privilege Vigilante CASL role.
 * Precedence: owner > admin > operator > viewer > defaultRole
 *
 * @param {string[]} groups
 * @param {Object} [roleMapping]
 * @param {string} [defaultRole='viewer']
 * @returns {'owner' | 'admin' | 'operator' | 'viewer' | null}
 */
export function mapLdapGroupsToRole(groups = [], roleMapping = DEFAULT_ROLE_MAPPING, defaultRole = 'viewer') {
  const normalized = new Set(
    (groups || []).map(g => {
      const s = String(g).trim();
      const match = /^cn=([^,]+)/i.exec(s);
      return (match ? match[1] : s).toLowerCase();
    })
  );

  const hasAny = list => (list || []).some(g => normalized.has(String(g).toLowerCase()));

  if (hasAny(roleMapping.ownerGroups)) return 'owner';
  if (hasAny(roleMapping.adminGroups)) return 'admin';
  if (hasAny(roleMapping.operatorGroups)) return 'operator';
  if (hasAny(roleMapping.viewerGroups)) return 'viewer';
  return defaultRole || null;
}

// =============================================================================
// Minimal Zero-Dependency ASN.1 BER / RFC 4511 LDAPv3 Wire Client
// =============================================================================

function berEncodeLength(len) {
  if (len < 0x80) {
    return Buffer.from([len]);
  }
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function berEncodeElement(tag, payload) {
  const buf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  return Buffer.concat([Buffer.from([tag]), berEncodeLength(buf.length), buf]);
}

function berEncodeInt(value) {
  let v = Number(value);
  if (v === 0) return berEncodeElement(0x02, Buffer.from([0]));
  const bytes = [];
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  if (bytes[0] & 0x80) bytes.unshift(0x00);
  return berEncodeElement(0x02, Buffer.from(bytes));
}

function berEncodeEnum(value) {
  return berEncodeElement(0x0a, Buffer.from([Number(value) & 0xff]));
}

function berEncodeBool(value) {
  return berEncodeElement(0x01, Buffer.from([value ? 0xff : 0x00]));
}

function berEncodeOctetString(str) {
  return berEncodeElement(0x04, Buffer.from(String(str ?? ''), 'utf8'));
}

function berEncodeSequence(items) {
  return berEncodeElement(0x30, Buffer.concat(items));
}

function berDecodeLength(buf, offset) {
  if (offset >= buf.length) return null;
  const first = buf[offset];
  if ((first & 0x80) === 0) {
    return { length: first, bytesRead: 1 };
  }
  const numBytes = first & 0x7f;
  if (numBytes === 0 || offset + 1 + numBytes > buf.length) return null;
  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | buf[offset + 1 + i];
  }
  return { length, bytesRead: 1 + numBytes };
}

function berReadElement(buf, offset = 0) {
  if (offset >= buf.length) return null;
  const tag = buf[offset];
  const lenInfo = berDecodeLength(buf, offset + 1);
  if (!lenInfo) return null;
  const valueStart = offset + 1 + lenInfo.bytesRead;
  const valueEnd = valueStart + lenInfo.length;
  if (valueEnd > buf.length) return null;
  return {
    tag,
    length: lenInfo.length,
    value: buf.subarray(valueStart, valueEnd),
    nextOffset: valueEnd
  };
}

function berReadChildren(buf) {
  const children = [];
  let offset = 0;
  while (offset < buf.length) {
    const el = berReadElement(buf, offset);
    if (!el) break;
    children.push(el);
    offset = el.nextOffset;
  }
  return children;
}

function berReadInt(el) {
  if (!el || el.value.length === 0) return 0;
  let v = 0;
  for (let i = 0; i < el.value.length; i++) {
    v = (v << 8) | el.value[i];
  }
  return v;
}

/**
 * Encode an RFC 4515 filter string into ASN.1 BER Filter bytes.
 */
function encodeLdapFilterAst(filterStr) {
  const s = String(filterStr || '').trim();
  const inner = s.startsWith('(') && s.endsWith(')') ? s.slice(1, -1).trim() : s;

  if (inner.startsWith('&') || inner.startsWith('|')) {
    const tag = inner[0] === '&' ? 0xa0 : 0xa1;
    const subFilters = splitTopLevelFilters(inner.slice(1));
    return berEncodeElement(tag, Buffer.concat(subFilters.map(encodeLdapFilterAst)));
  }

  if (inner.startsWith('!')) {
    return berEncodeElement(0xa2, encodeLdapFilterAst(inner.slice(1)));
  }

  const eqIdx = inner.indexOf('=');
  if (eqIdx === -1) {
    return berEncodeElement(0x87, Buffer.from(inner, 'utf8'));
  }

  const attr = inner.slice(0, eqIdx).trim();
  const rawVal = inner.slice(eqIdx + 1);

  if (rawVal === '*') {
    // Present filter [7] AttributeDescription
    return berEncodeElement(0x87, Buffer.from(attr, 'utf8'));
  }

  // Equality match [3] AttributeValueAssertion
  const unescapedBytes = unescapeFilterValueToBuffer(rawVal);
  return berEncodeElement(
    0xa3,
    Buffer.concat([berEncodeOctetString(attr), berEncodeElement(0x04, unescapedBytes)])
  );
}

function splitTopLevelFilters(s) {
  const parts = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '(') {
      if (depth === 0) start = i;
      depth++;
    } else if (s[i] === ')') {
      depth--;
      if (depth === 0 && start !== -1) {
        parts.push(s.slice(start, i + 1));
        start = -1;
      }
    }
  }
  return parts;
}

function unescapeFilterValueToBuffer(rawVal) {
  const bytes = [];
  for (let i = 0; i < rawVal.length; i++) {
    if (rawVal[i] === '\\' && i + 2 < rawVal.length && /^[0-9a-fA-F]{2}$/.test(rawVal.slice(i + 1, i + 3))) {
      bytes.push(parseInt(rawVal.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      const charBuf = Buffer.from(rawVal[i], 'utf8');
      for (const b of charBuf) bytes.push(b);
    }
  }
  return Buffer.from(bytes);
}

function buildBindRequest(messageId, bindDN, password) {
  const bindReq = berEncodeElement(
    0x60, // [APPLICATION 0] BindRequest
    Buffer.concat([
      berEncodeInt(3), // version 3
      berEncodeOctetString(bindDN || ''),
      berEncodeElement(0x80, Buffer.from(String(password ?? ''), 'utf8')) // [0] simple auth
    ])
  );
  return berEncodeSequence([berEncodeInt(messageId), bindReq]);
}

function buildSearchRequest(messageId, baseDN, filterStr, attributes = []) {
  const searchReq = berEncodeElement(
    0x63, // [APPLICATION 3] SearchRequest
    Buffer.concat([
      berEncodeOctetString(baseDN),
      berEncodeEnum(2), // wholeSubtree (2)
      berEncodeEnum(0), // neverDerefAliases (0)
      berEncodeInt(100), // sizeLimit
      berEncodeInt(10), // timeLimit
      berEncodeBool(false), // typesOnly
      encodeLdapFilterAst(filterStr),
      berEncodeSequence(attributes.map(a => berEncodeOctetString(a)))
    ])
  );
  return berEncodeSequence([berEncodeInt(messageId), searchReq]);
}

function buildUnbindRequest(messageId) {
  const unbindReq = berEncodeElement(0x42, Buffer.alloc(0)); // [APPLICATION 2] UnbindRequest
  return berEncodeSequence([berEncodeInt(messageId), unbindReq]);
}

function parseLdapTarget(uri) {
  const u = new URL(uri.includes('://') ? uri : `ldap://${uri}`);
  const isTls = u.protocol === 'ldaps:';
  const host = u.hostname || '127.0.0.1';
  const port = u.port ? Number(u.port) : isTls ? 636 : 389;
  return { isTls, host, port };
}

class MinimalLdapSession {
  constructor(uri, timeoutMs = 5000) {
    this.uri = uri;
    this.timeoutMs = timeoutMs;
    this.socket = null;
    this.buffer = Buffer.alloc(0);
    this.nextMsgId = 1;
    this.pending = null;
  }

  connect() {
    const { isTls, host, port } = parseLdapTarget(this.uri);
    return new Promise((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          this.close();
          reject(new Error(`LDAP connection timed out (${host}:${port})`));
        }
      }, this.timeoutMs);

      const onConnect = () => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          resolve();
        }
      };

      const onError = err => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(err);
        } else if (this.pending) {
          const p = this.pending;
          this.pending = null;
          p.reject(err);
        }
      };

      this.socket = isTls
        ? tls.connect({ host, port, rejectUnauthorized: false }, onConnect)
        : net.createConnection({ host, port }, onConnect);

      this.socket.on('error', onError);
      this.socket.on('data', chunk => {
        this.buffer = Buffer.concat([this.buffer, chunk]);
        this._drainBuffer();
      });
      this.socket.on('close', () => {
        if (this.pending) {
          const p = this.pending;
          this.pending = null;
          p.reject(new Error('LDAP socket closed unexpectedly'));
        }
      });
    });
  }

  _drainBuffer() {
    while (this.buffer.length > 0) {
      const msgEl = berReadElement(this.buffer, 0);
      if (!msgEl) break;
      this.buffer = this.buffer.subarray(msgEl.nextOffset);

      const children = berReadChildren(msgEl.value);
      if (children.length < 2) continue;
      const opEl = children[1];

      if (!this.pending) continue;

      if (opEl.tag === 0x61 && this.pending.type === 'bind') {
        // BindResponse [APPLICATION 1]
        const bindChildren = berReadChildren(opEl.value);
        const resultCode = berReadInt(bindChildren[0]);
        const diagnosticMessage = bindChildren[2] ? bindChildren[2].value.toString('utf8') : '';
        const p = this.pending;
        this.pending = null;
        clearTimeout(p.timer);
        p.resolve({ resultCode, diagnosticMessage });
      } else if (opEl.tag === 0x64 && this.pending.type === 'search') {
        // SearchResultEntry [APPLICATION 4]
        const entryChildren = berReadChildren(opEl.value);
        const objectName = entryChildren[0] ? entryChildren[0].value.toString('utf8') : '';
        const attrs = {};
        if (entryChildren[1]) {
          const attrSeqs = berReadChildren(entryChildren[1].value);
          for (const attrSeq of attrSeqs) {
            const parts = berReadChildren(attrSeq.value);
            if (parts.length >= 2) {
              const attrName = parts[0].value.toString('utf8').toLowerCase();
              const valEls = berReadChildren(parts[1].value);
              attrs[attrName] = valEls.map(v => v.value.toString('utf8'));
            }
          }
        }
        this.pending.entries.push({ dn: objectName, attributes: attrs });
      } else if (opEl.tag === 0x65 && this.pending.type === 'search') {
        // SearchResultDone [APPLICATION 5]
        const doneChildren = berReadChildren(opEl.value);
        const resultCode = berReadInt(doneChildren[0]);
        const p = this.pending;
        this.pending = null;
        clearTimeout(p.timer);
        p.resolve({ resultCode, entries: p.entries });
      }
    }
  }

  bind(bindDN, password) {
    const msgId = this.nextMsgId++;
    const packet = buildBindRequest(msgId, bindDN, password);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending = null;
        reject(new Error('LDAP bind request timed out'));
      }, this.timeoutMs);
      this.pending = { type: 'bind', timer, resolve, reject };
      this.socket.write(packet);
    });
  }

  search(baseDN, filterStr, attributes = []) {
    const msgId = this.nextMsgId++;
    const packet = buildSearchRequest(msgId, baseDN, filterStr, attributes);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending = null;
        reject(new Error('LDAP search request timed out'));
      }, this.timeoutMs);
      this.pending = { type: 'search', entries: [], timer, resolve, reject };
      this.socket.write(packet);
    });
  }

  close() {
    try {
      if (this.socket && !this.socket.destroyed) {
        const msgId = this.nextMsgId++;
        this.socket.write(buildUnbindRequest(msgId));
        this.socket.end();
        this.socket.destroy();
      }
    } catch {
      // Ignore socket close errors
    }
  }
}

function buildFilterFromTemplate(template, replacements) {
  let out = String(template || '(uid={username})');
  for (const [k, v] of Object.entries(replacements)) {
    const escaped = escapeLdapFilter(v);
    out = out
      .replace(new RegExp(`\\{\\{${k}\\}\\}`, 'g'), escaped)
      .replace(new RegExp(`\\{${k}\\}`, 'g'), escaped);
  }
  return out;
}

/**
 * Authenticate a user against Axonwall's local OpenLDAP directory (or configured LDAPv3 server)
 * and resolve their POSIX group memberships and Vigilante CASL role.
 *
 * @param {string} username
 * @param {string} password
 * @param {Object} [configOverrides]
 */
export async function authenticateLdapUser(username, password, configOverrides = {}) {
  const cleanUser = String(username ?? '').trim();
  const cleanPass = String(password ?? '');

  if (!cleanUser || !cleanPass) {
    return {
      ok: false,
      code: 'INVALID_CREDENTIALS',
      error: 'Username and password are required.'
    };
  }

  const cfg = resolveVigilanteLdapConfig(configOverrides);
  if (!cfg.enabled) {
    return {
      ok: false,
      code: 'LDAP_DISABLED',
      error: 'OpenLDAP authentication is not enabled.'
    };
  }

  const lookupSession = new MinimalLdapSession(cfg.uri, cfg.timeoutMs);
  let userDN = '';
  let displayName = cleanUser;
  let email = undefined;
  let groups = [];

  try {
    await lookupSession.connect();

    // Phase 1: Bind with service account (if configured) and search for the user entry
    if (cfg.bindDN && cfg.bindPassword) {
      const svcBind = await lookupSession.bind(cfg.bindDN, cfg.bindPassword);
      if (svcBind.resultCode !== 0) {
        return {
          ok: false,
          code: 'SERVICE_BIND_FAILED',
          error: `LDAP service account bind failed (code ${svcBind.resultCode}).`
        };
      }

      const userFilter = buildFilterFromTemplate(cfg.userSearchFilter, {
        username: cleanUser,
        uid: cleanUser
      });
      const userSearch = await lookupSession.search(cfg.userSearchBase, userFilter, [
        'uid',
        'cn',
        'displayName',
        'mail',
        'memberOf',
        'pwdAccountLockedTime'
      ]);

      if (!userSearch.entries || userSearch.entries.length === 0) {
        return {
          ok: false,
          code: 'USER_NOT_FOUND',
          error: `User '${cleanUser}' was not found in OpenLDAP directory.`
        };
      }

      const entry = userSearch.entries[0];
      userDN = entry.dn;
      const attrs = entry.attributes || {};

      if (attrs.pwdaccountlockedtime && attrs.pwdaccountlockedtime.length > 0) {
        return {
          ok: false,
          code: 'ACCOUNT_LOCKED',
          error: `Directory account '${cleanUser}' is locked by OpenLDAP password policy.`
        };
      }

      displayName =
        (attrs.displayname && attrs.displayname[0]) ||
        (attrs.cn && attrs.cn[0]) ||
        cleanUser;
      email = attrs.mail && attrs.mail[0] ? attrs.mail[0] : undefined;

      if (attrs.memberof && attrs.memberof.length > 0) {
        groups.push(...attrs.memberof);
      }
    } else {
      userDN = `uid=${escapeLdapDnValue(cleanUser)},${cfg.userSearchBase}`;
    }

    // Phase 2: Verify user password on a separate LDAP session
    const userSession = new MinimalLdapSession(cfg.uri, cfg.timeoutMs);
    try {
      await userSession.connect();
      const userBind = await userSession.bind(userDN, cleanPass);
      if (userBind.resultCode !== 0) {
        return {
          ok: false,
          code: 'INVALID_CREDENTIALS',
          error: 'Invalid OpenLDAP username or password.'
        };
      }
    } finally {
      userSession.close();
    }

    // Phase 3: Query POSIX / groupOfNames memberships in ou=groups,<baseDN>
    const groupFilter = buildFilterFromTemplate(cfg.groupSearchFilter, {
      username: cleanUser,
      uid: cleanUser,
      userDn: userDN,
      dn: userDN
    });
    const groupSearch = await lookupSession.search(cfg.groupSearchBase, groupFilter, ['cn']);
    if (groupSearch.entries && groupSearch.entries.length > 0) {
      for (const ge of groupSearch.entries) {
        const cns = ge.attributes?.cn || [];
        for (const cn of cns) {
          groups.push(cn);
        }
      }
    }

    const dedupGroups = Array.from(
      new Set(
        groups
          .map(g => {
            const m = /^cn=([^,]+)/i.exec(String(g).trim());
            return m ? m[1] : String(g).trim();
          })
          .filter(Boolean)
      )
    );

    const mappedRole = mapLdapGroupsToRole(dedupGroups, cfg.roleMapping, cfg.defaultRole);
    if (!mappedRole) {
      return {
        ok: false,
        code: 'NO_MAPPED_ROLE',
        error: `User '${cleanUser}' does not belong to any authorized Vigilante LDAP group.`
      };
    }

    return {
      ok: true,
      username: cleanUser,
      userDN,
      displayName,
      email,
      groups: dedupGroups,
      role: mappedRole,
      source: cfg.source
    };
  } catch (err) {
    return {
      ok: false,
      code: 'LDAP_UNAVAILABLE',
      error: err?.message || 'Failed to communicate with OpenLDAP server.'
    };
  } finally {
    lookupSession.close();
  }
}

/**
 * Inspect current Vigilante LDAP configuration and optionally probe TCP reachability.
 *
 * @param {Object} [configOverrides]
 */
export async function getVigilanteLdapStatus(configOverrides = {}) {
  const cfg = resolveVigilanteLdapConfig(configOverrides);
  const { host, port } = parseLdapTarget(cfg.uri);

  let reachable = false;
  if (cfg.enabled) {
    reachable = await new Promise(resolve => {
      const sock = net.createConnection({ host, port });
      const timer = setTimeout(() => {
        sock.destroy();
        resolve(false);
      }, 1200);
      sock.on('connect', () => {
        clearTimeout(timer);
        sock.destroy();
        resolve(true);
      });
      sock.on('error', () => {
        clearTimeout(timer);
        sock.destroy();
        resolve(false);
      });
    });
  }

  return {
    enabled: cfg.enabled,
    reachable,
    uri: cfg.uri,
    baseDN: cfg.baseDN,
    bindDN: cfg.bindDN,
    hasBindPassword: Boolean(cfg.bindPassword),
    userSearchBase: cfg.userSearchBase,
    groupSearchBase: cfg.groupSearchBase,
    autoProvisionPrincipals: cfg.autoProvisionPrincipals,
    allowLocalBreakGlass: cfg.allowLocalBreakGlass,
    defaultRole: cfg.defaultRole,
    roleMapping: cfg.roleMapping,
    source: cfg.source,
    discoveredPath: cfg.discoveredPath
  };
}
