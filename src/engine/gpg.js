import { execa } from 'execa';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { loadConfig } from './config.js';
import { logger } from '../utils/logger.js';

/**
 * Check if the gpg binary is available in the system PATH
 * @returns {Promise<boolean>}
 */
export async function isGpgAvailable() {
  try {
    await execa('which', ['gpg']);
    return true;
  } catch {
    try {
      await execa('which', ['gpg2']);
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Get GPG command binary name (gpg or gpg2)
 * @returns {Promise<string>}
 */
export async function getGpgBinary() {
  try {
    await execa('which', ['gpg']);
    return 'gpg';
  } catch {
    return 'gpg2';
  }
}

/**
 * Build env object including GNUPGHOME if configured
 * @param {string} [customHome]
 * @returns {Object}
 */
export function getGpgEnv(customHome) {
  const config = loadConfig();
  const gnupgHome = customHome || config.gpg?.gnupgHome || process.env.GNUPGHOME;
  if (gnupgHome && gnupgHome.trim()) {
    return { ...process.env, GNUPGHOME: gnupgHome.trim() };
  }
  return process.env;
}

/**
 * List all available secret (signing) GPG keys in keyring
 * @param {string} [gnupgHome]
 * @returns {Promise<Array<Object>>}
 */
export async function listSecretKeys(gnupgHome) {
  const isAvail = await isGpgAvailable();
  if (!isAvail) return [];

  const gpgBin = await getGpgBinary();
  const env = getGpgEnv(gnupgHome);

  try {
    const { stdout } = await execa(gpgBin, ['--batch', '--list-secret-keys', '--with-colons'], { env });
    return parseGpgKeyList(stdout);
  } catch (err) {
    logger.warn('GPG:LIST_KEYS', `Failed to list secret keys: ${err.message}`);
    return [];
  }
}

/**
 * List all public GPG keys in keyring
 * @param {string} [gnupgHome]
 * @returns {Promise<Array<Object>>}
 */
export async function listPublicKeys(gnupgHome) {
  const isAvail = await isGpgAvailable();
  if (!isAvail) return [];

  const gpgBin = await getGpgBinary();
  const env = getGpgEnv(gnupgHome);

  try {
    const { stdout } = await execa(gpgBin, ['--batch', '--list-keys', '--with-colons'], { env });
    return parseGpgKeyList(stdout);
  } catch (err) {
    logger.warn('GPG:LIST_PUB_KEYS', `Failed to list public keys: ${err.message}`);
    return [];
  }
}

/**
 * Helper to parse colon-delimited gpg key output
 * @param {string} text
 * @returns {Array<Object>}
 */
export function parseGpgKeyList(text) {
  const keys = [];
  if (!text) return keys;

  let currentKey = null;
  const lines = text.split('\n');

  for (const line of lines) {
    const fields = line.split(':');
    const recordType = fields[0];

    if (recordType === 'sec' || recordType === 'pub') {
      if (currentKey) keys.push(currentKey);
      currentKey = {
        type: recordType === 'sec' ? 'secret' : 'public',
        keyId: fields[4] || '',
        createdTimestamp: fields[5] ? parseInt(fields[5], 10) : null,
        expiresTimestamp: fields[6] ? parseInt(fields[6], 10) : null,
        fingerprint: '',
        uids: [],
        primaryUid: '',
        email: '',
        name: ''
      };
    } else if (recordType === 'fpr' && currentKey && !currentKey.fingerprint) {
      currentKey.fingerprint = fields[9] || '';
      if (!currentKey.keyId && currentKey.fingerprint) {
        currentKey.keyId = currentKey.fingerprint.slice(-16);
      }
    } else if (recordType === 'uid' && currentKey) {
      const uidStr = fields[9] || '';
      currentKey.uids.push(uidStr);
      if (!currentKey.primaryUid) {
        currentKey.primaryUid = uidStr;
        // Parse "Name <email@domain>"
        const match = uidStr.match(/^(.*?)(?:\s*<([^>]+)>)?$/);
        if (match) {
          currentKey.name = (match[1] || '').trim();
          currentKey.email = match[2] || '';
        }
      }
    }
  }

  if (currentKey) keys.push(currentKey);
  return keys;
}

/**
 * Sign a file using GPG (creates detached ASCII-armored .asc signature by default)
 * @param {string} filePath Full path to the file to sign
 * @param {Object} [options]
 * @param {string} [options.keyId] Specific key identity (email, keyId, or fingerprint)
 * @param {string} [options.gnupgHome] Custom GNUPGHOME directory
 * @param {string} [options.outputPath] Custom signature destination path
 * @param {boolean} [options.detached=true]
 * @param {boolean} [options.armor=true]
 * @returns {Promise<{ success: boolean, signaturePath?: string, keyId?: string, error?: string, output?: string }>}
 */
export async function signFile(filePath, {
  keyId = null,
  gnupgHome = null,
  outputPath = null,
  detached = true,
  armor = true
} = {}) {
  const isAvail = await isGpgAvailable();
  if (!isAvail) {
    return { success: false, error: 'GPG binary (gpg/gpg2) is not installed on system' };
  }

  const config = loadConfig();
  const effectiveKeyId = keyId || config.gpg?.keyId || null;
  const env = getGpgEnv(gnupgHome);
  const gpgBin = await getGpgBinary();

  const signaturePath = outputPath || `${filePath}.asc`;

  const args = ['--batch', '--yes'];
  if (armor) args.push('--armor');
  if (detached) args.push('--detach-sign');
  if (effectiveKeyId && effectiveKeyId.trim()) {
    args.push('--default-key', effectiveKeyId.trim());
  }
  args.push('--output', signaturePath, filePath);

  logger.info('GPG:SIGN', `Signing ${filePath} -> ${signaturePath} with key ${effectiveKeyId || 'default'}`);

  try {
    const { stdout, stderr } = await execa(gpgBin, args, { env });
    return {
      success: true,
      signaturePath,
      keyId: effectiveKeyId || 'default',
      timestamp: new Date().toISOString(),
      output: stdout || stderr
    };
  } catch (err) {
    logger.warn('GPG:SIGN:ERROR', `Failed to sign ${filePath}: ${err.message}`);
    return {
      success: false,
      error: err.message,
      output: err.stdout || err.stderr || err.message
    };
  }
}

/**
 * Verify a file signature using GPG
 * @param {string} filePath Target data file
 * @param {string} signaturePath Detached signature (.asc) file
 * @param {Object} [options]
 * @param {string} [options.gnupgHome] Custom GNUPGHOME directory
 * @returns {Promise<{ success: boolean, isValid: boolean, signerUid?: string, fingerprint?: string, keyId?: string, signedAt?: string, output: string, error?: string }>}
 */
export async function verifyFileSignature(filePath, signaturePath, { gnupgHome = null } = {}) {
  const isAvail = await isGpgAvailable();
  if (!isAvail) {
    return { success: false, isValid: false, output: '', error: 'GPG binary not available' };
  }

  const gpgBin = await getGpgBinary();
  const env = getGpgEnv(gnupgHome);

  logger.info('GPG:VERIFY', `Verifying signature ${signaturePath} on ${filePath}`);

  try {
    const { stdout, stderr } = await execa(gpgBin, ['--batch', '--verify', signaturePath, filePath], { env });
    const fullOutput = `${stdout}\n${stderr}`;

    const isGood = fullOutput.includes('Good signature from') || fullOutput.includes('signature valid');
    let signerUid = null;
    let fingerprint = null;
    let keyId = null;
    let signedAt = null;

    const signerMatch = fullOutput.match(/Good signature from "([^"]+)"/);
    if (signerMatch) signerUid = signerMatch[1];

    const keyMatch = fullOutput.match(/using [A-Z0-9]+ key ([A-Fa-f0-9]+)/);
    if (keyMatch) fingerprint = keyMatch[1];

    const timeMatch = fullOutput.match(/Signature made ([^\n]+)/);
    if (timeMatch) signedAt = timeMatch[1];

    return {
      success: true,
      isValid: isGood,
      signerUid,
      fingerprint,
      keyId: fingerprint ? fingerprint.slice(-16) : null,
      signedAt,
      output: fullOutput.trim()
    };
  } catch (err) {
    const fullOutput = `${err.stdout || ''}\n${err.stderr || err.message}`.trim();
    return {
      success: false,
      isValid: false,
      error: err.message,
      output: fullOutput
    };
  }
}

/**
 * Sign an evidence file automatically if GPG signing is enabled in config.yaml
 * @param {string} filePath
 * @param {Object} [options]
 * @returns {Promise<{ isSigned: boolean, signaturePath?: string, keyId?: string, error?: string }>}
 */
export async function autoSignIfConfigured(filePath, options = {}) {
  const config = loadConfig();
  if (!config.gpg?.enabled || !config.gpg?.autoSign) {
    return { isSigned: false, reason: 'GPG signing disabled in config.yaml' };
  }

  const signRes = await signFile(filePath, {
    keyId: config.gpg.keyId,
    gnupgHome: config.gpg.gnupgHome,
    ...options
  });

  if (signRes.success) {
    return {
      isSigned: true,
      signaturePath: signRes.signaturePath,
      keyId: signRes.keyId,
      timestamp: signRes.timestamp
    };
  }

  return {
    isSigned: false,
    error: signRes.error
  };
}
