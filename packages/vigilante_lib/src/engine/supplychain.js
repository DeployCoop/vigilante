/**
 * Supply Chain Security, SBOM & Container Image Attestation Engine
 * Generates CycloneDX and SPDX Software Bill of Materials (SBOMs),
 * verifies Cosign / Sigstore container cryptographic signatures, and evaluates admission policies.
 */

import crypto from 'node:crypto';
import { logger } from '../utils/logger.js';

/**
 * Generate a standard CycloneDX v1.5 JSON Software Bill of Materials (SBOM)
 * @param {Array<Object>} packageManifests List of { name, version, type, license, hash }
 * @param {Object} [metadata={}]
 * @returns {Object} CycloneDX v1.5 SBOM JSON structure
 */
export function generateCycloneDxSbom(packageManifests = [], metadata = {}) {
  const serialNumber = `urn:uuid:${crypto.randomUUID()}`;
  const timestamp = new Date().toISOString();

  const components = packageManifests.map(pkg => ({
    type: pkg.type || 'library',
    name: pkg.name,
    version: pkg.version,
    purl: `pkg:${pkg.ecosystem || 'generic'}/${pkg.name}@${pkg.version}`,
    licenses: pkg.license ? [{ license: { id: pkg.license } }] : [],
    hashes: pkg.hash ? [{ alg: 'SHA-256', content: pkg.hash }] : []
  }));

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber,
    version: 1,
    metadata: {
      timestamp,
      tools: [
        {
          vendor: 'Vigilante',
          name: 'vigilante-supplychain-engine',
          version: '1.0.0'
        }
      ],
      component: {
        type: 'container',
        name: metadata.imageName || 'container-image',
        version: metadata.imageTag || 'latest'
      }
    },
    components
  };
}

/**
 * Generate a standard SPDX v2.3 JSON Software Bill of Materials (SBOM)
 * @param {Array<Object>} packageManifests
 * @param {Object} [metadata={}]
 * @returns {Object} SPDX v2.3 SBOM JSON structure
 */
export function generateSpdxSbom(packageManifests = [], metadata = {}) {
  const docId = `SPDXRef-DOCUMENT-${Date.now()}`;
  const docNamespace = `http://spdx.org/spdxdocs/${metadata.imageName || 'image'}-${crypto.randomUUID()}`;

  const packages = packageManifests.map((pkg, idx) => ({
    SPDXID: `SPDXRef-Package-${idx + 1}-${pkg.name}`,
    name: pkg.name,
    versionInfo: pkg.version,
    licenseConcluded: pkg.license || 'NOASSERTION',
    downloadLocation: 'NOASSERTION',
    checksums: pkg.hash ? [{ algorithm: 'SHA256', checksumValue: pkg.hash }] : []
  }));

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: docId,
    name: metadata.imageName || 'container-image',
    documentNamespace: docNamespace,
    creationInfo: {
      creators: ['Tool: Vigilante-1.0.0'],
      created: new Date().toISOString()
    },
    packages
  };
}

/**
 * Verify container image Cosign digital signature using public key or verification payload
 * @param {string} imageDigest e.g. 'sha256:4f5a...'
 * @param {Object} signaturePayload { payload, signature }
 * @param {string} publicKeyPem Public Key in PEM format (or mock verifiable key)
 * @returns {{ verified: boolean, issuer?: string, timestamp?: string, error?: string }}
 */
export function verifyCosignSignature(imageDigest, signaturePayload = {}, publicKeyPem = '') {
  try {
    const rawPayload = signaturePayload.payload || '';
    const rawSignature = signaturePayload.signature || '';

    if (!rawPayload || !rawSignature) {
      return { verified: false, error: 'Missing signature payload or signature block' };
    }

    // Decode and parse cosign payload
    const decoded = Buffer.from(rawPayload, 'base64').toString('utf8');
    const claim = JSON.parse(decoded);

    // Verify claim matches target image digest
    const critical = claim.critical || {};
    const identity = critical.identity || {};
    const imagePayload = critical.image || {};

    const claimDigest = imagePayload['docker-manifest-digest'] || '';
    if (claimDigest && claimDigest !== imageDigest) {
      return {
        verified: false,
        error: `Digest mismatch: expected ${imageDigest}, found ${claimDigest}`
      };
    }

    // Cryptographic signature check if PEM provided
    if (publicKeyPem) {
      const verifier = crypto.createVerify('SHA256');
      verifier.update(rawPayload);
      verifier.end();

      const isValid = verifier.verify(publicKeyPem, Buffer.from(rawSignature, 'base64'));
      if (!isValid) {
        return { verified: false, error: 'Cryptographic signature verification failed' };
      }
    }

    return {
      verified: true,
      issuer: identity['docker-reference'] || 'cosign-trusted-registry',
      timestamp: claim.optional?.timestamp || new Date().toISOString()
    };
  } catch (err) {
    return { verified: false, error: err.message };
  }
}

/**
 * Evaluate Software Bill of Materials (SBOM) against supply chain admission policies
 * @param {Object} sbom CycloneDX or SPDX JSON document
 * @param {Object} [policyRules={}]
 * @returns {{ passed: boolean, score: number, violations: Array<Object> }}
 */
export function evaluateSupplyChainPolicy(sbom, policyRules = {}) {
  const violations = [];
  const bannedLicenses = (policyRules.bannedLicenses || ['GPL-3.0', 'AGPL-3.0']).map(l => l.toUpperCase());
  const maxCriticalVulnerabilities = policyRules.maxCriticalVulnerabilities ?? 0;

  // Normalize components list across CycloneDX and SPDX
  const items = sbom.components || (sbom.packages || []).map(p => ({
    name: p.name,
    version: p.versionInfo,
    licenses: [{ license: { id: p.licenseConcluded } }]
  }));

  for (const item of items) {
    // 1. Check for banned licenses
    const licenseId = item.licenses?.[0]?.license?.id || '';
    if (licenseId && bannedLicenses.includes(licenseId.toUpperCase())) {
      violations.push({
        type: 'BANNED_LICENSE',
        severity: 'HIGH',
        package: item.name,
        details: `Package utilizes banned open-source license: ${licenseId}`
      });
    }

    // 2. Check for missing version pinning
    if (!item.version || item.version === 'latest') {
      violations.push({
        type: 'UNPINNED_DEPENDENCY',
        severity: 'MEDIUM',
        package: item.name,
        details: 'Package version is unpinned or defaults to latest'
      });
    }
  }

  const passed = violations.length === 0;
  const score = Math.max(0, 100 - violations.length * 20);

  logger.info('SUPPLYCHAIN', `Evaluated SBOM (${items.length} components). Policy Passed: ${passed} (Score: ${score}/100)`);

  return {
    passed,
    score,
    violations
  };
}
