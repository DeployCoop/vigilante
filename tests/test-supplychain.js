import crypto from 'node:crypto';
import {
  generateCycloneDxSbom,
  generateSpdxSbom,
  verifyCosignSignature,
  evaluateSupplyChainPolicy
} from '../src/engine/supplychain.js';

async function runTests() {
  console.log('🧪 Testing Supply Chain Security, SBOM & Cosign Attestation Engine...');

  const mockPackages = [
    { name: 'express', version: '4.19.2', ecosystem: 'npm', license: 'MIT', hash: 'a1b2c3d4e5f6' },
    { name: 'lodash', version: '4.17.21', ecosystem: 'npm', license: 'MIT', hash: 'f6e5d4c3b2a1' },
    { name: 'insecure-addon', version: 'latest', ecosystem: 'npm', license: 'GPL-3.0' }
  ];

  // Test 1: CycloneDX v1.5 SBOM Generation
  const cdx = generateCycloneDxSbom(mockPackages, { imageName: 'auth-service', imageTag: 'v1.2.0' });
  if (cdx.bomFormat !== 'CycloneDX' || cdx.specVersion !== '1.5' || cdx.components.length !== 3) {
    throw new Error('Failed to generate valid CycloneDX v1.5 SBOM');
  }
  console.log(`✔ Test 1 passed: Generated valid CycloneDX v1.5 SBOM with ${cdx.components.length} components.`);

  // Test 2: SPDX v2.3 SBOM Generation
  const spdx = generateSpdxSbom(mockPackages, { imageName: 'auth-service' });
  if (spdx.spdxVersion !== 'SPDX-2.3' || spdx.packages.length !== 3) {
    throw new Error('Failed to generate valid SPDX v2.3 SBOM');
  }
  console.log(`✔ Test 2 passed: Generated valid SPDX v2.3 SBOM with ${spdx.packages.length} packages.`);

  // Test 3: Cosign Signature Verification
  const imageDigest = 'sha256:4f5a89b7829d67bc11eef453982';
  const claimJson = JSON.stringify({
    critical: {
      identity: { 'docker-reference': 'registry.vigilante.local/auth-service' },
      image: { 'docker-manifest-digest': imageDigest },
      type: 'cosign container image signature'
    },
    optional: { timestamp: new Date().toISOString() }
  });

  const encodedPayload = Buffer.from(claimJson).toString('base64');
  const mockSignature = Buffer.from('mock-sig-data').toString('base64');

  const verifyResult = verifyCosignSignature(imageDigest, {
    payload: encodedPayload,
    signature: mockSignature
  });

  if (!verifyResult.verified || verifyResult.issuer !== 'registry.vigilante.local/auth-service') {
    throw new Error(`Cosign signature verification failed: ${verifyResult.error}`);
  }
  console.log(`✔ Test 3 passed: Verified Cosign container image claim digest for: ${verifyResult.issuer}.`);

  // Test 4: Supply Chain Admission Policy Evaluation
  const policyResult = evaluateSupplyChainPolicy(cdx, { bannedLicenses: ['GPL-3.0'] });
  if (policyResult.passed !== false || policyResult.violations.length !== 2) {
    throw new Error(`Expected policy failure with 2 violations, got: ${policyResult.violations.length}`);
  }
  const licenseViolation = policyResult.violations.find(v => v.type === 'BANNED_LICENSE');
  const unpinnedViolation = policyResult.violations.find(v => v.type === 'UNPINNED_DEPENDENCY');

  if (!licenseViolation || !unpinnedViolation) {
    throw new Error('Missing expected policy violations');
  }
  console.log(`✔ Test 4 passed: Supply chain admission policy flagged 2 violations (Banned License & Unpinned Dependency).`);

  console.log('🎉 ALL 4 SUPPLY CHAIN ENGINE TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Supply Chain test failure:', err);
  process.exit(1);
});
