/**
 * Multi-Cloud Workload Identity & Entitlement Management (CIEM / CSPM)
 * Audits AWS IRSA, GCP Workload Identity, Azure Client IDs, and cloud storage bucket exposure.
 */

import { logger } from '../utils/logger.js';

/**
 * Audit cloud workload identities attached to Kubernetes ServiceAccounts and Workloads
 * @param {Array<Object>} workloads List of K8s workload or ServiceAccount manifests
 * @returns {Array<Object>} List of identity findings
 */
export function auditWorkloadIdentity(workloads = []) {
  const findings = [];

  for (const wl of workloads) {
    const meta = wl.metadata || {};
    const annotations = meta.annotations || {};
    const name = meta.name || 'unknown-workload';
    const namespace = meta.namespace || 'default';

    // 1. AWS IRSA Detection & Audit
    const awsRoleArn = annotations['eks.amazonaws.com/role-arn'];
    if (awsRoleArn) {
      const lowerArn = awsRoleArn.toLowerCase();
      let severity = 'LOW';
      let message = `Workload bound to AWS IAM Role: ${awsRoleArn}`;

      if (lowerArn.includes('admin') || lowerArn.includes('root') || lowerArn.includes('poweruser')) {
        severity = 'CRITICAL';
        message = `High-privilege AWS IAM Role detected: ${awsRoleArn}`;
      } else if (lowerArn.includes('s3') || lowerArn.includes('dynamo') || lowerArn.includes('sqs')) {
        severity = 'MEDIUM';
      }

      findings.push({
        provider: 'AWS',
        type: 'WORKLOAD_IDENTITY_IRSA',
        resourceName: name,
        namespace,
        identityArn: awsRoleArn,
        severity,
        message,
        remediation: 'Scope IAM policies to minimum required actions. Avoid AdministratorAccess.'
      });
    }

    // 2. GCP Workload Identity Detection & Audit
    const gcpSa = annotations['iam.gke.io/gcp-service-account'];
    if (gcpSa) {
      const lowerSa = gcpSa.toLowerCase();
      let severity = 'LOW';
      let message = `Workload bound to GCP Service Account: ${gcpSa}`;

      if (lowerSa.includes('admin') || lowerSa.includes('owner') || lowerSa.includes('editor')) {
        severity = 'CRITICAL';
        message = `High-privilege GCP Service Account detected: ${gcpSa}`;
      }

      findings.push({
        provider: 'GCP',
        type: 'WORKLOAD_IDENTITY_GCP',
        resourceName: name,
        namespace,
        identityArn: gcpSa,
        severity,
        message,
        remediation: 'Use fine-grained IAM roles rather than Owner or Editor primitives.'
      });
    }

    // 3. Azure Workload Identity Detection & Audit
    const azureClientId = annotations['azure.workload.identity/client-id'];
    if (azureClientId) {
      findings.push({
        provider: 'AZURE',
        type: 'WORKLOAD_IDENTITY_AZURE',
        resourceName: name,
        namespace,
        identityArn: azureClientId,
        severity: 'LOW',
        message: `Workload bound to Azure Entra Client ID: ${azureClientId}`,
        remediation: 'Ensure App Registration has least-privilege Graph and ARM permissions.'
      });
    }
  }

  return findings;
}

/**
 * Audit Cloud Storage configurations for public exposure and encryption gaps
 * @param {Array<Object>} storageConfigs List of bucket configurations (AWS S3, GCP GCS, Azure Blob)
 * @returns {Array<Object>} Storage security findings
 */
export function auditCloudStorageExposure(storageConfigs = []) {
  const findings = [];

  for (const b of storageConfigs) {
    const bucketName = b.bucketName || b.name || 'unnamed-bucket';
    const provider = b.provider || 'AWS';

    // Check 1: Public Read Exposure
    if (b.isPublic || b.publicRead || b.publicAccessBlock === false || (Array.isArray(b.grants) && b.grants.includes('allUsers'))) {
      findings.push({
        provider,
        type: 'STORAGE_PUBLIC_READ',
        resourceName: bucketName,
        severity: 'CRITICAL',
        message: `Storage bucket '${bucketName}' is publicly accessible over the internet`,
        remediation: 'Enable Block Public Access (AWS S3) or Public Access Prevention (GCP GCS).'
      });
    }

    // Check 2: Missing Server-Side Encryption
    const isEncrypted = b.encryptionEnabled === true || b.sse || b.encryption;
    if (!isEncrypted) {
      findings.push({
        provider,
        type: 'STORAGE_UNENCRYPTED',
        resourceName: bucketName,
        severity: 'HIGH',
        message: `Storage bucket '${bucketName}' lacks default server-side encryption (SSE-KMS)`,
        remediation: 'Enable default KMS encryption on the storage bucket.'
      });
    }

    // Check 3: Versioning Disabled
    if (b.versioning === false || b.versioningEnabled === false) {
      findings.push({
        provider,
        type: 'STORAGE_NO_VERSIONING',
        resourceName: bucketName,
        severity: 'MEDIUM',
        message: `Storage bucket '${bucketName}' does not have object versioning enabled`,
        remediation: 'Enable versioning and object locks to protect against ransomware.'
      });
    }
  }

  return findings;
}

/**
 * Calculate composite Cloud Security risk score (0-100)
 * @param {Array<Object>} allFindings 
 * @returns {Object} Score and risk tier
 */
export function calculateCloudRiskScore(allFindings = []) {
  let score = 0;
  for (const f of allFindings) {
    if (f.severity === 'CRITICAL') score += 35;
    else if (f.severity === 'HIGH') score += 20;
    else if (f.severity === 'MEDIUM') score += 10;
    else score += 3;
  }

  score = Math.min(score, 100);
  let tier = 'CLEAN';
  if (score >= 75) tier = 'CRITICAL';
  else if (score >= 50) tier = 'HIGH';
  else if (score >= 25) tier = 'MEDIUM';
  else if (score > 0) tier = 'LOW';

  return {
    score,
    tier,
    findingsCount: allFindings.length,
    criticalCount: allFindings.filter(f => f.severity === 'CRITICAL').length,
    highCount: allFindings.filter(f => f.severity === 'HIGH').length
  };
}

/**
 * Generate formatted Markdown CSPM & CIEM Report
 * @param {Array<Object>} identityFindings 
 * @param {Array<Object>} storageFindings 
 * @returns {string} Markdown report
 */
export function generateCloudSecReport(identityFindings = [], storageFindings = []) {
  const allFindings = [...identityFindings, ...storageFindings];
  const risk = calculateCloudRiskScore(allFindings);

  return `# ☁️ Multi-Cloud Workload Identity & CSPM Security Report

**Composite Cloud Risk**: **${risk.score}/100** [**${risk.tier}**]  
**Total Cloud Findings**: ${risk.findingsCount} (Critical: ${risk.criticalCount}, High: ${risk.highCount})  
**Timestamp**: ${new Date().toISOString()}  

---

## 🔑 Workload Identity & Cloud Entitlement (CIEM)

| Workload | Provider | Identity ARN / SA | Severity | Finding |
| :--- | :--- | :--- | :--- | :--- |
${identityFindings.length > 0
  ? identityFindings.map(f => `| \`${f.resourceName}\` | ${f.provider} | \`${f.identityArn}\` | **${f.severity}** | ${f.message} |`).join('\n')
  : '| *None* | - | - | - | No over-privileged identities detected |'}

---

## 🪣 Cloud Storage Posture (CSPM)

| Bucket Name | Provider | Severity | Finding | Remediation |
| :--- | :--- | :--- | :--- | :--- |
${storageFindings.length > 0
  ? storageFindings.map(f => `| \`${f.resourceName}\` | ${f.provider} | **${f.severity}** | ${f.message} | ${f.remediation} |`).join('\n')
  : '| *None* | - | - | No storage misconfigurations detected | - |'}

---

*Generated autonomously by Vigilante CloudSec Engine.*
`;
}
