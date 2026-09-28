import {
  auditWorkloadIdentity,
  auditCloudStorageExposure,
  calculateCloudRiskScore,
  generateCloudSecReport
} from '../src/engine/cloudsec.js';

async function runTests() {
  console.log('🧪 Testing Multi-Cloud Workload Identity & CSPM Engine...');

  const mockWorkloads = [
    {
      metadata: {
        name: 'payment-svc',
        namespace: 'prod',
        annotations: {
          'eks.amazonaws.com/role-arn': 'arn:aws:iam::123456789012:role/AdministratorAccessRole'
        }
      }
    },
    {
      metadata: {
        name: 'analytics-worker',
        namespace: 'data',
        annotations: {
          'iam.gke.io/gcp-service-account': 'bigquery-runner@gcp-project.iam.gserviceaccount.com'
        }
      }
    },
    {
      metadata: {
        name: 'frontend-app',
        namespace: 'web',
        annotations: {
          'azure.workload.identity/client-id': 'e8b0a991-81d3-455b-9f93-c90d0b04c865'
        }
      }
    }
  ];

  // Test 1: Audit Workload Identities
  const idFindings = auditWorkloadIdentity(mockWorkloads);
  if (idFindings.length !== 3) throw new Error(`Expected 3 identity findings, got: ${idFindings.length}`);
  const adminFinding = idFindings.find(f => f.severity === 'CRITICAL');
  if (!adminFinding || !adminFinding.identityArn.includes('AdministratorAccessRole')) {
    throw new Error('Failed to flag high-privilege AWS IAM administrator role');
  }
  console.log(`✔ Test 1 passed: Workload identity audit completed (flagged ${adminFinding.severity} AWS role).`);

  // Test 2: Audit Cloud Storage Exposures
  const mockBuckets = [
    {
      bucketName: 'customer-backups-2024',
      provider: 'AWS',
      publicAccessBlock: false,
      isPublic: true,
      encryptionEnabled: true,
      versioning: true
    },
    {
      bucketName: 'app-static-assets',
      provider: 'GCP',
      publicRead: false,
      encryptionEnabled: false,
      versioning: false
    }
  ];

  const storageFindings = auditCloudStorageExposure(mockBuckets);
  if (storageFindings.length !== 3) throw new Error(`Expected 3 storage findings, got: ${storageFindings.length}`);
  const publicFinding = storageFindings.find(f => f.type === 'STORAGE_PUBLIC_READ');
  if (!publicFinding || publicFinding.severity !== 'CRITICAL') {
    throw new Error('Failed to flag public bucket exposure as CRITICAL');
  }
  console.log(`✔ Test 2 passed: Cloud storage audit flagged ${storageFindings.length} configuration gaps.`);

  // Test 3: Composite Cloud Risk Score
  const allFindings = [...idFindings, ...storageFindings];
  const risk = calculateCloudRiskScore(allFindings);
  if (risk.score < 50 || risk.tier !== 'CRITICAL') {
    throw new Error(`Expected CRITICAL risk tier, got: ${risk.tier} (${risk.score})`);
  }
  console.log(`✔ Test 3 passed: Composite cloud risk score calculated: ${risk.score}/100 [${risk.tier}].`);

  // Test 4: Generate Markdown Report
  const report = generateCloudSecReport(idFindings, storageFindings);
  if (!report.includes('Multi-Cloud Workload Identity') || !report.includes('AdministratorAccessRole')) {
    throw new Error('Invalid Markdown report');
  }
  console.log('✔ Test 4 passed: Executive Markdown cloud security report generated.');

  console.log('🎉 ALL 4 CLOUD SECURITY TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ CloudSec test failure:', err);
  process.exit(1);
});
