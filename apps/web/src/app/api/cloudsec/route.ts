import { NextResponse } from 'next/server';
import {
  auditWorkloadIdentity,
  auditCloudStorageExposure,
  calculateCloudRiskScore
} from 'vigilante_lib/engine/cloudsec.js';
import { authorizeRequest } from '@/lib/authz';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const denied = await authorizeRequest(req, 'telemetry:read');
  if (denied) return denied;

  try {
    const mockWorkloads = [

      {
        metadata: {
          name: 'payment-gateway',
          namespace: 'prod',
          annotations: { 'eks.amazonaws.com/role-arn': 'arn:aws:iam::123456789012:role/AdministratorAccess' }
        }
      },
      {
        metadata: {
          name: 'report-pipeline',
          namespace: 'data',
          annotations: { 'iam.gke.io/gcp-service-account': 'analytics@corp.iam.gserviceaccount.com' }
        }
      },
      {
        metadata: {
          name: 'auth-broker',
          namespace: 'security',
          annotations: { 'azure.workload.identity/client-id': '00000000-0000-0000-0000-000000000000' }
        }
      }
    ];

    const mockBuckets = [
      { bucketName: 'prod-db-dumps', provider: 'AWS', isPublic: true, encryptionEnabled: false },
      { bucketName: 'customer-contracts', provider: 'AWS', isPublic: false, encryptionEnabled: false },
      { bucketName: 'app-assets', provider: 'GCP', isPublic: true, encryptionEnabled: true },
      { bucketName: 'secure-vault-backups', provider: 'GCP', isPublic: false, encryptionEnabled: true }
    ];

    const idFindings = auditWorkloadIdentity(mockWorkloads);
    const storageFindings = auditCloudStorageExposure(mockBuckets);
    const risk = calculateCloudRiskScore([...idFindings, ...storageFindings]);

    return NextResponse.json({
      success: true,
      risk,
      idFindings,
      storageFindings,
      workloadsCount: mockWorkloads.length,
      bucketsCount: mockBuckets.length
    });
  } catch (err: any) {
    return NextResponse.json(
      {
        success: false,
        error: err.message
      },
      { status: 500 }
    );
  }
}
