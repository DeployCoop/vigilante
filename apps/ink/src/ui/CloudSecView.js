import React, { useState } from 'react';
import { Box, Text } from 'ink';
import { auditWorkloadIdentity, auditCloudStorageExposure, calculateCloudRiskScore } from '../engine/cloudsec.js';
import { useTheme } from './theme.js';

export function CloudSecView({ onBack }) {
  const theme = useTheme();

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
    }
  ];

  const mockBuckets = [
    { bucketName: 'prod-db-dumps', provider: 'AWS', isPublic: true, encryptionEnabled: false },
    { bucketName: 'app-assets', provider: 'GCP', isPublic: false, encryptionEnabled: true }
  ];

  const idFindings = auditWorkloadIdentity(mockWorkloads);
  const storageFindings = auditCloudStorageExposure(mockBuckets);
  const risk = calculateCloudRiskScore([...idFindings, ...storageFindings]);

  return React.createElement(
    Box,
    { flexDirection: 'column', width: '100%', height: '100%', padding: 1 },
    React.createElement(
      Box,
      { borderStyle: 'round', borderColor: theme.colors.primary, paddingX: 1, marginBottom: 1 },
      React.createElement(Text, { color: theme.colors.header, bold: true }, '☁️ Multi-Cloud Workload Identity & CSPM Security Posture')
    ),
    React.createElement(
      Box,
      { marginBottom: 1 },
      React.createElement(Text, { color: theme.colors.muted }, 'AWS IRSA, GCP Workload Identity, Azure Client IDs, and Storage Exposure')
    ),
    React.createElement(
      Box,
      { borderStyle: 'double', borderColor: risk.tier === 'CRITICAL' ? theme.colors.error : theme.colors.warning, flexDirection: 'column', padding: 1, marginBottom: 1 },
      React.createElement(
        Box,
        { justifyContent: 'space-between' },
        React.createElement(Text, { color: theme.colors.header, bold: true }, `Composite Cloud Risk: ${risk.score}/100 [${risk.tier}]`),
        React.createElement(Text, { color: theme.colors.error, bold: true }, `Critical: ${risk.criticalCount} | High: ${risk.highCount}`)
      )
    ),
    React.createElement(
      Box,
      { borderStyle: 'single', borderColor: theme.colors.border, flexDirection: 'column', padding: 1 },
      React.createElement(Text, { color: theme.colors.accent, bold: true }, 'High-Risk Cloud Workloads & Buckets:'),
      idFindings.map((f, i) =>
        React.createElement(
          Box,
          { key: `id-${i}`, justifyContent: 'space-between' },
          React.createElement(Text, { color: f.severity === 'CRITICAL' ? theme.colors.error : theme.colors.text }, `🔑 [${f.provider}] ${f.resourceName}: ${f.message}`),
          React.createElement(Text, { color: theme.colors.warning, bold: true }, `[${f.severity}]`)
        )
      ),
      storageFindings.map((f, i) =>
        React.createElement(
          Box,
          { key: `st-${i}`, justifyContent: 'space-between' },
          React.createElement(Text, { color: f.severity === 'CRITICAL' ? theme.colors.error : theme.colors.text }, `🪣 [${f.provider}] ${f.resourceName}: ${f.message}`),
          React.createElement(Text, { color: theme.colors.error, bold: true }, `[${f.severity}]`)
        )
      )
    ),
    React.createElement(
      Box,
      { marginTop: 1, borderStyle: 'single', borderColor: theme.colors.border, paddingX: 1 },
      React.createElement(Text, { color: theme.colors.muted }, '[Esc/q] Back to Hub  |  [r] Rescan Cloud Providers  |  [p] Export Report')
    )
  );
}
