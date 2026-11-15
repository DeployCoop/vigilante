import { NextResponse } from 'next/server';
import { getClusterInfo } from 'vigilante_lib/engine/cluster.js';
import { getDeployedNamespaces, listInstances } from 'vigilante_lib/engine/instances.js';
import { checkCertificates } from 'vigilante_lib/engine/certs.js';
import { loadConfig } from 'vigilante_lib/engine/config.js';
import { globalModuleRegistry } from 'vigilante_lib/modules/registry.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const denied = await authorizeRequest(req, 'cluster:read');
  if (denied) return denied;

  try {
    const config = loadConfig();

    const clusterName = config.defaults?.clusterName || 'vigilante-dev';
    const domain = config.defaults?.domain || 'vigilante.local';

    const cluster = await getClusterInfo(clusterName);
    const namespaces = await getDeployedNamespaces(clusterName);
    const instances = await listInstances();
    const modules = await globalModuleRegistry.getModuleStatuses(clusterName, domain);
    // The event page's TLS card used to read a `certs` field this route
    // never returned. Report what checkCertificates actually checks:
    // presence of the cert/key pair (not expiry or key match — see the
    // certs.js limitation note in the hunt report).
    const certs = await checkCertificates(domain).catch(() => ({ exists: false }));

    return NextResponse.json({
      success: true,
      clusterName,
      domain,
      cluster,
      certs,
      namespaces,
      instancesCount: instances.length,
      modulesCount: modules.length,
      modules
    });
  } catch (err: unknown) {
    return NextResponse.json({
      success: false,
      error: errorMessage(err),
      clusterName: 'vigilante-dev',
      domain: 'vigilante.local',
      modules: []
    }, { status: 500 });
  }
}
