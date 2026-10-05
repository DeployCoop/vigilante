import { NextResponse } from 'next/server';
import { getClusterInfo } from 'vigilante_lib/engine/cluster.js';
import { getDeployedNamespaces, listInstances } from 'vigilante_lib/engine/instances.js';
import { loadConfig } from 'vigilante_lib/engine/config.js';
import { globalModuleRegistry } from 'vigilante_lib/modules/registry.js';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const config = loadConfig();
    const clusterName = config.defaults?.clusterName || 'vigilante-dev';
    const domain = config.defaults?.domain || 'vigilante.local';

    const cluster = await getClusterInfo(clusterName);
    const namespaces = await getDeployedNamespaces(clusterName);
    const instances = await listInstances();
    const modules = await globalModuleRegistry.getModuleStatuses(clusterName, domain);

    return NextResponse.json({
      success: true,
      clusterName,
      domain,
      cluster,
      namespaces,
      instancesCount: instances.length,
      modulesCount: modules.length,
      modules
    });
  } catch (err: any) {
    return NextResponse.json({
      success: false,
      error: err.message,
      clusterName: 'vigilante-dev',
      domain: 'vigilante.local',
      modules: []
    }, { status: 500 });
  }
}
