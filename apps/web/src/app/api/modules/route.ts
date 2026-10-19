import { NextResponse } from 'next/server';
import { globalModuleRegistry } from 'vigilante_lib/modules/registry.js';
import { loadConfig } from 'vigilante_lib/engine/config.js';
import { ensureNamespace } from 'vigilante_lib/engine/k8s.js';
import { setupCertificates } from 'vigilante_lib/engine/certs.js';
import { recordNamespaceDeployment } from 'vigilante_lib/engine/instances.js';
import { authorizeRequest } from '@/lib/authz';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const namespace = searchParams.get('namespace') || 'default';

  const denied = await authorizeRequest(request, 'modules:read', { namespace });
  if (denied) return denied;

  try {
    const config = loadConfig();
    const clusterName = config.defaults?.clusterName || 'vigilante-dev';
    const domain = config.defaults?.domain || 'vigilante.local';

    const allModules = globalModuleRegistry.getAll();
    const modulesStatus = await Promise.all(
      allModules.map(async (m: any) => {
        try {
          const status = await m.status({ domain, clusterName, namespace });
          const endpoints = await m.getEndpoints({ domain, namespace }).catch(() => []);
          return {
            id: m.id,
            name: m.name,
            description: m.description,
            dependencies: m.dependencies || [],
            ...status,
            endpoints
          };
        } catch (err: any) {
          return {
            id: m.id,
            name: m.name,
            description: m.description,
            dependencies: m.dependencies || [],
            installed: false,
            error: err.message,
            endpoints: []
          };
        }
      })
    );

    return NextResponse.json({
      success: true,
      clusterName,
      domain,
      namespace,
      modules: modulesStatus
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message, modules: [] }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { action = 'install', moduleId, namespace = 'default' } = body;

    const denied = await authorizeRequest(request, 'modules:deploy', { moduleId, namespace });
    if (denied) return denied;

    const config = loadConfig();

    const clusterName = config.defaults?.clusterName || 'vigilante-dev';
    const domain = config.defaults?.domain || 'vigilante.local';

    const mod = globalModuleRegistry.get(moduleId);
    if (!mod) {
      return NextResponse.json({ success: false, error: `Module ${moduleId} not found` }, { status: 404 });
    }

    const logs: string[] = [];
    const onLog = (msg: string) => logs.push(msg);

    if (action === 'install') {
      await ensureNamespace(namespace, { onLog });
      const certs = await setupCertificates(domain, { clusterName, instanceName: clusterName });

      await mod.install({
        domain,
        certPath: certs.certPath,
        keyPath: certs.keyPath,
        clusterName,
        namespace,
        onLog
      });

      return NextResponse.json({ success: true, action: 'installed', moduleId, logs });
    }

    if (action === 'uninstall') {
      await mod.uninstall({
        clusterName,
        namespace,
        onLog
      });

      return NextResponse.json({ success: true, action: 'uninstalled', moduleId, logs });
    }

    return NextResponse.json({ success: false, error: 'Unknown action' }, { status: 400 });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
