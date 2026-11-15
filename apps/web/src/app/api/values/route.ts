import { NextResponse } from 'next/server';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { listChartValues, exportStarterValues } from 'vigilante_lib/engine/helm.js';
import { getVigilanteConfigFile, getVigilanteValuesDir, ensureVigilanteConfig } from 'vigilante_lib/engine/config.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  const denied = await authorizeRequest(request, 'cluster:read');
  if (denied) return denied;

  try {
    // No ?file= branch: it used to read any server-readable path for any
    // cluster:read holder (viewer included), e.g. authz.yaml with its
    // password and token hashes. Chart contents are served below from the
    // chart set only, and nothing else in this route reads a caller path.
    await ensureVigilanteConfig();

    const charts = await listChartValues();
    const configFile = getVigilanteConfigFile();
    const xdgValuesDir = getVigilanteValuesDir();

    // Map chart items with their content/status
    const chartItems = await Promise.all(
      charts.map(async (c) => {
        let content = '';
        let hasOverride = false;
        const targetPath = c.userOverridePath || c.defaultPath;

        if (c.userOverridePath && fsSync.existsSync(c.userOverridePath)) {
          hasOverride = true;
          content = await fs.readFile(c.userOverridePath, 'utf8').catch(() => '');
        } else if (c.defaultPath && fsSync.existsSync(c.defaultPath)) {
          content = await fs.readFile(c.defaultPath, 'utf8').catch(() => '');
        }

        return {
          moduleId: c.moduleId,
          chartName: c.chartName,
          defaultPath: c.defaultPath,
          userOverridePath: c.userOverridePath,
          xdgPath: c.xdgPath,
          targetPath,
          hasOverride,
          content
        };
      })
    );

    return NextResponse.json({
      success: true,
      configFile,
      xdgValuesDir,
      charts: chartItems
    });
  } catch (err: unknown) {
    return NextResponse.json(
      {
        success: false,
        error: errorMessage(err),
        charts: []
      },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  const denied = await authorizeRequest(request, 'cluster:write');
  if (denied) return denied;

  try {
    const body = await request.json();

    const { action = 'save', filePath, content, exportType = 'local' } = body;

    if (action === 'export') {
      const exported = await exportStarterValues({
        useXdg: exportType === 'xdg'
      });
      return NextResponse.json({ success: true, exported });
    }

    if (action === 'save') {
      if (!filePath || typeof content !== 'string') {
        return NextResponse.json({ success: false, error: 'filePath and content are required' }, { status: 400 });
      }

      // Containment: only chart values files this route itself serves may
      // be written — a chart's default, its existing override, or its
      // canonical XDG override location. Any other path (config, secrets,
      // credentials, outside the chart set) is rejected even for
      // cluster:write holders. Paths are resolved before comparison so
      // relative, absolute, and ..-containing spellings of the same file
      // compare equal.
      const charts = await listChartValues();
      const allowed = new Set<string>();
      for (const c of charts) {
        if (c.defaultPath) allowed.add(path.resolve(c.defaultPath));
        if (c.userOverridePath) allowed.add(path.resolve(c.userOverridePath));
        if (c.xdgPath) allowed.add(path.resolve(c.xdgPath));
      }
      const resolved = path.resolve(filePath);
      if (!allowed.has(resolved)) {
        return NextResponse.json({ success: false, error: 'filePath is not a chart values file' }, { status: 403 });
      }

      await fs.mkdir(path.dirname(resolved), { recursive: true });
      await fs.writeFile(resolved, content, 'utf8');

      return NextResponse.json({ success: true, saved: filePath });
    }

    return NextResponse.json({ success: false, error: 'Unknown action' }, { status: 400 });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
