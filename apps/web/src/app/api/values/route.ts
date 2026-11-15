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
    const { searchParams } = new URL(request.url);

    const filePath = searchParams.get('file');

    await ensureVigilanteConfig();

    if (filePath) {
      if (fsSync.existsSync(filePath)) {
        const content = await fs.readFile(filePath, 'utf8');
        return NextResponse.json({ success: true, filePath, content });
      } else {
        return NextResponse.json({ success: false, error: 'File not found' }, { status: 404 });
      }
    }

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

      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, content, 'utf8');

      return NextResponse.json({ success: true, saved: filePath });
    }

    return NextResponse.json({ success: false, error: 'Unknown action' }, { status: 400 });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
