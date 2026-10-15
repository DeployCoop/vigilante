'use client';

import React, { useState, useEffect } from 'react';
import {
  FileText,
  Save,
  RefreshCw,
  Download,
  Check,
  AlertCircle,
  FolderTree,
  FileCode,
  Layers,
  ChevronRight
} from 'lucide-react';

interface ChartItem {
  moduleId: string;
  chartName: string;
  defaultPath: string;
  userOverridePath: string;
  xdgPath: string;
  targetPath: string;
  hasOverride: boolean;
  content: string;
}

export default function ValuesPage() {
  const [charts, setCharts] = useState<ChartItem[]>([]);
  const [selectedChart, setSelectedChart] = useState<ChartItem | null>(null);
  const [editorContent, setEditorContent] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [configFile, setConfigFile] = useState<string>('');
  const [xdgDir, setXdgDir] = useState<string>('');

  const fetchValues = () => {
    setLoading(true);
    fetch('/api/values')
      .then((res) => res.json())
      .then((data) => {
        if (data.success) {
          setCharts(data.charts || []);
          if (data.configFile) setConfigFile(data.configFile);
          if (data.xdgValuesDir) setXdgDir(data.xdgValuesDir);
          if (data.charts?.length > 0 && !selectedChart) {
            setSelectedChart(data.charts[0]);
            setEditorContent(data.charts[0].content || '');
          }
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    fetchValues();
  }, []);

  const handleSelectChart = (c: ChartItem) => {
    setSelectedChart(c);
    setEditorContent(c.content || '');
  };

  const handleSave = async () => {
    if (!selectedChart) return;
    setSaving(true);
    try {
      const filePath = selectedChart.userOverridePath || selectedChart.targetPath;
      const res = await fetch('/api/values', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'save',
          filePath,
          content: editorContent
        })
      });
      const data = await res.json();
      if (data.success) {
        setStatusMessage(`✔ Saved override to ${filePath}`);
        fetchValues();
        setTimeout(() => setStatusMessage(null), 3000);
      }
    } catch (err: any) {
      setStatusMessage(`Error saving: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleExportStarter = async (type: 'local' | 'xdg') => {
    try {
      const res = await fetch('/api/values', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'export', exportType: type })
      });
      const data = await res.json();
      if (data.success) {
        setStatusMessage(`✔ Exported ${data.exported?.length || 0} starter values files!`);
        fetchValues();
        setTimeout(() => setStatusMessage(null), 4000);
      }
    } catch (err: any) {
      setStatusMessage(`Error: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-teal-500/10 border border-teal-500/30 text-teal-400">
            <FileCode className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Helm Values Editor & Chart Overrides
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-teal-950 border border-teal-800 text-teal-300">
                values.yaml
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Inspect and configure chart parameters, override default templates, and manage local or XDG Helm values.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <button
            onClick={() => handleExportStarter('local')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Local Values</span>
          </button>

          <button
            onClick={fetchValues}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className="p-3 rounded-lg bg-teal-950/60 border border-teal-800 text-teal-300 font-mono text-xs">
          {statusMessage}
        </div>
      )}

      {/* Main Grid: Chart List + YAML Editor */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono text-xs">
        {/* Left: Charts List */}
        <div className="space-y-4 lg:col-span-1">
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 space-y-3">
            <div className="text-slate-400 font-bold uppercase text-[11px] pb-1 border-b border-slate-800 flex items-center justify-between">
              <span>Installed Module Charts</span>
              <span>{charts.length} Charts</span>
            </div>

            <div className="space-y-2 max-h-[500px] overflow-y-auto">
              {charts.map((c, i) => (
                <div
                  key={i}
                  onClick={() => handleSelectChart(c)}
                  className={`p-3 rounded-lg border cursor-pointer transition-all space-y-1 ${
                    selectedChart === c
                      ? 'bg-teal-950/40 border-teal-500/50 text-white'
                      : 'bg-slate-900/40 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between font-bold text-xs">
                    <span>{c.moduleId} / {c.chartName}</span>
                    <span
                      className={`text-[10px] px-1.5 py-0.2 rounded border ${
                        c.hasOverride
                          ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                          : 'bg-slate-900 text-slate-500 border-slate-800'
                      }`}
                    >
                      {c.hasOverride ? 'OVERRIDE' : 'DEFAULT'}
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-500 truncate">{c.targetPath}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: In-Browser YAML Editor */}
        <div className="lg:col-span-2 space-y-4">
          {selectedChart ? (
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/60 space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <div>
                  <h3 className="text-sm font-bold text-white">
                    {selectedChart.moduleId} / {selectedChart.chartName}.yaml
                  </h3>
                  <p className="text-[11px] text-slate-500 pt-0.5">
                    Target Override: <code>{selectedChart.userOverridePath || selectedChart.targetPath}</code>
                  </p>
                </div>

                <button
                  onClick={handleSave}
                  disabled={saving}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-teal-600 hover:bg-teal-500 disabled:bg-teal-900 text-white font-bold text-xs transition-colors shadow-lg shadow-teal-900/20"
                >
                  <Save className="w-3.5 h-3.5" />
                  <span>{saving ? 'Saving...' : 'Save Overrides'}</span>
                </button>
              </div>

              <textarea
                value={editorContent}
                onChange={(e) => setEditorContent(e.target.value)}
                rows={22}
                className="w-full bg-black/70 border border-slate-900 rounded-lg p-4 font-mono text-xs text-teal-300 leading-relaxed focus:outline-none selection:bg-teal-500/30"
                placeholder="# Helm values YAML content..."
              />
            </div>
          ) : (
            <div className="h-96 rounded-xl border border-slate-800 bg-slate-950/40 flex flex-col items-center justify-center text-center p-6 space-y-3 text-slate-500">
              <FileCode className="w-8 h-8 text-slate-600" />
              <p>Select a Helm chart on the left to edit and customize its configuration parameters.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
