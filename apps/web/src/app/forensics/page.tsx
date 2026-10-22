'use client';

import React, { useState, useEffect } from 'react';
import {
  FileSearch,
  RefreshCw,
  FileCode,
  Package,
} from 'lucide-react';

interface CarvedFile {
  fileName: string;
  filePath: string;
  sizeBytes: number;
  modifiedAt: string;
}

export default function ForensicsPage() {
  const [files, setFiles] = useState<CarvedFile[]>([]);
  const [ladder, setLadder] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<'files' | 'ladder'>('files');

  const fetchForensics = () => {
    fetch('/api/forensics')
      .then((res) => res.json())
      .then((data) => {
        if (data.success) {
          setFiles(data.files || []);
          setLadder(data.ladder || '');
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    fetchForensics();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
            <FileSearch className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Deep PCAP Forensic Extraction & Protocol Reconstruction
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950 border border-indigo-800 text-indigo-300">
                Payload Carving
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Carved file payloads (HTTP, SMB, FTP), decrypted TLS streams, and TCP sequence ladder telemetry.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 rounded-lg p-1 text-xs font-mono">
            <button
              onClick={() => setActiveTab('files')}
              className={`px-3 py-1.5 rounded transition-colors ${
                activeTab === 'files' ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/40' : 'text-slate-400'
              }`}
            >
              Carved Files ({files.length})
            </button>
            <button
              onClick={() => setActiveTab('ladder')}
              className={`px-3 py-1.5 rounded transition-colors ${
                activeTab === 'ladder' ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/40' : 'text-slate-400'
              }`}
            >
              TCP Sequence Ladder
            </button>
          </div>

          <button
            onClick={() => {
              setLoading(true);
              fetchForensics();
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-slate-300 border border-slate-800"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Rescan</span>
          </button>
        </div>
      </div>

      {/* Content */}
      {activeTab === 'files' ? (
        <div className="space-y-4 font-mono text-xs">
          {files.length === 0 ? (
            <div className="p-8 rounded-xl border border-slate-800 bg-slate-950/60 text-center space-y-3">
              <Package className="w-8 h-8 text-slate-600 mx-auto" />
              <p className="text-slate-400">No carved payloads currently discovered in forensic dropzone.</p>
              <p className="text-[11px] text-slate-500">
                Carve PCAP files with <code>vigilante forensics &lt;path-to-pcap&gt;</code> or capture live packet flows.
              </p>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden">
              <div className="p-3 bg-slate-900/80 border-b border-slate-800 text-slate-400 font-bold uppercase flex items-center justify-between text-[11px]">
                <span>Carved Forensic Artifacts</span>
                <span>Dropzone: ~/.vigilante/evidence/forensics/</span>
              </div>
              <div className="divide-y divide-slate-800/60">
                {files.map((f, i) => (
                  <div key={i} className="p-4 flex items-center justify-between hover:bg-slate-900/30 transition-colors">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded bg-slate-900 border border-slate-800 text-indigo-400">
                        <FileCode className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="font-bold text-white text-sm">{f.fileName}</div>
                        <div className="text-[11px] text-slate-500">{f.filePath}</div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="font-bold text-indigo-300">{f.sizeBytes.toLocaleString()} bytes</div>
                      <div className="text-[10px] text-slate-500">{new Date(f.modifiedAt).toLocaleString()}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/60 font-mono text-xs space-y-3">
          <div className="flex items-center justify-between text-slate-400 pb-2 border-b border-slate-800 text-[11px]">
            <span>TCP Handshake & Sequence Reconstruction</span>
            <span>Flow Diagram</span>
          </div>
          <pre className="p-4 rounded-lg bg-black/60 border border-slate-900 text-cyan-300 overflow-x-auto text-[11px] leading-relaxed">
            {ladder || 'No active TCP stream diagram generated.'}
          </pre>
        </div>
      )}
    </div>
  );
}
