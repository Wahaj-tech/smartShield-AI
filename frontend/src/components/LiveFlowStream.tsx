import { memo } from 'react';
import { categoryLabel, categoryColor } from '../utils/dataFormatter';
import type { FlowRecord } from '../types';

export interface LiveFlow {
  id: string;
  timestamp: string;
  domain: string;
  protocol: string;
  packets: number;
  category: string;
}

interface Props {
  flows: LiveFlow[];
  connected: boolean;
}

function LiveFlowStream({ flows, connected }: Props) {
  return (
    <div className="rounded-[14px] border border-dark-600 bg-dark-700 p-5 flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-accent animate-pulse' : 'bg-slate-muted'}`} />
          <h2 className="text-lg font-bold text-white">Live Flow Stream</h2>
        </div>
        <span className={`w-2.5 h-2.5 rounded-full ${connected ? 'bg-green-accent' : 'bg-slate-muted'}`} />
      </div>

      {/* Table */}
      <div className="flex-1 overflow-hidden rounded-lg border border-dark-500">
        {/* Table header */}
        <div className="grid grid-cols-[140px_1fr_100px_100px_130px] gap-2 px-4 py-3 bg-dark-600/50 border-b border-dark-500">
          <span className="text-xs font-semibold text-slate-label uppercase tracking-wider">Timestamp</span>
          <span className="text-xs font-semibold text-slate-label uppercase tracking-wider">Domain</span>
          <span className="text-xs font-semibold text-slate-label uppercase tracking-wider">Protocol</span>
          <span className="text-xs font-semibold text-slate-label uppercase tracking-wider">Packets</span>
          <span className="text-xs font-semibold text-slate-label uppercase tracking-wider">Category</span>
        </div>

        {/* Table body */}
        <div className="max-h-[440px] overflow-y-auto">
          {flows.length === 0 ? (
            <div className="flex items-center justify-center py-12 text-slate-muted text-sm">
              Waiting for live flow data…
            </div>
          ) : (
            flows.map((flow) => (
              <div
                key={flow.id}
                className="grid grid-cols-[140px_1fr_100px_100px_130px] gap-2 px-4 py-3 border-b border-dark-600/50
                           hover:bg-dark-600/30 transition-colors"
              >
                <span className="text-sm text-slate-muted font-mono">{flow.timestamp}</span>
                <span className="text-sm text-white font-medium truncate">{flow.domain}</span>
                <span className="text-sm text-slate-label">{flow.protocol}</span>
                <span className="text-sm text-white tabular-nums">{flow.packets.toLocaleString()}</span>
                <span>
                  <span
                    className="inline-block px-2.5 py-0.5 rounded text-xs font-medium border"
                    style={{
                      color: categoryColor(flow.category),
                      borderColor: categoryColor(flow.category) + '40',
                      backgroundColor: categoryColor(flow.category) + '15',
                    }}
                  >
                    {categoryLabel(flow.category)}
                  </span>
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

export default memo(LiveFlowStream);

/** Helper to convert a FlowRecord into a LiveFlow entry */
export function flowToLiveEntry(flow: FlowRecord, index: number): LiveFlow {
  const now = new Date();
  // Stagger timestamps by 2s for visual effect
  const ts = new Date(now.getTime() - index * 2000);
  return {
    id: `${flow.domain}-${index}-${ts.getTime()}`,
    timestamp: ts.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true }),
    domain: flow.domain,
    protocol: flow.protocol,
    packets: flow.packet_count,
    category: flow.category,
  };
}
