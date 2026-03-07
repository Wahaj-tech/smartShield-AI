import { memo } from 'react';
import { Bug, AlertTriangle } from 'lucide-react';
import { formatNumber } from '../utils/dataFormatter';
import type { AIDetection } from '../types';

interface Props {
  detections: AIDetection[];
}

function AIDetectionPanel({ detections }: Props) {
  return (
    <div className="rounded-[14px] border border-dark-600 bg-dark-700 flex flex-col">
      {/* Header */}
      <div className="px-6 pt-6 pb-2 flex items-center gap-2">
        <Bug className="w-5 h-5 text-red-accent" />
        <h3 className="text-base font-medium text-white leading-4">AI Tool Detection</h3>
      </div>

      {/* Content */}
      <div className="flex-1 px-6 pb-6 flex flex-col gap-3">
        <span className="text-sm text-slate-label leading-5">
          {detections.length} AI tool{detections.length !== 1 ? 's' : ''} detected
        </span>

        {detections.length === 0 ? (
          <div className="flex-1 flex items-center justify-center text-slate-muted text-sm py-8">
            No AI tools detected yet
          </div>
        ) : (
          <div className="flex flex-col gap-3 max-h-[480px] overflow-y-auto pr-1">
            {detections.map((d) => (
              <div
                key={d.domain}
                className="relative rounded-[10px] border border-[rgba(251,44,54,0.3)] p-4
                           bg-[rgba(251,44,54,0.10)] flex items-center gap-3"
              >
                <AlertTriangle className="w-4 h-4 text-red-accent shrink-0" />
                <div className="flex-1 min-w-0 flex items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-red-accent leading-5 truncate">
                      AI Tool Detected — {d.name}
                    </div>
                    <div className="text-xs text-slate-label leading-4 truncate">
                      {d.domain}
                    </div>
                  </div>
                  <span className="shrink-0 px-2 py-0.5 rounded-lg text-xs font-medium text-red-accent
                                   bg-[rgba(251,44,54,0.10)] border border-[rgba(251,44,54,0.3)]">
                    {formatNumber(d.packets)} packets
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default memo(AIDetectionPanel);
