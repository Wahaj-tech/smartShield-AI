import { memo } from 'react';
import { ShieldAlert, AlertOctagon } from 'lucide-react';
import { timeAgo } from '../utils/dataFormatter';
import type { ThreatAlert } from '../types';

interface Props {
  threats: ThreatAlert[];
  totalBlocked: number;
}

function AlertsPanel({ threats, totalBlocked }: Props) {
  return (
    <div className="rounded-[14px] border border-dark-600 bg-dark-700 flex flex-col">
      {/* Header */}
      <div className="px-6 pt-6 pb-2 flex items-center gap-2">
        <ShieldAlert className="w-5 h-5 text-red-accent" />
        <h3 className="text-base font-medium text-white leading-4">
          Threat &amp; Policy Alerts
        </h3>
      </div>

      {/* Content */}
      <div className="flex-1 px-6 pb-6 flex flex-col gap-3">
        {/* Total blocked badge */}
        <div className="flex items-center justify-between">
          <span className="text-sm text-slate-label">Total Blocked</span>
          <span className="px-3 py-1 rounded-lg text-lg font-medium text-red-accent
                           bg-[rgba(251,44,54,0.10)] border border-[rgba(251,44,54,0.3)]">
            {totalBlocked}
          </span>
        </div>

        {threats.length === 0 ? (
          <div className="flex-1 flex items-center justify-center text-slate-muted text-sm py-8">
            No threats detected
          </div>
        ) : (
          <div className="flex flex-col gap-3 max-h-[480px] overflow-y-auto pr-1">
            {threats.map((t, i) => (
              <div
                key={`${t.domain}-${i}`}
                className="rounded-[10px] border border-[rgba(251,44,54,0.20)] p-4
                           bg-[rgba(251,44,54,0.05)] flex items-center gap-3"
              >
                <AlertOctagon className="w-4 h-4 text-red-accent shrink-0" />
                <div className="flex-1 min-w-0 flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-red-accent leading-5 truncate">
                      {t.domain}
                    </div>
                    <div className="text-xs text-slate-label leading-4">
                      {t.reason}
                    </div>
                  </div>
                  <div className="flex flex-col items-end shrink-0 gap-1">
                    <span className="text-xs text-slate-muted">{timeAgo(t.timestamp)}</span>
                    <SeverityBadge severity={t.severity} />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: ThreatAlert['severity'] }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  };

  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase border ${colors[severity] ?? colors.medium}`}>
      {severity}
    </span>
  );
}

export default memo(AlertsPanel);
