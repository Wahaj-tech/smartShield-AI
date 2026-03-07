import { memo, useState } from 'react';
import { XCircle, Trash2, Plus } from 'lucide-react';

export interface BlockedSite {
  domain: string;
  reason: string;
  blockedAt: string;
  auto?: boolean;
}

interface Props {
  sites: BlockedSite[];
  onBlock: (domain: string, reason: string) => void;
  onUnblock: (domain: string) => void;
}

function BlockedSites({ sites, onBlock, onUnblock }: Props) {
  const [domain, setDomain] = useState('');
  const [reason, setReason] = useState('');

  const handleSubmit = () => {
    const d = domain.trim();
    if (!d) return;
    onBlock(d, reason.trim() || 'Manually blocked');
    setDomain('');
    setReason('');
  };

  return (
    <div className="rounded-[14px] border border-dark-600 bg-dark-700 p-5 flex flex-col">
      {/* Header */}
      <div className="mb-4">
        <h2 className="text-lg font-bold text-white">Blocked Sites</h2>
        <p className="text-sm text-slate-muted mt-0.5">
          {sites.length} site{sites.length !== 1 ? 's' : ''} currently blocked
        </p>
      </div>

      {/* Blocked sites list */}
      <div className="flex-1 min-h-[160px] max-h-[280px] overflow-y-auto mb-4 rounded-lg border border-dark-500 bg-dark-800/40">
        {sites.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full py-10 text-center">
            <XCircle className="w-10 h-10 text-red-accent/40 mb-3" />
            <p className="text-base font-medium text-slate-label">No blocked sites</p>
            <p className="text-sm text-slate-muted mt-1">Sites will appear here when blocked</p>
          </div>
        ) : (
          <ul className="divide-y divide-dark-600">
            {sites.map((s) => (
              <li key={s.domain} className="flex items-center justify-between px-4 py-3 hover:bg-dark-600/50 transition-colors">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium text-white truncate">{s.domain}</p>
                    {s.auto && (
                      <span className="shrink-0 px-1.5 py-0.5 text-[10px] font-semibold rounded bg-yellow-accent/15 text-yellow-accent border border-yellow-accent/30">
                        AUTO
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-muted truncate">{s.reason}</p>
                </div>
                {!s.auto && (
                  <button
                    onClick={() => onUnblock(s.domain)}
                    className="shrink-0 ml-3 p-1.5 rounded-md text-red-accent/70 hover:text-red-accent hover:bg-red-accent/10 transition-colors"
                    title="Unblock"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Block form */}
      <div className="border-t border-dark-600 pt-4">
        <p className="text-sm font-semibold text-white mb-3">Block a new site</p>
        <div className="flex flex-col gap-2.5">
          <input
            type="text"
            placeholder="Enter domain (e.g., example.com)"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
            className="w-full h-10 px-3 bg-dark-600 border border-dark-500 rounded-lg text-sm text-white
                       placeholder:text-slate-muted focus:outline-none focus:border-red-accent/50 transition-colors"
          />
          <input
            type="text"
            placeholder="Reason for blocking"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
            className="w-full h-10 px-3 bg-dark-600 border border-dark-500 rounded-lg text-sm text-white
                       placeholder:text-slate-muted focus:outline-none focus:border-red-accent/50 transition-colors"
          />
          <button
            onClick={handleSubmit}
            disabled={!domain.trim()}
            className="w-full h-10 rounded-lg text-sm font-semibold transition-colors flex items-center justify-center gap-2
                       bg-red-accent/15 border border-red-accent/30 text-red-accent hover:bg-red-accent/25
                       disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Plus className="w-4 h-4" />
            Block Site
          </button>
        </div>
      </div>
    </div>
  );
}

export default memo(BlockedSites);
