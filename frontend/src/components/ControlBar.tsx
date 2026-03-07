import { memo } from 'react';
import { Search, Filter, Pause, Play, Download } from 'lucide-react';

interface Props {
  searchQuery: string;
  onSearchChange: (q: string) => void;
  categoryFilter: string;
  onCategoryChange: (c: string) => void;
  paused: boolean;
  onTogglePause: () => void;
  onExport: () => void;
}

const CATEGORIES = [
  { value: 'all', label: 'All Categories' },
  { value: 'ai_tool', label: 'AI Tools' },
  { value: 'writing_assistant', label: 'Writing Assistant' },
  { value: 'social_media', label: 'Social Media' },
  { value: 'messaging', label: 'Messaging' },
  { value: 'streaming', label: 'Streaming' },
  { value: 'search', label: 'Search' },
  { value: 'development', label: 'Development' },
  { value: 'other', label: 'Other' },
];

function ControlBar({
  searchQuery,
  onSearchChange,
  categoryFilter,
  onCategoryChange,
  paused,
  onTogglePause,
  onExport,
}: Props) {
  return (
    <div className="rounded-[14px] border border-dark-600 bg-dark-700 p-4">
      <div className="flex flex-col lg:flex-row items-stretch lg:items-center gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-label" />
          <input
            type="text"
            placeholder="Search domains..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="w-full h-9 pl-10 pr-3 bg-dark-600 border border-dark-500 rounded-lg text-sm text-white
                       placeholder:text-slate-muted focus:outline-none focus:border-cyan-accent/50 transition-colors"
          />
        </div>

        {/* Category filter */}
        <div className="relative w-full lg:w-[200px]">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-muted" />
          <select
            value={categoryFilter}
            onChange={(e) => onCategoryChange(e.target.value)}
            className="w-full h-9 pl-10 pr-8 bg-dark-600 border border-dark-500 rounded-lg text-sm text-white
                       appearance-none focus:outline-none focus:border-cyan-accent/50 transition-colors cursor-pointer"
          >
            {CATEGORIES.map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </select>
          <div className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none">
            <svg width="10" height="6" viewBox="0 0 10 6" fill="none">
              <path d="M1 1L5 5L9 1" stroke="#717182" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
        </div>

        {/* Pause button */}
        <button
          onClick={onTogglePause}
          className={`flex items-center justify-center gap-2 h-9 px-4 rounded-lg text-sm font-medium transition-colors
            ${paused
              ? 'bg-green-accent/10 border border-green-accent/30 text-green-accent hover:bg-green-accent/20'
              : 'bg-yellow-accent/10 border border-yellow-accent/30 text-yellow-accent hover:bg-yellow-accent/20'
            }`}
        >
          {paused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
          {paused ? 'Resume' : 'Pause'}
        </button>

        {/* Export */}
        <button
          onClick={onExport}
          className="flex items-center justify-center gap-2 h-9 px-4 rounded-lg text-sm font-medium
                     bg-cyan-accent/10 border border-cyan-accent/30 text-cyan-accent hover:bg-cyan-accent/20 transition-colors"
        >
          <Download className="w-4 h-4" />
          Export CSV
        </button>
      </div>
    </div>
  );
}

export default memo(ControlBar);
