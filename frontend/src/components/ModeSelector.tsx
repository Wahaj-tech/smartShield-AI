import { memo } from 'react';
import { Shield, BookOpen, Users } from 'lucide-react';
import type { FilterMode } from '../types';

interface Props {
  mode: FilterMode;
  onModeChange: (mode: FilterMode) => void;
  blockedCategories: string[];
}

const MODES: { value: FilterMode; label: string; icon: React.ReactNode; description: string; color: string; activeClass: string }[] = [
  {
    value: 'free',
    label: 'Free Mode',
    icon: <Shield className="w-4 h-4" />,
    description: 'All sites allowed',
    color: 'text-green-accent',
    activeClass: 'bg-green-accent/15 border-green-accent/50 text-green-accent',
  },
  {
    value: 'exam',
    label: 'Exam Mode',
    icon: <BookOpen className="w-4 h-4" />,
    description: 'Blocks AI, writing tools & dev sites',
    color: 'text-yellow-accent',
    activeClass: 'bg-yellow-accent/15 border-yellow-accent/50 text-yellow-accent',
  },
  {
    value: 'parental',
    label: 'Parental Mode',
    icon: <Users className="w-4 h-4" />,
    description: 'Blocks adult & social media',
    color: 'text-purple-accent',
    activeClass: 'bg-purple-accent/15 border-purple-accent/50 text-purple-accent',
  },
];

function ModeSelector({ mode, onModeChange, blockedCategories }: Props) {
  return (
    <div className="rounded-[14px] border border-dark-600 bg-dark-700 p-4">
      <div className="flex items-center gap-2 mb-3">
        <Shield className="w-4 h-4 text-cyan-accent" />
        <span className="text-sm font-semibold text-white">Filtering Mode</span>
        {blockedCategories.length > 0 && (
          <span className="ml-auto text-xs text-slate-muted">
            Blocking: {blockedCategories.join(', ')}
          </span>
        )}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {MODES.map((m) => {
          const isActive = mode === m.value;
          return (
            <button
              key={m.value}
              onClick={() => onModeChange(m.value)}
              className={`flex items-center gap-3 p-3 rounded-lg border text-left transition-all duration-200
                ${isActive
                  ? m.activeClass
                  : 'border-dark-500 bg-dark-600 text-slate-label hover:border-dark-500/80 hover:bg-dark-600/80'
                }`}
            >
              <div className={`shrink-0 ${isActive ? '' : 'text-slate-muted'}`}>
                {m.icon}
              </div>
              <div className="min-w-0">
                <div className={`text-sm font-medium ${isActive ? '' : 'text-white'}`}>
                  {m.label}
                </div>
                <div className={`text-xs mt-0.5 ${isActive ? 'opacity-80' : 'text-slate-muted'}`}>
                  {m.description}
                </div>
              </div>
              {isActive && (
                <div className="ml-auto shrink-0">
                  <div className="w-2 h-2 rounded-full bg-current animate-pulse" />
                </div>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}

export default memo(ModeSelector);
