import { memo, useMemo } from 'react';
import { Activity, Users, GitBranch, ShieldAlert } from 'lucide-react';
import { formatNumber } from '../utils/dataFormatter';

interface Props {
  packetsProcessed: number;
  activeConnections: number;
  flowsCaptured: number;
  blocked: number;
}

interface CardData {
  label: string;
  value: number;
  icon: React.ReactNode;
  iconBg: string;
}

function StatsCards({ packetsProcessed, activeConnections, flowsCaptured, blocked }: Props) {
  const cards: CardData[] = useMemo(
    () => [
      {
        label: 'Packets Processed',
        value: packetsProcessed,
        icon: <Activity className="w-6 h-6 text-cyan-accent" />,
        iconBg: 'rgba(0,184,219,0.10)',
      },
      {
        label: 'Active Connections',
        value: activeConnections,
        icon: <Users className="w-6 h-6 text-purple-accent" />,
        iconBg: 'rgba(173,70,255,0.10)',
      },
      {
        label: 'Flows Captured',
        value: flowsCaptured,
        icon: <GitBranch className="w-6 h-6 text-blue-light" />,
        iconBg: 'rgba(43,127,255,0.10)',
      },
      {
        label: 'Blocked / Suspicious',
        value: blocked,
        icon: <ShieldAlert className="w-6 h-6 text-red-accent" />,
        iconBg: 'rgba(251,44,54,0.10)',
      },
    ],
    [packetsProcessed, activeConnections, flowsCaptured, blocked],
  );

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      {cards.map((card) => (
        <div
          key={card.label}
          className="rounded-[14px] border border-dark-600 bg-dark-700 p-6"
        >
          <div className="flex justify-between items-start">
            <div className="flex flex-col gap-2">
              <span className="text-sm text-slate-label leading-5">{card.label}</span>
              <span className="text-[30px] font-bold text-white leading-9">
                {formatNumber(card.value)}
              </span>
            </div>
            <div
              className="w-12 h-12 rounded-[10px] flex items-center justify-center shrink-0"
              style={{ background: card.iconBg }}
            >
              {card.icon}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

export default memo(StatsCards);
