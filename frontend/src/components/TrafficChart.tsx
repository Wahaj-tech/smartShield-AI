import { memo } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { BarChart3 } from 'lucide-react';
import type { TimelinePoint } from '../types';

interface Props {
  timeline: TimelinePoint[];
}

function TrafficChart({ timeline }: Props) {
  return (
    <div className="rounded-[14px] border border-dark-600 bg-dark-700 h-[400px] flex flex-col">
      {/* Header */}
      <div className="px-6 pt-6 pb-2 flex items-center gap-2">
        <BarChart3 className="w-5 h-5 text-cyan-accent" />
        <h3 className="text-base font-medium text-white leading-4">
          Traffic Timeline (Last 5 Minutes)
        </h3>
      </div>

      {/* Chart */}
      <div className="flex-1 px-4 pb-4">
        {timeline.length === 0 ? (
          <div className="h-full flex items-center justify-center text-slate-muted text-sm">
            Collecting timeline data…
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeline} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#06B6D4" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1D293D" vertical={false} />
              <XAxis
                dataKey="time"
                tick={{ fill: '#94A3B8', fontSize: 12 }}
                tickLine={false}
                axisLine={{ stroke: '#1D293D' }}
              />
              <YAxis
                tick={{ fill: '#94A3B8', fontSize: 12 }}
                tickLine={false}
                axisLine={{ stroke: '#1D293D' }}
                label={{
                  value: 'Packets/sec',
                  angle: -90,
                  position: 'insideLeft',
                  style: { fill: '#94A3B8', fontSize: 12 },
                }}
              />
              <Tooltip
                contentStyle={{
                  background: '#1D293D',
                  border: '1px solid #314158',
                  borderRadius: 8,
                  color: 'white',
                  fontSize: 13,
                }}
                labelStyle={{ color: '#94A3B8' }}
                formatter={(value: number) => [`${value} pkt/s`, 'Packets']}
              />
              <Area
                type="monotone"
                dataKey="packets"
                stroke="#06B6D4"
                strokeWidth={2}
                fill="url(#colorPackets)"
                dot={false}
                activeDot={{ r: 4, fill: '#06B6D4' }}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}

export default memo(TrafficChart);
