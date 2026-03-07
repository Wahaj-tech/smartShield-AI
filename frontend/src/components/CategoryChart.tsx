import { memo, useMemo } from 'react';
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import type { CategoryStats } from '../types';
import { categoryLabel, categoryColor } from '../utils/dataFormatter';

interface Props {
  categoryStats: CategoryStats;
}

function CategoryChart({ categoryStats }: Props) {
  const data = useMemo(() => {
    return Object.entries(categoryStats)
      .filter(([, v]) => v > 0)
      .map(([key, value]) => ({
        name: categoryLabel(key),
        value,
        color: categoryColor(key),
      }))
      .sort((a, b) => b.value - a.value);
  }, [categoryStats]);

  return (
    <div className="rounded-[14px] border border-dark-600 bg-dark-700 h-[400px] flex flex-col">
      {/* Header */}
      <div className="px-6 pt-6 pb-2 flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-cyan-accent opacity-[0.98]" />
        <h3 className="text-base font-medium text-white leading-4">Traffic by Category</h3>
      </div>

      {/* Chart */}
      <div className="flex-1 px-4 pb-4">
        {data.length === 0 ? (
          <div className="h-full flex items-center justify-center text-slate-muted text-sm">
            No traffic data yet
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="45%"
                innerRadius={60}
                outerRadius={110}
                paddingAngle={2}
                dataKey="value"
                stroke="rgba(255,255,255,0.1)"
                strokeWidth={1}
              >
                {data.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: '#1D293D',
                  border: '1px solid #314158',
                  borderRadius: 8,
                  color: 'white',
                  fontSize: 13,
                }}
                itemStyle={{ color: 'white' }}
                formatter={(value: number, name: string) => [`${value} flows`, name]}
              />
              <Legend
                verticalAlign="bottom"
                height={30}
                formatter={(value: string) => (
                  <span className="text-sm text-slate-label">{value}</span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}

export default memo(CategoryChart);
