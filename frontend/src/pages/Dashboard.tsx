import { useCallback } from 'react';
import DashboardHeader from '../components/DashboardHeader';
import ControlBar from '../components/ControlBar';
import StatsCards from '../components/StatsCards';
import CategoryChart from '../components/CategoryChart';
import TrafficChart from '../components/TrafficChart';
import AIDetectionPanel from '../components/AIDetectionPanel';
import AlertsPanel from '../components/AlertsPanel';
import { useSocket } from '../hooks/useSocket';
import { socketService } from '../services/socketService';

export default function Dashboard() {
  const {
    stats,
    connected,
    paused,
    setPaused,
    searchQuery,
    setSearchQuery,
    categoryFilter,
    setCategoryFilter,
  } = useSocket();

  const handleExport = useCallback(() => {
    window.open(socketService.getExportURL(), '_blank');
  }, []);

  const handleTogglePause = useCallback(() => {
    setPaused((p) => !p);
  }, [setPaused]);

  // Filter AI detections by search
  const filteredDetections = stats.ai_detections.filter(
    (d) =>
      d.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
      d.name.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  // Filter threats by search
  const filteredThreats = stats.threats.filter((t) =>
    t.domain.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  return (
    <div className="min-h-screen p-6 flex flex-col gap-6 max-w-[1520px] mx-auto">
      {/* 1. Header */}
      <DashboardHeader connected={connected} />

      {/* 2. Control Bar */}
      <ControlBar
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        categoryFilter={categoryFilter}
        onCategoryChange={setCategoryFilter}
        paused={paused}
        onTogglePause={handleTogglePause}
        onExport={handleExport}
      />

      {/* 3. KPI Metrics */}
      <StatsCards
        packetsProcessed={stats.packets_processed}
        activeConnections={stats.active_connections}
        flowsCaptured={stats.flows_captured}
        blocked={stats.blocked}
      />

      {/* 4 & 5. Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <CategoryChart categoryStats={stats.category_stats} />
        <TrafficChart timeline={stats.timeline} />
      </div>

      {/* 6 & 7. Detection & Alerts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <AIDetectionPanel detections={filteredDetections} />
        <AlertsPanel threats={filteredThreats} totalBlocked={stats.blocked} />
      </div>

      {/* Footer */}
      <footer className="text-center text-xs text-slate-muted py-4">
        SmartShield AI &mdash; Deep Packet Inspection Dashboard &copy; {new Date().getFullYear()}
      </footer>
    </div>
  );
}
