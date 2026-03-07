import { useCallback, useMemo } from 'react';
import DashboardHeader from '../components/DashboardHeader';
import ModeSelector from '../components/ModeSelector';
import ControlBar from '../components/ControlBar';
import StatsCards from '../components/StatsCards';
import CategoryChart from '../components/CategoryChart';
import TrafficChart from '../components/TrafficChart';
import AIDetectionPanel from '../components/AIDetectionPanel';
import AlertsPanel from '../components/AlertsPanel';
import BlockedSites from '../components/BlockedSites';
import LiveFlowStream from '../components/LiveFlowStream';
import { useSocket } from '../hooks/useSocket';
import { socketService } from '../services/socketService';
import { getAIToolName } from '../utils/dataFormatter';
import type { CategoryStats, TimelinePoint, AIDetection } from '../types';

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
    mode,
    setMode,
    blockedCategories,
    blockedSites,
    blockSite,
    unblockSite,
    liveFlows,
    allFlows,
    categoryTimeline,
  } = useSocket();

  const handleExport = useCallback(() => {
    window.open(socketService.getExportURL(), '_blank');
  }, []);

  const handleTogglePause = useCallback(() => {
    setPaused((p) => !p);
  }, [setPaused]);

  // ── Compute stats filtered by category dropdown + mode blocked categories ──
  const filteredCardStats = useMemo(() => {
    let flows = allFlows;

    // Exclude flows belonging to mode-blocked categories
    if (blockedCategories.length > 0) {
      flows = flows.filter((f) => !blockedCategories.includes(f.category));
    }

    // Further narrow by category dropdown
    if (categoryFilter !== 'all') {
      flows = flows.filter((f) => f.category === categoryFilter);
    }

    return {
      packetsProcessed: flows.reduce((sum, f) => sum + f.packet_count, 0),
      activeConnections: new Set(flows.map((f) => f.domain)).size,
      flowsCaptured: flows.length,
    };
  }, [allFlows, categoryFilter, blockedCategories]);

  // Blocked count – also respect category dropdown
  const filteredBlockedCount = useMemo(() => {
    if (categoryFilter === 'all') return blockedSites.length;
    return blockedSites.filter((s) => {
      const catMatch = s.reason.match(/\(([^)]+)\)/);
      return catMatch?.[1] === categoryFilter;
    }).length;
  }, [blockedSites, categoryFilter]);

  // ── CategoryChart: filtered by mode + category dropdown ──
  const filteredCategoryStats = useMemo((): CategoryStats => {
    let flows = allFlows;
    if (blockedCategories.length > 0) {
      flows = flows.filter((f) => !blockedCategories.includes(f.category));
    }
    if (categoryFilter !== 'all') {
      flows = flows.filter((f) => f.category === categoryFilter);
    }
    const cats: CategoryStats = {
      ai_tool: 0, writing_assistant: 0, social_media: 0, messaging: 0,
      streaming: 0, search: 0, development: 0, ecommerce: 0,
      productivity: 0, cloud_cdn: 0, adult: 0, other: 0,
    };
    for (const f of flows) {
      if (f.category in cats) {
        cats[f.category as keyof CategoryStats] += 1;
      } else {
        cats.other += 1;
      }
    }
    return cats;
  }, [allFlows, blockedCategories, categoryFilter]);

  // ── TrafficChart: filtered timeline by mode + category dropdown ──
  const filteredTimeline = useMemo((): TimelinePoint[] => {
    return categoryTimeline.map((pt) => {
      let total = 0;
      let count = 0;
      for (const [cat, val] of Object.entries(pt.byCategory)) {
        if (blockedCategories.includes(cat)) continue;
        if (categoryFilter !== 'all' && cat !== categoryFilter) continue;
        total += val;
        count += 1;
      }
      return { time: pt.time, packets: count > 0 ? Math.round(total / count) : 0 };
    });
  }, [categoryTimeline, blockedCategories, categoryFilter]);

  // Filter AI detections by mode + category + search (recompute from filtered flows)
  const filteredDetections = useMemo((): AIDetection[] => {
    let flows = allFlows;
    if (blockedCategories.length > 0) {
      flows = flows.filter((f) => !blockedCategories.includes(f.category));
    }
    if (categoryFilter !== 'all') {
      flows = flows.filter((f) => f.category === categoryFilter);
    }
    const aiMap = new Map<string, { name: string; packets: number }>();
    for (const f of flows) {
      const toolName = getAIToolName(f.domain);
      if (toolName || f.category === 'ai_tool') {
        const name = toolName ?? f.domain;
        const existing = aiMap.get(f.domain);
        if (existing) {
          existing.packets += f.packet_count;
        } else {
          aiMap.set(f.domain, { name, packets: f.packet_count });
        }
      }
    }
    const detections = Array.from(aiMap.entries())
      .map(([domain, v]) => ({ domain, name: v.name, packets: v.packets }))
      .sort((a, b) => b.packets - a.packets);
    if (!searchQuery) return detections;
    const q = searchQuery.toLowerCase();
    return detections.filter(
      (d) => d.domain.toLowerCase().includes(q) || d.name.toLowerCase().includes(q),
    );
  }, [allFlows, blockedCategories, categoryFilter, searchQuery]);

  // Filter live flows by mode + category + search
  const filteredLiveFlows = useMemo(() => {
    let flows = liveFlows;
    if (blockedCategories.length > 0) {
      flows = flows.filter((f) => !blockedCategories.includes(f.category));
    }
    if (categoryFilter !== 'all') {
      flows = flows.filter((f) => f.category === categoryFilter);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      flows = flows.filter((f) => f.domain.toLowerCase().includes(q));
    }
    return flows;
  }, [liveFlows, blockedCategories, categoryFilter, searchQuery]);

  // Derive threat alerts from real blocked sites
  const threats = useMemo(() => {
    const CATEGORY_SEVERITY: Record<string, 'critical' | 'high' | 'medium' | 'low'> = {
      adult: 'critical',
      ai_tool: 'high',
      writing_assistant: 'high',
      development: 'medium',
      social_media: 'medium',
    };
    return blockedSites.map((s) => {
      // Extract category from reason like "Auto-blocked (adult)"
      const catMatch = s.reason.match(/\(([^)]+)\)/);
      const cat = catMatch?.[1] ?? '';
      const severity = CATEGORY_SEVERITY[cat] ?? (s.auto ? 'medium' : 'high');
      return {
        domain: s.domain,
        reason: s.reason,
        timestamp: s.blockedAt,
        severity,
      };
    });
  }, [blockedSites]);

  // Filter threats by search
  const filteredThreats = threats.filter((t) =>
    t.domain.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  return (
    <div className="min-h-screen p-6 flex flex-col gap-6 max-w-[1520px] mx-auto">
      {/* 1. Header */}
      <DashboardHeader connected={connected} />

      {/* 2. Mode Selector */}
      <ModeSelector mode={mode} onModeChange={setMode} blockedCategories={blockedCategories} />

      {/* 3. Control Bar */}
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
        packetsProcessed={filteredCardStats.packetsProcessed}
        activeConnections={filteredCardStats.activeConnections}
        flowsCaptured={filteredCardStats.flowsCaptured}
        blocked={filteredBlockedCount}
      />

      {/* 4 & 5. Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <CategoryChart categoryStats={filteredCategoryStats} />
        <TrafficChart timeline={filteredTimeline} />
      </div>

      {/* Live Flow Stream */}
      <LiveFlowStream flows={filteredLiveFlows} connected={connected} />

      {/* Blocked Sites + Detection & Alerts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <BlockedSites sites={blockedSites} onBlock={blockSite} onUnblock={unblockSite} />
        <AIDetectionPanel detections={filteredDetections} />
      </div>

      {/* Alerts */}
      <AlertsPanel threats={filteredThreats} totalBlocked={filteredBlockedCount} />

      {/* Footer */}
      <footer className="text-center text-xs text-slate-muted py-4">
        SmartShield AI &mdash; Deep Packet Inspection Dashboard &copy; {new Date().getFullYear()}
      </footer>
    </div>
  );
}
