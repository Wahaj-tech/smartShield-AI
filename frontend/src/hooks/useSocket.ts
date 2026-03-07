// ── useSocket hook — manages WebSocket connection + flow dataset polling ────

import { useEffect, useRef, useState, useCallback } from 'react';
import { socketService } from '../services/socketService';
import { getAIToolName } from '../utils/dataFormatter';
import type {
  DashboardStats,
  FlowRecord,
  AIDetection,
  TimelinePoint,
  CategoryStats,
  FilterMode,
} from '../types';
import type { BlockedSite } from '../components/BlockedSites';
import type { LiveFlow } from '../components/LiveFlowStream';
import { flowToLiveEntry } from '../components/LiveFlowStream';

const FLOW_POLL_MS = 3000;
const TIMELINE_MAX = 30; // data points kept

export interface CategoryTimelinePoint {
  time: string;
  byCategory: Record<string, number>;
}

const EMPTY_CATEGORIES: CategoryStats = {
  ai_tool: 0,
  writing_assistant: 0,
  social_media: 0,
  messaging: 0,
  streaming: 0,
  search: 0,
  development: 0,
  ecommerce: 0,
  productivity: 0,
  cloud_cdn: 0,
  adult: 0,
  other: 0,
};

function buildStatsFromFlows(flows: FlowRecord[]): DashboardStats {
  const categoryCounts: CategoryStats = { ...EMPTY_CATEGORIES };
  const aiMap = new Map<string, { name: string; packets: number }>();
  let totalPackets = 0;
  const domainSet = new Set<string>();

  for (const f of flows) {
    totalPackets += f.packet_count;
    domainSet.add(f.domain);

    if (f.category in categoryCounts) {
      categoryCounts[f.category as keyof CategoryStats] += 1;
    } else {
      categoryCounts.other += 1;
    }

    // AI detection
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

  const ai_detections: AIDetection[] = Array.from(aiMap.entries())
    .map(([domain, v]) => ({ domain, name: v.name, packets: v.packets }))
    .sort((a, b) => b.packets - a.packets);

  return {
    packets_processed: totalPackets,
    active_connections: domainSet.size,
    flows_captured: flows.length,
    blocked: 0,
    category_stats: categoryCounts,
    ai_detections,
    timeline: [],
    threats: [],
  };
}



export function useSocket() {
  const [stats, setStats] = useState<DashboardStats>({
    packets_processed: 0,
    active_connections: 0,
    flows_captured: 0,
    blocked: 0,
    category_stats: { ...EMPTY_CATEGORIES },
    ai_detections: [],
    timeline: [],
    threats: [],
  });

  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [mode, setModeState] = useState<FilterMode>('free');
  const [blockedCategories, setBlockedCategories] = useState<string[]>([]);
  const [blockedSites, setBlockedSites] = useState<BlockedSite[]>([]);
  const [liveFlows, setLiveFlows] = useState<LiveFlow[]>([]);
  const [allFlows, setAllFlows] = useState<FlowRecord[]>([]);
  const [categoryTimeline, setCategoryTimeline] = useState<CategoryTimelinePoint[]>([]);
  const timelineRef = useRef<TimelinePoint[]>([]);
  const catTimelineRef = useRef<CategoryTimelinePoint[]>([]);
  const flowsRef = useRef<FlowRecord[]>([]);
  const pausedRef = useRef(false);

  // Keep pausedRef in sync
  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  const pollFlows = useCallback(async () => {
    if (pausedRef.current) return;
    try {
      const flows = await socketService.fetchFlowDataset();
      if (flows && flows.length > 0) {
        flowsRef.current = flows;
        setAllFlows(flows);
        const newStats = buildStatsFromFlows(flows);

        // Build live flow stream — pick a random sample of flows each cycle
        // so the stream shows different domains on each refresh, simulating
        // real-time traffic from the static dataset.
        const shuffled = [...flows].sort(() => Math.random() - 0.5);
        const seen = new Set<string>();
        const latest: FlowRecord[] = [];
        for (let i = 0; i < shuffled.length && latest.length < 30; i++) {
          if (!seen.has(shuffled[i].domain)) {
            seen.add(shuffled[i].domain);
            latest.push(shuffled[i]);
          }
        }
        setLiveFlows(latest.map((f, i) => flowToLiveEntry(f, i)));

        // Add timeline point — sample a random window so the chart
        // shows realistic variation instead of a flat line from the
        // same static dataset being averaged identically each cycle.
        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false });
        const sampleSize = Math.max(30, Math.floor(flows.length * (0.3 + Math.random() * 0.5)));
        const startIdx = Math.floor(Math.random() * Math.max(1, flows.length - sampleSize));
        const sample = flows.slice(startIdx, startIdx + sampleSize);

        const avgPPS =
          sample.length > 0
            ? Math.round(sample.reduce((s, f) => s + f.packets_per_second, 0) / sample.length)
            : 0;
        timelineRef.current = [
          ...timelineRef.current.slice(-TIMELINE_MAX + 1),
          { time: timeStr, packets: avgPPS },
        ];

        // Per-category PPS from the same sample for filtered timeline
        const byCategory: Record<string, number> = {};
        const catCounts: Record<string, number> = {};
        for (const f of sample) {
          byCategory[f.category] = (byCategory[f.category] || 0) + f.packets_per_second;
          catCounts[f.category] = (catCounts[f.category] || 0) + 1;
        }
        for (const cat of Object.keys(byCategory)) {
          byCategory[cat] = Math.round(byCategory[cat] / (catCounts[cat] || 1));
        }
        catTimelineRef.current = [
          ...catTimelineRef.current.slice(-TIMELINE_MAX + 1),
          { time: timeStr, byCategory },
        ];
        setCategoryTimeline([...catTimelineRef.current]);

        setStats((prev) => ({
          ...newStats,
          timeline: timelineRef.current,
        }));
      }
    } catch {
      // Backend may not be running — keep last known state
    }
  }, []);

  useEffect(() => {
    // Connect WebSocket
    socketService.connect();

    // Fetch initial mode
    socketService.getMode().then((info) => {
      setModeState(info.mode);
      setBlockedCategories(info.blocked_categories);
    });

    // Fetch persisted blocked domains
    socketService.fetchBlockedDomains().then((domains) => {
      setBlockedSites(
        domains.map((d) => ({
          domain: d.domain,
          reason: d.reason || 'Blocked',
          blockedAt: new Date().toISOString(),
          auto: d.auto || false,
        })),
      );
    });

    const unsub = socketService.subscribe((data) => {
      if (pausedRef.current) return;
      setConnected(true);

      // Handle mode from WS payload
      if (data.mode) {
        setModeState(data.mode as FilterMode);
      }
      if (Array.isArray(data.blocked_categories)) {
        setBlockedCategories(data.blocked_categories as string[]);
      }
    });

    // Connection status polling
    const connInterval = setInterval(() => {
      setConnected(socketService.connected);
    }, 2000);

    // Poll flow dataset
    pollFlows();
    const flowInterval = setInterval(pollFlows, FLOW_POLL_MS);

    return () => {
      unsub();
      clearInterval(connInterval);
      clearInterval(flowInterval);
      socketService.disconnect();
    };
  }, [pollFlows]);

  const setMode = useCallback(async (newMode: FilterMode) => {
    const info = await socketService.setMode(newMode);
    setModeState(info.mode);
    setBlockedCategories(info.blocked_categories);

    // Refresh blocked sites from the response (includes auto-blocked)
    if (info.blocked_domains && Array.isArray(info.blocked_domains)) {
      setBlockedSites(
        info.blocked_domains.map((d) => ({
          domain: d.domain,
          reason: d.reason || 'Blocked',
          blockedAt: new Date().toISOString(),
          auto: d.auto || false,
        })),
      );
    } else {
      // Fallback: fetch from API
      socketService.fetchBlockedDomains().then((domains) => {
        setBlockedSites(
          domains.map((d) => ({
            domain: d.domain,
            reason: d.reason || 'Blocked',
            blockedAt: new Date().toISOString(),
            auto: d.auto || false,
          })),
        );
      });
    }
  }, []);

  const blockSite = useCallback(async (domain: string, reason: string) => {
    try {
      await socketService.blockDomain(domain, reason);
      setBlockedSites((prev) => {
        if (prev.some((s) => s.domain === domain)) return prev;
        return [...prev, { domain, reason, blockedAt: new Date().toISOString() }];
      });
    } catch (err) {
      console.error('[SmartShield] Failed to block domain:', err);
    }
  }, []);

  const unblockSite = useCallback(async (domain: string) => {
    try {
      await socketService.unblockDomain(domain);
      setBlockedSites((prev) => prev.filter((s) => s.domain !== domain));
    } catch (err) {
      console.error('[SmartShield] Failed to unblock domain:', err);
    }
  }, []);

  return {
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
  };
}
