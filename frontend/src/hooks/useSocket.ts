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
  ThreatAlert,
} from '../types';

const FLOW_POLL_MS = 3000;
const TIMELINE_MAX = 30; // data points kept

const EMPTY_CATEGORIES: CategoryStats = {
  ai_tool: 0,
  writing_assistant: 0,
  social_media: 0,
  messaging: 0,
  streaming: 0,
  search: 0,
  development: 0,
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

// Sample threat data (in production this would come from the backend)
const SAMPLE_THREATS: ThreatAlert[] = [
  { domain: 'malicious-site.com', reason: 'Malware detected', timestamp: new Date(Date.now() - 120000).toISOString(), severity: 'critical' },
  { domain: 'phishing-attempt.net', reason: 'Phishing attempt', timestamp: new Date(Date.now() - 300000).toISOString(), severity: 'high' },
  { domain: 'suspicious-tracker.io', reason: 'Tracking script blocked', timestamp: new Date(Date.now() - 480000).toISOString(), severity: 'medium' },
  { domain: 'crypto-miner.xyz', reason: 'Crypto mining detected', timestamp: new Date(Date.now() - 600000).toISOString(), severity: 'critical' },
  { domain: 'data-exfil.ru', reason: 'Data exfiltration attempt', timestamp: new Date(Date.now() - 900000).toISOString(), severity: 'high' },
  { domain: 'ad-injector.com', reason: 'Ad injection blocked', timestamp: new Date(Date.now() - 1200000).toISOString(), severity: 'medium' },
  { domain: 'keylogger-cdn.net', reason: 'Keylogger script detected', timestamp: new Date(Date.now() - 1500000).toISOString(), severity: 'critical' },
  { domain: 'fake-update.com', reason: 'Fake software update', timestamp: new Date(Date.now() - 1800000).toISOString(), severity: 'high' },
];

export function useSocket() {
  const [stats, setStats] = useState<DashboardStats>({
    packets_processed: 0,
    active_connections: 0,
    flows_captured: 0,
    blocked: SAMPLE_THREATS.length,
    category_stats: { ...EMPTY_CATEGORIES },
    ai_detections: [],
    timeline: [],
    threats: SAMPLE_THREATS,
  });

  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const timelineRef = useRef<TimelinePoint[]>([]);
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
        const newStats = buildStatsFromFlows(flows);

        // Add timeline point
        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false });
        const avgPPS =
          flows.length > 0
            ? Math.round(flows.reduce((s, f) => s + f.packets_per_second, 0) / Math.max(flows.length, 1))
            : 0;
        timelineRef.current = [
          ...timelineRef.current.slice(-TIMELINE_MAX + 1),
          { time: timeStr, packets: avgPPS },
        ];

        setStats((prev) => ({
          ...newStats,
          blocked: prev.blocked,
          threats: prev.threats,
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

    const unsub = socketService.subscribe((data) => {
      if (pausedRef.current) return;
      setConnected(true);

      // Handle WS payload from backend (blocked stats)
      setStats((prev) => ({
        ...prev,
        blocked:
          (Number(data.blocked_domains) || 0) +
          (Number(data.blocked_ips) || 0) ||
          prev.blocked,
      }));
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

  return {
    stats,
    connected,
    paused,
    setPaused,
    searchQuery,
    setSearchQuery,
    categoryFilter,
    setCategoryFilter,
  };
}
