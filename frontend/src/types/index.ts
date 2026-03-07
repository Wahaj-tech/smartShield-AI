// ── Type definitions for SmartShield Dashboard ─────────────────────────────

export interface FlowRecord {
  domain: string;
  protocol: string;
  packet_count: number;
  avg_packet_size: number;
  flow_duration: number;
  packets_per_second: number;
  bytes_per_second: number;
  category: FlowCategory;
}

export type FlowCategory =
  | 'ai_tool'
  | 'writing_assistant'
  | 'social_media'
  | 'messaging'
  | 'streaming'
  | 'search'
  | 'development'
  | 'other';

export interface CategoryStats {
  ai_tool: number;
  writing_assistant: number;
  social_media: number;
  messaging: number;
  streaming: number;
  search: number;
  development: number;
  other: number;
}

export interface AIDetection {
  domain: string;
  name: string;
  packets: number;
}

export interface ThreatAlert {
  domain: string;
  reason: string;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface TimelinePoint {
  time: string;
  packets: number;
}

export interface DashboardStats {
  packets_processed: number;
  active_connections: number;
  flows_captured: number;
  blocked: number;
  category_stats: CategoryStats;
  ai_detections: AIDetection[];
  timeline: TimelinePoint[];
  threats: ThreatAlert[];
}

export interface WSPayload {
  blocked_ips: number;
  blocked_apps: number;
  blocked_domains: number;
  blocked_ports: number;
  ip_list: string[];
  domain_list: string[];
  app_list: string[];
}
