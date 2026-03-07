// ── WebSocket service for SmartShield backend ──────────────────────────────
// The backend uses a native WebSocket at /ws (not Socket.IO).
// We also parse flow_dataset.csv periodically for rich dashboard data.

import type { FlowRecord, FlowCategory } from '../types';

const WS_URL =
  import.meta.env.VITE_WS_URL ??
  `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws`;

const API_BASE =
  import.meta.env.VITE_API_URL ?? '';

export type WSListener = (data: Record<string, unknown>) => void;

class SocketService {
  private ws: WebSocket | null = null;
  private listeners: Set<WSListener> = new Set();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private _connected = false;

  get connected() {
    return this._connected;
  }

  connect() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    try {
      this.ws = new WebSocket(WS_URL);

      this.ws.onopen = () => {
        this._connected = true;
        console.log('[SmartShield] WebSocket connected');
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this.listeners.forEach((fn) => fn(data));
        } catch {
          console.warn('[SmartShield] Failed to parse WS message');
        }
      };

      this.ws.onclose = () => {
        this._connected = false;
        console.log('[SmartShield] WebSocket disconnected, reconnecting…');
        this.scheduleReconnect();
      };

      this.ws.onerror = () => {
        this._connected = false;
      };
    } catch {
      this.scheduleReconnect();
    }
  }

  disconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.ws?.close();
    this.ws = null;
    this._connected = false;
  }

  subscribe(fn: WSListener) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private scheduleReconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => this.connect(), 3000);
  }

  // ── REST helpers ───────────────────────────────────────────────────

  async fetchStats() {
    const res = await fetch(`${API_BASE}/stats`);
    return res.json();
  }

  async fetchFlowDataset(): Promise<FlowRecord[]> {
    const res = await fetch(`${API_BASE}/api/flows`);
    if (!res.ok) return [];
    return res.json();
  }

  getExportURL() {
    return `${API_BASE}/api/flows/export`;
  }
}

export const socketService = new SocketService();

// ── CSV parser helper (used if backend serves raw CSV) ─────────────────────

export function parseCSV(text: string): FlowRecord[] {
  const lines = text.trim().split('\n');
  if (lines.length < 2) return [];
  return lines.slice(1).map((line) => {
    const [domain, protocol, packet_count, avg_packet_size, flow_duration, packets_per_second, bytes_per_second, category] =
      line.split(',');
    return {
      domain: domain?.trim() ?? '',
      protocol: protocol?.trim() ?? '',
      packet_count: Number(packet_count) || 0,
      avg_packet_size: Number(avg_packet_size) || 0,
      flow_duration: Number(flow_duration) || 0,
      packets_per_second: Number(packets_per_second) || 0,
      bytes_per_second: Number(bytes_per_second) || 0,
      category: (category?.trim() ?? 'other') as FlowCategory,
    };
  });
}
