import { memo } from 'react';
import { Shield, Wifi, Bug, BarChart3, Download } from 'lucide-react';

interface Props {
  connected: boolean;
}

function DashboardHeader({ connected }: Props) {
  return (
    <div className="relative overflow-hidden rounded-[14px] border border-[rgba(0,117,149,0.3)]"
         style={{ background: 'linear-gradient(90deg, rgba(16,78,100,0.20) 0%, rgba(28,57,142,0.20) 50%, rgba(89,22,139,0.20) 100%)' }}>
      <div className="absolute inset-0"
           style={{ background: 'linear-gradient(90deg, rgba(0,184,219,0.05) 0%, rgba(43,127,255,0.05) 100%)' }} />

      <div className="relative p-6">
        {/* Title row */}
        <div className="flex items-start gap-4 mb-6">
          <div className="w-12 h-12 rounded-[14px] flex items-center justify-center shrink-0"
               style={{ background: 'linear-gradient(135deg, #00B8DB 0%, #155DFC 100%)' }}>
            <Shield className="w-7 h-7 text-white" />
          </div>
          <div className="flex-1 min-w-0">
            <h1 className="text-2xl font-bold text-white leading-8">
              Welcome to SmartShield AI Dashboard
            </h1>
            <p className="text-[#CAD5E2] text-base mt-2 leading-6">
              Real-time network security monitoring powered by Deep Packet Inspection (DPI) engine.
              Monitor traffic, detect AI tools, and analyze network patterns in real-time.
            </p>
          </div>

          {/* Connection indicator */}
          <div className="flex items-center gap-2 shrink-0">
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-accent animate-pulse' : 'bg-red-accent'}`} />
            <span className="text-xs text-slate-label">
              {connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>

        {/* Feature indicators */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <FeatureItem icon={<Wifi className="w-5 h-5 text-green-accent" />}
                       title="Live Monitoring" subtitle="Real-time flow capture and analysis" />
          <FeatureItem icon={<Bug className="w-5 h-5 text-red-accent" />}
                       title="AI Detection" subtitle="Identify ChatGPT, Claude, and more" />
          <FeatureItem icon={<BarChart3 className="w-5 h-5 text-cyan-accent" />}
                       title="Traffic Analytics" subtitle="Visual insights and trends" />
          <FeatureItem icon={<Download className="w-5 h-5 text-purple-accent" />}
                       title="Export Data" subtitle="Download reports as CSV" />
        </div>
      </div>
    </div>
  );
}

function FeatureItem({ icon, title, subtitle }: { icon: React.ReactNode; title: string; subtitle: string }) {
  return (
    <div className="flex items-start gap-3">
      <div className="mt-0.5">{icon}</div>
      <div>
        <div className="text-sm font-semibold text-white leading-5">{title}</div>
        <div className="text-xs text-slate-label leading-4">{subtitle}</div>
      </div>
    </div>
  );
}

export default memo(DashboardHeader);
