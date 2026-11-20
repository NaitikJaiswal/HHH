import React from 'react';
import { LayoutDashboard, Search, ShieldCheck, Cpu, FileText, Settings, ShieldAlert } from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab }) {
  const navItems = [
    { id: 'dashboard', label: 'SOC Overview', icon: LayoutDashboard, badge: null },
    { id: 'logs', label: 'Log Explorer (Hunt)', icon: Search, badge: 'Live' },
    { id: 'integrity', label: 'Evidence & Hash (Harden)', icon: ShieldCheck, badge: 'Verified' },
    { id: 'agents', label: 'Collectors & Agents', icon: Cpu, badge: '3 Active' },
    { id: 'audit', label: 'Audit & Compliance', icon: FileText, badge: null },
  ];

  return (
    <aside className="w-64 border-r border-cyber-border bg-cyber-bg hidden lg:flex flex-col justify-between p-4 min-h-[calc(100vh-4rem)]">
      <div className="space-y-6">
        <div>
          <p className="px-3 text-[11px] font-mono uppercase tracking-wider text-slate-500 mb-2">Operations</p>
          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-500/15 to-blue-500/10 text-cyan-300 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                      : 'text-slate-400 hover:bg-cyber-card hover:text-slate-200 border border-transparent'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <Icon className={`h-4 w-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded-full font-mono ${
                        item.badge === 'Live'
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                          : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* System Architecture Card */}
        <div className="p-3.5 rounded-xl bg-cyber-card/60 border border-cyber-border space-y-2.5">
          <div className="flex items-center space-x-2 text-xs font-semibold text-slate-300 font-mono">
            <ShieldAlert className="h-4 w-4 text-cyan-400" />
            <span>Architecture</span>
          </div>
          <div className="text-[11px] text-slate-400 space-y-1.5 font-mono">
            <div className="flex justify-between">
              <span className="text-slate-500">M1 Backend:</span>
              <span className="text-emerald-400">Node/Mongo</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">M2 Frontend:</span>
              <span className="text-cyan-400">React (Active)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">M3/4 Storage:</span>
              <span className="text-blue-400">Python Agent</span>
            </div>
          </div>
        </div>
      </div>

      {/* Footer Info */}
      <div className="border-t border-cyber-border pt-4 px-2 text-[11px] text-slate-500 font-mono flex items-center justify-between">
        <span>v1.0.0-rc</span>
        <span className="text-cyan-500">SecureLog</span>
      </div>
    </aside>
  );
}
