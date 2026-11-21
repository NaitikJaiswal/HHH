import React, { useState } from 'react';
import { 
  LayoutDashboard, Archive, Hash, GitCommit, Database, 
  Crosshair, Briefcase, History, FileSpreadsheet, Sliders, 
  ChevronLeft, ChevronRight, Shield, Terminal, ShieldCheck, Cpu 
} from 'lucide-react';

export default function NavigationRail({ activeTab, setActiveTab }) {
  const [collapsed, setCollapsed] = useState(false);

  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'logs', label: 'Log Explorer', icon: Terminal },
    { id: 'integrity', label: 'Integrity Verifier', icon: ShieldCheck },
    { id: 'agents', label: 'Collector Agents', icon: Cpu },
    { id: 'vault', label: 'Evidence Vault', icon: Archive, badge: '4' },
    { id: 'hash', label: 'Hash Verification', icon: Hash },
    { id: 'merkle', label: 'Merkle Explorer', icon: GitCommit },
    { id: 'ledger', label: 'Blockchain Ledger', icon: Database, badge: 'Quai' },
    { id: 'threats', label: 'Threat Hunting', icon: Crosshair, alert: true },
    { id: 'investigations', label: 'Investigations', icon: Briefcase, badge: '2' },
    { id: 'audit', label: 'Audit Trail', icon: History },
    { id: 'reports', label: 'Reports', icon: FileSpreadsheet },
    { id: 'settings', label: 'Settings', icon: Sliders },
  ];

  return (
    <aside 
      className={`relative h-[calc(100vh-4rem)] border-r border-white/5 bg-obsidian-900/90 backdrop-blur-xl flex flex-col justify-between transition-all duration-300 z-20 ${
        collapsed ? 'w-16' : 'w-64'
      }`}
    >
      {/* Navigation Links */}
      <div className="py-4 px-2 space-y-1">
        <div className="px-3 py-2 flex items-center justify-between">
          {!collapsed && (
            <span className="text-[10px] font-mono uppercase tracking-widest text-platinum-500">
              Command Modules
            </span>
          )}
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1 rounded-md text-platinum-500 hover:text-white hover:bg-white/5 transition"
            title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          </button>
        </div>

        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                title={collapsed ? item.label : undefined}
                className={`w-full flex items-center ${
                  collapsed ? 'justify-center px-0' : 'justify-between px-3'
                } py-2.5 rounded-xl text-xs font-mono transition-all group ${
                  isActive
                    ? 'bg-white/10 text-white font-bold border border-white/20 shadow-glow-platinum'
                    : 'text-platinum-400 hover:text-white hover:bg-white/5 border border-transparent'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Icon className={`h-4 w-4 shrink-0 transition-colors ${
                    isActive ? 'text-white' : 'text-platinum-500 group-hover:text-platinum-300'
                  }`} />
                  {!collapsed && <span className="truncate">{item.label}</span>}
                </div>

                {!collapsed && (
                  <div>
                    {item.alert && (
                      <span className="h-2 w-2 rounded-full bg-status-critical inline-block shadow-glow-red animate-pulse" />
                    )}
                    {item.badge && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/10 text-platinum-300 border border-white/10">
                        {item.badge}
                      </span>
                    )}
                  </div>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Status Docket */}
      <div className="p-3 border-t border-white/5 font-mono text-[11px] text-platinum-500">
        {!collapsed ? (
          <div className="space-y-1">
            <div className="flex justify-between text-platinum-400">
              <span>Security Enclave:</span>
              <span className="text-white font-bold">SEC-ALPHA</span>
            </div>
            <div className="flex justify-between text-[10px]">
              <span>Consensus Engine:</span>
              <span className="text-status-anchored">SEPOLIA-SYNCED</span>
            </div>
          </div>
        ) : (
          <div className="text-center">
            <Shield className="h-4 w-4 text-platinum-400 mx-auto" />
          </div>
        )}
      </div>
    </aside>
  );
}
