import React, { useState } from 'react';
import { 
  Shield, Search, Bell, User, CheckCircle2, ChevronDown, 
  ExternalLink, Sliders, LogOut, Globe, Lock 
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function TopBar({ onOpenAuth, onSearch = () => {} }) {
  const { user, logout } = useAuth();
  const [searchValue, setSearchValue] = useState('');
  const [workspace, setWorkspace] = useState('Global Forensic Enclave // SEC-ALPHA');
  const [showWorkspaceMenu, setShowWorkspaceMenu] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);

  const notifications = [
    { id: 1, title: 'Tamper Alert: Config Hash Mismatch', time: '12m ago', type: 'critical' },
    { id: 2, title: 'Blockchain Anchor Confirmed #7219402', time: '25m ago', type: 'success' },
    { id: 3, title: 'Memory Dump EVD-9801 Sealed', time: '40m ago', type: 'info' },
  ];

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    onSearch(searchValue);
  };

  return (
    <header className="h-16 border-b border-white/5 bg-obsidian-950/90 backdrop-blur-xl px-6 flex items-center justify-between sticky top-0 z-30 font-sans">
      {/* Brand & Identity */}
      <div className="flex items-center space-x-6">
        <div className="flex items-center space-x-3">
          <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-white/20 via-platinum-300/10 to-transparent border border-white/20 flex items-center justify-center shadow-glow-platinum">
            <Shield className="h-5 w-5 text-white" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-extrabold tracking-widest text-lg text-white font-mono">HHH</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-white/10 text-platinum-200 font-mono border border-white/15">
                FORENSICS
              </span>
            </div>
            <p className="text-[9px] text-platinum-500 tracking-wider font-mono">HASH • HUNT • HARDEN</p>
          </div>
        </div>

        {/* Workspace Selector */}
        <div className="relative hidden md:block">
          <button
            onClick={() => setShowWorkspaceMenu(!showWorkspaceMenu)}
            className="flex items-center space-x-2 px-3 py-1.5 rounded-xl glass-panel-subtle text-xs font-mono text-platinum-300 hover:text-white transition"
          >
            <Lock className="h-3.5 w-3.5 text-platinum-400" />
            <span className="max-w-[200px] truncate">{workspace}</span>
            <ChevronDown className="h-3.5 w-3.5 text-platinum-500" />
          </button>

          {showWorkspaceMenu && (
            <div className="absolute left-0 mt-2 w-64 glass-dropdown rounded-xl p-2 z-50">
              <div className="text-[10px] font-mono text-platinum-500 px-2 py-1 uppercase">Select Enclave</div>
              {['Global Forensic Enclave // SEC-ALPHA', 'Regional Vault // EU-CENTRAL-1', 'Air-Gapped Sovereign Node // AP-01'].map((w) => (
                <button
                  key={w}
                  onClick={() => {
                    setWorkspace(w);
                    setShowWorkspaceMenu(false);
                  }}
                  className="w-full text-left px-2 py-1.5 rounded-lg text-xs font-mono text-platinum-300 hover:bg-white/10 hover:text-white transition"
                >
                  {w}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Global Search Bar */}
      <form onSubmit={handleSearchSubmit} className="hidden lg:flex items-center w-80 relative font-mono text-xs">
        <Search className="absolute left-3.5 h-3.5 w-3.5 text-platinum-500" />
        <input
          type="text"
          value={searchValue}
          onChange={(e) => setSearchValue(e.target.value)}
          placeholder="Search by Hash, Case, Evidence ID..."
          className="w-full pl-9 pr-3 py-1.5 rounded-xl bg-graphite-900/60 border border-white/5 text-platinum-200 placeholder-platinum-600 focus:outline-none focus:border-white/30 transition text-xs"
        />
      </form>

      {/* Right Telemetry & Profile */}
      <div className="flex items-center space-x-4">
        {/* Blockchain Status Badge */}
        <div className="hidden sm:flex items-center space-x-2 px-3 py-1.5 rounded-xl glass-panel-subtle text-xs font-mono">
          <Globe className="h-3.5 w-3.5 text-status-anchored animate-spin-slow" />
          <span className="text-platinum-400">Sepolia:</span>
          <span className="text-white font-bold">#7219402</span>
          <span className="h-1.5 w-1.5 rounded-full bg-status-anchored shadow-glow-chrome" />
        </div>

        {/* Notifications Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="p-2 rounded-xl glass-panel-subtle text-platinum-400 hover:text-white transition relative"
            title="Notifications"
          >
            <Bell className="h-4 w-4" />
            <span className="absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-status-critical shadow-glow-red" />
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 glass-dropdown rounded-2xl p-4 z-50 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-white/10 pb-2">
                <span className="font-bold text-white uppercase text-xs">Forensic Alerts</span>
                <span className="text-[10px] text-platinum-500">3 Unread</span>
              </div>
              <div className="space-y-2">
                {notifications.map((n) => (
                  <div key={n.id} className="p-2 rounded-lg bg-white/5 border border-white/5 space-y-0.5">
                    <div className="text-xs font-semibold text-platinum-200 truncate">{n.title}</div>
                    <div className="text-[10px] text-platinum-500">{n.time}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* User Profile */}
        {user ? (
          <div className="flex items-center space-x-3">
            <div className="text-right hidden sm:block font-mono">
              <div className="text-xs font-bold text-white">{user.name}</div>
              <div className="text-[10px] text-platinum-400 uppercase tracking-wider">{user.role}</div>
            </div>
            <div className="h-8 w-8 rounded-full bg-white/10 border border-white/20 flex items-center justify-center text-xs font-mono font-bold text-white">
              {user.name.charAt(0).toUpperCase()}
            </div>
            <button
              onClick={logout}
              title="Sign Out"
              className="p-2 rounded-xl glass-panel-subtle text-platinum-400 hover:text-status-critical transition"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        ) : (
          <button
            onClick={onOpenAuth}
            className="px-4 py-2 rounded-xl bg-white hover:bg-platinum-200 text-obsidian-950 font-bold text-xs font-mono shadow-glow-platinum transition"
          >
            Authenticate Enclave
          </button>
        )}
      </div>
    </header>
  );
}
