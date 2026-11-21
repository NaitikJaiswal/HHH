import React, { useState, useEffect } from 'react';
import { Shield, Activity, Lock, User, LogOut, LogIn, Bell, CheckCircle2, AlertTriangle, RefreshCw } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function Navbar({ onOpenAuth }) {
  const { user, logout, isBackendLive, checkServerStatus } = useAuth();
  const [currentTime, setCurrentTime] = useState(new Date().toUTCString());
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date().toUTCString()), 1000);
    return () => clearInterval(timer);
  }, []);

  const handleRefreshStatus = async () => {
    setRefreshing(true);
    await checkServerStatus();
    setTimeout(() => setRefreshing(false), 600);
  };

  const getRoleBadge = (role) => {
    switch (role) {
      case 'admin':
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/30">ADMIN</span>;
      case 'auditor':
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">AUDITOR</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">ANALYST</span>;
    }
  };

  return (
    <header className="h-16 border-b border-cyber-border bg-cyber-bg/95 backdrop-blur px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Brand & Project Identity */}
      <div className="flex items-center space-x-3">
        <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
          <Shield className="h-6 w-6 text-white" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-extrabold tracking-wider text-lg text-white font-mono">HHH</span>
            <span className="text-xs px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono border border-cyan-500/30">SECURELOG</span>
          </div>
          <p className="text-[10px] text-slate-400 tracking-wider">HASH • HUNT • HARDEN</p>
        </div>
      </div>

      {/* Center status info */}
      <div className="hidden md:flex items-center space-x-6 text-xs text-slate-400 font-mono">
        <div className="flex items-center space-x-2 bg-cyber-card px-3 py-1.5 rounded-lg border border-cyber-border">
          <span className="text-slate-500">UTC:</span>
          <span className="text-slate-200">{currentTime.slice(17, 25)}</span>
        </div>

        {/* Backend health status badge */}
        <button 
          onClick={handleRefreshStatus}
          title="Click to check backend health status"
          className="flex items-center space-x-2 bg-cyber-card px-3 py-1.5 rounded-lg border border-cyber-border hover:border-slate-600 transition"
        >
          <span className="relative flex h-2 w-2">
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${isBackendLive ? 'bg-emerald-400' : 'bg-amber-400'}`}></span>
            <span className={`relative inline-flex rounded-full h-2 w-2 ${isBackendLive ? 'bg-emerald-500' : 'bg-amber-500'}`}></span>
          </span>
          <span className="text-slate-300">
            API: {isBackendLive ? <span className="text-emerald-400 font-medium">LIVE (:5000)</span> : <span className="text-amber-400 font-medium">DEMO / STANDALONE</span>}
          </span>
          <RefreshCw className={`h-3 w-3 text-slate-400 ${refreshing ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* User profile & Actions */}
      <div className="flex items-center space-x-4">
        {user ? (
          <div className="flex items-center space-x-3">
            <div className="text-right hidden sm:block">
              <div className="text-xs font-semibold text-slate-200">{user.name}</div>
              <div className="flex items-center justify-end space-x-1 mt-0.5">
                {getRoleBadge(user.role)}
              </div>
            </div>
            <div className="h-9 w-9 rounded-full bg-cyber-card border border-cyber-border flex items-center justify-center text-cyan-400 font-mono text-sm font-bold">
              {user.name.charAt(0).toUpperCase()}
            </div>
            <button
              onClick={logout}
              title="Logout"
              className="p-2 rounded-lg bg-cyber-card text-slate-400 hover:text-red-400 hover:border-red-500/30 border border-cyber-border transition"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        ) : (
          <button
            onClick={onOpenAuth}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-medium text-xs shadow-lg shadow-cyan-500/20 transition"
          >
            <LogIn className="h-4 w-4" />
            <span>Sign In / Register</span>
          </button>
        )}
      </div>
    </header>
  );
}
