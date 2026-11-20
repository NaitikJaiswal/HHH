import React, { useState } from 'react';
import { X, Lock, Mail, User, Shield, AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function AuthModal({ isOpen, onClose }) {
  const { login, register } = useAuth();
  const [isRegister, setIsRegister] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    role: 'security_analyst',
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      let res;
      if (isRegister) {
        res = await register(formData);
      } else {
        res = await login({ email: formData.email, password: formData.password });
      }

      if (res.success) {
        onClose();
      } else {
        setError(res.message || 'Authentication failed');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleQuickDemo = (role) => {
    setFormData({
      name: role === 'admin' ? 'Security Admin' : role === 'auditor' ? 'Compliance Auditor' : 'SOC Analyst',
      email: `${role}@securelog.io`,
      password: 'Password123!',
      role,
    });
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-cyber-card border border-cyber-border rounded-2xl p-6 shadow-2xl relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-cyber-surface transition"
        >
          <X className="h-5 w-5" />
        </button>

        <div className="flex items-center space-x-3 mb-6">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
            <Shield className="h-5 w-5 text-white" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white font-mono">
              {isRegister ? 'Register Security Operator' : 'Sign In to SecureLog'}
            </h2>
            <p className="text-xs text-slate-400">Authenticate with RBAC permissions</p>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center space-x-2 text-xs text-red-300">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {isRegister && (
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Full Name</label>
              <div className="relative">
                <User className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                <input
                  type="text"
                  required
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="e.g. Agent Smith"
                  className="w-full pl-9 pr-3 py-2 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-white focus:outline-none focus:border-cyan-400 font-mono"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1">Email Address</label>
            <div className="relative">
              <Mail className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
              <input
                type="email"
                required
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                placeholder="analyst@securelog.io"
                className="w-full pl-9 pr-3 py-2 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-white focus:outline-none focus:border-cyan-400 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1">Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
              <input
                type="password"
                required
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-3 py-2 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-white focus:outline-none focus:border-cyan-400 font-mono"
              />
            </div>
          </div>

          {isRegister && (
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Role Assignment</label>
              <select
                value={formData.role}
                onChange={(e) => setFormData({ ...formData, role: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-white focus:outline-none focus:border-cyan-400 font-mono"
              >
                <option value="security_analyst">Security Analyst (Hunt & Triage)</option>
                <option value="auditor">Auditor (Compliance & Proof Verifier)</option>
                <option value="admin">Administrator (Full Access)</option>
              </select>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-medium text-xs font-mono shadow-lg shadow-cyan-500/20 transition disabled:opacity-50"
          >
            {loading ? 'Authenticating...' : isRegister ? 'Create Account' : 'Authenticate Session'}
          </button>
        </form>

        {/* Quick Demo Logins */}
        <div className="mt-5 pt-4 border-t border-cyber-border">
          <p className="text-[11px] font-mono text-slate-400 mb-2 text-center">Quick Demo Personas:</p>
          <div className="grid grid-cols-3 gap-2">
            <button
              type="button"
              onClick={() => handleQuickDemo('security_analyst')}
              className="px-2 py-1.5 rounded-lg bg-cyber-bg hover:bg-cyber-surface border border-cyber-border text-[11px] font-mono text-cyan-300 transition"
            >
              Analyst
            </button>
            <button
              type="button"
              onClick={() => handleQuickDemo('auditor')}
              className="px-2 py-1.5 rounded-lg bg-cyber-bg hover:bg-cyber-surface border border-cyber-border text-[11px] font-mono text-emerald-300 transition"
            >
              Auditor
            </button>
            <button
              type="button"
              onClick={() => handleQuickDemo('admin')}
              className="px-2 py-1.5 rounded-lg bg-cyber-bg hover:bg-cyber-surface border border-cyber-border text-[11px] font-mono text-purple-300 transition"
            >
              Admin
            </button>
          </div>
        </div>

        <div className="mt-4 text-center">
          <button
            type="button"
            onClick={() => setIsRegister(!isRegister)}
            className="text-xs text-cyan-400 hover:underline font-mono"
          >
            {isRegister ? 'Already have an account? Sign in' : "Don't have an account? Register"}
          </button>
        </div>
      </div>
    </div>
  );
}
