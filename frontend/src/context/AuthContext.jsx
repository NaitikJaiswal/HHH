import React, { createContext, useContext, useState, useEffect } from 'react';
import { authApi } from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem('securelog_user');
      return saved && saved !== 'undefined' ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });
  const [token, setToken] = useState(() => localStorage.getItem('securelog_token') || null);
  const [isBackendLive, setIsBackendLive] = useState(false);
  const [loading, setLoading] = useState(true);

  // Check backend server status
  const checkServerStatus = async () => {
    const health = await authApi.checkHealth();
    setIsBackendLive(health.isLive);
  };

  useEffect(() => {
    checkServerStatus();
    const interval = setInterval(checkServerStatus, 15000);
    setLoading(false);
    return () => clearInterval(interval);
  }, []);

  const login = async (credentials) => {
    const result = await authApi.login(credentials);
    if (result.success && result.data) {
      setUser(result.data.user);
      setToken(result.data.token);
      localStorage.setItem('securelog_user', JSON.stringify(result.data.user));
      localStorage.setItem('securelog_token', result.data.token);
      return { success: true };
    }
    return { success: false, message: result.message };
  };

  const register = async (userData) => {
    const result = await authApi.register(userData);
    if (result.success && result.data) {
      setUser(result.data.user);
      setToken(result.data.token);
      localStorage.setItem('securelog_user', JSON.stringify(result.data.user));
      localStorage.setItem('securelog_token', result.data.token);
      return { success: true };
    }
    return { success: false, message: result.message };
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('securelog_user');
    localStorage.removeItem('securelog_token');
  };

  return (
    <AuthContext.Provider value={{ user, token, isBackendLive, login, register, logout, loading, checkServerStatus }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
