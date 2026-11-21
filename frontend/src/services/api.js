// API Service Layer for HHH SecureLog Frontend
// Direct backend integration for operational telemetry, logs, integrity audits, and Quai anchoring.

const API_BASE = '/api';

/**
 * Returns authorization headers with stored JWT token if present.
 */
function getAuthHeaders(tokenOverride = null) {
  const token = tokenOverride || localStorage.getItem('securelog_token');
  const headers = { 'Content-Type': 'application/json' };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

// ── 1. Authentication API ───────────────────────────────────────────────────
export const authApi = {
  async register({ name, email, password, role }) {
    const response = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, password, role }),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.message || 'Registration failed');
    }
    return data;
  },

  async login({ email, password }) {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.message || 'Login failed');
    }
    return data;
  },

  async getMe(token) {
    try {
      const response = await fetch(`${API_BASE}/auth/me`, {
        headers: getAuthHeaders(token),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message);
      return data;
    } catch {
      return null;
    }
  },

  async checkHealth() {
    try {
      const res = await fetch('/health', { signal: AbortSignal.timeout(2500) });
      if (res.ok) {
        const json = await res.json();
        return { isLive: true, ...json };
      }
      return { isLive: false };
    } catch {
      return { isLive: false };
    }
  },
};

// ── 2. Dashboard API ────────────────────────────────────────────────────────
export const dashboardApi = {
  async getStats() {
    const res = await fetch(`${API_BASE}/dashboard/stats`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch dashboard stats');
    return data.data;
  },

  async getActivity(limit = 15) {
    const res = await fetch(`${API_BASE}/dashboard/activity?limit=${limit}`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch activity feed');
    return data.data;
  },
};

// ── 3. Logs API ─────────────────────────────────────────────────────────────
export const logsApi = {
  async getLogs(params = {}) {
    const query = new URLSearchParams(params).toString();
    const res = await fetch(`${API_BASE}/logs${query ? `?${query}` : ''}`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch logs');
    return data.data;
  },

  async getLogById(id) {
    const res = await fetch(`${API_BASE}/logs/${id}`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch log details');
    return data.data;
  },

  async getStats() {
    const res = await fetch(`${API_BASE}/logs/stats`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch log stats');
    return data.data;
  },

  async ingestLog(payload) {
    const res = await fetch(`${API_BASE}/logs`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to ingest log');
    return data.data;
  },
};

// ── 4. Integrity & Checkpoints API ──────────────────────────────────────────
export const integrityApi = {
  async getStatus() {
    const res = await fetch(`${API_BASE}/integrity/status`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch integrity status');
    return data.data;
  },

  async verifyChain(sourceId) {
    const res = await fetch(`${API_BASE}/integrity/verify`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(sourceId ? { sourceId } : {}),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Integrity audit failed');
    return data.data;
  },

  async getCheckpoints(params = {}) {
    const query = new URLSearchParams(params).toString();
    const res = await fetch(`${API_BASE}/integrity/checkpoints${query ? `?${query}` : ''}`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch checkpoints');
    return data.data;
  },

  async createCheckpoint(sourceId) {
    const res = await fetch(`${API_BASE}/integrity/checkpoints`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ sourceId }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to create checkpoint');
    return data.data;
  },

  async getAlerts() {
    const res = await fetch(`${API_BASE}/integrity/alerts`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch alerts');
    return data.data;
  },
};

// ── 5. Edge Sources / Collectors API ────────────────────────────────────────
export const sourcesApi = {
  async getSources() {
    const res = await fetch(`${API_BASE}/sources`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch sources');
    return data.data;
  },

  async createSource(sourceData) {
    const res = await fetch(`${API_BASE}/sources`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(sourceData),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to create source');
    return data.data;
  },

  async heartbeat(payload) {
    const res = await fetch(`${API_BASE}/sources/heartbeat`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to record heartbeat');
    return data.data;
  },
};

// ── 6. Incident Management API ──────────────────────────────────────────────
export const incidentsApi = {
  async getIncidents(params = {}) {
    const query = new URLSearchParams(params).toString();
    const res = await fetch(`${API_BASE}/incidents${query ? `?${query}` : ''}`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch incidents');
    return data.data;
  },

  async getIncidentById(id) {
    const res = await fetch(`${API_BASE}/incidents/${id}`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch incident details');
    return data.data;
  },

  async updateStatus(id, status) {
    const res = await fetch(`${API_BASE}/incidents/${id}/status`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ status }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to update incident status');
    return data.data;
  },
};

// ── 7. Forward-Secure Cryptography (FSS) API ────────────────────────────────
export const fssApi = {
  async getStatus() {
    const res = await fetch(`${API_BASE}/integrity/fss/status`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch FSS status');
    return data.data;
  },

  async evolveEpoch() {
    const res = await fetch(`${API_BASE}/integrity/fss/evolve`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to evolve FSS epoch');
    return data.data;
  },

  async emergencyRevoke(payload = {}) {
    const res = await fetch(`${API_BASE}/integrity/fss/revoke`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Emergency revocation failed');
    return data.data;
  },
};

// ── 8. Quai Blockchain Anchoring API ────────────────────────────────────────
export const blockchainApi = {
  async getStatus() {
    const res = await fetch(`${API_BASE}/integrity/blockchain/status`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch blockchain status');
    return data.data;
  },
};

// ── 9. Evidence Engine API ──────────────────────────────────────────────────
export const evidenceApi = {
  async getEvidenceList() {
    const res = await fetch(`${API_BASE}/evidence`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch evidence list');
    return data.data;
  },

  async packageEvidence(payload = {}) {
    const res = await fetch(`${API_BASE}/evidence/package`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to package evidence');
    return data.data;
  },

  async verifyEvidence(bundle) {
    const res = await fetch(`${API_BASE}/evidence/verify`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(bundle),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to verify evidence bundle');
    return data.data;
  },
};

// ── 10. Forensic Engine API ─────────────────────────────────────────────────
export const forensicsApi = {
  async getInvestigations() {
    const res = await fetch(`${API_BASE}/forensics/investigations`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch investigations');
    return data.data;
  },

  async createInvestigation(payload) {
    const res = await fetch(`${API_BASE}/forensics/investigations`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to create investigation');
    return data.data;
  },

  async getReports() {
    const res = await fetch(`${API_BASE}/forensics/reports`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch forensic reports');
    return data.data;
  },

  async generateReport(payload) {
    const res = await fetch(`${API_BASE}/forensics/report`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to generate forensic report');
    return data.data;
  },

  async getTimeline(params = {}) {
    const qs = new URLSearchParams(params).toString();
    const res = await fetch(`${API_BASE}/forensics/timeline${qs ? `?${qs}` : ''}`, {
      headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to fetch forensic timeline');
    return data.data;
  },
};

export default {
  authApi,
  dashboardApi,
  logsApi,
  integrityApi,
  sourcesApi,
  incidentsApi,
  fssApi,
  blockchainApi,
  evidenceApi,
  forensicsApi,
};
