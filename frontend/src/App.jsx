import React, { useState } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import AuthModal from './components/AuthModal';
import LogDetailModal from './components/LogDetailModal';

// Pages
import Dashboard from './pages/Dashboard';
import LogsExplorer from './pages/LogsExplorer';
import IntegrityVerifier from './pages/IntegrityVerifier';
import AgentMonitor from './pages/AgentMonitor';
import AuditCompliance from './pages/AuditCompliance';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isAuthOpen, setIsAuthOpen] = useState(false);
  const [selectedLog, setSelectedLog] = useState(null);

  const renderActiveTab = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard setActiveTab={setActiveTab} onSelectLog={setSelectedLog} />;
      case 'logs':
        return <LogsExplorer onSelectLog={setSelectedLog} />;
      case 'integrity':
        return <IntegrityVerifier />;
      case 'agents':
        return <AgentMonitor />;
      case 'audit':
        return <AuditCompliance />;
      default:
        return <Dashboard setActiveTab={setActiveTab} onSelectLog={setSelectedLog} />;
    }
  };

  return (
    <div className="min-h-screen bg-[#070B14] flex flex-col text-slate-100">
      {/* Top Navbar */}
      <Navbar onOpenAuth={() => setIsAuthOpen(true)} />

      {/* Main Body */}
      <div className="flex flex-1">
        {/* Navigation Sidebar */}
        <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

        {/* Content Area */}
        <main className="flex-1 p-6 max-w-7xl mx-auto w-full overflow-x-hidden">
          {renderActiveTab()}
        </main>
      </div>

      {/* Auth Modal */}
      <AuthModal isOpen={isAuthOpen} onClose={() => setIsAuthOpen(false)} />

      {/* Log Detail Inspector Modal */}
      <LogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />
    </div>
  );
}
