import React, { useState } from 'react';
import TopBar from './components/TopBar';
import NavigationRail from './components/NavigationRail';
import NodeDetailPanel from './components/NodeDetailPanel';
import AuthModal from './components/AuthModal';

// 10 Command Modules
import OverviewDashboard from './pages/OverviewDashboard';
import EvidenceVault from './pages/EvidenceVault';
import HashVerification from './pages/HashVerification';
import MerkleExplorer from './pages/MerkleExplorer';
import BlockchainLedger from './pages/BlockchainLedger';
import ThreatHunting from './pages/ThreatHunting';
import Investigations from './pages/Investigations';
import AuditTrail from './pages/AuditTrail';
import Reports from './pages/Reports';
import Settings from './pages/Settings';

// Forensic Store Data
import { 
  FORENSIC_NODES, 
  FORENSIC_LINKS 
} from './services/forensicStore';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [nodes, setNodes] = useState(FORENSIC_NODES);
  const [links, setLinks] = useState(FORENSIC_LINKS);
  const [selectedNode, setSelectedNode] = useState(null);
  const [isAuthOpen, setIsAuthOpen] = useState(false);

  // Ingest new evidence dynamically & add to 3D constellation
  const handleAddEvidence = (newEvidence) => {
    setNodes((prev) => [newEvidence, ...prev]);

    // Create automatic hash node for the new evidence
    const hashNode = {
      id: `HSH-${newEvidence.id}`,
      name: `SHA-256 (${newEvidence.name})`,
      label: `SHA256:${newEvidence.hash.slice(0, 8)}...`,
      category: 'HASH',
      algorithm: 'SHA-256',
      hash: newEvidence.hash,
      status: 'VERIFIED',
      verifiedAt: new Date().toISOString(),
      targetEvidence: newEvidence.id,
      x: newEvidence.x + (Math.random() - 0.5) * 12,
      y: newEvidence.y + (Math.random() - 0.5) * 12,
      z: newEvidence.z + (Math.random() - 0.5) * 12,
    };

    setNodes((prev) => [hashNode, ...prev]);

    // Link evidence to its hash and to core
    const newLinks = [
      { from: newEvidence.id, to: 'CORE', type: 'RADIAL' },
      { from: newEvidence.id, to: hashNode.id, type: 'HASH' },
    ];
    setLinks((prev) => [...prev, ...newLinks]);
  };

  const renderActiveTab = () => {
    switch (activeTab) {
      case 'overview':
        return (
          <OverviewDashboard
            nodes={nodes}
            links={links}
            selectedNode={selectedNode}
            onSelectNode={setSelectedNode}
            setActiveTab={setActiveTab}
          />
        );
      case 'vault':
        return (
          <EvidenceVault
            nodes={nodes}
            onAddEvidence={handleAddEvidence}
            onSelectNode={setSelectedNode}
          />
        );
      case 'hash':
        return <HashVerification nodes={nodes} />;
      case 'merkle':
        return <MerkleExplorer nodes={nodes} />;
      case 'ledger':
        return <BlockchainLedger nodes={nodes} />;
      case 'threats':
        return (
          <ThreatHunting
            nodes={nodes}
            onSelectNode={setSelectedNode}
            setActiveTab={setActiveTab}
          />
        );
      case 'investigations':
        return (
          <Investigations
            nodes={nodes}
            onSelectNode={setSelectedNode}
            setActiveTab={setActiveTab}
          />
        );
      case 'audit':
        return <AuditTrail nodes={nodes} />;
      case 'reports':
        return <Reports nodes={nodes} />;
      case 'settings':
        return <Settings />;
      default:
        return (
          <OverviewDashboard
            nodes={nodes}
            links={links}
            selectedNode={selectedNode}
            onSelectNode={setSelectedNode}
            setActiveTab={setActiveTab}
          />
        );
    }
  };

  return (
    <div className="min-h-screen bg-obsidian-950 flex flex-col text-platinum-300 font-sans selection:bg-white/20 selection:text-white">
      {/* Top Navigation */}
      <TopBar onOpenAuth={() => setIsAuthOpen(true)} />

      {/* Main Command Center Body */}
      <div className="flex flex-1">
        {/* Slim Collapsible Navigation Rail */}
        <NavigationRail activeTab={activeTab} setActiveTab={setActiveTab} />

        {/* Dynamic Workspace Canvas */}
        <main className="flex-1 p-6 max-w-7xl mx-auto w-full overflow-x-hidden">
          {renderActiveTab()}
        </main>
      </div>

      {/* Contextual 3D Node Detail Panel */}
      <NodeDetailPanel
        node={selectedNode}
        onClose={() => setSelectedNode(null)}
        onNavigateTab={setActiveTab}
      />

      {/* Auth Modal */}
      <AuthModal isOpen={isAuthOpen} onClose={() => setIsAuthOpen(false)} />
    </div>
  );
}
