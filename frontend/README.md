# HHH (Hash. Hunt. Harden.) — 3D Forensics Platform

**Category:** Blockchain-Powered Digital Forensics & Cybersecurity Command Platform  
**Branch:** `feature-frontend`  
**Lead Contributor:** Member 2 (Frontend & 3D Spatial Architecture)

---

## 🏛️ Design System & Monochromatic Aesthetic
- **Primary Background:** Obsidian Black (`#030508`, `#06090F`)
- **Secondary Background:** Graphite (`#141824`, `#1C2232`)
- **Main Surfaces:** Smoked Glass (`rgba(14, 19, 31, 0.75)` with 16px blur)
- **Primary Accents:** Platinum & Brushed Silver (`#E2E8F0`, `#CBD5E1`)
- **Highlights:** Liquid Chrome & Soft White Illumination
- **Warning Indicator:** Muted Amber (`#F59E0B`)
- **Critical Violation:** Controlled Red (`#EF4444`)
- **Blockchain Anchored:** Metallic Ice Cyan/Silver (`#38BDF8`)

---

## 🌐 Central 3D Experience — Forensic Constellation
The interactive 3D environment represents the entire HHH ecosystem as a spatial network of interconnected forensic objects rendered in Three.js WebGL:
1. **Evidence Nodes:** Raw memory images, packet captures, and audit logs floating in 3D coordinate space.
2. **Hash Nodes:** Real SHA-256 cryptographic digests generated in-browser with the Web Crypto API.
3. **Merkle Nodes:** Hierarchical hash relationships and immutable Merkle tree roots.
4. **Blockchain Nodes:** Ethereum Sepolia EVM block anchors and transaction receipts.
5. **Threat Nodes:** Suspicious events, sequence gaps (#148920), and tampering alerts.
6. **Investigation Nodes:** Case dossiers (Operation DarkVessel, Incident CobaltBreeze).

### 3D Spatial Controls:
- **Orbit & Pan:** Drag with mouse to orbit dynamically around the constellation.
- **Traveling Light Pulses:** Visual evidence packets traveling between connected nodes.
- **Hover Raycaster:** Real-time metadata tooltips on pointer movement.
- **Contextual Inspector:** Click any node to open the Forensic Detail Panel.
- **2D Schematic Fallback:** One-click toggle for low-power devices and reduced motion preferences.

---

## 🎛️ 10 Required Command Modules
1. **Overview Dashboard (`OverviewDashboard.jsx`)**: Central 3D Forensic Constellation with operational telemetry cards and real-time cryptographic activity stream.
2. **Evidence Vault (`EvidenceVault.jsx`)**: Ingest local files with live in-browser SHA-256 computation, filter by type, and inspect custody manifests.
3. **Hash Verification Studio (`HashVerification.jsx`)**: Real-time cryptographic hasher with character-by-character visual diffing for tamper detection.
4. **Merkle Tree Explorer (`MerkleExplorer.jsx`)**: Hierarchical tree visualization with leaf-to-root proof path verification traces.
5. **Blockchain Ledger (`BlockchainLedger.jsx`)**: Ethereum Sepolia and consortium ledger explorer with on-chain receipts and gas metrics.
6. **Threat Hunting (`ThreatHunting.jsx`)**: Forensic threat matrix correlated with MITRE ATT&CK techniques (`T1562.001`, `T1070.006`).
7. **Investigations (`Investigations.jsx`)**: Case docket workspaces, evidence collections, analyst assignments, and chain-of-custody tracking.
8. **Audit Trail (`AuditTrail.jsx`)**: Append-only cryptographic hash chain with full immutability verification.
9. **Reports & Attestation (`Reports.jsx`)**: Formal court-ready forensic proof packages and JSON attestation exports.
10. **Settings (`Settings.jsx`)**: Enclave hardware key configuration, RPC endpoints, and 3D graphics fidelity tuning.

---

## 🚀 Running Locally

```bash
cd frontend
npm run dev
```

Server starts at `http://localhost:5173`.
