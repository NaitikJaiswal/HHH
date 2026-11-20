/**
 * Central Forensic Store for HHH (Hash. Hunt. Harden.)
 * Holds the unified multi-node forensic universe matching the exact node specifications:
 * - Geometric faceted polyhedrons (Dodecahedrons with flat shading)
 * - Identifiers: APP-2025-ER0-3398, APP-2025-SR0-2290, APP-2025-WR0-0512, etc.
 * - Subtitles: Location • Risk: XX
 * - Featured Hero Node: Emerald Green faceted polyhedron in core focus
 */

export const INITIAL_CONSTELLATION_NODES = [
  // 1. Featured Core Node (Vivid Emerald Green Faceted Polyhedron)
  {
    id: 'APP-2025-ER0-3398',
    code: 'APP-2025-ER0-3398',
    name: 'memdump_srv01.raw',
    label: 'RAM Dump SVR-01',
    location: 'Kolkata',
    riskScore: 20,
    category: 'EVIDENCE',
    isHero: true, // Vivid Emerald Green
    type: 'Memory Image',
    size: '4.29 GB',
    source: 'CORP-WIN-DC01',
    timestamp: '2026-11-20T14:12:00Z',
    hash: 'a57e3f89d0c2e9b114d7a12b6f10c376189bb51e44a6ec588e390c9b60d703fc',
    status: 'VERIFIED',
    caseId: 'CASE-2026-08',
    custody: ['Agent Smith (Acquisition)', 'Evidence Vault (Enclave Ingest)'],
    x: 2, y: -4, z: 10,
  },

  // 2. Front Left Node
  {
    id: 'APP-2025-SR0-2290',
    code: 'APP-2025-SR0-2290',
    name: 'auth_audit.log',
    label: 'Syslog Auth Stream',
    location: 'Coimbatore',
    riskScore: 15,
    category: 'EVIDENCE',
    type: 'Audit Log',
    size: '142 MB',
    source: 'prod-k8s-ingress-02',
    timestamp: '2026-11-20T14:28:30Z',
    hash: '7c891e4b31a0dc6790bcf42a9816e883dc14f09148d56b2cfd01e4a5b678c19a',
    status: 'VERIFIED',
    caseId: 'CASE-2026-08',
    custody: ['Linux Auditd Daemon', 'SecureLog Shipper'],
    x: -24, y: -6, z: 8,
  },

  // 3. Front Right Node
  {
    id: 'APP-2025-WR0-0512',
    code: 'APP-2025-WR0-0512',
    name: 'exfil_traffic.pcap',
    label: 'Network PCAP Capture',
    location: 'Veermata',
    riskScore: 30,
    category: 'EVIDENCE',
    type: 'Packet Capture',
    size: '890 MB',
    source: 'Core Switch SW-04',
    timestamp: '2026-11-20T15:02:11Z',
    hash: '22b7a0c918ef91024bdca601e309f874cbe90184b901aef09c123498bcf09e41',
    status: 'VERIFIED',
    caseId: 'CASE-2026-09',
    custody: ['Network TAP Probe', 'Evidence Enclave'],
    x: 24, y: -16, z: 6,
  },

  // 4. Upper Right Node
  {
    id: 'APP-2025-NR0-1104',
    code: 'APP-2025-NR0-1104',
    name: 'security_headers.conf',
    label: 'NGINX Config File',
    location: 'Delhi',
    riskScore: 50,
    category: 'EVIDENCE',
    type: 'Configuration',
    size: '12 KB',
    source: 'prod-k8s-ingress-02',
    timestamp: '2026-11-20T15:45:00Z',
    hash: 'e45b91a700192837461524354657687980a9b8c7d6e5f4019283746574635241',
    status: 'FAILED',
    anomaly: 'UNAUTHORIZED_ALTERATION',
    caseId: 'CASE-2026-09',
    custody: ['File Integrity Monitor'],
    x: 32, y: 16, z: -8,
  },

  // 5. Mid-Right Node
  {
    id: 'APP-2025-WR0-0491',
    code: 'APP-2025-WR0-0491',
    name: 'SHA-256 (EVD-9801)',
    label: 'SHA256:a57e3f...03fc',
    location: 'Veermata',
    riskScore: 52,
    category: 'HASH',
    hash: 'a57e3f89d0c2e9b114d7a12b6f10c376189bb51e44a6ec588e390c9b60d703fc',
    status: 'VERIFIED',
    algorithm: 'SHA-256',
    verifiedAt: '2026-11-20T14:12:05Z',
    targetEvidence: 'APP-2025-ER0-3398',
    x: 21, y: 7, z: -2,
  },

  // 6. Far-Right Node
  {
    id: 'APP-2025-NR0-1349',
    code: 'APP-2025-NR0-1349',
    name: 'SHA-256 (EVD-9802)',
    label: 'SHA256:7c891e...c19a',
    location: 'Delhi',
    riskScore: 35,
    category: 'HASH',
    hash: '7c891e4b31a0dc6790bcf42a9816e883dc14f09148d56b2cfd01e4a5b678c19a',
    status: 'VERIFIED',
    algorithm: 'SHA-256',
    verifiedAt: '2026-11-20T14:28:32Z',
    targetEvidence: 'APP-2025-SR0-2290',
    x: 32, y: -4, z: -10,
  },

  // 7. Upper Center Node
  {
    id: 'APP-2025-WR0-0677',
    code: 'APP-2025-WR0-0677',
    name: 'Merkle Root Batch #88',
    label: 'Root: 7e2c99b2...',
    location: 'Veermata',
    riskScore: 8,
    category: 'MERKLE',
    hash: '7e2c99b244670f5e714652434688d8b375b4aa23f81e33054e1abf192b0051e8',
    status: 'ANCHORED',
    batchSize: 400,
    depth: 4,
    x: 13, y: 13, z: -14,
  },

  // 8. Mid Center Node
  {
    id: 'APP-2025-NR0-1188',
    code: 'APP-2025-NR0-1188',
    name: 'Consortium Block #44190',
    label: 'Consortium Block #44190',
    location: 'Delhi',
    riskScore: 8,
    category: 'BLOCKCHAIN',
    txHash: '0x12b8901823094810293840192834019283401928340192834019283401928340',
    blockNumber: 44190,
    network: 'Hyperledger Besu Consortium',
    status: 'ANCHORED',
    x: -3, y: 9, z: -10,
  },

  // 9. Mid Left Center Node
  {
    id: 'APP-2025-SW0-4411',
    code: 'APP-2025-SW0-4411',
    name: 'Ethereum Sepolia Anchor',
    label: 'Block #7219402',
    location: 'Bengaluru',
    riskScore: 15,
    category: 'BLOCKCHAIN',
    txHash: '0x91f893e110cb84a9194e8234abcf90128475cdafe89104bce9013857102948ca',
    blockNumber: 7219402,
    network: 'Ethereum Sepolia (EVM)',
    status: 'ANCHORED',
    x: -14, y: 9, z: -8,
  },

  // 10. Top Center Node
  {
    id: 'APP-2025-SW0-4482',
    code: 'APP-2025-SW0-4482',
    name: 'Audit Sequence Gap #148920',
    label: 'Sequence Gap #148920',
    location: 'Bengaluru',
    riskScore: 0,
    category: 'THREAT',
    severity: 'SUSPICIOUS',
    technique: 'T1070.006 - Indicator Removal',
    status: 'SUSPICIOUS',
    x: 4, y: 20, z: -18,
  },

  // 11. Upper Left Node
  {
    id: 'APP-2025-SR0-2415',
    code: 'APP-2025-SR0-2415',
    name: 'Tamper Alert: Config Hash Mismatch',
    label: 'Integrity Violation',
    location: 'Coimbatore',
    riskScore: 15,
    category: 'THREAT',
    severity: 'CRITICAL',
    technique: 'T1562.001 - Impair Defenses',
    status: 'FAILED',
    x: -22, y: 17, z: -16,
  },

  // 12. Mid Left Node
  {
    id: 'APP-2025-ER0-3341',
    code: 'APP-2025-ER0-3341',
    name: 'Operation DarkVessel',
    label: 'Case #2026-08',
    location: 'Kolkata',
    riskScore: 15,
    category: 'INVESTIGATION',
    priority: 'P1-CRITICAL',
    status: 'ACTIVE',
    x: -34, y: 3, z: -4,
  },

  // 13. Lower Left Node
  {
    id: 'APP-2025-SR0-2201',
    code: 'APP-2025-SR0-2201',
    name: 'Incident CobaltBreeze',
    label: 'Case #2026-09',
    location: 'Coimbatore',
    riskScore: 15,
    category: 'INVESTIGATION',
    priority: 'P2-HIGH',
    status: 'ACTIVE',
    x: -28, y: -16, z: 2,
  },
];

export const INITIAL_CONSTELLATION_LINKS = [
  { from: 'APP-2025-ER0-3398', to: 'APP-2025-SR0-2290', type: 'EVIDENCE_LINK' },
  { from: 'APP-2025-ER0-3398', to: 'APP-2025-WR0-0512', type: 'EVIDENCE_LINK' },
  { from: 'APP-2025-ER0-3398', to: 'APP-2025-WR0-0491', type: 'HASH_LINK' },
  { from: 'APP-2025-SR0-2290', to: 'APP-2025-SW0-4411', type: 'CONSORTIUM_LINK' },
  { from: 'APP-2025-WR0-0491', to: 'APP-2025-WR0-0677', type: 'MERKLE_LINK' },
  { from: 'APP-2025-WR0-0512', to: 'APP-2025-NR0-1349', type: 'HASH_LINK' },
  { from: 'APP-2025-NR0-1104', to: 'APP-2025-WR0-0491', type: 'INVESTIGATION_LINK' },
  { from: 'APP-2025-SW0-4482', to: 'APP-2025-SW0-4411', type: 'THREAT_LINK' },
  { from: 'APP-2025-SR0-2415', to: 'APP-2025-ER0-3341', type: 'THREAT_LINK' },
  { from: 'APP-2025-ER0-3341', to: 'APP-2025-SR0-2201', type: 'CASE_LINK' },
  { from: 'APP-2025-SR0-2201', to: 'APP-2025-SR0-2290', type: 'EVIDENCE_LINK' },
];

export const INITIAL_AUDIT_TRAIL = [
  {
    id: 'AUD-001',
    actor: 'Agent A. Vance',
    action: 'EVIDENCE_INGESTED',
    resource: 'APP-2025-ER0-3398 (memdump_srv01.raw)',
    timestamp: '2026-11-20T14:12:00Z',
    prevHash: '0000000000000000000000000000000000000000000000000000000000000000',
    recordHash: '8b9c018239012384901283409128304918230948120938410293841029384102',
    verified: true,
  },
  {
    id: 'AUD-002',
    actor: 'Cryptographic HSM Engine',
    action: 'HASH_GENERATED_SHA256',
    resource: 'APP-2025-WR0-0491 (a57e3f89...)',
    timestamp: '2026-11-20T14:12:05Z',
    prevHash: '8b9c018239012384901283409128304918230948120938410293841029384102',
    recordHash: 'f42a9816e883dc14f09148d56b2cfd01e4a5b678c19a7c891e4b31a0dc6790bc',
    verified: true,
  },
  {
    id: 'AUD-003',
    actor: 'Merkle Batcher Service',
    action: 'MERKLE_TREE_SEALED',
    resource: 'APP-2025-WR0-0677 (Root: 7e2c99b2...)',
    timestamp: '2026-11-20T15:05:00Z',
    prevHash: 'f42a9816e883dc14f09148d56b2cfd01e4a5b678c19a7c891e4b31a0dc6790bc',
    recordHash: '33a9018409123847102938471029384710293847102938471029384710293847',
    verified: true,
  },
  {
    id: 'AUD-004',
    actor: 'Ethereum Anchor Relay',
    action: 'BLOCKCHAIN_TRANSACTION_CONFIRMED',
    resource: 'APP-2025-SW0-4411 (Sepolia Block #7219402)',
    timestamp: '2026-11-20T15:10:00Z',
    prevHash: '33a9018409123847102938471029384710293847102938471029384710293847',
    recordHash: '91f893e110cb84a9194e8234abcf90128475cdafe89104bce9013857102948ca',
    verified: true,
  },
  {
    id: 'AUD-005',
    actor: 'Integrity Sentinel',
    action: 'TAMPER_ALERT_TRIGGERED',
    resource: 'APP-2025-SR0-2415 (Config Hash Mismatch)',
    timestamp: '2026-11-20T15:45:10Z',
    prevHash: '91f893e110cb84a9194e8234abcf90128475cdafe89104bce9013857102948ca',
    recordHash: 'ee48291039481029384019283401928340192834019283401928340192834019',
    verified: true,
  },
];
