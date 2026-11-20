import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { 
  Maximize2, Minimize2, RotateCcw, Filter, Eye, Shield, 
  Layers, Link as LinkIcon, AlertTriangle, Cpu, Database 
} from 'lucide-react';

export default function ForensicConstellation3D({ 
  nodes = [], 
  links = [], 
  selectedNode = null, 
  onSelectNode = () => {},
  performanceMode = 'high' 
}) {
  const containerRef = useRef(null);
  const canvasRef = useRef(null);
  const [activeFilter, setActiveFilter] = useState('ALL');
  const [hoveredNode, setHoveredNode] = useState(null);
  const [is2DFallback, setIs2DFallback] = useState(false);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  // Filter definitions
  const categories = [
    { id: 'ALL', label: 'All Entities' },
    { id: 'EVIDENCE', label: 'Evidence', color: '#E2E8F0' },
    { id: 'HASH', label: 'Hashes', color: '#CBD5E1' },
    { id: 'MERKLE', label: 'Merkle Roots', color: '#94A3B8' },
    { id: 'BLOCKCHAIN', label: 'Ledger Tx', color: '#38BDF8' },
    { id: 'THREAT', label: 'Threats / Gaps', color: '#EF4444' },
    { id: 'INVESTIGATION', label: 'Cases', color: '#F8FAFC' },
  ];

  // Helper to determine node color based on state & category
  const getNodeColor = (node) => {
    if (node.status === 'FAILED') return 0xEF4444; // Controlled red
    if (node.status === 'SUSPICIOUS') return 0xF59E0B; // Muted amber
    if (node.status === 'ANCHORED') return 0x38BDF8; // Metallic icy cyan/silver ledger
    if (node.category === 'THREAT') return 0xF59E0B;
    if (node.status === 'PENDING') return 0x64748B;
    return 0xE2E8F0; // Platinum / white
  };

  const getNodeHexStr = (node) => {
    if (node.status === 'FAILED') return '#EF4444';
    if (node.status === 'SUSPICIOUS') return '#F59E0B';
    if (node.status === 'ANCHORED') return '#38BDF8';
    if (node.category === 'THREAT') return '#F59E0B';
    return '#E2E8F0';
  };

  useEffect(() => {
    if (is2DFallback || !canvasRef.current || !containerRef.current) return;

    let animationFrameId;
    const width = containerRef.current.clientWidth;
    const height = containerRef.current.clientHeight;

    // 1. Scene & Camera
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x06090F, 0.008);

    const camera = new THREE.PerspectiveCamera(50, width / height, 0.1, 1000);
    camera.position.set(0, 15, 80);

    // 2. WebGL Renderer with High Precision & Antialiasing
    const renderer = new THREE.WebGLRenderer({
      canvas: canvasRef.current,
      alpha: true,
      antialias: true,
      powerPreference: 'high-performance',
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // 3. Cinematic Lighting (Brushed silver highlights & soft shadows)
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.6);
    scene.add(ambientLight);

    const keyLight = new THREE.DirectionalLight(0xe2e8f0, 1.2);
    keyLight.position.set(40, 60, 50);
    scene.add(keyLight);

    const rimLight = new THREE.DirectionalLight(0x38bdf8, 0.8);
    rimLight.position.set(-50, -30, -40);
    scene.add(rimLight);

    // 4. Create 3D Nodes
    const nodeMeshes = new Map();
    const nodeGroup = new THREE.Group();
    scene.add(nodeGroup);

    nodes.forEach((node) => {
      let geometry;
      if (node.category === 'BLOCKCHAIN') {
        geometry = new THREE.BoxGeometry(3.5, 3.5, 3.5);
      } else if (node.category === 'MERKLE') {
        geometry = new THREE.OctahedronGeometry(3.2);
      } else if (node.category === 'THREAT') {
        geometry = new THREE.TetrahedronGeometry(3.4);
      } else if (node.category === 'INVESTIGATION') {
        geometry = new THREE.DodecahedronGeometry(3.2);
      } else {
        geometry = new THREE.SphereGeometry(2.5, 24, 24);
      }

      const color = getNodeColor(node);
      const isSelected = selectedNode?.id === node.id;

      const material = new THREE.MeshStandardMaterial({
        color: isSelected ? 0xffffff : color,
        metalness: 0.85,
        roughness: 0.2,
        emissive: color,
        emissiveIntensity: isSelected ? 0.7 : 0.25,
      });

      const mesh = new THREE.Mesh(geometry, material);
      mesh.position.set(node.x, node.y, node.z);
      mesh.userData = { node };
      nodeMeshes.set(node.id, mesh);
      nodeGroup.add(mesh);

      // Subtle Outer Halo Glow for Anchored & Critical Nodes
      if (node.status === 'ANCHORED' || node.status === 'FAILED' || isSelected) {
        const glowGeo = new THREE.SphereGeometry(3.8, 16, 16);
        const glowMat = new THREE.MeshBasicMaterial({
          color: color,
          transparent: true,
          opacity: 0.18,
          wireframe: true,
        });
        const glowMesh = new THREE.Mesh(glowGeo, glowMat);
        mesh.add(glowMesh);
      }
    });

    // 5. Connecting Lines & Traveling Light Pulses
    const lineGroup = new THREE.Group();
    scene.add(lineGroup);

    const pulses = [];
    const pulseGeo = new THREE.SphereGeometry(0.5, 8, 8);
    const pulseMat = new THREE.MeshBasicMaterial({ color: 0xffffff });

    links.forEach((link, idx) => {
      const fromNode = nodes.find((n) => n.id === link.from);
      const toNode = nodes.find((n) => n.id === link.to);

      if (fromNode && toNode) {
        const p1 = new THREE.Vector3(fromNode.x, fromNode.y, fromNode.z);
        const p2 = new THREE.Vector3(toNode.x, toNode.y, toNode.z);

        const isRelatedToSelected = 
          selectedNode && (selectedNode.id === fromNode.id || selectedNode.id === toNode.id);

        const lineGeo = new THREE.BufferGeometry().setFromPoints([p1, p2]);
        const lineMat = new THREE.LineBasicMaterial({
          color: isRelatedToSelected ? 0x38bdf8 : 0x263348,
          transparent: true,
          opacity: isRelatedToSelected ? 0.9 : 0.4,
          linewidth: isRelatedToSelected ? 2 : 1,
        });

        const line = new THREE.Line(lineGeo, lineMat);
        lineGroup.add(line);

        // Light pulse packet
        const pulseMesh = new THREE.Mesh(pulseGeo, pulseMat);
        pulseMesh.position.copy(p1);
        lineGroup.add(pulseMesh);
        pulses.push({
          mesh: pulseMesh,
          start: p1,
          end: p2,
          progress: (idx * 0.25) % 1,
          speed: 0.006 + (idx % 3) * 0.002,
        });
      }
    });

    // 6. Interactive Raycasting & Camera Controls
    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2(-999, -999);
    let targetRotationX = 0;
    let targetRotationY = 0;
    let isDragging = false;
    let prevMouseX = 0;
    let prevMouseY = 0;

    const handlePointerMove = (e) => {
      const rect = containerRef.current.getBoundingClientRect();
      pointer.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
      setMousePos({ x: e.clientX, y: e.clientY });

      if (isDragging) {
        const deltaX = e.clientX - prevMouseX;
        const deltaY = e.clientY - prevMouseY;
        targetRotationY += deltaX * 0.005;
        targetRotationX += deltaY * 0.005;
        prevMouseX = e.clientX;
        prevMouseY = e.clientY;
      }
    };

    const handlePointerDown = (e) => {
      isDragging = true;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    };

    const handlePointerUp = () => {
      isDragging = false;
    };

    const handleClick = () => {
      raycaster.setFromCamera(pointer, camera);
      const intersects = raycaster.intersectObjects(nodeGroup.children, true);
      if (intersects.length > 0) {
        let hit = intersects[0].object;
        while (hit && !hit.userData.node && hit.parent) {
          hit = hit.parent;
        }
        if (hit && hit.userData.node) {
          onSelectNode(hit.userData.node);
        }
      }
    };

    const container = containerRef.current;
    container.addEventListener('mousemove', handlePointerMove);
    container.addEventListener('mousedown', handlePointerDown);
    window.addEventListener('mouseup', handlePointerUp);
    container.addEventListener('click', handleClick);

    // 7. Animation Loop
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      // Smooth camera dampening / orbiting
      nodeGroup.rotation.y += (targetRotationY - nodeGroup.rotation.y) * 0.05;
      nodeGroup.rotation.x += (targetRotationX - nodeGroup.rotation.x) * 0.05;
      lineGroup.rotation.copy(nodeGroup.rotation);

      // Idle floating oscillation
      nodeMeshes.forEach((mesh) => {
        mesh.rotation.y += 0.008;
        mesh.rotation.x += 0.004;
      });

      // Animate Light Pulses
      pulses.forEach((pulse) => {
        pulse.progress += pulse.speed;
        if (pulse.progress > 1) pulse.progress = 0;
        pulse.mesh.position.lerpVectors(pulse.start, pulse.end, pulse.progress);
      });

      // Raycasting for Hover Tooltip
      raycaster.setFromCamera(pointer, camera);
      const intersects = raycaster.intersectObjects(nodeGroup.children, true);
      if (intersects.length > 0) {
        let hit = intersects[0].object;
        while (hit && !hit.userData.node && hit.parent) {
          hit = hit.parent;
        }
        if (hit && hit.userData.node) {
          setHoveredNode(hit.userData.node);
          document.body.style.cursor = 'pointer';
        }
      } else {
        setHoveredNode(null);
        document.body.style.cursor = 'default';
      }

      renderer.render(scene, camera);
    };

    animate();

    const handleResize = () => {
      if (!containerRef.current) return;
      const w = containerRef.current.clientWidth;
      const h = containerRef.current.clientHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animationFrameId);
      container.removeEventListener('mousemove', handlePointerMove);
      container.removeEventListener('mousedown', handlePointerDown);
      window.removeEventListener('mouseup', handlePointerUp);
      container.removeEventListener('click', handleClick);
      window.removeEventListener('resize', handleResize);
      renderer.dispose();
    };
  }, [nodes, links, selectedNode, is2DFallback]);

  // Filter visible nodes based on active tab
  const filteredNodes = activeFilter === 'ALL' 
    ? nodes 
    : nodes.filter((n) => n.category === activeFilter);

  return (
    <div 
      ref={containerRef} 
      className="relative w-full h-[580px] rounded-2xl overflow-hidden glass-panel border border-white/10 select-none group"
    >
      {/* 3D WebGL Canvas */}
      {!is2DFallback ? (
        <canvas ref={canvasRef} className="w-full h-full block cursor-grab active:cursor-grabbing" />
      ) : (
        /* 2D Schematic Fallback (for low-power or reduced motion) */
        <div className="w-full h-full p-8 overflow-auto flex flex-col justify-center items-center bg-obsidian-950">
          <p className="text-xs font-mono text-platinum-400 mb-6 uppercase tracking-wider">
            Schematic Forensic Topology (Reduced Motion Mode)
          </p>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4 max-w-3xl w-full">
            {filteredNodes.map((node) => (
              <div
                key={node.id}
                onClick={() => onSelectNode(node)}
                className={`p-3.5 rounded-xl border cursor-pointer transition ${
                  selectedNode?.id === node.id 
                    ? 'bg-graphite-800 border-white text-white shadow-glow-platinum' 
                    : 'bg-graphite-900/80 border-white/5 hover:border-white/20 text-platinum-300'
                }`}
              >
                <div className="flex items-center justify-between text-[10px] font-mono mb-1">
                  <span className="text-platinum-500">{node.category}</span>
                  <span className={`px-1.5 py-0.2 rounded font-semibold ${
                    node.status === 'FAILED' ? 'text-status-critical bg-red-500/10' :
                    node.status === 'SUSPICIOUS' ? 'text-status-warning bg-amber-500/10' :
                    'text-platinum-300 bg-white/10'
                  }`}>
                    {node.status}
                  </span>
                </div>
                <div className="text-xs font-semibold font-mono text-white truncate">{node.name}</div>
                <div className="text-[10px] text-platinum-500 font-mono mt-0.5 truncate">{node.id}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Floating HUD Top Overlay: Categories & Filters */}
      <div className="absolute top-4 left-4 right-4 flex flex-wrap items-center justify-between gap-3 pointer-events-none">
        <div className="flex items-center space-x-1 p-1 rounded-xl glass-dropdown pointer-events-auto">
          {categories.map((cat) => (
            <button
              key={cat.id}
              onClick={() => setActiveFilter(cat.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono transition flex items-center space-x-1.5 ${
                activeFilter === cat.id
                  ? 'bg-white/15 text-white font-semibold shadow-sm'
                  : 'text-platinum-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <span>{cat.label}</span>
            </button>
          ))}
        </div>

        {/* 3D Controls HUD */}
        <div className="flex items-center space-x-2 pointer-events-auto">
          <button
            onClick={() => setIs2DFallback(!is2DFallback)}
            title="Toggle 2D / 3D Mode"
            className="px-2.5 py-1.5 rounded-lg glass-dropdown text-[11px] font-mono text-platinum-300 hover:text-white flex items-center space-x-1.5 transition"
          >
            <Layers className="h-3.5 w-3.5" />
            <span>{is2DFallback ? 'Enable 3D' : '2D Schematic'}</span>
          </button>
        </div>
      </div>

      {/* Hover Floating Metadata Card */}
      {hoveredNode && !selectedNode && (
        <div 
          className="fixed pointer-events-none z-50 glass-dropdown p-3 rounded-xl border border-white/20 shadow-2xl space-y-1 animate-fadeIn font-mono text-xs max-w-xs"
          style={{ left: mousePos.x + 15, top: mousePos.y + 15 }}
        >
          <div className="flex items-center justify-between space-x-3">
            <span className="text-[10px] uppercase text-platinum-500">{hoveredNode.category}</span>
            <span 
              className="text-[10px] px-1.5 py-0.5 rounded font-semibold"
              style={{ color: getNodeHexStr(hoveredNode) }}
            >
              {hoveredNode.status}
            </span>
          </div>
          <div className="text-white font-bold truncate">{hoveredNode.name}</div>
          <div className="text-[10px] text-platinum-400 truncate">ID: {hoveredNode.id}</div>
          {hoveredNode.hash && (
            <div className="text-[9px] text-platinum-500 break-all pt-1 border-t border-white/10">
              SHA: {hoveredNode.hash.slice(0, 24)}...
            </div>
          )}
          <div className="text-[9px] text-status-anchored pt-0.5">Click to inspect forensic docket →</div>
        </div>
      )}

      {/* Bottom Telemetry Legend */}
      <div className="absolute bottom-4 left-4 right-4 flex items-center justify-between text-[11px] font-mono text-platinum-400 pointer-events-none">
        <div className="flex items-center space-x-4 glass-panel px-3 py-1.5 rounded-lg pointer-events-auto">
          <div className="flex items-center space-x-1.5">
            <span className="h-2 w-2 rounded-full bg-white shadow-glow-platinum"></span>
            <span>Verified</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2 w-2 rounded-full bg-status-anchored shadow-glow-chrome"></span>
            <span>Anchored</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2 w-2 rounded-full bg-status-warning shadow-glow-amber"></span>
            <span>Suspicious</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2 w-2 rounded-full bg-status-critical shadow-glow-red"></span>
            <span>Tampered</span>
          </div>
        </div>

        <div className="hidden sm:block text-slate-500 text-[10px]">
          DRAG TO ORBIT • SCROLL TO ZOOM • CLICK NODE TO INSPECT
        </div>
      </div>
    </div>
  );
}
