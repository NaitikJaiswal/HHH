import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { Layers } from 'lucide-react';

export default function ForensicConstellation3D({ 
  nodes = [], 
  links = [], 
  selectedNode = null, 
  onSelectNode = () => {},
}) {
  const containerRef = useRef(null);
  const canvasRef = useRef(null);
  const [activeFilter, setActiveFilter] = useState('ALL');
  const [is2DFallback, setIs2DFallback] = useState(false);
  const [screenNodes, setScreenNodes] = useState([]);

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

  useEffect(() => {
    if (is2DFallback || !canvasRef.current || !containerRef.current) return;

    let animationFrameId;
    const container = containerRef.current;
    const width = container.clientWidth;
    const height = container.clientHeight;

    // 1. Scene & Camera setup
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x06090F, 0.007);

    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 5, 75);

    // 2. High-Precision WebGL Renderer
    const renderer = new THREE.WebGLRenderer({
      canvas: canvasRef.current,
      alpha: true,
      antialias: true,
      powerPreference: 'high-performance',
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // 3. Cinematic Studio Lighting for Faceted Polyhedrons
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
    scene.add(ambientLight);

    const mainLight = new THREE.DirectionalLight(0xffffff, 1.3);
    mainLight.position.set(40, 50, 45);
    scene.add(mainLight);

    const rimLight = new THREE.DirectionalLight(0x718096, 0.7);
    rimLight.position.set(-45, -30, -35);
    scene.add(rimLight);

    const topLight = new THREE.DirectionalLight(0xa0aec0, 0.5);
    topLight.position.set(0, 60, 0);
    scene.add(topLight);

    // 4. Subtle Background Starfield / Dust
    const starsGeo = new THREE.BufferGeometry();
    const starCount = 180;
    const starCoords = new Float32Array(starCount * 3);
    for (let i = 0; i < starCount * 3; i += 3) {
      starCoords[i] = (Math.random() - 0.5) * 220;
      starCoords[i + 1] = (Math.random() - 0.5) * 160;
      starCoords[i + 2] = (Math.random() - 0.5) * 160;
    }
    starsGeo.setAttribute('position', new THREE.BufferAttribute(starCoords, 3));
    const starsMat = new THREE.PointsMaterial({
      color: 0x718096,
      size: 1.2,
      transparent: true,
      opacity: 0.45,
    });
    const stars = new THREE.Points(starsGeo, starsMat);
    scene.add(stars);

    // 5. Central Wireframe Octahedron Cage & Orbit Loops
    const cageGeo = new THREE.OctahedronGeometry(12, 0);
    const cageMat = new THREE.MeshBasicMaterial({
      color: 0x242d3d,
      wireframe: true,
      transparent: true,
      opacity: 0.5,
    });
    const centralCage = new THREE.Mesh(cageGeo, cageMat);
    scene.add(centralCage);

    // Orbit Ring 1
    const curve1 = new THREE.EllipseCurve(0, 0, 24, 15, 0, 2 * Math.PI, false, 0);
    const ringGeo1 = new THREE.BufferGeometry().setFromPoints(curve1.getPoints(64));
    const ringMat1 = new THREE.LineBasicMaterial({ color: 0x2d3748, transparent: true, opacity: 0.35 });
    const ring1 = new THREE.Line(ringGeo1, ringMat1);
    ring1.rotation.x = Math.PI / 2.5;
    scene.add(ring1);

    // Orbit Ring 2
    const curve2 = new THREE.EllipseCurve(0, 0, 28, 18, 0, 2 * Math.PI, false, 0);
    const ringGeo2 = new THREE.BufferGeometry().setFromPoints(curve2.getPoints(64));
    const ring2 = new THREE.Line(ringGeo2, ringMat1);
    ring2.rotation.x = -Math.PI / 3;
    ring2.rotation.y = Math.PI / 6;
    scene.add(ring2);

    // 6. Create Faceted Dodecahedron Polyhedral Meshes
    const nodeMeshes = new Map();
    const nodeGroup = new THREE.Group();
    scene.add(nodeGroup);

    nodes.forEach((node) => {
      const isHero = node.isHero || node.id === 'APP-2025-ER0-3398';
      const isSelected = selectedNode?.id === node.id;

      // Faceted Dodecahedron with detail 0 for crisp polygonal facets
      const radius = isHero ? 4.8 : 3.4;
      const geometry = new THREE.DodecahedronGeometry(radius, 0);

      // Material: flatShading: true generates the exact low-poly crystal facet lighting
      let nodeColor;
      let emissiveColor;

      if (isHero) {
        nodeColor = 0x0fa968; // Vivid emerald green
        emissiveColor = 0x03442a;
      } else if (node.status === 'FAILED') {
        nodeColor = 0xc53030; // Red
        emissiveColor = 0x4a0e0e;
      } else if (node.status === 'SUSPICIOUS') {
        nodeColor = 0xdd6b20; // Amber
        emissiveColor = 0x4a2408;
      } else {
        nodeColor = 0x8c96a7; // Matte stone graphite / silver
        emissiveColor = 0x141a24;
      }

      const material = new THREE.MeshStandardMaterial({
        color: isSelected ? 0xffffff : nodeColor,
        roughness: 0.36,
        metalness: 0.3,
        flatShading: true,
        emissive: isSelected ? 0x334155 : emissiveColor,
        emissiveIntensity: isSelected ? 0.8 : 0.3,
      });

      const mesh = new THREE.Mesh(geometry, material);
      mesh.position.set(node.x, node.y, node.z);
      mesh.userData = { node };

      // Subtle slight rotation for varied facet angles
      mesh.rotation.x = Math.random() * Math.PI;
      mesh.rotation.y = Math.random() * Math.PI;

      nodeMeshes.set(node.id, mesh);
      nodeGroup.add(mesh);
    });

    // 7. Connecting Lines Between Polyhedral Nodes
    const lineGroup = new THREE.Group();
    scene.add(lineGroup);

    links.forEach((link) => {
      const fromNode = nodes.find((n) => n.id === link.from);
      const toNode = nodes.find((n) => n.id === link.to);

      if (fromNode && toNode) {
        const p1 = new THREE.Vector3(fromNode.x, fromNode.y, fromNode.z);
        const p2 = new THREE.Vector3(toNode.x, toNode.y, toNode.z);

        const lineGeo = new THREE.BufferGeometry().setFromPoints([p1, p2]);
        const lineMat = new THREE.LineBasicMaterial({
          color: 0x334155,
          transparent: true,
          opacity: 0.45,
        });

        const line = new THREE.Line(lineGeo, lineMat);
        lineGroup.add(line);
      }
    });

    // 8. Orbit Controls (Mouse Drag & Inertia)
    let isDragging = false;
    let prevMouseX = 0;
    let prevMouseY = 0;
    let targetRotationX = 0;
    let targetRotationY = 0;

    const handlePointerDown = (e) => {
      isDragging = true;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    };

    const handlePointerMove = (e) => {
      if (isDragging) {
        const deltaX = e.clientX - prevMouseX;
        const deltaY = e.clientY - prevMouseY;
        targetRotationY += deltaX * 0.005;
        targetRotationX += deltaY * 0.005;
        prevMouseX = e.clientX;
        prevMouseY = e.clientY;
      }
    };

    const handlePointerUp = () => {
      isDragging = false;
    };

    container.addEventListener('mousedown', handlePointerDown);
    window.addEventListener('mousemove', handlePointerMove);
    window.addEventListener('mouseup', handlePointerUp);

    // 9. Animation Loop & Screen Projection for Floating Labels
    const tempVec = new THREE.Vector3();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);

      // Smooth camera dampening / orbiting
      nodeGroup.rotation.y += (targetRotationY - nodeGroup.rotation.y) * 0.06;
      nodeGroup.rotation.x += (targetRotationX - nodeGroup.rotation.x) * 0.06;
      lineGroup.rotation.copy(nodeGroup.rotation);
      centralCage.rotation.y -= 0.003;
      centralCage.rotation.x += 0.001;

      // Project each 3D node to 2D screen coordinates
      const currentWidth = container.clientWidth;
      const currentHeight = container.clientHeight;
      const updatedScreens = [];

      nodeMeshes.forEach((mesh) => {
        mesh.getWorldPosition(tempVec);
        tempVec.project(camera);

        const x = (tempVec.x * 0.5 + 0.5) * currentWidth;
        const y = (-tempVec.y * 0.5 + 0.5) * currentHeight;

        // Depth scaling: nodes closer to camera have larger label cards
        const scale = THREE.MathUtils.clamp(1.15 - tempVec.z * 0.35, 0.72, 1.25);
        const opacity = THREE.MathUtils.clamp(1.05 - tempVec.z * 0.45, 0.55, 1.0);
        const zIndex = Math.round((1 - tempVec.z) * 100);
        const isVisible = tempVec.z < 1.0;

        updatedScreens.push({
          id: mesh.userData.node.id,
          node: mesh.userData.node,
          x,
          y,
          scale,
          opacity,
          zIndex,
          isVisible,
        });
      });

      setScreenNodes(updatedScreens);
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
      container.removeEventListener('mousedown', handlePointerDown);
      window.removeEventListener('mousemove', handlePointerMove);
      window.removeEventListener('mouseup', handlePointerUp);
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
      className="relative w-full h-[620px] rounded-2xl overflow-hidden glass-panel border border-white/10 select-none group bg-[#06090F]"
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
                <div className="text-xs font-semibold font-mono text-white truncate">{node.code || node.name}</div>
                <div className="text-[10px] text-platinum-500 font-mono mt-0.5 truncate">{node.location} • Risk: {node.riskScore}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Floating HTML Node Cards (Tracking 3D Coordinates Exactly Like Reference Image) */}
      {!is2DFallback && screenNodes.map((item) => {
        if (!item.isVisible) return null;
        if (activeFilter !== 'ALL' && item.node.category !== activeFilter) return null;

        const isHero = item.node.isHero || item.node.id === 'APP-2025-ER0-3398';
        const isSelected = selectedNode?.id === item.node.id;

        return (
          <div
            key={item.id}
            onClick={() => onSelectNode(item.node)}
            className="absolute pointer-events-auto cursor-pointer select-none transition-transform duration-75 group"
            style={{
              left: `${item.x}px`,
              top: `${item.y - 18}px`,
              transform: `translate(-50%, -100%) scale(${item.scale})`,
              zIndex: item.zIndex + (isSelected ? 200 : isHero ? 100 : 0),
              opacity: item.opacity,
            }}
          >
            <div className={`px-3 py-1.5 rounded-xl border backdrop-blur-md shadow-2xl flex items-center space-x-2.5 transition-all ${
              isSelected
                ? 'bg-[#0E1524]/95 border-emerald-400 shadow-[0_0_25px_rgba(16,185,129,0.4)]'
                : isHero
                ? 'bg-[#0B0F17]/95 border-white/20 hover:border-emerald-400 shadow-[0_12px_35px_rgba(0,0,0,0.9)]'
                : 'bg-[#0B0F17]/90 border-white/10 hover:border-white/30 shadow-[0_8px_25px_rgba(0,0,0,0.7)]'
            }`}>
              {/* Glowing Indicator Dot (Mint / Emerald Green) */}
              <span className={`h-2.5 w-2.5 rounded-full shrink-0 ${
                item.node.status === 'FAILED'
                  ? 'bg-red-500 shadow-[0_0_8px_#EF4444]'
                  : item.node.status === 'SUSPICIOUS'
                  ? 'bg-amber-400 shadow-[0_0_8px_#F59E0B]'
                  : 'bg-[#2DD4BF] shadow-[0_0_10px_#2DD4BF]'
              }`} />

              {/* Node Card Details (Title & Subtitle with Middle Dot) */}
              <div className="text-left font-mono leading-tight whitespace-nowrap">
                <div className={`text-xs font-bold tracking-wide ${
                  isHero ? 'text-white text-[13px]' : 'text-slate-100'
                }`}>
                  {item.node.code || item.node.id}
                </div>
                <div className="text-[10px] text-slate-400 mt-0.5 flex items-center space-x-1">
                  <span>{item.node.location || item.node.type || 'Cluster'}</span>
                  <span className="text-slate-600">•</span>
                  <span className={item.node.riskScore > 40 ? 'text-amber-400 font-semibold' : 'text-slate-400'}>
                    Risk: {item.node.riskScore ?? 15}
                  </span>
                </div>
              </div>
            </div>
          </div>
        );
      })}

      {/* Floating HUD Top Overlay: Categories & Filters */}
      <div className="absolute top-4 left-4 right-4 flex flex-wrap items-center justify-between gap-3 pointer-events-none z-30">
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

        {/* 2D / 3D Toggle */}
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

      {/* Bottom Telemetry Legend */}
      <div className="absolute bottom-4 left-4 right-4 flex items-center justify-between text-[11px] font-mono text-platinum-400 pointer-events-none z-30">
        <div className="flex items-center space-x-4 glass-panel px-3 py-1.5 rounded-lg pointer-events-auto">
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-[#2DD4BF] shadow-[0_0_8px_#2DD4BF]"></span>
            <span>Active Enclave Node</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-amber-400 shadow-[0_0_8px_#F59E0B]"></span>
            <span>Elevated Risk</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-red-500 shadow-[0_0_8px_#EF4444]"></span>
            <span>Tampered</span>
          </div>
        </div>

        <div className="hidden sm:block text-slate-500 text-[10px]">
          DRAG TO ORBIT 360° • HOVER / CLICK CARDS TO INSPECT
        </div>
      </div>
    </div>
  );
}
