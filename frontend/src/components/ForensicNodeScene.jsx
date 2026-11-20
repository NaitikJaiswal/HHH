import React, { useEffect, useRef, useState, useCallback } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { 
  RotateCcw, ZoomIn, ZoomOut, Play, Pause, Layers, 
  Search, Filter, ShieldCheck, Crosshair, Database, Hash 
} from 'lucide-react';

export default function ForensicNodeScene({
  nodes = [],
  links = [],
  selectedNode = null,
  onSelectNode = () => {},
  searchQuery = '',
  activeFilter = 'ALL',
}) {
  const containerRef = useRef(null);
  const canvasRef = useRef(null);
  const controlsRef = useRef(null);
  const cameraRef = useRef(null);

  const [hoveredNode, setHoveredNode] = useState(null);
  const [hoverPos, setHoverPos] = useState({ x: 0, y: 0 });
  const [autoRotate, setAutoRotate] = useState(false);
  const [is2DMode, setIs2DMode] = useState(false);

  // Category Color and Material Config
  const getCategoryTheme = (category, status) => {
    if (status === 'FAILED') {
      return { base: 0x991B1B, wire: 0xEF4444, glow: 0xEF4444, hex: '#EF4444' };
    }
    if (status === 'SUSPICIOUS' || category === 'THREAT') {
      return { base: 0xB45309, wire: 0xF59E0B, glow: 0xF59E0B, hex: '#F59E0B' };
    }
    switch (category) {
      case 'EVIDENCE':
        return { base: 0x881337, wire: 0xEF4444, glow: 0xFDA4AF, hex: '#EF4444' }; // Red mesh + silver
      case 'HASH':
        return { base: 0xCBD5E1, wire: 0xFFFFFF, glow: 0xE2E8F0, hex: '#E2E8F0' }; // Metallic silver wireframe
      case 'MERKLE':
        return { base: 0x475569, wire: 0x94A3B8, glow: 0xCBD5E1, hex: '#94A3B8' }; // Geometric mesh
      case 'BLOCKCHAIN':
        return { base: 0xE2E8F0, wire: 0x38BDF8, glow: 0x38BDF8, hex: '#38BDF8' }; // Platinum + ice cyan
      case 'INVESTIGATION':
        return { base: 0x0F172A, wire: 0x94A3B8, glow: 0xE2E8F0, hex: '#CBD5E1' }; // Dark chrome
      default:
        return { base: 0x64748B, wire: 0xE2E8F0, glow: 0xFFFFFF, hex: '#E2E8F0' };
    }
  };

  useEffect(() => {
    if (is2DMode || !canvasRef.current || !containerRef.current) return;

    const container = containerRef.current;
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 660;

    // 1. Scene, Camera, and Fog setup
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x05070B, 0.007);

    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 22, 92);
    cameraRef.current = camera;

    // 2. High-Fidelity WebGL Renderer with graceful fallback
    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({
        canvas: canvasRef.current,
        alpha: true,
        antialias: true,
        powerPreference: 'high-performance',
      });
      renderer.setSize(width, height);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    } catch (err) {
      console.warn('WebGL unavailable, falling back to 2D:', err);
      setIs2DMode(true);
      return;
    }

    // 3. Smooth Orbit Controls
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.minDistance = 22;
    controls.maxDistance = 165;
    controls.autoRotate = autoRotate;
    controls.autoRotateSpeed = 0.6;
    controlsRef.current = controls;

    // 4. Cinematic Studio Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.55);
    scene.add(ambientLight);

    const keyLight = new THREE.DirectionalLight(0xffffff, 1.4);
    keyLight.position.set(45, 60, 50);
    scene.add(keyLight);

    const rimLight = new THREE.DirectionalLight(0x38bdf8, 0.85);
    rimLight.position.set(-50, -35, -45);
    scene.add(rimLight);

    const softFill = new THREE.DirectionalLight(0xef4444, 0.4);
    softFill.position.set(0, -50, 20);
    scene.add(softFill);

    // 5. Minimal Background Space Particles
    const starGeo = new THREE.BufferGeometry();
    const starCount = 140;
    const starPos = new Float32Array(starCount * 3);
    for (let i = 0; i < starCount * 3; i += 3) {
      starPos[i] = (Math.random() - 0.5) * 220;
      starPos[i + 1] = (Math.random() - 0.5) * 160;
      starPos[i + 2] = (Math.random() - 0.5) * 160;
    }
    starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
    const starMat = new THREE.PointsMaterial({
      color: 0x64748b,
      size: 1.2,
      transparent: true,
      opacity: 0.35,
    });
    const stars = new THREE.Points(starGeo, starMat);
    scene.add(stars);

    // 6. CENTRAL CRYPTOGRAPHIC CORE (Representing HHH Forensic Intelligence Engine)
    const coreGroup = new THREE.Group();
    scene.add(coreGroup);

    // A. Outer Geometric 3D Polyhedron with triangular faces
    const coreGeo = new THREE.IcosahedronGeometry(7.2, 1);
    const coreMat = new THREE.MeshStandardMaterial({
      color: 0x0a0e17,
      metalness: 0.95,
      roughness: 0.22,
      flatShading: true,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    coreGroup.add(coreMesh);

    // Triangular silver wireframe structure
    const coreWireMat = new THREE.MeshBasicMaterial({
      color: 0xe2e8f0,
      wireframe: true,
      transparent: true,
      opacity: 0.65,
    });
    const coreWireMesh = new THREE.Mesh(coreGeo, coreWireMat);
    coreGroup.add(coreWireMesh);

    // B. Subtle glowing inner core (Breathing light effect)
    const innerCoreGeo = new THREE.SphereGeometry(3.6, 32, 32);
    const innerCoreMat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.45,
    });
    const innerCoreMesh = new THREE.Mesh(innerCoreGeo, innerCoreMat);
    coreGroup.add(innerCoreMesh);

    // C. Close Core Orbital Rings (Thin silver rings orbiting immediately around the core)
    const innerRingGeo1 = new THREE.BufferGeometry().setFromPoints(
      new THREE.EllipseCurve(0, 0, 11, 11, 0, 2 * Math.PI, false, 0).getPoints(64)
    );
    const innerRingMat = new THREE.LineBasicMaterial({ color: 0xe2e8f0, transparent: true, opacity: 0.5 });
    const innerRing1 = new THREE.Line(innerRingGeo1, innerRingMat);
    innerRing1.rotation.x = Math.PI / 3;
    coreGroup.add(innerRing1);

    const innerRing2 = new THREE.Line(innerRingGeo1, innerRingMat);
    innerRing2.rotation.y = Math.PI / 2.8;
    innerRing2.rotation.x = -Math.PI / 4;
    coreGroup.add(innerRing2);

    // 7. ORBITAL RINGS (Multiple large circular paths at different angles and depths)
    const orbitalGroup = new THREE.Group();
    scene.add(orbitalGroup);

    const ringDefs = [
      { radius: 26, tiltX: Math.PI / 2 + 0.1, tiltY: 0, tiltZ: 0, color: 0x475569, speed: 0.008 },
      { radius: 36, tiltX: Math.PI / 3.2, tiltY: Math.PI / 5, tiltZ: 0, color: 0x64748b, speed: 0.006 },
      { radius: 46, tiltX: -Math.PI / 2.6, tiltY: Math.PI / 3, tiltZ: Math.PI / 6, color: 0x334155, speed: 0.004 },
      { radius: 56, tiltX: Math.PI / 4, tiltY: -Math.PI / 4, tiltZ: Math.PI / 3, color: 0x475569, speed: 0.003 },
    ];

    const orbitalParticles = [];

    ringDefs.forEach((def, rIdx) => {
      const curve = new THREE.EllipseCurve(0, 0, def.radius, def.radius, 0, 2 * Math.PI, false, 0);
      const ringGeo = new THREE.BufferGeometry().setFromPoints(curve.getPoints(96));
      const ringMat = new THREE.LineBasicMaterial({ color: def.color, transparent: true, opacity: 0.35 });
      const ring = new THREE.Line(ringGeo, ringMat);
      ring.rotation.set(def.tiltX, def.tiltY, def.tiltZ);
      orbitalGroup.add(ring);

      // Subtle moving particles traveling along the orbital paths
      const pCount = 3;
      for (let p = 0; p < pCount; p++) {
        const particleMesh = new THREE.Mesh(
          new THREE.SphereGeometry(0.5, 8, 8),
          new THREE.MeshBasicMaterial({ color: 0xe2e8f0, transparent: true, opacity: 0.85 })
        );
        orbitalGroup.add(particleMesh);
        orbitalParticles.push({
          mesh: particleMesh,
          radius: def.radius,
          tiltX: def.tiltX,
          tiltY: def.tiltY,
          tiltZ: def.tiltZ,
          theta: (p / pCount) * Math.PI * 2 + rIdx,
          speed: def.speed,
        });
      }
    });

    // 8. 12–18 OUTER SPHERICAL NODES (Floating with depth, fine wireframe & internal glow)
    const nodeMeshes = new Map();
    const nodeGroup = new THREE.Group();
    scene.add(nodeGroup);

    nodes.forEach((node) => {
      if (!node || typeof node.x !== 'number') return;
      const theme = getCategoryTheme(node.category, node.status);
      const isSelected = selectedNode?.id === node.id;
      const subGroup = new THREE.Group();
      subGroup.position.set(node.x, node.y, node.z);

      // A. Inner Sphere
      const sphereGeo = new THREE.SphereGeometry(2.3, 32, 32);
      const sphereMat = new THREE.MeshStandardMaterial({
        color: isSelected ? 0xffffff : theme.base,
        metalness: node.category === 'HASH' || node.category === 'BLOCKCHAIN' ? 0.95 : 0.45,
        roughness: 0.25,
        emissive: theme.base,
        emissiveIntensity: isSelected ? 0.8 : 0.35,
      });
      const sphere = new THREE.Mesh(sphereGeo, sphereMat);
      subGroup.add(sphere);

      // B. Fine Wireframe Mesh (Red or Silver depending on category)
      const wireGeo = new THREE.SphereGeometry(2.4, 16, 16);
      const wireMat = new THREE.MeshBasicMaterial({
        color: isSelected ? 0xffffff : theme.wire,
        wireframe: true,
        transparent: true,
        opacity: isSelected ? 0.9 : 0.55,
      });
      const wireMesh = new THREE.Mesh(wireGeo, wireMat);
      subGroup.add(wireMesh);

      // C. Category Special: Blockchain small orbital ring
      if (node.category === 'BLOCKCHAIN') {
        const bRingCurve = new THREE.EllipseCurve(0, 0, 3.8, 3.8, 0, 2 * Math.PI, false, 0);
        const bRingGeo = new THREE.BufferGeometry().setFromPoints(bRingCurve.getPoints(32));
        const bRingMat = new THREE.LineBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.7 });
        const bRing = new THREE.Line(bRingGeo, bRingMat);
        bRing.rotation.x = Math.PI / 3;
        subGroup.add(bRing);
      }

      // D. Category Special: Merkle Geometric Cage
      if (node.category === 'MERKLE') {
        const mCageGeo = new THREE.OctahedronGeometry(3.1, 0);
        const mCageMat = new THREE.MeshBasicMaterial({ color: 0x94a3b8, wireframe: true, transparent: true, opacity: 0.6 });
        const mCage = new THREE.Mesh(mCageGeo, mCageMat);
        subGroup.add(mCage);
      }

      subGroup.userData = { node, basePos: new THREE.Vector3(node.x, node.y, node.z), theme };
      nodeMeshes.set(node.id, subGroup);
      nodeGroup.add(subGroup);
    });

    // 9. RADIAL CONNECTIONS & INTER-NODE LINKS WITH TRAVELING DATA PARTICLES
    const lineGroup = new THREE.Group();
    scene.add(lineGroup);

    const radialConnections = [];
    const connectionParticles = [];
    const particleGeometry = new THREE.SphereGeometry(0.4, 8, 8);
    const particleMaterial = new THREE.MeshBasicMaterial({ color: 0xe2e8f0 });

    // Radial lines from Core (0,0,0) to each outer node
    nodes.forEach((node, idx) => {
      const p1 = new THREE.Vector3(0, 0, 0);
      const p2 = new THREE.Vector3(node.x, node.y, node.z);

      const isRelated = selectedNode && (selectedNode.id === node.id);
      const lineGeo = new THREE.BufferGeometry().setFromPoints([p1, p2]);
      const lineMat = new THREE.LineBasicMaterial({
        color: isRelated ? 0x38bdf8 : 0x334155,
        transparent: true,
        opacity: isRelated ? 0.95 : 0.32,
      });

      const line = new THREE.Line(lineGeo, lineMat);
      lineGroup.add(line);
      radialConnections.push({ line, lineMat, nodeId: node.id });

      // Animated traveling data particle along selected connections
      const pMesh = new THREE.Mesh(particleGeometry, particleMaterial);
      pMesh.position.copy(p1);
      lineGroup.add(pMesh);
      connectionParticles.push({
        mesh: pMesh,
        start: p1,
        end: p2,
        progress: (idx * 0.15) % 1,
        speed: 0.005 + (idx % 3) * 0.002,
      });
    });

    // Inter-node links
    links.forEach((link, idx) => {
      if (link.to === 'CORE') return;
      const n1 = nodes.find(n => n.id === link.from);
      const n2 = nodes.find(n => n.id === link.to);
      if (n1 && n2) {
        const p1 = new THREE.Vector3(n1.x, n1.y, n1.z);
        const p2 = new THREE.Vector3(n2.x, n2.y, n2.z);

        const isHighlighted = selectedNode && (selectedNode.id === n1.id || selectedNode.id === n2.id);
        const lineGeo = new THREE.BufferGeometry().setFromPoints([p1, p2]);
        const lineMat = new THREE.LineBasicMaterial({
          color: isHighlighted ? 0xef4444 : 0x1e293b,
          transparent: true,
          opacity: isHighlighted ? 0.9 : 0.25,
          linewidth: isHighlighted ? 2 : 1,
        });

        const line = new THREE.Line(lineGeo, lineMat);
        lineGroup.add(line);
      }
    });

    // 10. RAYCASTING INTERACTION (Hover, Click, Double-Click)
    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2(-999, -999);

    const handlePointerMove = (e) => {
      const rect = container.getBoundingClientRect();
      pointer.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
      setHoverPos({ x: e.clientX, y: e.clientY });
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
          // Animate camera target towards the selected node
          controls.target.lerp(new THREE.Vector3(hit.userData.node.x * 0.6, hit.userData.node.y * 0.6, hit.userData.node.z * 0.6), 0.6);
        }
      }
    };

    const handleDoubleClick = () => {
      raycaster.setFromCamera(pointer, camera);
      const intersects = raycaster.intersectObjects(nodeGroup.children, true);
      if (intersects.length > 0) {
        let hit = intersects[0].object;
        while (hit && !hit.userData.node && hit.parent) {
          hit = hit.parent;
        }
        if (hit && hit.userData.node) {
          const n = hit.userData.node;
          onSelectNode(n);
          // Zoom closely onto node
          const targetPos = new THREE.Vector3(n.x, n.y, n.z);
          controls.target.copy(targetPos);
          camera.position.lerp(new THREE.Vector3(n.x + 8, n.y + 6, n.z + 18), 0.8);
        }
      }
    };

    container.addEventListener('mousemove', handlePointerMove);
    container.addEventListener('click', handleClick);
    container.addEventListener('dblclick', handleDoubleClick);

    // 11. ANIMATION & RENDER LOOP
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      // Controls update for smooth damping
      controls.update();

      // A. Central Core Multi-Axis Slow Rotation
      coreGroup.rotation.y += 0.003;
      coreGroup.rotation.x += 0.001;
      coreGroup.rotation.z += 0.0015;

      // Core Breathing Light effect
      const breathScale = 1 + Math.sin(elapsedTime * 2.2) * 0.08;
      innerCoreMesh.scale.set(breathScale, breathScale, breathScale);
      innerCoreMat.opacity = 0.35 + Math.sin(elapsedTime * 2.2) * 0.15;

      // B. Orbital Particles Moving Along Ring Paths
      orbitalParticles.forEach((p) => {
        p.theta += p.speed;
        const x = Math.cos(p.theta) * p.radius;
        const y = Math.sin(p.theta) * p.radius;
        const pos = new THREE.Vector3(x, y, 0);
        pos.applyEuler(new THREE.Euler(p.tiltX, p.tiltY, p.tiltZ));
        p.mesh.position.copy(pos);
      });

      // C. Outer Nodes Subtle Floating Animation & Individual Rotation
      nodeMeshes.forEach((mesh) => {
        const node = mesh.userData.node;
        const base = mesh.userData.basePos;
        mesh.position.y = base.y + Math.sin(elapsedTime * 1.5 + node.x * 0.1) * 0.8;
        mesh.rotation.y += 0.006;
      });

      // D. Animated Traveling Data Particles Along Radial Lines
      connectionParticles.forEach((p) => {
        p.progress += p.speed;
        if (p.progress > 1) p.progress = 0;
        p.mesh.position.lerpVectors(p.start, p.end, p.progress);
      });

      // E. Raycasting for Hover Detection
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
      container.removeEventListener('click', handleClick);
      container.removeEventListener('dblclick', handleDoubleClick);
      window.removeEventListener('resize', handleResize);
      controls.dispose();
      renderer.dispose();
    };
  }, [nodes, links, selectedNode, autoRotate, is2DMode]);

  // Camera Action Helpers
  const handleResetCamera = () => {
    if (controlsRef.current && cameraRef.current) {
      controlsRef.current.target.set(0, 0, 0);
      cameraRef.current.position.set(0, 22, 92);
      controlsRef.current.update();
    }
  };

  const handleZoom = (delta) => {
    if (cameraRef.current) {
      cameraRef.current.position.multiplyScalar(delta);
      if (controlsRef.current) controlsRef.current.update();
    }
  };

  // Filtered nodes
  const filteredNodes = nodes.filter((n) => {
    const matchesFilter = 
      activeFilter === 'ALL' ||
      n.category === activeFilter ||
      (activeFilter === 'VERIFIED' && n.status === 'VERIFIED') ||
      (activeFilter === 'SUSPICIOUS' && n.status === 'SUSPICIOUS') ||
      (activeFilter === 'FAILED' && n.status === 'FAILED');

    const matchesSearch = 
      !searchQuery ||
      n.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      n.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (n.hash && n.hash.toLowerCase().includes(searchQuery.toLowerCase()));

    return matchesFilter && matchesSearch;
  });

  return (
    <div 
      ref={containerRef} 
      className="relative w-full h-[660px] rounded-2xl overflow-hidden glass-panel border border-white/10 select-none bg-[#05070B]"
    >
      {/* 3D WebGL Canvas */}
      {!is2DMode ? (
        <canvas ref={canvasRef} className="w-full h-full block cursor-grab active:cursor-grabbing" />
      ) : (
        /* 2D Schematic Fallback */
        <div className="w-full h-full p-8 overflow-auto flex flex-col justify-center items-center bg-obsidian-950">
          <p className="text-xs font-mono text-platinum-400 mb-6 uppercase tracking-wider">
            Schematic Forensic Topology (Reduced Motion Mode)
          </p>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4 max-w-3xl w-full font-mono text-xs">
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
                <div className="flex items-center justify-between text-[10px] mb-1">
                  <span className="text-platinum-500">{node.category}</span>
                  <span className={`px-1.5 py-0.2 rounded font-semibold ${
                    node.status === 'FAILED' ? 'text-status-critical bg-red-500/10' :
                    node.status === 'SUSPICIOUS' ? 'text-status-warning bg-amber-500/10' :
                    'text-platinum-300 bg-white/10'
                  }`}>
                    {node.status}
                  </span>
                </div>
                <div className="text-xs font-semibold text-white truncate">{node.name}</div>
                <div className="text-[10px] text-platinum-500 mt-0.5 truncate">{node.id}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Floating HUD Camera Controls (Top Right) */}
      <div className="absolute top-4 right-4 flex items-center space-x-1.5 glass-dropdown p-1.5 rounded-xl z-20 font-mono text-xs">
        <button
          onClick={() => setAutoRotate(!autoRotate)}
          className={`p-1.5 rounded-lg transition ${autoRotate ? 'bg-white/20 text-white' : 'text-platinum-400 hover:text-white'}`}
          title={autoRotate ? 'Pause Auto-Rotation' : 'Enable Cinematic Auto-Rotation'}
        >
          {autoRotate ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
        </button>

        <div className="h-4 w-[1px] bg-white/10 mx-1" />

        <button
          onClick={() => handleZoom(0.85)}
          className="p-1.5 rounded-lg text-platinum-400 hover:text-white hover:bg-white/5 transition"
          title="Zoom In"
        >
          <ZoomIn className="h-4 w-4" />
        </button>

        <button
          onClick={() => handleZoom(1.15)}
          className="p-1.5 rounded-lg text-platinum-400 hover:text-white hover:bg-white/5 transition"
          title="Zoom Out"
        >
          <ZoomOut className="h-4 w-4" />
        </button>

        <button
          onClick={handleResetCamera}
          className="p-1.5 rounded-lg text-platinum-400 hover:text-white hover:bg-white/5 transition"
          title="Reset Camera View"
        >
          <RotateCcw className="h-4 w-4" />
        </button>

        <div className="h-4 w-[1px] bg-white/10 mx-1" />

        <button
          onClick={() => setIs2DMode(!is2DMode)}
          className="px-2 py-1 rounded-lg text-[11px] text-platinum-300 hover:text-white hover:bg-white/5 transition flex items-center space-x-1"
          title="Toggle 2D Schematic"
        >
          <Layers className="h-3.5 w-3.5" />
          <span>{is2DMode ? '3D' : '2D'}</span>
        </button>
      </div>

      {/* Compact Floating Label on Hover with Connector Pin */}
      {hoveredNode && (
        <div
          className="fixed pointer-events-none z-50 glass-dropdown p-3 rounded-xl border border-white/20 shadow-2xl space-y-1 font-mono text-xs max-w-xs animate-fadeIn"
          style={{ left: hoverPos.x + 18, top: hoverPos.y - 20 }}
        >
          <div className="flex items-center justify-between space-x-4">
            <span className="text-[10px] text-platinum-500 uppercase tracking-widest">{hoveredNode.category}</span>
            <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded ${
              hoveredNode.status === 'FAILED' ? 'text-status-critical bg-red-500/10' :
              hoveredNode.status === 'SUSPICIOUS' ? 'text-status-warning bg-amber-500/10' :
              'text-white bg-white/10'
            }`}>
              {hoveredNode.status}
            </span>
          </div>
          <div className="text-white font-bold truncate">{hoveredNode.name}</div>
          <div className="text-[10px] text-platinum-400">ID: {hoveredNode.id}</div>
          {hoveredNode.hash && (
            <div className="text-[9px] text-platinum-500 break-all pt-1 border-t border-white/10">
              SHA: {hoveredNode.hash.slice(0, 20)}...
            </div>
          )}
          <div className="text-[9px] text-sky-400 pt-0.5">Click to inspect • Double-click to focus</div>
        </div>
      )}

      {/* Bottom Category Visual Legend */}
      <div className="absolute bottom-4 left-4 right-4 flex items-center justify-between text-[11px] font-mono text-platinum-400 pointer-events-none z-20">
        <div className="flex flex-wrap items-center gap-3 glass-panel px-3.5 py-2 rounded-xl pointer-events-auto">
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-red-500 shadow-glow-red" />
            <span className="text-white">Evidence</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-slate-200 shadow-glow-platinum" />
            <span>Hashes</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-slate-400" />
            <span>Merkle Roots</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-sky-400 shadow-glow-chrome" />
            <span>Blockchain</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-amber-400 shadow-glow-amber" />
            <span>Threats</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-slate-700 border border-slate-400" />
            <span>Cases</span>
          </div>
        </div>

        <div className="hidden lg:block text-platinum-500 text-[10px]">
          DRAG TO ORBIT 360° • SCROLL TO ZOOM • DOUBLE-CLICK NODE TO FLY IN
        </div>
      </div>
    </div>
  );
}
