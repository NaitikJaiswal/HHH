import React, { useEffect, useRef, useState, useCallback } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { 
  RotateCcw, ZoomIn, ZoomOut, Play, Pause, Layers, 
  Search, Filter, ShieldCheck, Crosshair, Database, Hash, Eye, Sparkles 
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
  const labelsContainerRef = useRef(null);
  const labelElementsRef = useRef({});

  const [hoveredNode, setHoveredNode] = useState(null);
  const [autoRotate, setAutoRotate] = useState(false);
  const [is2DMode, setIs2DMode] = useState(false);

  // Category Color and Material Config
  const getCategoryTheme = (category, status) => {
    if (status === 'FAILED') {
      return { base: 0x991B1B, wire: 0xEF4444, glow: 0xEF4444, dot: 'bg-red-500 shadow-glow-red', hex: '#EF4444' };
    }
    if (status === 'SUSPICIOUS' || category === 'THREAT') {
      return { base: 0xB45309, wire: 0xF59E0B, glow: 0xF59E0B, dot: 'bg-amber-400 shadow-glow-amber', hex: '#F59E0B' };
    }
    switch (category) {
      case 'EVIDENCE':
        return { base: 0x881337, wire: 0xEF4444, glow: 0xFDA4AF, dot: 'bg-emerald-400 shadow-glow-platinum', hex: '#EF4444' }; // Crimson wireframe + silver
      case 'HASH':
        return { base: 0xCBD5E1, wire: 0xFFFFFF, glow: 0xE2E8F0, dot: 'bg-slate-200 shadow-glow-platinum', hex: '#E2E8F0' }; // Metallic silver
      case 'MERKLE':
        return { base: 0x334155, wire: 0x94A3B8, glow: 0xCBD5E1, dot: 'bg-sky-400', hex: '#94A3B8' }; // Geometric mesh
      case 'BLOCKCHAIN':
        return { base: 0xE2E8F0, wire: 0x38BDF8, glow: 0x38BDF8, dot: 'bg-sky-400 shadow-glow-chrome', hex: '#38BDF8' }; // Platinum + cyan
      case 'INVESTIGATION':
        return { base: 0x0F172A, wire: 0x94A3B8, glow: 0xE2E8F0, dot: 'bg-purple-400', hex: '#CBD5E1' }; // Dark chrome
      default:
        return { base: 0x64748B, wire: 0xE2E8F0, glow: 0xFFFFFF, dot: 'bg-emerald-400', hex: '#E2E8F0' };
    }
  };

  useEffect(() => {
    if (is2DMode || !canvasRef.current || !containerRef.current) return;

    const container = containerRef.current;
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 660;

    // 1. Scene, Camera, and Atmospheric Fog
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x070809, 0.0075);

    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 22, 92);
    cameraRef.current = camera;

    // 2. High-Performance WebGL Renderer
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
      console.warn('WebGL init error, falling back to 2D:', err);
      setIs2DMode(true);
      return;
    }

    // 3. OrbitControls (Left: Rotate, Right: Pan, Wheel: Zoom, Damping)
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.minDistance = 16;
    controls.maxDistance = 175;
    controls.enablePan = true;
    controls.screenSpacePanning = true;
    controls.mouseButtons = {
      LEFT: THREE.MOUSE.ROTATE,
      MIDDLE: THREE.MOUSE.DOLLY,
      RIGHT: THREE.MOUSE.PAN,
    };
    controls.touches = {
      ONE: THREE.TOUCH.ROTATE,
      TWO: THREE.TOUCH.DOLLY_PAN,
    };
    controlsRef.current = controls;

    // Automatic movement pause on user drag, resume after delay
    let isUserDragging = false;
    let idleResumeTimer = null;
    controls.addEventListener('start', () => {
      isUserDragging = true;
      if (idleResumeTimer) clearTimeout(idleResumeTimer);
    });
    controls.addEventListener('end', () => {
      idleResumeTimer = setTimeout(() => {
        isUserDragging = false;
      }, 2400);
    });

    // 4. Cinematic Forensic Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.6);
    scene.add(ambientLight);

    const keyLight = new THREE.DirectionalLight(0xffffff, 1.45);
    keyLight.position.set(45, 60, 50);
    scene.add(keyLight);

    const rimLight = new THREE.DirectionalLight(0x38bdf8, 0.85);
    rimLight.position.set(-50, -35, -45);
    scene.add(rimLight);

    const crimsonAccentLight = new THREE.DirectionalLight(0xef4444, 0.45);
    crimsonAccentLight.position.set(0, -45, 25);
    scene.add(crimsonAccentLight);

    // 5. Minimal Background Starfield Particles
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
      color: 0x747a83,
      size: 1.1,
      transparent: true,
      opacity: 0.35,
    });
    const stars = new THREE.Points(starGeo, starMat);
    scene.add(stars);

    // 6. CENTRAL CRYPTOGRAPHIC CORE (Representing HHH Intelligence Engine)
    const coreGroup = new THREE.Group();
    scene.add(coreGroup);

    // A. Irregular Angular Polyhedron (Obsidian Black with reflective flat faces)
    const coreGeo = new THREE.IcosahedronGeometry(7.4, 0);
    const coreMat = new THREE.MeshStandardMaterial({
      color: 0x070809,
      metalness: 0.96,
      roughness: 0.18,
      flatShading: true,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    coreGroup.add(coreMesh);

    // Silver wireframe edge highlights
    const coreEdgesGeo = new THREE.EdgesGeometry(coreGeo);
    const coreEdgesMat = new THREE.LineBasicMaterial({
      color: 0xcbd5e1,
      transparent: true,
      opacity: 0.75,
    });
    const coreEdges = new THREE.LineSegments(coreEdgesGeo, coreEdgesMat);
    coreGroup.add(coreEdges);

    // B. Subtle glowing inner core (Breathing light effect)
    const innerCoreGeo = new THREE.SphereGeometry(3.6, 24, 24);
    const innerCoreMat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.4,
    });
    const innerCoreMesh = new THREE.Mesh(innerCoreGeo, innerCoreMat);
    coreGroup.add(innerCoreMesh);

    // C. Prominent Circular Orbital Ring around the Core
    const prominentRingCurve = new THREE.EllipseCurve(0, 0, 13.5, 13.5, 0, 2 * Math.PI, false, 0);
    const prominentRingGeo = new THREE.BufferGeometry().setFromPoints(prominentRingCurve.getPoints(96));
    const prominentRingMat = new THREE.LineBasicMaterial({ color: 0xcbd5e1, transparent: true, opacity: 0.65 });
    const prominentRing = new THREE.Line(prominentRingGeo, prominentRingMat);
    prominentRing.rotation.x = Math.PI / 2.6;
    coreGroup.add(prominentRing);

    // 7. ORBITAL RINGS & MOVING PARTICLES
    const orbitalGroup = new THREE.Group();
    scene.add(orbitalGroup);

    const ringDefs = [
      { radius: 26, tiltX: Math.PI / 2 + 0.1, tiltY: 0, tiltZ: 0, color: 0x475569, speed: 0.007 },
      { radius: 36, tiltX: Math.PI / 3.2, tiltY: Math.PI / 5, tiltZ: 0, color: 0x747a83, speed: 0.005 },
      { radius: 46, tiltX: -Math.PI / 2.6, tiltY: Math.PI / 3, tiltZ: Math.PI / 6, color: 0x334155, speed: 0.0035 },
    ];

    const orbitalParticles = [];
    ringDefs.forEach((def, rIdx) => {
      const curve = new THREE.EllipseCurve(0, 0, def.radius, def.radius, 0, 2 * Math.PI, false, 0);
      const ringGeo = new THREE.BufferGeometry().setFromPoints(curve.getPoints(96));
      const ringMat = new THREE.LineBasicMaterial({ color: def.color, transparent: true, opacity: 0.32 });
      const ring = new THREE.Line(ringGeo, ringMat);
      ring.rotation.set(def.tiltX, def.tiltY, def.tiltZ);
      orbitalGroup.add(ring);

      // Moving particles along ring
      const pCount = 3;
      for (let p = 0; p < pCount; p++) {
        const particleMesh = new THREE.Mesh(
          new THREE.SphereGeometry(0.45, 8, 8),
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

    // 8. 14 OUTER SPHERICAL NODES (Dense Geodesic Structure, Crimson/Silver Wireframe, Real 3D)
    const nodeMeshes = new Map();
    const nodeGroup = new THREE.Group();
    scene.add(nodeGroup);

    nodes.forEach((node) => {
      if (!node || typeof node.x !== 'number') return;
      const theme = getCategoryTheme(node.category, node.status);
      const isSelected = selectedNode?.id === node.id;
      const subGroup = new THREE.Group();
      subGroup.position.set(node.x, node.y, node.z);

      // A. Hollow transparent inner sphere
      const sphereGeo = new THREE.SphereGeometry(2.2, 24, 24);
      const sphereMat = new THREE.MeshStandardMaterial({
        color: isSelected ? 0xffffff : theme.base,
        metalness: node.category === 'HASH' || node.category === 'BLOCKCHAIN' ? 0.95 : 0.4,
        roughness: 0.28,
        transparent: true,
        opacity: isSelected ? 0.85 : 0.45,
        emissive: theme.base,
        emissiveIntensity: isSelected ? 0.8 : 0.35,
      });
      const sphere = new THREE.Mesh(sphereGeo, sphereMat);
      subGroup.add(sphere);

      // B. Dense triangular / geodesic wireframe shell (Crimson or category-specific)
      const wireGeo = new THREE.IcosahedronGeometry(2.35, 1);
      const wireMat = new THREE.MeshBasicMaterial({
        color: isSelected ? 0xffffff : theme.wire,
        wireframe: true,
        transparent: true,
        opacity: isSelected ? 0.95 : 0.65,
      });
      const wireMesh = new THREE.Mesh(wireGeo, wireMat);
      subGroup.add(wireMesh);

      // C. Category Decorators
      if (node.category === 'BLOCKCHAIN') {
        const bRingCurve = new THREE.EllipseCurve(0, 0, 3.8, 3.8, 0, 2 * Math.PI, false, 0);
        const bRingGeo = new THREE.BufferGeometry().setFromPoints(bRingCurve.getPoints(32));
        const bRingMat = new THREE.LineBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.75 });
        const bRing = new THREE.Line(bRingGeo, bRingMat);
        bRing.rotation.x = Math.PI / 3;
        subGroup.add(bRing);
      } else if (node.category === 'MERKLE') {
        const mCageGeo = new THREE.OctahedronGeometry(3.2, 0);
        const mCageMat = new THREE.MeshBasicMaterial({ color: 0x94a3b8, wireframe: true, transparent: true, opacity: 0.65 });
        const mCage = new THREE.Mesh(mCageGeo, mCageMat);
        subGroup.add(mCage);
      }

      subGroup.userData = { node, basePos: new THREE.Vector3(node.x, node.y, node.z), theme, wireMesh, sphere };
      nodeMeshes.set(node.id, subGroup);
      nodeGroup.add(subGroup);
    });

    // 9. RADIAL METALLIC CONNECTIONS & TRAVELING DATA PARTICLES
    const lineGroup = new THREE.Group();
    scene.add(lineGroup);

    const radialConnections = [];
    const connectionParticles = [];
    const particleGeometry = new THREE.SphereGeometry(0.38, 8, 8);
    const particleMaterial = new THREE.MeshBasicMaterial({ color: 0xe2e8f0 });

    nodes.forEach((node, idx) => {
      const p1 = new THREE.Vector3(0, 0, 0);
      const p2 = new THREE.Vector3(node.x, node.y, node.z);

      const isRelated = selectedNode && (selectedNode.id === node.id);
      const lineGeo = new THREE.BufferGeometry().setFromPoints([p1, p2]);
      const lineMat = new THREE.LineBasicMaterial({
        color: isRelated ? 0xef4444 : 0x747a83,
        transparent: true,
        opacity: isRelated ? 0.95 : 0.32,
      });

      const line = new THREE.Line(lineGeo, lineMat);
      lineGroup.add(line);
      radialConnections.push({ line, lineMat, nodeId: node.id });

      // Animated traveling data packet
      const pMesh = new THREE.Mesh(particleGeometry, particleMaterial);
      pMesh.position.copy(p1);
      lineGroup.add(pMesh);
      connectionParticles.push({
        mesh: pMesh,
        start: p1,
        end: p2,
        progress: (idx * 0.12) % 1,
        speed: 0.005 + (idx % 3) * 0.002,
      });
    });

    // Inter-node links
    links.forEach((link) => {
      if (link.to === 'CORE') return;
      const n1 = nodes.find(n => n.id === link.from);
      const n2 = nodes.find(n => n.id === link.to);
      if (n1 && n2) {
        const p1 = new THREE.Vector3(n1.x, n1.y, n1.z);
        const p2 = new THREE.Vector3(n2.x, n2.y, n2.z);

        const isHighlighted = selectedNode && (selectedNode.id === n1.id || selectedNode.id === n2.id);
        const lineGeo = new THREE.BufferGeometry().setFromPoints([p1, p2]);
        const lineMat = new THREE.LineBasicMaterial({
          color: isHighlighted ? 0xef4444 : 0x272e39,
          transparent: true,
          opacity: isHighlighted ? 0.9 : 0.25,
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
          // Animate camera target towards selected node
          controls.target.lerp(new THREE.Vector3(n.x, n.y, n.z), 0.85);
          camera.position.lerp(new THREE.Vector3(n.x + 8, n.y + 6, n.z + 18), 0.85);
        }
      }
    };

    container.addEventListener('mousemove', handlePointerMove);
    container.addEventListener('click', handleClick);
    container.addEventListener('dblclick', handleDoubleClick);

    // 11. ANIMATION & RENDER LOOP WITH REAL-TIME 3D SCREEN PROJECTION
    let clock = new THREE.Clock();
    let animationFrameId;
    const tempProjVec = new THREE.Vector3();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      // Controls update for smooth damping
      controls.update();

      // Idle Rotation: central core & subtle environment drift when user is not dragging
      if (!isUserDragging) {
        coreGroup.rotation.y += 0.0035;
        coreGroup.rotation.x += 0.0012;
        coreGroup.rotation.z += 0.0018;

        if (autoRotate) {
          controls.autoRotate = true;
          controls.autoRotateSpeed = 0.5;
        } else {
          controls.autoRotate = false;
        }
      } else {
        controls.autoRotate = false;
      }

      // Breathing Light effect on central core
      const breathScale = 1 + Math.sin(elapsedTime * 2.2) * 0.08;
      innerCoreMesh.scale.set(breathScale, breathScale, breathScale);
      innerCoreMat.opacity = 0.35 + Math.sin(elapsedTime * 2.2) * 0.15;

      // Orbital particles moving along paths
      orbitalParticles.forEach((p) => {
        p.theta += p.speed;
        const x = Math.cos(p.theta) * p.radius;
        const y = Math.sin(p.theta) * p.radius;
        const pos = new THREE.Vector3(x, y, 0);
        pos.applyEuler(new THREE.Euler(p.tiltX, p.tiltY, p.tiltZ));
        p.mesh.position.copy(pos);
      });

      // Outer Nodes Subtle Floating Animation & Individual Rotation
      nodeMeshes.forEach((mesh) => {
        const node = mesh.userData.node;
        const base = mesh.userData.basePos;
        mesh.position.y = base.y + Math.sin(elapsedTime * 1.5 + node.x * 0.1) * 0.7;
        mesh.rotation.y += 0.008;
        mesh.rotation.x += 0.004;

        // Dim unrelated nodes when a node is selected or filter applied
        const isSelected = selectedNode && selectedNode.id === node.id;
        const matchesSearch = !searchQuery || node.name.toLowerCase().includes(searchQuery.toLowerCase()) || node.id.toLowerCase().includes(searchQuery.toLowerCase());
        const matchesFilter = activeFilter === 'ALL' || node.category === activeFilter || node.status === activeFilter;

        const isDimmed = (selectedNode && !isSelected) || !matchesSearch || !matchesFilter;
        if (mesh.userData.wireMesh) {
          mesh.userData.wireMesh.material.opacity = isSelected ? 1.0 : (isDimmed ? 0.22 : 0.65);
        }
        if (mesh.userData.sphere) {
          mesh.userData.sphere.material.opacity = isSelected ? 0.9 : (isDimmed ? 0.15 : 0.45);
        }
      });

      // Traveling data packets along radial lines
      connectionParticles.forEach((p) => {
        p.progress += p.speed;
        if (p.progress > 1) p.progress = 0;
        p.mesh.position.lerpVectors(p.start, p.end, p.progress);
      });

      // REAL-TIME SCREEN PROJECTION FOR FLOATING CARDS (Matching Reference Screenshot)
      const cWidth = container.clientWidth;
      const cHeight = container.clientHeight;

      nodes.forEach((node) => {
        const el = labelElementsRef.current[node.id];
        const meshGroup = nodeMeshes.get(node.id);
        if (!el || !meshGroup) return;

        meshGroup.getWorldPosition(tempProjVec);
        const dist = camera.position.distanceTo(tempProjVec);
        tempProjVec.project(camera);

        // Check if behind camera or outside container viewport
        const isInFront = tempProjVec.z < 1.0;
        const isWithinView = tempProjVec.x >= -1.2 && tempProjVec.x <= 1.2 && tempProjVec.y >= -1.2 && tempProjVec.y <= 1.2;

        const matchesSearch = !searchQuery || node.name.toLowerCase().includes(searchQuery.toLowerCase()) || node.id.toLowerCase().includes(searchQuery.toLowerCase());
        const matchesFilter = activeFilter === 'ALL' || node.category === activeFilter || node.status === activeFilter;

        if (!isInFront || !isWithinView || !matchesSearch || !matchesFilter) {
          el.style.opacity = '0';
          el.style.pointerEvents = 'none';
        } else {
          const screenX = (tempProjVec.x * 0.5 + 0.5) * cWidth;
          const screenY = (-tempProjVec.y * 0.5 + 0.5) * cHeight;
          const scale = Math.max(0.78, Math.min(1.08, 62 / dist));
          const zIndex = Math.round((1 - tempProjVec.z) * 100);

          el.style.display = 'block';
          el.style.transform = `translate3d(${screenX}px, ${screenY}px, 0) translate(-50%, -125%) scale(${scale})`;
          el.style.zIndex = zIndex;
          el.style.opacity = selectedNode?.id === node.id ? '1' : (dist > 115 ? '0.45' : '0.94');
          el.style.pointerEvents = 'auto';
        }
      });

      // Raycaster Hover Detection
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
  }, [nodes, links, selectedNode, autoRotate, is2DMode, searchQuery, activeFilter]);

  // Camera Action Helpers
  const handleResetCamera = () => {
    if (controlsRef.current && cameraRef.current) {
      controlsRef.current.target.set(0, 0, 0);
      cameraRef.current.position.set(0, 22, 92);
      controlsRef.current.update();
    }
  };

  const handleZoom = (factor) => {
    if (cameraRef.current) {
      cameraRef.current.position.multiplyScalar(factor);
      if (controlsRef.current) controlsRef.current.update();
    }
  };

  const handleFocusNode = (node) => {
    onSelectNode(node);
    if (controlsRef.current && cameraRef.current) {
      controlsRef.current.target.set(node.x, node.y, node.z);
      cameraRef.current.position.set(node.x + 8, node.y + 6, node.z + 18);
      controlsRef.current.update();
    }
  };

  // Filtered nodes for 2D fallback
  const filteredNodes = nodes.filter((n) => {
    const matchesFilter = activeFilter === 'ALL' || n.category === activeFilter || n.status === activeFilter;
    const matchesSearch = !searchQuery || n.name.toLowerCase().includes(searchQuery.toLowerCase()) || n.id.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  return (
    <div 
      ref={containerRef} 
      className="relative w-full h-[680px] rounded-2xl overflow-hidden border border-white/10 select-none bg-[#070809]"
    >
      {/* 3D WebGL Canvas */}
      {!is2DMode ? (
        <canvas ref={canvasRef} className="w-full h-full block cursor-grab active:cursor-grabbing" />
      ) : (
        /* 2D Schematic Fallback */
        <div className="w-full h-full p-8 overflow-auto flex flex-col justify-center items-center bg-[#070809]">
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
                    ? 'bg-[#15171B] border-white text-white shadow-glow-platinum' 
                    : 'bg-[#101114]/90 border-white/5 hover:border-white/20 text-platinum-300'
                }`}
              >
                <div className="flex items-center justify-between text-[10px] mb-1">
                  <span className="text-platinum-500">{node.category}</span>
                  <span className="text-white bg-white/10 px-1.5 py-0.5 rounded font-semibold">{node.status}</span>
                </div>
                <div className="text-xs font-semibold text-white truncate">{node.name}</div>
                <div className="text-[10px] text-platinum-500 mt-0.5 truncate">{node.id}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* FLOATING INFORMATION CARDS ATTACHED TO EACH 3D NODE (Matching Reference Composition) */}
      {!is2DMode && (
        <div ref={labelsContainerRef} className="absolute inset-0 pointer-events-none overflow-hidden">
          {nodes.map((node) => {
            const isSelected = selectedNode?.id === node.id;
            const theme = getCategoryTheme(node.category, node.status);

            return (
              <div
                key={node.id}
                ref={(el) => (labelElementsRef.current[node.id] = el)}
                onClick={(e) => {
                  e.stopPropagation();
                  onSelectNode(node);
                }}
                onDoubleClick={(e) => {
                  e.stopPropagation();
                  handleFocusNode(node);
                }}
                className={`absolute top-0 left-0 transition-all duration-150 cursor-pointer ${
                  isSelected 
                    ? 'bg-[#15171B] border-white/80 ring-2 ring-white/40 shadow-glow-platinum' 
                    : 'bg-[#101114]/95 border-white/10 hover:border-white/40 hover:bg-[#15171B]'
                } border rounded-xl px-3 py-1.5 backdrop-blur-md shadow-2xl flex items-center space-x-2.5 font-mono pointer-events-auto`}
                style={{ willChange: 'transform, opacity' }}
              >
                {/* Glowing status dot */}
                <span className={`h-2.5 w-2.5 rounded-full shrink-0 ${theme.dot}`} />

                {/* Node Identifier & Subtitle */}
                <div className="leading-tight">
                  <div className="text-[11px] font-bold text-white tracking-wide flex items-center space-x-1.5">
                    <span>{node.id}</span>
                    {isSelected && <span className="text-[9px] text-sky-400 font-normal">● ACTIVE</span>}
                  </div>
                  <div className="text-[9px] text-platinum-400 whitespace-nowrap">
                    {node.subtitle || node.label || node.name}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Top Left: Forensic Constellation Watermark & Mode */}
      <div className="absolute top-4 left-4 z-20 pointer-events-none font-mono">
        <div className="text-[10px] text-platinum-500 tracking-widest uppercase flex items-center space-x-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span>Forensic Constellation Engine • Live Telemetry</span>
        </div>
        <div className="text-xs font-bold text-white tracking-wide mt-0.5">
          Spatial Orbital Network
        </div>
      </div>

      {/* Top Right: Camera & Viewport HUD Controls */}
      <div className="absolute top-4 right-4 flex items-center space-x-1.5 bg-[#15171B]/90 backdrop-blur-md border border-white/10 p-1.5 rounded-xl z-20 font-mono text-xs shadow-xl">
        <button
          onClick={() => setAutoRotate(!autoRotate)}
          className={`p-1.5 rounded-lg transition ${autoRotate ? 'bg-white/20 text-white' : 'text-platinum-400 hover:text-white hover:bg-white/5'}`}
          title={autoRotate ? 'Pause Auto-Rotation' : 'Enable Cinematic Auto-Rotation'}
        >
          {autoRotate ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
        </button>

        <div className="h-4 w-[1px] bg-white/10 mx-1" />

        <button
          onClick={() => handleZoom(0.82)}
          className="p-1.5 rounded-lg text-platinum-400 hover:text-white hover:bg-white/5 transition"
          title="Zoom In"
        >
          <ZoomIn className="h-4 w-4" />
        </button>

        <button
          onClick={() => handleZoom(1.18)}
          className="p-1.5 rounded-lg text-platinum-400 hover:text-white hover:bg-white/5 transition"
          title="Zoom Out"
        >
          <ZoomOut className="h-4 w-4" />
        </button>

        <button
          onClick={handleResetCamera}
          className="p-1.5 rounded-lg text-platinum-400 hover:text-white hover:bg-white/5 transition"
          title="Reset Camera Vantage Point"
        >
          <RotateCcw className="h-4 w-4" />
        </button>

        <div className="h-4 w-[1px] bg-white/10 mx-1" />

        <button
          onClick={() => setIs2DMode(!is2DMode)}
          className="px-2.5 py-1 rounded-lg text-[11px] text-platinum-300 hover:text-white hover:bg-white/5 transition flex items-center space-x-1"
          title="Toggle 2D Schematic"
        >
          <Layers className="h-3.5 w-3.5" />
          <span>{is2DMode ? '3D' : '2D'}</span>
        </button>
      </div>

      {/* Bottom Category Legend & Navigation Instructions */}
      <div className="absolute bottom-4 left-4 right-4 flex items-center justify-between text-[11px] font-mono text-platinum-400 pointer-events-none z-20">
        <div className="flex flex-wrap items-center gap-3 bg-[#15171B]/90 backdrop-blur-md border border-white/10 px-3.5 py-2 rounded-xl pointer-events-auto shadow-xl">
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
            <span className="text-white">Evidence</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-slate-200" />
            <span>Hashes</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-sky-400" />
            <span>Merkle Roots</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-sky-300" />
            <span>Blockchain</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-amber-400" />
            <span>Threats</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-purple-400" />
            <span>Cases</span>
          </div>
        </div>

        <div className="hidden lg:block text-platinum-400 text-[10px] bg-[#15171B]/80 px-3 py-1.5 rounded-xl border border-white/5 backdrop-blur-sm">
          LEFT-DRAG: ORBIT 360° • RIGHT-DRAG: PAN • SCROLL: ZOOM • CLICK: INSPECT • DOUBLE-CLICK: FOCUS
        </div>
      </div>
    </div>
  );
}
