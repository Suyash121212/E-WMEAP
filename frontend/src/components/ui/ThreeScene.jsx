// src/components/ui/ThreeScene.jsx
// Three.js 3D scene — wireframe globe + risk bars + network graph

import { useEffect, useRef } from "react";

const THREE_CDN = "https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js";

function loadThree() {
  return new Promise((resolve) => {
    if (window.THREE) { resolve(window.THREE); return; }
    const s = document.createElement("script");
    s.src = THREE_CDN;
    s.onload = () => resolve(window.THREE);
    document.head.appendChild(s);
  });
}

// ── Phase: IDLE — rotating globe ──────────────────────────────────────────
function buildGlobe(THREE, scene) {
  const group = new THREE.Group();

  // Wireframe sphere
  const geo  = new THREE.SphereGeometry(2, 24, 16);
  const mat  = new THREE.MeshBasicMaterial({
    color:     0x00ff41,
    wireframe: true,
    transparent: true,
    opacity:   0.25,
  });
  const sphere = new THREE.Mesh(geo, mat);
  group.add(sphere);

  // Equator ring
  const ringGeo = new THREE.TorusGeometry(2.1, 0.008, 8, 64);
  const ringMat = new THREE.MeshBasicMaterial({ color: 0x00ff41, transparent: true, opacity: 0.5 });
  const ring    = new THREE.Mesh(ringGeo, ringMat);
  group.add(ring);

  // Orbit ring 2
  const ring2 = new THREE.Mesh(
    new THREE.TorusGeometry(2.5, 0.005, 8, 64),
    new THREE.MeshBasicMaterial({ color: 0x0080ff, transparent: true, opacity: 0.3 })
  );
  ring2.rotation.x = Math.PI / 3;
  group.add(ring2);

  // Pulsing dot (target point)
  const dotGeo = new THREE.SphereGeometry(0.07, 8, 8);
  const dotMat = new THREE.MeshBasicMaterial({ color: 0xff0040 });
  const dot    = new THREE.Mesh(dotGeo, dotMat);
  dot.position.set(0, 2, 0.3);
  group.add(dot);

  // Particles around globe
  const pGeo    = new THREE.BufferGeometry();
  const pCount  = 200;
  const pPos    = new Float32Array(pCount * 3);
  for (let i = 0; i < pCount; i++) {
    const theta = Math.random() * Math.PI * 2;
    const phi   = Math.random() * Math.PI;
    const r     = 2.8 + Math.random() * 1.5;
    pPos[i*3]   = r * Math.sin(phi) * Math.cos(theta);
    pPos[i*3+1] = r * Math.cos(phi);
    pPos[i*3+2] = r * Math.sin(phi) * Math.sin(theta);
  }
  pGeo.setAttribute("position", new THREE.BufferAttribute(pPos, 3));
  const pMat  = new THREE.PointsMaterial({ color: 0x00ff41, size: 0.04, transparent: true, opacity: 0.6 });
  const pMesh = new THREE.Points(pGeo, pMat);
  group.add(pMesh);

  scene.add(group);
  return { group, sphere, ring, ring2, dot, pMesh };
}

// ── Phase: RESULTS — risk bar chart ──────────────────────────────────────
function buildRiskBars(THREE, scene, severityCounts) {
  const group = new THREE.Group();
  const modules = [
    { label: "HDR",  key: "headers",     color: 0x00ff41 },
    { label: "TLS",  key: "tls",         color: 0x0080ff },
    { label: "PORT", key: "ports",       color: 0xff0040 },
    { label: "DIR",  key: "directories", color: 0xffaa00 },
    { label: "BIZ",  key: "business",    color: 0xaa00ff },
    { label: "SEC",  key: "secrets",     color: 0xff0040 },
    { label: "CLD",  key: "cloud",       color: 0x00aaff },
  ];

  const counts = severityCounts || {};

  modules.forEach((mod, i) => {
    const height = Math.max(0.1, Math.random() * 3); // replace with real score
    const x      = (i - modules.length / 2 + 0.5) * 1.0;

    // Bar
    const barGeo = new THREE.BoxGeometry(0.5, height, 0.5);
    const barMat = new THREE.MeshBasicMaterial({
      color:       mod.color,
      transparent: true,
      opacity:     0.7,
      wireframe:   false,
    });
    const bar = new THREE.Mesh(barGeo, barMat);
    bar.position.set(x, height / 2 - 1.5, 0);
    group.add(bar);

    // Wireframe outline
    const wfMat = new THREE.MeshBasicMaterial({ color: mod.color, wireframe: true, opacity: 0.3, transparent: true });
    const wf    = new THREE.Mesh(barGeo, wfMat);
    wf.position.copy(bar.position);
    group.add(wf);

    // Glow plane at top
    const glowGeo = new THREE.PlaneGeometry(0.6, 0.6);
    const glowMat = new THREE.MeshBasicMaterial({
      color: mod.color, transparent: true, opacity: 0.3, side: THREE.DoubleSide
    });
    const glow = new THREE.Mesh(glowGeo, glowMat);
    glow.position.set(x, height - 1.5 + 0.01, 0);
    glow.rotation.x = -Math.PI / 2;
    group.add(glow);
  });

  // Floor grid
  const gridHelper = new THREE.GridHelper(8, 16, 0x00ff41, 0x003310);
  gridHelper.position.y = -1.5;
  group.add(gridHelper);

  scene.add(group);
  return group;
}

// ── Main component ────────────────────────────────────────────────────────
export default function ThreeScene({ phase = "idle", scanData = null }) {
  const mountRef = useRef(null);
  const stateRef = useRef({ renderer: null, animFrame: null });

  useEffect(() => {
    if (!mountRef.current) return;

    loadThree().then((THREE) => {
      const el = mountRef.current;
      const W  = el.clientWidth;
      const H  = el.clientHeight;

      // ── Renderer ──────────────────────────────────────────────────
      const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
      renderer.setSize(W, H);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
      renderer.setClearColor(0x000000, 0);
      el.appendChild(renderer.domElement);
      stateRef.current.renderer = renderer;

      // ── Scene + Camera ────────────────────────────────────────────
      const scene  = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(60, W / H, 0.1, 100);
      camera.position.set(0, 1, 6);

      // ── Ambient light ─────────────────────────────────────────────
      scene.add(new THREE.AmbientLight(0x00ff41, 0.3));
      const pLight = new THREE.PointLight(0x00ff41, 1, 20);
      pLight.position.set(0, 3, 3);
      scene.add(pLight);

      // ── Build scene based on phase ─────────────────────────────────
      let objects = {};
      if (phase === "idle" || phase === "scanning") {
        objects = buildGlobe(THREE, scene);
      } else if (phase === "results") {
        objects.riskBars = buildRiskBars(THREE, scene, scanData?.severity_counts);
        objects.group    = objects.riskBars;
      }

      // ── Mouse interaction ─────────────────────────────────────────
      let mouseX = 0, mouseY = 0;
      const onMouse = (e) => {
        mouseX = (e.clientX / window.innerWidth  - 0.5) * 2;
        mouseY = (e.clientY / window.innerHeight - 0.5) * 2;
      };
      window.addEventListener("mousemove", onMouse);

      // ── Animation loop ────────────────────────────────────────────
      let t = 0;
      const animate = () => {
        t += 0.005;
        stateRef.current.animFrame = requestAnimationFrame(animate);

        if (objects.group) {
          if (phase === "idle" || phase === "scanning") {
            objects.group.rotation.y  = t * 0.5 + mouseX * 0.3;
            objects.group.rotation.x  = Math.sin(t * 0.3) * 0.1 + mouseY * 0.1;
          } else {
            objects.group.rotation.y += 0.003;
          }
        }

        // Dot pulse
        if (objects.dot) {
          const s = 1 + Math.sin(t * 3) * 0.4;
          objects.dot.scale.setScalar(s);
        }

        // Camera subtle drift
        camera.position.x = Math.sin(t * 0.2) * 0.3;
        camera.position.y = 1 + Math.cos(t * 0.15) * 0.2;
        camera.lookAt(0, 0, 0);

        renderer.render(scene, camera);
      };
      animate();

      // ── Resize ────────────────────────────────────────────────────
      const onResize = () => {
        const W2 = el.clientWidth;
        const H2 = el.clientHeight;
        camera.aspect = W2 / H2;
        camera.updateProjectionMatrix();
        renderer.setSize(W2, H2);
      };
      window.addEventListener("resize", onResize);

      stateRef.current.cleanup = () => {
        cancelAnimationFrame(stateRef.current.animFrame);
        window.removeEventListener("mousemove", onMouse);
        window.removeEventListener("resize", onResize);
        renderer.dispose();
        if (el.contains(renderer.domElement)) el.removeChild(renderer.domElement);
      };
    });

    return () => {
      stateRef.current.cleanup?.();
    };
  }, [phase]);

  return (
    <div
      ref={mountRef}
      id="threejs-mount"
      className="w-full h-full"
      style={{ minHeight: "320px" }}
    />
  );
}