// src/components/ui/ParticleField.jsx
// Animated floating data particles — always running in background

import { useEffect, useRef } from "react";

export default function ParticleField() {
  const canvasRef = useRef(null);
  const frameRef  = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx    = canvas.getContext("2d");

    const resize = () => {
      canvas.width  = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener("resize", resize);

    // ── Particle class ────────────────────────────────────────────────
    const CHARS = "01アイウエオカキクケコサシスセソタチツテト<>{}[]//\\|=+-*&^%$#@!?";

    class Particle {
      constructor() { this.reset(); }
      reset() {
        this.x    = Math.random() * canvas.width;
        this.y    = Math.random() * canvas.height;
        this.vy   = 0.3 + Math.random() * 0.8;
        this.vx   = (Math.random() - 0.5) * 0.2;
        this.char = CHARS[Math.floor(Math.random() * CHARS.length)];
        this.size = 9 + Math.random() * 5;
        this.life = 0;
        this.maxLife = 80 + Math.random() * 120;
        this.type = Math.random() < 0.3 ? "matrix" : "binary";
        this.changeTimer = 0;
        // Color variety: mostly green, occasional blue/red
        const r = Math.random();
        this.color = r < 0.7 ? "#00ff41" : r < 0.9 ? "#0080ff" : "#ff0040";
      }
      update() {
        this.y += this.vy;
        this.x += this.vx;
        this.life++;
        this.changeTimer++;
        if (this.changeTimer > 15) {
          this.char = CHARS[Math.floor(Math.random() * CHARS.length)];
          this.changeTimer = 0;
        }
        if (this.y > canvas.height + 20 || this.life > this.maxLife) {
          this.reset();
          this.y = -10;
        }
      }
      draw() {
        const alpha = Math.min(
          this.life / 20,
          1 - (this.life - this.maxLife * 0.7) / (this.maxLife * 0.3),
          0.5
        );
        ctx.globalAlpha = Math.max(0, alpha);
        ctx.fillStyle   = this.color;
        ctx.font        = `${this.size}px 'JetBrains Mono', monospace`;
        ctx.fillText(this.char, this.x, this.y);
      }
    }

    // ── Connection lines ──────────────────────────────────────────────
    class ConnectionLine {
      constructor() { this.reset(); }
      reset() {
        this.x1    = Math.random() * canvas.width;
        this.y1    = Math.random() * canvas.height;
        this.x2    = this.x1 + (Math.random() - 0.5) * 200;
        this.y2    = this.y1 + (Math.random() - 0.5) * 200;
        this.alpha = 0;
        this.maxA  = 0.06 + Math.random() * 0.08;
        this.phase = 0;
        this.speed = 0.02 + Math.random() * 0.03;
      }
      update() {
        this.phase += this.speed;
        this.alpha = Math.sin(this.phase) * this.maxA;
        if (this.phase > Math.PI * 2) this.reset();
      }
      draw() {
        if (this.alpha <= 0) return;
        ctx.globalAlpha = this.alpha;
        ctx.strokeStyle = "#00ff41";
        ctx.lineWidth   = 0.5;
        ctx.beginPath();
        ctx.moveTo(this.x1, this.y1);
        ctx.lineTo(this.x2, this.y2);
        ctx.stroke();
      }
    }

    // Initialise particles
    const COUNT_P = Math.min(80, Math.floor(canvas.width * canvas.height / 12000));
    const COUNT_L = 20;
    const particles = Array.from({ length: COUNT_P }, () => new Particle());
    const lines     = Array.from({ length: COUNT_L }, () => new ConnectionLine());

    // Stagger initial positions
    particles.forEach((p, i) => {
      p.y = (i / COUNT_P) * canvas.height;
    });

    const loop = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.globalAlpha = 1;

      lines.forEach(l => { l.update(); l.draw(); });
      particles.forEach(p => { p.update(); p.draw(); });

      ctx.globalAlpha = 1;
      frameRef.current = requestAnimationFrame(loop);
    };

    loop();

    return () => {
      window.removeEventListener("resize", resize);
      cancelAnimationFrame(frameRef.current);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      id="particle-canvas"
      className="fixed inset-0 pointer-events-none"
      style={{ zIndex: 1 }}
    />
  );
}