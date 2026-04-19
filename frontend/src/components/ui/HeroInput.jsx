// src/components/ui/HeroInput.jsx
// Landing page hero — animated tagline + target input

import { useState, useEffect } from "react";

const TAGLINE_WORDS = ["IDENTIFY.", "ENUMERATE.", "EXPLOIT.", "REPORT."];

function TypewriterTagline() {
  const [text, setText]   = useState("");
  const [wordIdx, setWordIdx] = useState(0);
  const [charIdx, setCharIdx] = useState(0);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    const word    = TAGLINE_WORDS[wordIdx];
    const timeout = deleting
      ? 60
      : charIdx === word.length
        ? 1800
        : 100;

    const timer = setTimeout(() => {
      if (!deleting && charIdx < word.length) {
        setText(word.slice(0, charIdx + 1));
        setCharIdx(c => c + 1);
      } else if (!deleting && charIdx === word.length) {
        setDeleting(true);
      } else if (deleting && charIdx > 0) {
        setText(word.slice(0, charIdx - 1));
        setCharIdx(c => c - 1);
      } else {
        setDeleting(false);
        setWordIdx(i => (i + 1) % TAGLINE_WORDS.length);
        setCharIdx(0);
      }
    }, timeout);

    return () => clearTimeout(timer);
  }, [text, charIdx, deleting, wordIdx]);

  return (
    <span
      className="font-bold"
      style={{
        color:      "#00ff41",
        fontFamily: "var(--font-disp)",
        textShadow: "0 0 20px rgba(0,255,65,0.5), 0 0 60px rgba(0,255,65,0.2)",
      }}
    >
      {text}
      <span style={{ animation: "blink 1s step-end infinite", color: "#00ff41" }}>█</span>
    </span>
  );
}

export default function HeroInput({ onScan, onRepoScan, scanning }) {
  const [url, setUrl]         = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [focused, setFocused] = useState(false);
  const [repoFocused, setRepoFocused] = useState(false);

  const handleScan = () => {
    if ((!url.trim() && !repoUrl.trim()) || scanning) return;
    onScan({ url: url.trim(), repoUrl: repoUrl.trim() });
  };

  const handleRepoOnlyScan = () => {
    if (!repoUrl.trim() || scanning) return;
    onRepoScan(repoUrl.trim());
  };

  return (
    <div className="flex flex-col items-center text-center" style={{ position: "relative", zIndex: 10 }}>

      {/* ── Logo mark ── */}
      <div className="mb-8 flex items-center gap-3">
        <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
          <polygon points="20,2 38,11 38,29 20,38 2,29 2,11"
            stroke="#00ff41" strokeWidth="1.5" fill="none"
            style={{ filter: "drop-shadow(0 0 8px rgba(0,255,65,0.5))" }}/>
          <polygon points="20,8 32,15 32,25 20,32 8,25 8,15"
            fill="#00ff41" opacity="0.08"/>
          <circle cx="20" cy="20" r="4" fill="#00ff41"
            style={{ filter: "drop-shadow(0 0 6px rgba(0,255,65,0.8))" }}/>
          <line x1="20" y1="2"  x2="20" y2="8"  stroke="#00ff41" strokeWidth="1" opacity="0.5"/>
          <line x1="38" y1="11" x2="32" y2="15" stroke="#00ff41" strokeWidth="1" opacity="0.5"/>
          <line x1="38" y1="29" x2="32" y2="25" stroke="#00ff41" strokeWidth="1" opacity="0.5"/>
          <line x1="20" y1="38" x2="20" y2="32" stroke="#00ff41" strokeWidth="1" opacity="0.5"/>
          <line x1="2"  y1="29" x2="8"  y2="25" stroke="#00ff41" strokeWidth="1" opacity="0.5"/>
          <line x1="2"  y1="11" x2="8"  y2="15" stroke="#00ff41" strokeWidth="1" opacity="0.5"/>
        </svg>
        <div className="text-left">
          <div style={{ fontFamily: "var(--font-disp)", fontSize: "24px", fontWeight: 900, color: "#00ff41", letterSpacing: "0.1em", textShadow: "0 0 20px rgba(0,255,65,0.4)" }}>
            E-WMEAP
          </div>
          <div style={{ fontSize: "9px", color: "rgba(0,255,65,0.78)", letterSpacing: "0.2em", fontFamily: "var(--font-mono)" }}>
            ENTERPRISE WEB EXPOSURE ASSESSMENT
          </div>
        </div>
      </div>

      {/* ── Main headline ── */}
      <h1 className="mb-4" style={{ fontSize: "clamp(28px, 5vw, 52px)", lineHeight: 1.1 }}>
        <span style={{ color: "#c8ffd4", fontFamily: "var(--font-disp)", fontWeight: 900, letterSpacing: "0.05em" }}>
          BREACH
        </span>
        <br/>
        <span style={{ color: "#ffffff55", fontSize: "0.6em", fontFamily: "var(--font-mono)", fontWeight: 300, letterSpacing: "0.3em" }}>
          PROTOCOL
        </span>
      </h1>

      {/* ── Typewriter tagline ── */}
      <div className="mb-10" style={{ fontSize: "clamp(14px, 2vw, 20px)", fontFamily: "var(--font-disp)", letterSpacing: "0.15em" }}>
        <TypewriterTagline />
      </div>

      {/* ── Input block (below title/tagline) ── */}
      <div className="w-full max-w-2xl mb-6">
        {/* ── Web target input ── */}
        <div className="w-full max-w-2xl">
          <div
            className="flex items-center rounded-xl overflow-hidden transition-all duration-300"
            style={{
              border:     focused ? "1px solid rgba(0,255,65,0.7)" : "1px solid rgba(0,255,65,0.28)",
              background: "rgba(0,10,0,0.6)",
              backdropFilter: "blur(10px)",
              boxShadow:  focused
                ? "0 0 30px rgba(0,255,65,0.2), inset 0 0 30px rgba(0,255,65,0.04)"
                : "0 0 10px rgba(0,255,65,0.08)",
            }}
          >
            <div className="px-4 py-4 flex-shrink-0 flex items-center gap-2">
              <span style={{ color: "rgba(0,255,65,0.78)", fontSize: "11px", letterSpacing: "0.2em" }}>TARGET</span>
              <span style={{ color: "rgba(0,255,65,0.55)" }}>›</span>
            </div>

            <input
              type="text"
              value={url}
              onChange={e => setUrl(e.target.value)}
              onFocus={() => setFocused(true)}
              onBlur={() => setFocused(false)}
              onKeyDown={e => e.key === "Enter" && handleScan()}
              placeholder="https://target.example.com"
              disabled={scanning}
              style={{
                flex:        1,
                background:  "transparent",
                border:      "none",
                outline:     "none",
                color:       "#00ff41",
                fontFamily:  "var(--font-mono)",
                fontSize:    "14px",
                padding:     "16px 0",
                caretColor:  "#00ff41",
              }}
            />

            <button
              onClick={handleScan}
              disabled={scanning || (!url.trim() && !repoUrl.trim())}
              style={{
                margin:     "8px",
                padding:    "12px 28px",
                background: scanning ? "rgba(0,255,65,0.05)" : "rgba(0,255,65,0.15)",
                border:     "1px solid rgba(0,255,65,0.4)",
                borderRadius: "8px",
                color:      "#00ff41",
                fontFamily: "var(--font-disp)",
                fontSize:   "11px",
                fontWeight: 700,
                letterSpacing: "0.15em",
                cursor:     scanning || (!url.trim() && !repoUrl.trim()) ? "not-allowed" : "pointer",
                transition: "all 0.2s",
                opacity:    (!url.trim() && !repoUrl.trim()) ? 0.4 : 1,
                boxShadow:  !scanning && (url.trim() || repoUrl.trim())
                  ? "0 0 15px rgba(0,255,65,0.2)"
                  : "none",
              }}
              onMouseEnter={e => { if (!scanning && (url.trim() || repoUrl.trim())) e.target.style.background = "rgba(0,255,65,0.25)"; }}
              onMouseLeave={e => { e.target.style.background = scanning ? "rgba(0,255,65,0.05)" : "rgba(0,255,65,0.15)"; }}
            >
              {scanning ? (
                <span style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span style={{ animation: "statusPulse 1s infinite" }}>◉</span>
                  SCANNING
                </span>
              ) : "INITIATE"}
            </button>
          </div>
        </div>

        {/* ── GitHub repo input ── */}
        <div className="w-full max-w-2xl mt-4">
          <div
            className="flex items-center rounded-xl overflow-hidden transition-all duration-300"
            style={{
              border:     repoFocused ? "1px solid rgba(167,139,250,0.78)" : "1px solid rgba(167,139,250,0.35)",
              background: "rgba(15,10,30,0.6)",
              backdropFilter: "blur(10px)",
              boxShadow:  repoFocused
                ? "0 0 30px rgba(167,139,250,0.25), inset 0 0 30px rgba(167,139,250,0.06)"
                : "0 0 10px rgba(167,139,250,0.12)",
            }}
          >
            <div className="px-4 py-4 flex-shrink-0 flex items-center gap-2">
              <span style={{ color: "rgba(196,181,253,0.9)", fontSize: "11px", letterSpacing: "0.2em" }}>GITHUB</span>
              <span style={{ color: "rgba(196,181,253,0.6)" }}>›</span>
            </div>

            <input
              type="text"
              value={repoUrl}
              onChange={e => setRepoUrl(e.target.value)}
              onFocus={() => setRepoFocused(true)}
              onBlur={() => setRepoFocused(false)}
              onKeyDown={e => e.key === "Enter" && handleRepoOnlyScan()}
              placeholder="https://github.com/owner/repo"
              disabled={scanning}
              style={{
                flex:        1,
                background:  "transparent",
                border:      "none",
                outline:     "none",
                color:       "#c4b5fd",
                fontFamily:  "var(--font-mono)",
                fontSize:    "14px",
                padding:     "16px 0",
                caretColor:  "#a78bfa",
              }}
            />

            <button
              onClick={handleRepoOnlyScan}
              disabled={scanning || !repoUrl.trim()}
              style={{
                margin: "8px",
                padding: "12px 18px",
                background: scanning ? "rgba(167,139,250,0.08)" : "rgba(167,139,250,0.2)",
                border: "1px solid rgba(167,139,250,0.45)",
                borderRadius: "8px",
                color: "#c4b5fd",
                fontFamily: "var(--font-disp)",
                fontSize: "10px",
                fontWeight: 700,
                letterSpacing: "0.14em",
                cursor: scanning || !repoUrl.trim() ? "not-allowed" : "pointer",
                transition: "all 0.2s",
                opacity: !repoUrl.trim() ? 0.45 : 1,
                boxShadow: !scanning && repoUrl.trim() ? "0 0 14px rgba(167,139,250,0.28)" : "none",
              }}
              onMouseEnter={e => { if (!scanning && repoUrl.trim()) e.target.style.background = "rgba(167,139,250,0.3)"; }}
              onMouseLeave={e => { e.target.style.background = scanning ? "rgba(167,139,250,0.08)" : "rgba(167,139,250,0.2)"; }}
            >
              {scanning ? "SCANNING" : "SCAN REPO"}
            </button>
          </div>
        </div>

        <p style={{ color: "rgba(226,232,240,0.82)", fontSize: "10px", marginTop: "12px", letterSpacing: "0.1em" }}>
          ENTER WEB TARGET, GITHUB REPO, OR BOTH. PRESS ENTER OR CLICK INITIATE TO BEGIN.
        </p>
      </div>

      {/* ── Stats strip ── */}
      <div className="flex gap-8 mt-4" style={{ color: "rgba(226,232,240,0.75)", fontSize: "10px", letterSpacing: "0.15em" }}>
        {[
          { label: "MODULES",   value: "7" },
          { label: "CHECKS",    value: "200+" },
          { label: "CVE DB",    value: "LIVE" },
          { label: "COST",      value: "$0" },
        ].map(s => (
          <div key={s.label} className="text-center">
            <div style={{ color: "#00ff41", fontSize: "18px", fontFamily: "var(--font-disp)", fontWeight: 700, textShadow: "0 0 10px rgba(0,255,65,0.4)" }}>
              {s.value}
            </div>
            <div>{s.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}