import { useState, useEffect, useRef } from "react";

const COLORS = {
  bg: "#0a0c10",
  surface: "#12151c",
  surfaceRaised: "#181c25",
  border: "#252a36",
  borderSubtle: "#1c2029",
  text: "#e2e4e9",
  textMuted: "#8b919e",
  textDim: "#565c6a",
  accent: "#c9945a",
  accentMuted: "rgba(201,148,90,0.12)",
  accentBorder: "rgba(201,148,90,0.25)",
  red: "#d4534b",
  redMuted: "rgba(212,83,75,0.12)",
  green: "#5a9e6f",
  greenMuted: "rgba(90,158,111,0.12)",
  blue: "#5a8ec9",
  blueMuted: "rgba(90,142,201,0.12)",
};

const mono = "'IBM Plex Mono', 'JetBrains Mono', 'Fira Code', monospace";
const sans = "'IBM Plex Sans', -apple-system, BlinkMacSystemFont, sans-serif";

// Typing animation hook
function useTyping(text, speed = 40, delay = 0, active = true) {
  const [displayed, setDisplayed] = useState("");
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (!active) return;
    setDisplayed("");
    setDone(false);
    const timeout = setTimeout(() => {
      let i = 0;
      const interval = setInterval(() => {
        i++;
        setDisplayed(text.slice(0, i));
        if (i >= text.length) {
          clearInterval(interval);
          setDone(true);
        }
      }, speed);
      return () => clearInterval(interval);
    }, delay);
    return () => clearTimeout(timeout);
  }, [text, speed, delay, active]);
  return [displayed, done];
}

function Cursor() {
  const [visible, setVisible] = useState(true);
  useEffect(() => {
    const i = setInterval(() => setVisible((v) => !v), 530);
    return () => clearInterval(i);
  }, []);
  return (
    <span
      style={{
        display: "inline-block",
        width: 8,
        height: 16,
        background: visible ? COLORS.accent : "transparent",
        marginLeft: 2,
        verticalAlign: "text-bottom",
      }}
    />
  );
}

function TerminalWindow({ title, children, style }) {
  return (
    <div
      style={{
        background: COLORS.surface,
        border: `1px solid ${COLORS.border}`,
        borderRadius: 8,
        overflow: "hidden",
        ...style,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "10px 16px",
          background: COLORS.surfaceRaised,
          borderBottom: `1px solid ${COLORS.border}`,
        }}
      >
        <div style={{ display: "flex", gap: 6 }}>
          <div
            style={{
              width: 10,
              height: 10,
              borderRadius: "50%",
              background: "#3a3e47",
            }}
          />
          <div
            style={{
              width: 10,
              height: 10,
              borderRadius: "50%",
              background: "#3a3e47",
            }}
          />
          <div
            style={{
              width: 10,
              height: 10,
              borderRadius: "50%",
              background: "#3a3e47",
            }}
          />
        </div>
        <span
          style={{
            fontFamily: mono,
            fontSize: 11,
            color: COLORS.textDim,
            marginLeft: 8,
          }}
        >
          {title}
        </span>
      </div>
      <div style={{ padding: "16px 20px", fontFamily: mono, fontSize: 13, lineHeight: 1.7 }}>
        {children}
      </div>
    </div>
  );
}

function PromptLine({ prompt = "❯", children }) {
  return (
    <div>
      <span style={{ color: COLORS.textDim }}>{prompt} </span>
      <span style={{ color: COLORS.text }}>{children}</span>
    </div>
  );
}

function OutputLine({ children, color, indent = 0 }) {
  return (
    <div style={{ color: color || COLORS.textMuted, paddingLeft: indent * 16 }}>
      {children}
    </div>
  );
}

function Badge({ children, color = COLORS.accent }) {
  return (
    <span
      style={{
        display: "inline-block",
        fontFamily: mono,
        fontSize: 10,
        fontWeight: 600,
        letterSpacing: "0.08em",
        textTransform: "uppercase",
        color: color,
        background: color === COLORS.accent ? COLORS.accentMuted : `${color}18`,
        border: `1px solid ${color === COLORS.accent ? COLORS.accentBorder : `${color}30`}`,
        padding: "3px 8px",
        borderRadius: 4,
      }}
    >
      {children}
    </span>
  );
}

function FeatureCard({ title, description, badge, details }) {
  return (
    <div
      style={{
        background: COLORS.surface,
        border: `1px solid ${COLORS.border}`,
        borderRadius: 8,
        padding: 28,
        flex: 1,
        minWidth: 280,
      }}
    >
      <div style={{ marginBottom: 12 }}>
        <Badge>{badge}</Badge>
      </div>
      <h3
        style={{
          fontFamily: sans,
          fontSize: 18,
          fontWeight: 600,
          color: COLORS.text,
          margin: "0 0 10px",
          letterSpacing: "-0.01em",
        }}
      >
        {title}
      </h3>
      <p
        style={{
          fontFamily: sans,
          fontSize: 14,
          color: COLORS.textMuted,
          margin: "0 0 18px",
          lineHeight: 1.6,
        }}
      >
        {description}
      </p>
      <div
        style={{
          borderTop: `1px solid ${COLORS.borderSubtle}`,
          paddingTop: 14,
        }}
      >
        {details.map((d, i) => (
          <div
            key={i}
            style={{
              fontFamily: mono,
              fontSize: 12,
              color: COLORS.textDim,
              padding: "4px 0",
              display: "flex",
              alignItems: "flex-start",
              gap: 8,
            }}
          >
            <span style={{ color: COLORS.accent, flexShrink: 0 }}>—</span>
            <span>{d}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function CompetitorRow({ name, sentinel, firewall, budget, vibeUx }) {
  const Cell = ({ value }) => {
    if (value === true)
      return <span style={{ color: COLORS.green, fontWeight: 600 }}>Yes</span>;
    if (value === false)
      return <span style={{ color: COLORS.textDim }}>No</span>;
    return <span style={{ color: COLORS.accent }}>{value}</span>;
  };
  return (
    <tr style={{ borderBottom: `1px solid ${COLORS.borderSubtle}` }}>
      <td
        style={{
          padding: "10px 16px",
          fontFamily: mono,
          fontSize: 12,
          color: COLORS.text,
          fontWeight: name === "Sanctum" ? 600 : 400,
        }}
      >
        {name}
      </td>
      <td style={{ padding: "10px 16px", textAlign: "center", fontSize: 12 }}>
        <Cell value={sentinel} />
      </td>
      <td style={{ padding: "10px 16px", textAlign: "center", fontSize: 12 }}>
        <Cell value={firewall} />
      </td>
      <td style={{ padding: "10px 16px", textAlign: "center", fontSize: 12 }}>
        <Cell value={budget} />
      </td>
      <td style={{ padding: "10px 16px", textAlign: "center", fontSize: 12 }}>
        <Cell value={vibeUx} />
      </td>
    </tr>
  );
}

function ArchDiagram() {
  const boxStyle = (highlight) => ({
    padding: "10px 14px",
    borderRadius: 6,
    fontFamily: mono,
    fontSize: 11,
    textAlign: "center",
    border: `1px solid ${highlight ? COLORS.accentBorder : COLORS.border}`,
    background: highlight ? COLORS.accentMuted : COLORS.surfaceRaised,
    color: highlight ? COLORS.accent : COLORS.textMuted,
  });

  return (
    <div
      style={{
        background: COLORS.surface,
        border: `1px solid ${COLORS.border}`,
        borderRadius: 8,
        padding: 32,
      }}
    >
      <div style={{ textAlign: "center", marginBottom: 24 }}>
        <span
          style={{
            fontFamily: mono,
            fontSize: 10,
            color: COLORS.textDim,
            letterSpacing: "0.1em",
            textTransform: "uppercase",
          }}
        >
          Composable Defence Stack
        </span>
      </div>

      {/* Developer tools row */}
      <div
        style={{
          display: "flex",
          gap: 12,
          justifyContent: "center",
          marginBottom: 16,
        }}
      >
        <div style={boxStyle(false)}>Python / Node</div>
        <div style={boxStyle(false)}>Claude Code</div>
        <div style={boxStyle(false)}>Cursor / IDE</div>
      </div>

      <div style={{ textAlign: "center", color: COLORS.textDim, fontSize: 11, margin: "4px 0" }}>
        │
      </div>

      {/* Sanctum */}
      <div
        style={{
          border: `1px solid ${COLORS.accentBorder}`,
          borderRadius: 8,
          padding: 20,
          margin: "8px 0",
          background: COLORS.accentMuted,
        }}
      >
        <div
          style={{
            fontFamily: mono,
            fontSize: 11,
            fontWeight: 600,
            color: COLORS.accent,
            textAlign: "center",
            marginBottom: 14,
            letterSpacing: "0.06em",
          }}
        >
          SANCTUM DAEMON
        </div>
        <div style={{ display: "flex", gap: 10, justifyContent: "center", flexWrap: "wrap" }}>
          <div style={boxStyle(true)}>Sentinel<br /><span style={{fontSize: 9, color: COLORS.textDim}}>.pth watch · proc mon</span></div>
          <div style={boxStyle(true)}>AI Firewall<br /><span style={{fontSize: 9, color: COLORS.textDim}}>prompt redact · hooks</span></div>
          <div style={boxStyle(true)}>Budget Ctrl<br /><span style={{fontSize: 9, color: COLORS.textDim}}>spend limits · alerts</span></div>
        </div>
      </div>

      <div style={{ textAlign: "center", color: COLORS.textDim, fontSize: 11, margin: "4px 0" }}>
        │
      </div>

      {/* Integration layer */}
      <div
        style={{
          border: `1px solid ${COLORS.border}`,
          borderRadius: 8,
          padding: 16,
          margin: "8px 0",
        }}
      >
        <div
          style={{
            fontFamily: mono,
            fontSize: 10,
            color: COLORS.textDim,
            textAlign: "center",
            marginBottom: 12,
            letterSpacing: "0.06em",
            textTransform: "uppercase",
          }}
        >
          Integrations (optional)
        </div>
        <div style={{ display: "flex", gap: 10, justifyContent: "center", flexWrap: "wrap" }}>
          <div style={boxStyle(false)}>nono<br /><span style={{fontSize: 9}}>sandbox + proxy</span></div>
          <div style={boxStyle(false)}>Socket.dev<br /><span style={{fontSize: 9}}>dep scanning</span></div>
          <div style={boxStyle(false)}>1Pass / Doppler<br /><span style={{fontSize: 9}}>vault backend</span></div>
          <div style={boxStyle(false)}>Sigstore<br /><span style={{fontSize: 9}}>provenance</span></div>
        </div>
      </div>
    </div>
  );
}

function AttackTimeline() {
  const steps = [
    { time: "T+0s", event: "Malicious .pth installed via pip", sanctum: "Quarantined instantly", status: "blocked" },
    { time: "T+0s", event: ".pth tries to exec base64 payload", sanctum: "File replaced with empty stub", status: "blocked" },
    { time: "T+1s", event: "Attacker reads os.environ for API keys", sanctum: "Finds phantom tokens (if nono) or real keys", status: "partial" },
    { time: "T+2s", event: "Encrypted POST to C2 domain (1 day old)", sanctum: "Network anomaly alert fired", status: "detected" },
    { time: "T+5s", event: "Developer notified, package quarantined", sanctum: "`sanctum review` shows full context", status: "resolved" },
  ];

  return (
    <div
      style={{
        background: COLORS.surface,
        border: `1px solid ${COLORS.border}`,
        borderRadius: 8,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          padding: "14px 20px",
          borderBottom: `1px solid ${COLORS.border}`,
          background: COLORS.surfaceRaised,
        }}
      >
        <span
          style={{
            fontFamily: mono,
            fontSize: 10,
            color: COLORS.textDim,
            letterSpacing: "0.1em",
            textTransform: "uppercase",
          }}
        >
          TeamPCP Attack vs. Sanctum — simulated timeline
        </span>
      </div>
      <div style={{ padding: "4px 0" }}>
        {steps.map((s, i) => (
          <div
            key={i}
            style={{
              display: "flex",
              alignItems: "flex-start",
              padding: "10px 20px",
              borderBottom:
                i < steps.length - 1 ? `1px solid ${COLORS.borderSubtle}` : "none",
              gap: 16,
            }}
          >
            <span
              style={{
                fontFamily: mono,
                fontSize: 11,
                color: COLORS.textDim,
                flexShrink: 0,
                width: 40,
              }}
            >
              {s.time}
            </span>
            <span
              style={{
                fontFamily: sans,
                fontSize: 13,
                color: COLORS.textMuted,
                flex: 1,
              }}
            >
              {s.event}
            </span>
            <span
              style={{
                fontFamily: mono,
                fontSize: 12,
                color:
                  s.status === "blocked"
                    ? COLORS.green
                    : s.status === "detected"
                    ? COLORS.accent
                    : COLORS.blue,
                flexShrink: 0,
                textAlign: "right",
                maxWidth: 240,
              }}
            >
              {s.sanctum}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function SanctumMockup() {
  const [activeTab, setActiveTab] = useState("overview");

  return (
    <div
      style={{
        background: COLORS.bg,
        color: COLORS.text,
        minHeight: "100vh",
        fontFamily: sans,
      }}
    >
      {/* Noise texture overlay */}
      <div
        style={{
          position: "fixed",
          inset: 0,
          pointerEvents: "none",
          opacity: 0.025,
          backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")`,
          backgroundSize: 200,
          zIndex: 0,
        }}
      />

      <div
        style={{
          maxWidth: 920,
          margin: "0 auto",
          padding: "48px 24px 80px",
          position: "relative",
          zIndex: 1,
        }}
      >
        {/* Header */}
        <header style={{ marginBottom: 56 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              marginBottom: 48,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              {/* Logo mark */}
              <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
                <rect
                  x="2"
                  y="2"
                  width="24"
                  height="24"
                  rx="4"
                  stroke={COLORS.accent}
                  strokeWidth="1.5"
                  fill="none"
                />
                <rect
                  x="8"
                  y="8"
                  width="12"
                  height="12"
                  rx="2"
                  stroke={COLORS.accent}
                  strokeWidth="1.5"
                  fill={COLORS.accentMuted}
                />
                <rect
                  x="12"
                  y="12"
                  width="4"
                  height="4"
                  rx="1"
                  fill={COLORS.accent}
                />
              </svg>
              <span
                style={{
                  fontFamily: mono,
                  fontSize: 16,
                  fontWeight: 600,
                  color: COLORS.text,
                  letterSpacing: "0.04em",
                }}
              >
                sanctum
              </span>
            </div>
            <div style={{ display: "flex", gap: 20, alignItems: "center" }}>
              <span
                style={{
                  fontFamily: mono,
                  fontSize: 12,
                  color: COLORS.textDim,
                }}
              >
                v0.1.0
              </span>
              <a
                href="#"
                style={{
                  fontFamily: mono,
                  fontSize: 12,
                  color: COLORS.textMuted,
                  textDecoration: "none",
                }}
              >
                Docs
              </a>
              <a
                href="#"
                style={{
                  fontFamily: mono,
                  fontSize: 12,
                  color: COLORS.textMuted,
                  textDecoration: "none",
                }}
              >
                GitHub
              </a>
            </div>
          </div>

          {/* Hero */}
          <div style={{ maxWidth: 680 }}>
            <div style={{ marginBottom: 16 }}>
              <Badge>Open Source — MIT License</Badge>
            </div>
            <h1
              style={{
                fontFamily: sans,
                fontSize: 36,
                fontWeight: 700,
                color: COLORS.text,
                margin: "0 0 18px",
                lineHeight: 1.2,
                letterSpacing: "-0.025em",
              }}
            >
              The developer security daemon
              <br />
              for the AI coding era.
            </h1>
            <p
              style={{
                fontFamily: sans,
                fontSize: 16,
                color: COLORS.textMuted,
                margin: "0 0 28px",
                lineHeight: 1.65,
                maxWidth: 560,
              }}
            >
              Runtime integrity monitoring, AI credential firewall, and LLM spend enforcement. Catches .pth injection attacks, redacts credentials from AI prompts, and prevents runaway API bills — without interrupting your flow.
            </p>
            <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
              <div
                style={{
                  fontFamily: mono,
                  fontSize: 13,
                  color: COLORS.text,
                  background: COLORS.surfaceRaised,
                  border: `1px solid ${COLORS.border}`,
                  padding: "10px 18px",
                  borderRadius: 6,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 10,
                }}
              >
                <span style={{ color: COLORS.textDim }}>$</span>
                brew install sanctum
                <span
                  style={{
                    color: COLORS.textDim,
                    fontSize: 10,
                    marginLeft: 4,
                    borderLeft: `1px solid ${COLORS.border}`,
                    paddingLeft: 10,
                  }}
                >
                  copy
                </span>
              </div>
              <span style={{ fontFamily: sans, fontSize: 13, color: COLORS.textDim }}>
                Single binary. No runtime dependencies.
              </span>
            </div>
          </div>
        </header>

        {/* Tab navigation */}
        <nav
          style={{
            display: "flex",
            gap: 0,
            borderBottom: `1px solid ${COLORS.border}`,
            marginBottom: 36,
          }}
        >
          {[
            ["overview", "Overview"],
            ["sentinel", "Sentinel"],
            ["firewall", "AI Firewall"],
            ["budget", "Budget"],
          ].map(([key, label]) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              style={{
                fontFamily: mono,
                fontSize: 12,
                color: activeTab === key ? COLORS.accent : COLORS.textDim,
                background: "transparent",
                border: "none",
                borderBottom:
                  activeTab === key
                    ? `2px solid ${COLORS.accent}`
                    : "2px solid transparent",
                padding: "10px 18px",
                cursor: "pointer",
                letterSpacing: "0.02em",
                transition: "color 0.15s",
              }}
            >
              {label}
            </button>
          ))}
        </nav>

        {/* Overview tab */}
        {activeTab === "overview" && (
          <div>
            {/* Three features */}
            <div
              style={{
                display: "flex",
                gap: 16,
                marginBottom: 40,
                flexWrap: "wrap",
              }}
            >
              <FeatureCard
                badge="Sentinel"
                title="Runtime integrity monitoring"
                description="Watches Python startup hooks, credential file access, and process behaviour. Catches .pth injection — the exact vector used in the LiteLLM compromise — with near-zero false positives."
                details={[
                  ".pth file monitoring with process lineage analysis",
                  "Credential file access alerts (SSH, AWS, GCP, K8s)",
                  "Quarantine protocol with guided review",
                  "MITRE ATT&CK T1546.018 mitigation",
                ]}
              />
              <FeatureCard
                badge="AI Firewall"
                title="Credential protection for AI workflows"
                description="Scans outbound prompts for leaked credentials, hooks into Claude Code tool execution, and audits MCP server interactions — before sensitive data leaves your machine."
                details={[
                  "Prompt credential redaction (regex + entropy)",
                  "Claude Code PreToolUse / PostToolUse hooks",
                  "MCP tool auditing with policy restrictions",
                  "Command sandboxing for AI-generated shell",
                ]}
              />
              <FeatureCard
                badge="Budget"
                title="LLM spend enforcement"
                description="Per-session and per-provider spending limits with real-time tracking. Hard stops before runaway API bills. Works with any LLM proxy or direct API calls."
                details={[
                  "Per-session, per-day, per-provider budgets",
                  "Real-time cost tracking from API responses",
                  "Model restrictions (allow/deny specific models)",
                  "Desktop notifications at configurable thresholds",
                ]}
              />
            </div>

            {/* Architecture */}
            <div style={{ marginBottom: 40 }}>
              <h2
                style={{
                  fontFamily: sans,
                  fontSize: 14,
                  fontWeight: 600,
                  color: COLORS.textDim,
                  letterSpacing: "0.06em",
                  textTransform: "uppercase",
                  margin: "0 0 16px",
                }}
              >
                Composable architecture
              </h2>
              <ArchDiagram />
            </div>

            {/* Attack timeline */}
            <div style={{ marginBottom: 40 }}>
              <h2
                style={{
                  fontFamily: sans,
                  fontSize: 14,
                  fontWeight: 600,
                  color: COLORS.textDim,
                  letterSpacing: "0.06em",
                  textTransform: "uppercase",
                  margin: "0 0 16px",
                }}
              >
                Defence against the TeamPCP attack chain
              </h2>
              <AttackTimeline />
            </div>

            {/* Competitive table */}
            <div style={{ marginBottom: 40 }}>
              <h2
                style={{
                  fontFamily: sans,
                  fontSize: 14,
                  fontWeight: 600,
                  color: COLORS.textDim,
                  letterSpacing: "0.06em",
                  textTransform: "uppercase",
                  margin: "0 0 16px",
                }}
              >
                What exists today
              </h2>
              <div
                style={{
                  background: COLORS.surface,
                  border: `1px solid ${COLORS.border}`,
                  borderRadius: 8,
                  overflow: "hidden",
                }}
              >
                <table
                  style={{
                    width: "100%",
                    borderCollapse: "collapse",
                    fontFamily: mono,
                  }}
                >
                  <thead>
                    <tr
                      style={{
                        borderBottom: `1px solid ${COLORS.border}`,
                        background: COLORS.surfaceRaised,
                      }}
                    >
                      <th
                        style={{
                          padding: "10px 16px",
                          textAlign: "left",
                          fontSize: 10,
                          color: COLORS.textDim,
                          fontWeight: 500,
                          letterSpacing: "0.08em",
                          textTransform: "uppercase",
                        }}
                      >
                        Tool
                      </th>
                      <th
                        style={{
                          padding: "10px 16px",
                          textAlign: "center",
                          fontSize: 10,
                          color: COLORS.textDim,
                          fontWeight: 500,
                          letterSpacing: "0.08em",
                          textTransform: "uppercase",
                        }}
                      >
                        .pth Monitor
                      </th>
                      <th
                        style={{
                          padding: "10px 16px",
                          textAlign: "center",
                          fontSize: 10,
                          color: COLORS.textDim,
                          fontWeight: 500,
                          letterSpacing: "0.08em",
                          textTransform: "uppercase",
                        }}
                      >
                        AI Firewall
                      </th>
                      <th
                        style={{
                          padding: "10px 16px",
                          textAlign: "center",
                          fontSize: 10,
                          color: COLORS.textDim,
                          fontWeight: 500,
                          letterSpacing: "0.08em",
                          textTransform: "uppercase",
                        }}
                      >
                        Spend Ctrl
                      </th>
                      <th
                        style={{
                          padding: "10px 16px",
                          textAlign: "center",
                          fontSize: 10,
                          color: COLORS.textDim,
                          fontWeight: 500,
                          letterSpacing: "0.08em",
                          textTransform: "uppercase",
                        }}
                      >
                        Vibe UX
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    <CompetitorRow
                      name="nono.sh"
                      sentinel={false}
                      firewall={false}
                      budget={false}
                      vibeUx={true}
                    />
                    <CompetitorRow
                      name="API Stronghold"
                      sentinel={false}
                      firewall={false}
                      budget={false}
                      vibeUx={false}
                    />
                    <CompetitorRow
                      name="Beyond Identity"
                      sentinel={false}
                      firewall="Partial"
                      budget={false}
                      vibeUx={false}
                    />
                    <CompetitorRow
                      name="Socket.dev"
                      sentinel={false}
                      firewall={false}
                      budget={false}
                      vibeUx={false}
                    />
                    <CompetitorRow
                      name="1Password CLI"
                      sentinel={false}
                      firewall={false}
                      budget={false}
                      vibeUx={true}
                    />
                    <CompetitorRow
                      name="Sanctum"
                      sentinel={true}
                      firewall={true}
                      budget={true}
                      vibeUx={true}
                    />
                  </tbody>
                </table>
              </div>
            </div>

            {/* Positioning */}
            <div
              style={{
                background: COLORS.surface,
                border: `1px solid ${COLORS.border}`,
                borderRadius: 8,
                padding: 32,
                textAlign: "center",
              }}
            >
              <p
                style={{
                  fontFamily: sans,
                  fontSize: 17,
                  color: COLORS.textMuted,
                  margin: 0,
                  lineHeight: 1.7,
                  maxWidth: 620,
                  marginLeft: "auto",
                  marginRight: "auto",
                }}
              >
                nono keeps untrusted code from reaching your credentials.
                <br />
                <span style={{ color: COLORS.text }}>
                  Sanctum watches what happens when code runs
                </span>{" "}
                — catching .pth injection, AI credential leaks, and runaway LLM spend before they become incidents.
              </p>
            </div>
          </div>
        )}

        {/* Sentinel tab */}
        {activeTab === "sentinel" && (
          <div>
            <div style={{ marginBottom: 32 }}>
              <h2
                style={{
                  fontFamily: sans,
                  fontSize: 22,
                  fontWeight: 600,
                  color: COLORS.text,
                  margin: "0 0 10px",
                  letterSpacing: "-0.01em",
                }}
              >
                The .pth attack vector — detected and neutralised
              </h2>
              <p
                style={{
                  fontFamily: sans,
                  fontSize: 14,
                  color: COLORS.textMuted,
                  margin: 0,
                  maxWidth: 600,
                  lineHeight: 1.6,
                }}
              >
                MITRE ATT&CK T1546.018 states this technique "cannot be easily mitigated with preventive controls." Sanctum's process-lineage-aware file monitoring proves otherwise.
              </p>
            </div>

            {/* Malicious vs benign */}
            <div style={{ display: "flex", gap: 16, marginBottom: 32, flexWrap: "wrap" }}>
              <TerminalWindow title="benign.pth — path entry only" style={{ flex: 1, minWidth: 300 }}>
                <OutputLine color={COLORS.green}>/usr/local/lib/python3.12/</OutputLine>
                <OutputLine color={COLORS.green}>dist-packages/setuptools</OutputLine>
                <div style={{ marginTop: 12, borderTop: `1px solid ${COLORS.borderSubtle}`, paddingTop: 10 }}>
                  <OutputLine color={COLORS.textDim}>
                    Sanctum: <span style={{ color: COLORS.green }}>OK</span> — path entry, no executable code
                  </OutputLine>
                </div>
              </TerminalWindow>
              <TerminalWindow title="litellm_init.pth — obfuscated payload" style={{ flex: 1, minWidth: 300 }}>
                <OutputLine color={COLORS.red}>
                  import base64;exec(base64.b64decode(
                </OutputLine>
                <OutputLine color={COLORS.red}>
                  &nbsp;&nbsp;"aW1wb3J0IG9zO2ltcG9ydCBz..."
                </OutputLine>
                <OutputLine color={COLORS.red}>))</OutputLine>
                <div style={{ marginTop: 12, borderTop: `1px solid ${COLORS.borderSubtle}`, paddingTop: 10 }}>
                  <OutputLine color={COLORS.textDim}>
                    Sanctum: <span style={{ color: COLORS.red }}>CRITICAL</span> — executable code with base64 obfuscation. Quarantined.
                  </OutputLine>
                </div>
              </TerminalWindow>
            </div>

            {/* Review flow */}
            <TerminalWindow title="sanctum review" style={{ marginBottom: 32 }}>
              <PromptLine>sanctum review</PromptLine>
              <OutputLine />
              <OutputLine color={COLORS.accent}>
                &nbsp;&nbsp;1 item needs review
              </OutputLine>
              <OutputLine />
              <OutputLine color={COLORS.text}>
                &nbsp;&nbsp;1. Quarantined .pth file: litellm_init.pth
              </OutputLine>
              <OutputLine indent={2}>
                Created: 2 minutes ago by pip install litellm==1.82.8
              </OutputLine>
              <OutputLine indent={2}>
                Risk: <span style={{ color: COLORS.red }}>HIGH</span> — executable
                code (base64-encoded payload, 34,628 bytes)
              </OutputLine>
              <OutputLine indent={2}>
                Process: pip (PID 48291) → python3.12 (PID 48102) → zsh (PID 1204)
              </OutputLine>
              <OutputLine />
              <OutputLine indent={2}>Content preview:</OutputLine>
              <OutputLine indent={2} color={COLORS.red}>
                import base64;exec(base64.b64decode("aW1wb3J0...
              </OutputLine>
              <OutputLine />
              <OutputLine indent={2} color={COLORS.textDim}>
                [a]pprove&nbsp;&nbsp;[d]elete&nbsp;&nbsp;[i]nspect full&nbsp;&nbsp;[r]eport
              </OutputLine>
              <OutputLine />
              <PromptLine prompt="?">d</PromptLine>
              <OutputLine color={COLORS.green}>
                &nbsp;&nbsp;Deleted. litellm_init.pth removed.
              </OutputLine>
              <OutputLine>
                &nbsp;&nbsp;Recommend: pip install litellm==1.82.6 (last known safe)
              </OutputLine>
            </TerminalWindow>

            {/* How detection works */}
            <div
              style={{
                background: COLORS.surface,
                border: `1px solid ${COLORS.border}`,
                borderRadius: 8,
                padding: 28,
              }}
            >
              <h3
                style={{
                  fontFamily: sans,
                  fontSize: 14,
                  fontWeight: 600,
                  color: COLORS.textDim,
                  letterSpacing: "0.06em",
                  textTransform: "uppercase",
                  margin: "0 0 18px",
                }}
              >
                Detection logic
              </h3>
              <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
                <div style={{ flex: 1, minWidth: 240 }}>
                  <div style={{ fontFamily: mono, fontSize: 12, color: COLORS.accent, marginBottom: 8 }}>
                    Who created it?
                  </div>
                  <div style={{ fontFamily: sans, fontSize: 13, color: COLORS.textMuted, lineHeight: 1.6 }}>
                    Process lineage tracing via /proc. If the root ancestor is pip, poetry, uv, or conda — expected. If it's a Python startup hook creating more hooks — that's self-replicating behaviour. Critical alert.
                  </div>
                </div>
                <div style={{ flex: 1, minWidth: 240 }}>
                  <div style={{ fontFamily: mono, fontSize: 12, color: COLORS.accent, marginBottom: 8 }}>
                    What does it contain?
                  </div>
                  <div style={{ fontFamily: sans, fontSize: 13, color: COLORS.textMuted, lineHeight: 1.6 }}>
                    Content analysis: path entries are benign. Lines starting with "import" are executable — flagged. Lines with exec(), base64, eval(), or __import__ are obfuscated execution — quarantined immediately.
                  </div>
                </div>
                <div style={{ flex: 1, minWidth: 240 }}>
                  <div style={{ fontFamily: mono, fontSize: 12, color: COLORS.accent, marginBottom: 8 }}>
                    False positive rate?
                  </div>
                  <div style={{ fontFamily: sans, fontSize: 13, color: COLORS.textMuted, lineHeight: 1.6 }}>
                    Only 3 of the top 50 PyPI packages use executable .pth files (setuptools, editables, coverage). All are allowlisted by content hash. New executable .pth from unknown packages is the signal.
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* AI Firewall tab */}
        {activeTab === "firewall" && (
          <div>
            <div style={{ marginBottom: 32 }}>
              <h2
                style={{
                  fontFamily: sans,
                  fontSize: 22,
                  fontWeight: 600,
                  color: COLORS.text,
                  margin: "0 0 10px",
                  letterSpacing: "-0.01em",
                }}
              >
                Credentials never reach the LLM
              </h2>
              <p
                style={{
                  fontFamily: sans,
                  fontSize: 14,
                  color: COLORS.textMuted,
                  margin: 0,
                  maxWidth: 600,
                  lineHeight: 1.6,
                }}
              >
                Automatic prompt scanning, Claude Code tool hooks, and MCP auditing — protecting against credential leakage through AI conversations and agentic tool use.
              </p>
            </div>

            {/* Prompt redaction */}
            <TerminalWindow title="prompt redaction — automatic" style={{ marginBottom: 24 }}>
              <OutputLine color={COLORS.textDim}>
                ── outbound prompt to api.anthropic.com ──
              </OutputLine>
              <OutputLine />
              <OutputLine color={COLORS.text}>
                Before redaction:
              </OutputLine>
              <OutputLine>
                "Set OPENAI_API_KEY=<span style={{ color: COLORS.red }}>sk-proj-abc123xyz789def456</span> in .env"
              </OutputLine>
              <OutputLine />
              <OutputLine color={COLORS.text}>After redaction:</OutputLine>
              <OutputLine>
                "Set OPENAI_API_KEY=<span style={{ color: COLORS.green }}>[REDACTED:openai_key:a1b2]</span> in .env"
              </OutputLine>
              <OutputLine />
              <OutputLine color={COLORS.textDim}>
                sanctum: 1 credential redacted (OpenAI API key). LLM received sanitised prompt.
              </OutputLine>
            </TerminalWindow>

            {/* Hook demo */}
            <TerminalWindow title="claude code — PreToolUse hook" style={{ marginBottom: 24 }}>
              <OutputLine color={COLORS.textDim}>
                ── Claude requests Bash tool ──
              </OutputLine>
              <OutputLine color={COLORS.text}>
                Command: cat ~/.aws/credentials
              </OutputLine>
              <OutputLine />
              <OutputLine color={COLORS.accent}>
                sanctum hook pre-bash: BLOCKED
              </OutputLine>
              <OutputLine>
                Reason: Read access to ~/.aws/credentials is restricted.
              </OutputLine>
              <OutputLine>
                This file contains cloud provider secrets.
              </OutputLine>
              <OutputLine />
              <OutputLine color={COLORS.textDim}>
                ── Claude receives block message, explains to user ──
              </OutputLine>
              <OutputLine color={COLORS.text}>
                Claude: "I tried to read your AWS credentials but Sanctum
              </OutputLine>
              <OutputLine color={COLORS.text}>
                blocked the access for security. If you need AWS access,
              </OutputLine>
              <OutputLine color={COLORS.text}>
                configure it in .sanctum/policy.toml"
              </OutputLine>
            </TerminalWindow>

            {/* MCP auditing */}
            <div
              style={{
                background: COLORS.surface,
                border: `1px solid ${COLORS.border}`,
                borderRadius: 8,
                padding: 28,
              }}
            >
              <h3
                style={{
                  fontFamily: sans,
                  fontSize: 14,
                  fontWeight: 600,
                  color: COLORS.textDim,
                  letterSpacing: "0.06em",
                  textTransform: "uppercase",
                  margin: "0 0 14px",
                }}
              >
                MCP tool policy
              </h3>
              <div style={{ fontFamily: mono, fontSize: 12, color: COLORS.textMuted, lineHeight: 1.8 }}>
                <div>
                  <span style={{ color: COLORS.textDim }}>[mcp.restrictions]</span>
                </div>
                <div>
                  <span style={{ color: COLORS.accent }}>"filesystem:read"</span>
                  <span style={{ color: COLORS.textDim }}> = </span>
                  <span>{"{ block = [\"~/.ssh/*\", \"~/.aws/*\", \"**/.env\"] }"}</span>
                </div>
                <div>
                  <span style={{ color: COLORS.accent }}>"filesystem:write"</span>
                  <span style={{ color: COLORS.textDim }}> = </span>
                  <span>{"{ block = [\"**/*.pth\", \"**/sitecustomize.py\"] }"}</span>
                </div>
                <div>
                  <span style={{ color: COLORS.accent }}>"bash:execute"</span>
                  <span style={{ color: COLORS.textDim }}> = </span>
                  <span>{"{ warn = [\"curl.*-d\", \"wget.*--post\"] }"}</span>
                </div>
              </div>
              <p
                style={{
                  fontFamily: sans,
                  fontSize: 13,
                  color: COLORS.textDim,
                  margin: "16px 0 0",
                  lineHeight: 1.5,
                }}
              >
                Addresses CVE-2025-54135 (Cursor MCP), CVE-2025-53109 (Anthropic MCP), CVE-2025-55284 (Claude Code DNS exfil).
              </p>
            </div>
          </div>
        )}

        {/* Budget tab */}
        {activeTab === "budget" && (
          <div>
            <div style={{ marginBottom: 32 }}>
              <h2
                style={{
                  fontFamily: sans,
                  fontSize: 22,
                  fontWeight: 600,
                  color: COLORS.text,
                  margin: "0 0 10px",
                  letterSpacing: "-0.01em",
                }}
              >
                No more surprise API bills
              </h2>
              <p
                style={{
                  fontFamily: sans,
                  fontSize: 14,
                  color: COLORS.textMuted,
                  margin: 0,
                  maxWidth: 600,
                  lineHeight: 1.6,
                }}
              >
                Per-session and per-provider budgets with hard enforcement. Real-time cost tracking from API response metadata. Configurable alerts and automatic cutoffs.
              </p>
            </div>

            {/* Config example */}
            <TerminalWindow title=".sanctum/config.toml" style={{ marginBottom: 24 }}>
              <div style={{ color: COLORS.textDim }}>[budgets]</div>
              <div>
                <span style={{ color: COLORS.accent }}>default_session</span>
                <span style={{ color: COLORS.textDim }}> = </span>
                <span style={{ color: COLORS.green }}>"$50"</span>
              </div>
              <div>
                <span style={{ color: COLORS.accent }}>default_daily</span>
                <span style={{ color: COLORS.textDim }}> = </span>
                <span style={{ color: COLORS.green }}>"$200"</span>
              </div>
              <div>
                <span style={{ color: COLORS.accent }}>alert_at_percent</span>
                <span style={{ color: COLORS.textDim }}> = </span>
                <span style={{ color: COLORS.blue }}>75</span>
              </div>
              <div style={{ color: COLORS.textDim, marginTop: 8 }}>[budgets.openai]</div>
              <div>
                <span style={{ color: COLORS.accent }}>session</span>
                <span style={{ color: COLORS.textDim }}> = </span>
                <span style={{ color: COLORS.green }}>"$100"</span>
              </div>
              <div>
                <span style={{ color: COLORS.accent }}>allowed_models</span>
                <span style={{ color: COLORS.textDim }}> = </span>
                <span style={{ color: COLORS.green }}>["gpt-4o", "gpt-4o-mini"]</span>
              </div>
              <div style={{ color: COLORS.textDim, marginTop: 8 }}>[budgets.anthropic]</div>
              <div>
                <span style={{ color: COLORS.accent }}>session</span>
                <span style={{ color: COLORS.textDim }}> = </span>
                <span style={{ color: COLORS.green }}>"$200"</span>
              </div>
            </TerminalWindow>

            {/* Status */}
            <TerminalWindow title="sanctum budget" style={{ marginBottom: 24 }}>
              <PromptLine>sanctum budget</PromptLine>
              <OutputLine />
              <OutputLine color={COLORS.text}>
                &nbsp;&nbsp;Session: 2h 14m active
              </OutputLine>
              <OutputLine />
              <OutputLine>
                &nbsp;&nbsp;Provider&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Spent&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Limit&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Remaining
              </OutputLine>
              <OutputLine color={COLORS.textDim}>
                &nbsp;&nbsp;──────────&nbsp;&nbsp;&nbsp;&nbsp;─────&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;─────&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;─────────
              </OutputLine>
              <OutputLine>
                &nbsp;&nbsp;OpenAI&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;$23.41&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;$100.00&nbsp;&nbsp;&nbsp;&nbsp;
                <span style={{ color: COLORS.green }}>$76.59</span>
              </OutputLine>
              <OutputLine>
                &nbsp;&nbsp;Anthropic&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;$5.21&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;$200.00&nbsp;&nbsp;&nbsp;&nbsp;
                <span style={{ color: COLORS.green }}>$194.79</span>
              </OutputLine>
              <OutputLine />
              <OutputLine>
                &nbsp;&nbsp;Total session: $28.62 / $300.00
              </OutputLine>
              <OutputLine>&nbsp;&nbsp;Daily: $47.83 / $500.00</OutputLine>
            </TerminalWindow>

            {/* Hard stop demo */}
            <TerminalWindow title="budget enforcement — hard stop" style={{ marginBottom: 24 }}>
              <OutputLine color={COLORS.textDim}>
                ── API response from api.openai.com ──
              </OutputLine>
              <OutputLine>
                Request #847: gpt-4o, 12,400 tokens, est. $0.37
              </OutputLine>
              <OutputLine>
                Cumulative: <span style={{ color: COLORS.red }}>$100.02 / $100.00</span>
              </OutputLine>
              <OutputLine />
              <OutputLine color={COLORS.red}>
                sanctum: OpenAI session budget exceeded.
              </OutputLine>
              <OutputLine>
                Subsequent requests will receive HTTP 429.
              </OutputLine>
              <OutputLine />
              <OutputLine color={COLORS.textDim}>
                To continue:
              </OutputLine>
              <OutputLine>
                &nbsp;&nbsp;sanctum budget extend --session +50
              </OutputLine>
              <OutputLine>
                &nbsp;&nbsp;sanctum budget reset
              </OutputLine>
            </TerminalWindow>
          </div>
        )}

        {/* Footer */}
        <footer
          style={{
            marginTop: 56,
            paddingTop: 24,
            borderTop: `1px solid ${COLORS.border}`,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 12,
          }}
        >
          <div style={{ fontFamily: mono, fontSize: 11, color: COLORS.textDim }}>
            Sanctum — built with Rust. Open source (MIT).
            <br />
            Composes with nono.sh for kernel sandboxing + phantom proxy.
          </div>
          <div style={{ fontFamily: mono, fontSize: 11, color: COLORS.textDim }}>
            An Arbiter Security project.
          </div>
        </footer>
      </div>
    </div>
  );
}
