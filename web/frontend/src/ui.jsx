// src/ui.jsx — UI primitives, exported to window
(function() {
const { useState, useEffect, useRef } = React;

// ── ProgressBar ────────────────────────────────────────────────
function ProgressBar({ progress, color = 'purple' }) {
  const grad = color === 'purple'
    ? 'linear-gradient(90deg, oklch(0.52 0.26 285), oklch(0.74 0.22 308))'
    : 'linear-gradient(90deg, oklch(0.50 0.2 145), oklch(0.74 0.18 162))';
  const glow = color === 'purple'
    ? '0 0 12px oklch(0.67 0.24 290 / 0.55)'
    : '0 0 12px oklch(0.72 0.19 148 / 0.55)';
  return (
    <div style={{ background: 'var(--border)', borderRadius: 99, height: 6, overflow: 'hidden', position: 'relative' }}>
      <div style={{ width: `${Math.max(progress, 0)}%`, height: '100%', background: grad, borderRadius: 99, transition: 'width 0.35s ease', boxShadow: glow, position: 'relative', overflow: 'hidden' }}>
        {progress < 100 && progress > 0 && (
          <div style={{ position: 'absolute', top: 0, left: 0, width: '40%', height: '100%', background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.35), transparent)', animation: 'shimmer 1.4s infinite' }} />
        )}
      </div>
    </div>
  );
}

// ── Terminal ───────────────────────────────────────────────────
function Terminal({ lines = [], color = 'purple' }) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines]);

  const accent = color === 'purple' ? 'oklch(0.74 0.22 295)' : 'oklch(0.74 0.18 155)';
  const getColor = (l) => {
    if (/\[SUCCESS\]|OK -/.test(l) || l.includes('✓')) return 'oklch(0.76 0.18 148)';
    if (/\[ERROR\]|ERROR/.test(l)) return 'oklch(0.65 0.22 22)';
    if (/\[WARN\]/.test(l)) return 'oklch(0.80 0.18 80)';
    if (/^={3,}|^-{3,}/.test(l)) return 'oklch(0.38 0.02 280)';
    if (/✗|RECHAZADO|TIMEOUT/.test(l)) return 'oklch(0.65 0.2 22)';
    if (/\[INFO\]|→|•/.test(l)) return accent;
    return 'oklch(0.72 0.012 280)';
  };

  return (
    <div ref={ref} style={{ background: 'var(--term-bg)', borderRadius: 9, padding: '11px 14px', fontFamily: "'JetBrains Mono', monospace", fontSize: 11.5, lineHeight: 1.78, height: 248, overflowY: 'auto', border: '1px solid var(--border)' }}>
      {lines.map((l, i) => (
        <div key={i} style={{ color: getColor(l), whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{l}</div>
      ))}
      {lines.length > 0 && (
        <span style={{ color: 'var(--text-muted)', animation: 'blink 1s step-end infinite' }}>▌</span>
      )}
    </div>
  );
}

// ── Badge ──────────────────────────────────────────────────────
function Badge({ status }) {
  const cfg = {
    idle:    { label: 'Listo',       bg: 'var(--surface-3)', color: 'var(--text-dim)',           border: 'var(--border)' },
    locked:  { label: 'Bloqueado',   bg: 'var(--surface-2)', color: 'var(--text-muted)',          border: 'var(--border)' },
    running: { label: 'Ejecutando',  bg: 'oklch(0.14 0.05 62)', color: 'oklch(0.84 0.18 80)', border: 'oklch(0.42 0.16 62 / 0.5)' },
    done:    { label: 'Completado',  bg: 'oklch(0.12 0.05 148)', color: 'oklch(0.74 0.19 148)', border: 'oklch(0.42 0.15 148 / 0.5)' },
    error:   { label: 'Error',       bg: 'oklch(0.14 0.06 25)',  color: 'oklch(0.74 0.22 25)',  border: 'oklch(0.42 0.18 25 / 0.5)' },
  };
  const c = cfg[status] || cfg.idle;
  return (
    <span style={{ background: c.bg, color: c.color, border: `1px solid ${c.border}`, borderRadius: 99, padding: '2px 10px', fontSize: 11, fontFamily: "'JetBrains Mono', monospace", fontWeight: 500, display: 'inline-flex', alignItems: 'center', gap: 5, whiteSpace: 'nowrap' }}>
      {status === 'running' && (
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'oklch(0.84 0.18 80)', animation: 'pulse 1s ease-in-out infinite', display: 'inline-block', flexShrink: 0 }} />
      )}
      {c.label}
    </span>
  );
}

// ── Btn ────────────────────────────────────────────────────────
function Btn({ children, onClick, color = 'purple', disabled = false, variant = 'fill', size = 'md' }) {
  const [hov, setHov] = useState(false);
  const acc  = color === 'purple' ? 'var(--purple)' : 'var(--green)';
  const accH = color === 'purple' ? 'oklch(0.74 0.24 290)' : 'oklch(0.79 0.19 150)';
  const glow = color === 'purple' ? 'var(--purple-glow)' : 'var(--green-glow)';
  const pad  = size === 'sm' ? '6px 14px' : size === 'lg' ? '13px 30px' : '9px 20px';
  const fs   = size === 'sm' ? 12 : size === 'lg' ? 15 : 13.5;
  const fillStyle  = { background: hov && !disabled ? accH : acc, color: 'oklch(0.99 0.004 280)', border: 'none', boxShadow: hov && !disabled ? `0 0 22px ${glow}` : 'none' };
  const ghostStyle = { background: hov && !disabled ? `${acc}18` : 'transparent', color: acc, border: `1px solid ${acc}55` };
  return (
    <button
      onClick={disabled ? undefined : onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{ ...(variant === 'ghost' ? ghostStyle : fillStyle), padding: pad, fontSize: fs, fontWeight: 600, fontFamily: "'Space Grotesk', sans-serif", borderRadius: 8, cursor: disabled ? 'not-allowed' : 'pointer', opacity: disabled ? 0.4 : 1, transition: 'all 0.15s ease', display: 'inline-flex', alignItems: 'center', gap: 7 }}
    >{children}</button>
  );
}

// ── StatCard ───────────────────────────────────────────────────
function StatCard({ label, value, color = 'purple' }) {
  const border = color === 'purple' ? 'var(--purple-border)' : 'var(--green-border)';
  const accent = color === 'purple' ? 'var(--purple)' : 'var(--green)';
  return (
    <div style={{ background: 'var(--surface-2)', borderRadius: 10, padding: '13px 15px', border: `1px solid ${border}`, flex: 1, minWidth: 100 }}>
      <div style={{ fontSize: 20, fontWeight: 700, color: accent, letterSpacing: '-0.02em', lineHeight: 1.15 }}>{value}</div>
      <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 4, lineHeight: 1.35 }}>{label}</div>
    </div>
  );
}

// ── HBarChart ──────────────────────────────────────────────────
function HBarChart({ data, color = 'purple', unit = '%', title }) {
  const max = Math.max(...data.map(d => d.value), 1);
  const [g1, g2] = color === 'purple' ? ['oklch(0.52 0.26 285)', 'oklch(0.74 0.22 308)'] : ['oklch(0.50 0.2 145)', 'oklch(0.74 0.18 162)'];
  const gid = `hbc-${color}`;
  const rowH = 25;
  return (
    <div>
      {title && <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-dim)', marginBottom: 9, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{title}</div>}
      <svg width="100%" viewBox={`0 0 420 ${data.length * rowH + 8}`} style={{ fontFamily: "'JetBrains Mono', monospace", overflow: 'visible' }}>
        <defs>
          <linearGradient id={gid} x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor={g1} /><stop offset="100%" stopColor={g2} />
          </linearGradient>
        </defs>
        {data.map((d, i) => {
          const bw = (d.value / max) * 240;
          const y  = i * rowH;
          const lbl = d.label.length > 21 ? d.label.slice(0, 19) + '…' : d.label;
          return (
            <g key={i}>
              <text x="0" y={y + 15} fontSize="10" fill="var(--text-dim)">{lbl}</text>
              <rect x="152" y={y + 5} width={Math.max(bw, 2)} height="14" rx="3" fill={`url(#${gid})`} opacity="0.88" />
              <text x={152 + Math.max(bw, 2) + 5} y={y + 15} fontSize="10" fill="var(--text)" fontWeight="600">{d.value}{unit}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// ── VBarChart ──────────────────────────────────────────────────
function VBarChart({ data, color = 'purple', unit = 'ms', title, note }) {
  const max = Math.max(...data.map(d => d.value), 1);
  const [g1, g2] = color === 'purple' ? ['oklch(0.74 0.22 308)', 'oklch(0.52 0.26 285)'] : ['oklch(0.74 0.18 162)', 'oklch(0.50 0.2 145)'];
  const gid = `vbc-${color}`;
  const chartH = 120, n = data.length, bw = Math.min(34, (360 / n) - 8);
  return (
    <div>
      {title && <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-dim)', marginBottom: 9, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{title}</div>}
      <svg width="100%" viewBox="0 0 420 200" style={{ fontFamily: "'JetBrains Mono', monospace", overflow: 'visible' }}>
        <defs>
          <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={g1} /><stop offset="100%" stopColor={g2} />
          </linearGradient>
        </defs>
        {[0, 0.25, 0.5, 0.75, 1].map(t => (
          <g key={t}>
            <line x1="34" y1={14 + (1 - t) * chartH} x2="408" y2={14 + (1 - t) * chartH} stroke="var(--border)" strokeWidth="1" />
            <text x="31" y={14 + (1 - t) * chartH} fontSize="9" fill="var(--text-muted)" textAnchor="end" dominantBaseline="middle">{Math.round(max * t)}</text>
          </g>
        ))}
        {data.map((d, i) => {
          const bh = (d.value / max) * chartH;
          const x  = 38 + i * (370 / n) + (370 / n - bw) / 2;
          const y  = 14 + chartH - bh;
          const lbl = d.label.length > 11 ? d.label.slice(0, 10) + '…' : d.label;
          return (
            <g key={i}>
              {d.value > 0 && <rect x={x} y={y} width={bw} height={bh} rx="3" fill={`url(#${gid})`} opacity="0.88" />}
              {d.value === 0 && <rect x={x} y={14 + chartH - 3} width={bw} height={3} rx="1" fill="var(--border)" />}
              <text x={x + bw / 2} y={y - 4} fontSize="9" fill="var(--text)" textAnchor="middle" fontWeight="600">
                {d.value > 0 ? `+${d.value}` : d.value}{unit}
              </text>
              <text x={x + bw / 2} y={150} fontSize="8.5" fill="var(--text-dim)" textAnchor="middle" transform={`rotate(-36,${x + bw / 2},150)`}>{lbl}</text>
            </g>
          );
        })}
      </svg>
      {note && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, lineHeight: 1.4 }}>{note}</div>}
    </div>
  );
}

// ── GroupedBar ─────────────────────────────────────────────────
function GroupedBar({ groups, series, title }) {
  const allVals = series.flatMap(s => s.values.filter(v => v > 0));
  const max = Math.max(...allVals, 1);
  const chartH = 110, gw = 370 / groups.length, bw = Math.min(16, gw / series.length - 4);
  return (
    <div>
      {title && <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-dim)', marginBottom: 9, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{title}</div>}
      <svg width="100%" viewBox="0 0 420 205" style={{ fontFamily: "'JetBrains Mono', monospace", overflow: 'visible' }}>
        <defs>
          {series.map((s, i) => (
            <linearGradient key={i} id={`gb-${i}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={s.color} stopOpacity="0.9" />
              <stop offset="100%" stopColor={s.color} stopOpacity="0.5" />
            </linearGradient>
          ))}
        </defs>
        {[0, 0.5, 1].map(t => (
          <line key={t} x1="34" y1={14 + (1 - t) * chartH} x2="408" y2={14 + (1 - t) * chartH} stroke="var(--border)" strokeWidth="1" />
        ))}
        {[0, 0.5, 1].map(t => (
          <text key={t} x="31" y={14 + (1 - t) * chartH} fontSize="9" fill="var(--text-muted)" textAnchor="end" dominantBaseline="middle">{Math.round(max * t)}ms</text>
        ))}
        {groups.map((g, gi) => {
          const cx = 38 + gi * gw + gw / 2;
          return (
            <g key={gi}>
              {series.map((s, si) => {
                const v = s.values[gi];
                if (!v) return null;
                const bh = (v / max) * chartH;
                const x  = cx + (si - (series.length - 1) / 2) * (bw + 3) - bw / 2;
                const y  = 14 + chartH - bh;
                return <rect key={si} x={x} y={y} width={bw} height={bh} rx="2" fill={`url(#gb-${si})`} />;
              })}
              <text x={cx} y={140} fontSize="8.5" fill="var(--text-dim)" textAnchor="middle" transform={`rotate(-32,${cx},140)`}>
                {g.length > 13 ? g.slice(0, 12) + '…' : g}
              </text>
            </g>
          );
        })}
        {series.map((s, i) => (
          <g key={i} transform={`translate(${38 + i * 130}, 175)`}>
            <rect width="10" height="10" rx="2" fill={s.color} />
            <text x="14" y="9" fontSize="9" fill="var(--text-dim)">{s.name}</text>
          </g>
        ))}
      </svg>
    </div>
  );
}

// ── ConfMatrix ─────────────────────────────────────────────────
function ConfMatrix({ labels, data, color = 'purple' }) {
  const n   = labels.length;
  const max = Math.max(...data.flat(), 1);
  const acc = color === 'purple' ? 'var(--purple)' : 'var(--green)';
  const cs  = 52;
  return (
    <svg width="100%" viewBox={`0 0 ${n * cs + 90} ${n * cs + 66}`} style={{ fontFamily: "'JetBrains Mono', monospace" }}>
      <text x={90 + n * cs / 2} y={13} fontSize="9" fill="var(--text-muted)" textAnchor="middle">← Predicción →</text>
      {labels.map((l, i) => (
        <g key={i}>
          <text x={90 + i * cs + cs / 2} y={26} fontSize="8.5" fill="var(--text-dim)" textAnchor="middle">{l}</text>
          <text x="82" y={34 + i * cs + cs / 2} fontSize="8" fill="var(--text-dim)" textAnchor="end" dominantBaseline="middle">{l}</text>
        </g>
      ))}
      {data.map((row, ri) => row.map((val, ci) => {
        const t = val / max;
        const isDiag = ri === ci;
        return (
          <g key={`${ri}-${ci}`}>
            <rect x={90 + ci * cs} y={30 + ri * cs} width={cs - 3} height={cs - 3} rx="5" fill={isDiag ? acc : 'var(--surface-3)'} opacity={isDiag ? 0.22 + t * 0.78 : t * 0.45} />
            <text x={90 + ci * cs + cs / 2} y={30 + ri * cs + cs / 2} fontSize="13" fill="var(--text)" textAnchor="middle" dominantBaseline="middle" fontWeight="700">{val}</text>
          </g>
        );
      }))}
      <text x="14" y={34 + n * cs / 2} fontSize="9" fill="var(--text-muted)" textAnchor="middle" transform={`rotate(-90,14,${34 + n * cs / 2})`}>Real →</text>
    </svg>
  );
}

// ── FormField / inputs ─────────────────────────────────────────
function FormField({ label, hint, children }) {
  return (
    <div style={{ marginBottom: 13 }}>
      <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-dim)', marginBottom: 5, letterSpacing: '0.02em' }}>{label}</label>
      {children}
      {hint && <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.4 }}>{hint}</p>}
    </div>
  );
}
function TInput({ value, onChange, placeholder }) {
  return <input type="text" value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} />;
}
function NInput({ value, onChange, min, max, step = 1 }) {
  return <input type="number" value={value} onChange={e => onChange(e.target.value)} min={min} max={max} step={step} />;
}
function SInput({ value, onChange, options }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)}>
      {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  );
}

Object.assign(window, {
  ProgressBar, Terminal, Badge, Btn, StatCard,
  HBarChart, VBarChart, GroupedBar, ConfMatrix,
  FormField, TInput, NInput, SInput,
});
})();
