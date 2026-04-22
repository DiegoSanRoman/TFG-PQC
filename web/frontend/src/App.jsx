// src/App.jsx — Aplicación principal conectada al backend real
(function() {
const { useState, useEffect, useRef } = React;

// ── Step definitions (mismas que backend/config.py) ────────────
const STEPS = [
  {
    id: 'pqc_sonda', pipeline: 'pqc', num: '01',
    label: 'Sonda PQC', script: 'ejecutar_sonda.sh',
    desc: 'Escanea dominios HTTPS reales comprobando la aceptación de 14 grupos criptográficos PQC mediante OpenSSL OQS en Docker.',
    unlocks: ['pqc_analisis', 'pqc_clasificacion'],
    args: [
      { key: 'input_csv',     label: '--input-csv',      type: 'text',   default: 'majestic_million.csv', hint: 'CSV de dominios (Majestic Million o Tranco)' },
      { key: 'max_hostnames', label: '--max-hostnames',  type: 'number', default: 100,  min: 1, max: 10000, hint: 'Número máximo de dominios a probar' },
      { key: 'repeticiones',  label: '--repeticiones',   type: 'number', default: 3,    min: 1, max: 20,    hint: 'Repeticiones por (hostname, grupo)' },
      { key: 'max_workers',   label: '--max-workers',    type: 'number', default: 20,   min: 1, max: 50,    hint: 'Hilos concurrentes' },
    ],
  },
  {
    id: 'pqc_analisis', pipeline: 'pqc', num: '02',
    label: 'Análisis PQC', script: 'ejecutar_analisis.sh',
    desc: 'Carga los resultados de la sonda, filtra outliers, construye cohorte justa y genera las gráficas de publicación.',
    unlocks: [],
    args: [],
  },
  {
    id: 'pqc_clasificacion', pipeline: 'pqc', num: '03',
    label: 'Clasificación ML', script: 'ejecutar_clasificacion_pqc.sh',
    desc: 'Clasifica el grupo PQC negociado usando solo features observables (timing y bytes). RandomForest y GradientBoosting en 3 experimentos.',
    unlocks: [],
    args: [
      { key: 'input_json', label: '--input-json', type: 'text',   default: 'resultados/resultados_sonda_pqc.json', hint: 'JSON de resultados de la sonda PQC' },
      { key: 'n_splits',   label: '--n-splits',   type: 'number', default: 5, min: 2, max: 20, hint: 'Folds para GroupKFold (validación cruzada sin leakage)' },
    ],
  },
  {
    id: 'ech_sonda', pipeline: 'ech', num: '01',
    label: 'Sonda ECH', script: 'ejecutar_sonda_ech.sh',
    desc: 'Detecta dominios con ECH activo a gran escala: descubre registros HTTPS RR, decodifica ECHConfigList y mide longitud de ClientHello.',
    unlocks: ['ech_latencia_ech', 'ech_latencia_pqc'],
    args: [
      { key: 'input_csv',       label: '--input-csv',       type: 'text',   default: 'data/majestic_million.csv', hint: 'CSV de dominios de entrada' },
      { key: 'max_dominios',    label: '--max-dominios',    type: 'number', default: 1000, min: 10, max: 1000000, hint: 'Máximo de dominios a procesar' },
      { key: 'max_concurrency', label: '--max-concurrency', type: 'number', default: 40,   min: 1,  max: 200,     hint: 'Concurrencia asyncio' },
      { key: 'tls_client',      label: '--tls-client',      type: 'select', default: 'auto',
        options: [{value:'auto',label:'auto'},{value:'bssl',label:'bssl'},{value:'openssl',label:'openssl'}],
        hint: 'Cliente TLS a usar para verificar ECH' },
      { key: 'dns_timeout',     label: '--dns-timeout',     type: 'number', default: 8,  min: 1, max: 60,  hint: 'Timeout DNS en segundos' },
      { key: 'tls_timeout',     label: '--tls-timeout',     type: 'number', default: 20, min: 1, max: 120, hint: 'Timeout TLS en segundos' },
    ],
  },
  {
    id: 'ech_latencia_ech', pipeline: 'ech', num: '02',
    label: 'Latencia ECH', script: 'ejecutar_sonda_latencia_ech.sh',
    desc: 'Mide el overhead real de ECH comparando handshakes TLS con y sin ECH activo usando bssl. Genera media y desviación típica por hostname.',
    unlocks: [],
    args: [
      { key: 'input_csv',     label: '--input-csv',     type: 'text',   default: 'data/hostnames_ech.csv', hint: 'CSV de hostnames con ECH (salida de la sonda ECH)' },
      { key: 'repeticiones',  label: '--repeticiones',  type: 'number', default: 30,    min: 5,   max: 200,    hint: 'Mediciones por hostname para media/stddev' },
      { key: 'concurrency',   label: '--concurrency',   type: 'number', default: 10,    min: 1,   max: 50,     hint: 'Hostnames en paralelo' },
      { key: 'max_hostnames', label: '--max-hostnames', type: 'number', default: 10000, min: 1,   max: 100000, hint: 'Máximo de hostnames a procesar' },
      { key: 'dns_timeout',   label: '--dns-timeout',   type: 'number', default: 5,     min: 1,   max: 60,     hint: 'Timeout DNS en segundos' },
      { key: 'tls_timeout',   label: '--tls-timeout',   type: 'number', default: 10,    min: 1,   max: 120,    hint: 'Timeout por handshake TLS en segundos' },
    ],
  },
  {
    id: 'ech_latencia_pqc', pipeline: 'ech', num: '03',
    label: 'Latencia PQC+ECH', script: 'ejecutar_sonda_latencia_pqc.sh',
    desc: 'Mide la latencia del handshake TLS para múltiples grupos PQC (bssl y OQS), combinando con ECH cuando es posible.',
    unlocks: [],
    args: [
      { key: 'input_csv',     label: '--input-csv',     type: 'text',   default: 'data/hostnames_ech.csv', hint: 'CSV de hostnames con ECH' },
      { key: 'repeticiones',  label: '--repeticiones',  type: 'number', default: 30, min: 5, max: 200,    hint: 'Mediciones por combinación (hostname × grupo)' },
      { key: 'concurrency',   label: '--concurrency',   type: 'number', default: 5,  min: 1, max: 20,     hint: 'Hostnames en paralelo' },
      { key: 'max_hostnames', label: '--max-hostnames', type: 'number', default: 10000, min: 1, max: 100000, hint: 'Máximo de hostnames a procesar' },
      { key: 'grupos_pqc',    label: '--grupos-pqc',    type: 'text',   default: 'X25519Kyber768Draft00 X25519MLKEM768', hint: 'Grupos bssl separados por espacio (vacío = todos los predefinidos)' },
      { key: 'dns_timeout',   label: '--dns-timeout',   type: 'number', default: 5,  min: 1, max: 60,     hint: 'Timeout DNS en segundos' },
      { key: 'tls_timeout',   label: '--tls-timeout',   type: 'number', default: 10, min: 1, max: 120,    hint: 'Timeout por handshake en segundos' },
    ],
  },
];

// ── ArgsForm ───────────────────────────────────────────────────
function ArgsForm({ step, args, onChange }) {
  if (!step.args || step.args.length === 0) {
    return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '10px 0', fontStyle: 'italic' }}>Este script no requiere argumentos adicionales.</div>;
  }
  return (
    <div>
      {step.args.map(a => (
        <FormField key={a.key} label={a.label} hint={a.hint}>
          {a.type === 'select'
            ? <SInput value={args[a.key] ?? a.default} onChange={v => onChange(a.key, v)} options={a.options} />
            : a.type === 'number'
            ? <NInput value={args[a.key] ?? a.default} onChange={v => onChange(a.key, v)} min={a.min} max={a.max} />
            : <TInput value={args[a.key] ?? a.default} onChange={v => onChange(a.key, v)} placeholder={String(a.default)} />
          }
        </FormField>
      ))}
    </div>
  );
}

// ── StepCard ───────────────────────────────────────────────────
function StepCard({ step, status, onClick, color }) {
  const [hov, setHov] = useState(false);
  const locked = status === 'locked';
  const accent  = color === 'purple' ? 'var(--purple)'        : 'var(--green)';
  const bg      = color === 'purple' ? 'var(--purple-bg)'     : 'var(--green-bg)';
  const border  = color === 'purple' ? 'var(--purple-border)' : 'var(--green-border)';
  const glowShadow = color === 'purple'
    ? '0 4px 22px oklch(0.67 0.24 290 / 0.25)'
    : '0 4px 22px oklch(0.72 0.19 148 / 0.25)';

  return (
    <div
      onClick={locked ? undefined : onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        background: hov && !locked ? bg : 'var(--surface)',
        border: `1px solid ${hov && !locked ? border : 'var(--border)'}`,
        borderRadius: 12, padding: '15px 17px',
        cursor: locked ? 'not-allowed' : 'pointer',
        opacity: locked ? 0.48 : 1,
        transition: 'all 0.18s ease',
        boxShadow: hov && !locked ? glowShadow : 'none',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8, marginBottom: 7 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <div style={{
            width: 28, height: 28, borderRadius: 7, flexShrink: 0,
            background: locked ? 'var(--surface-3)' : bg,
            border: `1px solid ${locked ? 'var(--border)' : border}`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 10.5, fontWeight: 700, color: locked ? 'var(--text-muted)' : accent,
            fontFamily: "'JetBrains Mono', monospace",
          }}>{step.num}</div>
          <div style={{ fontSize: 14, fontWeight: 650, color: locked ? 'var(--text-muted)' : 'var(--text)', lineHeight: 1.2 }}>{step.label}</div>
        </div>
        <Badge status={status} />
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.55, marginBottom: 8 }}>{step.desc}</div>
      {!locked && (
        <div style={{ fontSize: 11, color: accent, fontFamily: "'JetBrains Mono', monospace", opacity: 0.75 }}>
          $ ./{step.script}
        </div>
      )}
    </div>
  );
}

// ── StepDrawer ─────────────────────────────────────────────────
function StepDrawer({ step, status, args, onArgChange, onRun, onStop, onReset, onClose, progress, termLines, color, doneKey }) {
  const [activeTab, setActiveTab] = useState('config');
  const accent = color === 'purple' ? 'var(--purple)' : 'var(--green)';

  useEffect(() => {
    if (status === 'running') setActiveTab('terminal');
    else if (status === 'done') setActiveTab('results');
    else setActiveTab('config');
  }, [status]);

  const tabs = [
    { id: 'config',   label: 'Configuración', disabled: status === 'running' },
    { id: 'terminal', label: 'Terminal',       disabled: status === 'idle' },
    { id: 'results',  label: 'Resultados',     disabled: status !== 'done' },
  ];

  return (
    <div style={{
      position: 'fixed', top: 0, right: 0, bottom: 0, width: 'min(488px, 100vw)',
      background: 'var(--surface)', borderLeft: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column', zIndex: 50,
      animation: 'slideIn 0.24s ease',
      boxShadow: '-6px 0 40px oklch(0 0 0 / 0.35)',
    }}>
      {/* Header */}
      <div style={{ padding: '18px 20px 14px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div style={{ flex: 1, paddingRight: 12 }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace", marginBottom: 5 }}>
              ./{step.script}
            </div>
            <div style={{ fontSize: 18, fontWeight: 700, letterSpacing: '-0.01em', marginBottom: 5 }}>{step.label}</div>
            <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.5 }}>{step.desc}</div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 20, lineHeight: 1, padding: '2px 4px', flexShrink: 0, borderRadius: 5 }}>✕</button>
        </div>
      </div>

      {/* Progress */}
      {(status === 'running' || status === 'done' || status === 'error') && (
        <div style={{ padding: '11px 20px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 7 }}>
            <Badge status={status} />
            <span style={{ fontSize: 12, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace" }}>
              {status === 'done' ? '100%' : `${Math.round(progress)}%`}
            </span>
          </div>
          <ProgressBar progress={status === 'done' ? 100 : progress} color={color} />
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => !t.disabled && setActiveTab(t.id)} style={{
            flex: 1, padding: '10px 0', fontSize: 12.5, fontWeight: 600,
            background: 'none', border: 'none',
            cursor: t.disabled ? 'not-allowed' : 'pointer',
            color: activeTab === t.id ? accent : t.disabled ? 'var(--text-muted)' : 'var(--text-dim)',
            borderBottom: activeTab === t.id ? `2px solid ${accent}` : '2px solid transparent',
            transition: 'all 0.14s', fontFamily: "'Space Grotesk', sans-serif",
          }}>{t.label}</button>
        ))}
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '18px 20px' }}>
        {activeTab === 'config' && (
          <div>
            <ArgsForm step={step} args={args} onChange={onArgChange} />
            <div style={{ marginTop: 16, display: 'flex', gap: 8 }}>
              <Btn onClick={onRun} color={color} disabled={status === 'running'}>
                {status === 'done' || status === 'error' ? '↻ Re-ejecutar' : '▶ Ejecutar'}
              </Btn>
              {status === 'running' && (
                <Btn onClick={onStop} color={color} variant="ghost">■ Detener</Btn>
              )}
            </div>
            {status === 'idle' && step.args.length > 0 && (
              <div style={{ marginTop: 12, padding: '9px 12px', background: 'var(--surface-2)', borderRadius: 7, fontSize: 11, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.5, wordBreak: 'break-all' }}>
                $ ./{step.script} {step.args.map(a => `${a.label} ${args[a.key] ?? a.default}`).join(' ')}
              </div>
            )}
          </div>
        )}
        {activeTab === 'terminal' && (
          <div>
            <Terminal lines={termLines} color={color} />
            <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>
              Ejecución real — stdout/stderr del subprocess en el backend
            </div>
          </div>
        )}
        {activeTab === 'results' && <ResultsView stepId={step.id} reloadKey={doneKey} />}
      </div>

      {/* Footer */}
      <div style={{ padding: '13px 20px', borderTop: '1px solid var(--border)', flexShrink: 0, display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        {(status === 'done' || status === 'error') && (
          <Btn onClick={onReset} color={color} variant="ghost" size="sm">↺ Reiniciar paso</Btn>
        )}
        <Btn onClick={onClose} variant="ghost" color={color} size="sm">Cerrar</Btn>
      </div>
    </div>
  );
}

// ── PipelineCol ────────────────────────────────────────────────
function PipelineCol({ steps, states, onOpen, color, title, subtitle, icon }) {
  const accent  = color === 'purple' ? 'var(--purple)'        : 'var(--green)';
  const bg      = color === 'purple' ? 'var(--purple-bg)'     : 'var(--green-bg)';
  const border  = color === 'purple' ? 'var(--purple-border)' : 'var(--green-border)';
  const done    = steps.filter(s => states[s.id] === 'done').length;

  return (
    <div style={{ flex: 1, minWidth: 290 }}>
      <div style={{ background: bg, border: `1px solid ${border}`, borderRadius: 13, padding: '15px 18px', marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 12 }}>
          <div>
            <div style={{ fontSize: 10.5, fontWeight: 700, color: accent, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>
              {icon} Pipeline
            </div>
            <div style={{ fontSize: 16, fontWeight: 700, letterSpacing: '-0.01em', marginBottom: 2 }}>{title}</div>
            <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>{subtitle}</div>
          </div>
          <div style={{ textAlign: 'right', flexShrink: 0 }}>
            <div style={{ fontSize: 22, fontWeight: 700, color: accent, letterSpacing: '-0.02em', lineHeight: 1 }}>{done}/{steps.length}</div>
            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 2 }}>completados</div>
          </div>
        </div>
        <ProgressBar progress={(done / steps.length) * 100} color={color} />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
        {steps.map((step, i) => (
          <div key={step.id} style={{ position: 'relative' }}>
            {i < steps.length - 1 && (
              <div style={{
                position: 'absolute', left: 31, top: '100%', width: 1, height: 14,
                background: states[step.id] === 'done' ? accent : 'var(--border)',
                transition: 'background 0.4s ease', zIndex: 1,
              }} />
            )}
            <div style={{ marginBottom: i < steps.length - 1 ? 14 : 0 }}>
              <StepCard step={step} status={states[step.id]} onClick={() => onOpen(step.id)} color={color} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Dashboard ──────────────────────────────────────────────────
function Dashboard({ theme, toggleTheme, onLogout }) {
  const [openId, setOpenId]       = useState(null);
  const [states, setStates]       = useState({
    pqc_sonda: 'idle', pqc_analisis: 'locked', pqc_clasificacion: 'locked',
    ech_sonda: 'idle', ech_latencia_ech: 'locked', ech_latencia_pqc: 'locked',
  });
  const [args, setArgs]           = useState(() => {
    const a = {};
    STEPS.forEach(s => { a[s.id] = {}; s.args.forEach(arg => { a[s.id][arg.key] = arg.default; }); });
    return a;
  });
  const [progress, setProgress]   = useState({});
  const [termLines, setTermLines] = useState({});
  const [doneKeys, setDoneKeys]   = useState({});   // cambia cuando un step termina → invalida caché de ResultsView

  // Cierres de SSE y job_ids por step
  const sseCleanups = useRef({});
  const jobIds      = useRef({});

  const openStep = STEPS.find(s => s.id === openId);

  // Cancelar cualquier SSE al desmontar
  useEffect(() => () => {
    Object.values(sseCleanups.current).forEach(fn => { try { fn(); } catch(e) {} });
  }, []);

  const handleArgChange = (stepId, key, val) =>
    setArgs(prev => ({ ...prev, [stepId]: { ...prev[stepId], [key]: val } }));

  const appendLine = (stepId, line) => {
    setTermLines(prev => ({ ...prev, [stepId]: [...(prev[stepId] || []), line] }));
  };

  const handleRun = async (stepId) => {
    const step = STEPS.find(s => s.id === stepId);

    // Reset local state
    setStates(prev => ({ ...prev, [stepId]: 'running' }));
    setProgress(prev => ({ ...prev, [stepId]: 0 }));
    setTermLines(prev => ({ ...prev, [stepId]: [] }));

    // Cerrar un SSE previo si lo hubiera
    if (sseCleanups.current[stepId]) {
      try { sseCleanups.current[stepId](); } catch(e) {}
      sseCleanups.current[stepId] = null;
    }

    let resp;
    try {
      resp = await API.startJob(stepId, args[stepId] || {});
    } catch (e) {
      appendLine(stepId, `[ERROR] No se pudo arrancar el job: ${e.message}`);
      setStates(prev => ({ ...prev, [stepId]: 'error' }));
      return;
    }

    jobIds.current[stepId] = resp.job_id;

    // Mostrar el comando que se está ejecutando
    appendLine(stepId, `[INFO] job_id=${resp.job_id}`);

    // Heurística de progreso: aproximamos según líneas recibidas.
    // Intentamos capturar porcentaje real si aparece "[ N/M]" o "X%" en la línea.
    const parseProgress = (line) => {
      // Patrón [  N/M]
      let m = line.match(/\[\s*(\d+)\/(\d+)\s*\]/);
      if (m) {
        const p = (parseInt(m[1], 10) / parseInt(m[2], 10)) * 100;
        return Math.min(99, p);
      }
      // "XX.X%" o "XX%"
      m = line.match(/(\d+(?:\.\d+)?)\s*%/);
      if (m) {
        const p = parseFloat(m[1]);
        if (p >= 0 && p <= 100) return p;
      }
      return null;
    };

    let linesCount = 0;
    const cleanup = API.streamJob(resp.job_id, {
      onLine: (line) => {
        linesCount++;
        appendLine(stepId, line);
        setProgress(prev => {
          const explicit = parseProgress(line);
          if (explicit !== null) {
            return { ...prev, [stepId]: explicit };
          }
          // Fallback: crecimiento asintótico hacia 90%
          const curr = prev[stepId] || 0;
          return { ...prev, [stepId]: Math.min(90, curr + 100 / 120) };
        });
      },
      onDone: (finalState, exitCode) => {
        setProgress(prev => ({ ...prev, [stepId]: 100 }));
        setStates(prev => {
          const nextStatus = finalState === 'done' ? 'done'
                           : finalState === 'cancelled' ? 'idle'
                           : 'error';
          const next = { ...prev, [stepId]: nextStatus };
          if (nextStatus === 'done') {
            step.unlocks.forEach(uid => { if (next[uid] === 'locked') next[uid] = 'idle'; });
          }
          return next;
        });
        setDoneKeys(prev => ({ ...prev, [stepId]: Date.now() }));
        sseCleanups.current[stepId] = null;
      },
      onError: (err) => {
        appendLine(stepId, `[WARN] Conexión SSE interrumpida`);
      },
    });

    sseCleanups.current[stepId] = cleanup;
  };

  const handleStop = async (stepId) => {
    const jobId = jobIds.current[stepId];
    if (!jobId) return;
    try { await API.stopJob(jobId); } catch(e) {}
    appendLine(stepId, `[WARN] Solicitud de cancelación enviada`);
  };

  const handleReset = (stepId) => {
    const step = STEPS.find(s => s.id === stepId);
    if (sseCleanups.current[stepId]) {
      try { sseCleanups.current[stepId](); } catch(e) {}
      sseCleanups.current[stepId] = null;
    }
    setStates(prev => {
      const next = { ...prev, [stepId]: 'idle' };
      step.unlocks.forEach(uid => { if (prev[uid] === 'idle') next[uid] = 'locked'; });
      return next;
    });
    setProgress(prev => ({ ...prev, [stepId]: 0 }));
    setTermLines(prev => ({ ...prev, [stepId]: [] }));
  };

  const pqcSteps = STEPS.filter(s => s.pipeline === 'pqc');
  const echSteps = STEPS.filter(s => s.pipeline === 'ech');

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg)', display: 'flex', flexDirection: 'column' }}>
      <header style={{ borderBottom: '1px solid var(--border)', padding: '13px 28px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'var(--surface)', position: 'sticky', top: 0, zIndex: 40, flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
            <rect width="32" height="32" rx="8" fill="var(--purple-bg)" stroke="var(--purple-border)" strokeWidth="1"/>
            <path d="M8 16 L14 10 L20 16 L14 22 Z" fill="var(--purple)" opacity="0.85"/>
            <path d="M14 10 L20 10 L26 16 L20 22 L14 22 L20 16 Z" fill="var(--green)" opacity="0.65"/>
          </svg>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, letterSpacing: '-0.01em' }}>PQC in TLS</div>
            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace" }}>Research Dashboard</div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <button onClick={toggleTheme} style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 8, padding: '7px 13px', cursor: 'pointer', color: 'var(--text-dim)', fontSize: 13, fontFamily: "'Space Grotesk', sans-serif", fontWeight: 500, transition: 'all 0.15s' }}>
            {theme === 'dark' ? '☀ Claro' : '☾ Oscuro'}
          </button>
          <Btn onClick={onLogout} variant="ghost" color="purple" size="sm">← Inicio</Btn>
        </div>
      </header>

      <main style={{ flex: 1, padding: '26px 28px', maxWidth: 1180, margin: '0 auto', width: '100%' }}>
        <div style={{ marginBottom: 26 }}>
          <h1 style={{ fontSize: 23, fontWeight: 700, letterSpacing: '-0.02em', marginBottom: 4 }}>Pipelines de investigación</h1>
          <p style={{ fontSize: 13.5, color: 'var(--text-dim)' }}>Selecciona un paso para configurar sus argumentos, ejecutar la sonda y visualizar resultados.</p>
        </div>
        <div style={{ display: 'flex', gap: 22, flexWrap: 'wrap' }}>
          <PipelineCol steps={pqcSteps} states={states} onOpen={setOpenId} color="purple" title="Criptografía Post-Cuántica" subtitle="Adopción PQC, latencia y clasificación ML" icon="◈" />
          <PipelineCol steps={echSteps} states={states} onOpen={setOpenId} color="green"  title="Encrypted Client Hello" subtitle="Prevalencia ECH y overhead de latencia" icon="◉" />
        </div>
      </main>

      {openId && openStep && (
        <>
          <div onClick={() => setOpenId(null)} style={{ position: 'fixed', inset: 0, background: 'oklch(0 0 0 / 0.42)', zIndex: 49, backdropFilter: 'blur(2px)' }} />
          <StepDrawer
            step={openStep} status={states[openId]}
            args={args[openId] || {}}
            onArgChange={(k, v) => handleArgChange(openId, k, v)}
            onRun={() => handleRun(openId)}
            onStop={() => handleStop(openId)}
            onReset={() => handleReset(openId)}
            onClose={() => setOpenId(null)}
            progress={progress[openId] || 0}
            termLines={termLines[openId] || []}
            color={openStep.pipeline === 'pqc' ? 'purple' : 'green'}
            doneKey={doneKeys[openId] || 0}
          />
        </>
      )}
    </div>
  );
}

// ── Welcome ────────────────────────────────────────────────────
function Welcome({ onEnter, theme, toggleTheme }) {
  const [leaving, setLeaving] = useState(false);
  const go = () => { setLeaving(true); setTimeout(onEnter, 420); };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', background: 'var(--bg)', position: 'relative', overflow: 'hidden' }}>
      <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', top: '18%', left: '12%', width: 520, height: 520, borderRadius: '50%', background: 'oklch(0.67 0.24 290 / 0.09)', filter: 'blur(90px)', animation: 'gradMove 9s ease-in-out infinite' }} />
        <div style={{ position: 'absolute', bottom: '18%', right: '12%', width: 420, height: 420, borderRadius: '50%', background: 'oklch(0.72 0.19 148 / 0.08)', filter: 'blur(80px)', animation: 'gradMove 11s ease-in-out infinite reverse' }} />
        <div style={{ position: 'absolute', top: '58%', left: '48%', width: 320, height: 320, borderRadius: '50%', background: 'oklch(0.67 0.24 290 / 0.05)', filter: 'blur(60px)', animation: 'gradMove 14s ease-in-out infinite 3s', transform: 'translateX(-50%)' }} />
      </div>
      <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none', backgroundImage: 'linear-gradient(var(--border) 1px, transparent 1px), linear-gradient(90deg, var(--border) 1px, transparent 1px)', backgroundSize: '50px 50px', opacity: 0.35, maskImage: 'radial-gradient(ellipse 75% 75% at 50% 50%, black 30%, transparent 100%)' }} />

      <div style={{ position: 'absolute', top: 22, right: 22 }}>
        <button onClick={toggleTheme} style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '7px 14px', cursor: 'pointer', color: 'var(--text-dim)', fontSize: 13, fontFamily: "'Space Grotesk', sans-serif", fontWeight: 500 }}>
          {theme === 'dark' ? '☀ Claro' : '☾ Oscuro'}
        </button>
      </div>

      <div style={{ textAlign: 'center', maxWidth: 680, padding: '0 24px', position: 'relative', zIndex: 1, opacity: leaving ? 0 : 1, transform: leaving ? 'scale(0.96) translateY(-8px)' : 'scale(1)', transition: 'opacity 0.38s ease, transform 0.38s ease', animation: 'fadeUp 0.55s ease' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 7, background: 'var(--purple-bg)', border: '1px solid var(--purple-border)', borderRadius: 99, padding: '5px 15px', marginBottom: 30, fontSize: 11.5, fontWeight: 600, color: 'var(--purple)', fontFamily: "'JetBrains Mono', monospace" }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--purple)', display: 'inline-block', animation: 'pulse 2.2s ease-in-out infinite' }} />
          TFG — Post-Quantum Cryptography Research Tool
        </div>

        <h1 style={{ fontSize: 'clamp(40px, 7vw, 66px)', fontWeight: 700, lineHeight: 1.08, letterSpacing: '-0.03em', marginBottom: 18, background: 'linear-gradient(135deg, var(--text) 0%, var(--purple) 52%, var(--green) 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
          PQC in TLS
        </h1>

        <p style={{ fontSize: 15.5, color: 'var(--text-dim)', lineHeight: 1.7, marginBottom: 34, maxWidth: 520, margin: '0 auto 34px' }}>
          Dashboard de investigación para medir la adopción de algoritmos post-cuánticos y Encrypted Client Hello en servidores HTTPS reales.
        </p>

        <div style={{ display: 'flex', gap: 7, justifyContent: 'center', flexWrap: 'wrap', marginBottom: 42 }}>
          {['Sonda PQC', 'Análisis estadístico', 'Clasificación ML', 'Sonda ECH', 'Latencia ECH', 'Latencia PQC'].map(f => (
            <span key={f} style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 99, padding: '4px 13px', fontSize: 11.5, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace" }}>{f}</span>
          ))}
        </div>

        <Btn onClick={go} color="purple" size="lg">Entrar al Dashboard →</Btn>

        <div style={{ marginTop: 42, fontSize: 11, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.7 }}>
          OpenSSL OQS · BoringSSL · Docker · Python 3 · scikit-learn
        </div>
      </div>
    </div>
  );
}

// ── App root ───────────────────────────────────────────────────
function App() {
  const [theme, setTheme]   = useState('dark');
  const [screen, setScreen] = useState('welcome');

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  const toggleTheme = () => setTheme(t => t === 'dark' ? 'light' : 'dark');

  return screen === 'welcome'
    ? <Welcome onEnter={() => setScreen('dashboard')} theme={theme} toggleTheme={toggleTheme} />
    : <Dashboard theme={theme} toggleTheme={toggleTheme} onLogout={() => setScreen('welcome')} />;
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
})();
