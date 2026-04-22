// src/results.jsx — Vistas de resultados alimentadas por /api/results/<step_id>
(function() {
const { useState, useEffect } = React;

// ── Helper de color según pipeline ─────────────────────────────
const colorFor = (stepId) => stepId.startsWith('pqc_') ? 'purple' : 'green';

// ── Estados vacíos ─────────────────────────────────────────────
function EmptyState({ title, hint }) {
  return (
    <div style={{ padding: '28px 20px', textAlign: 'center', color: 'var(--text-muted)' }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-dim)', marginBottom: 6 }}>{title}</div>
      {hint && <div style={{ fontSize: 11.5, lineHeight: 1.5, maxWidth: 360, margin: '0 auto' }}>{hint}</div>}
    </div>
  );
}

function LoadingState() {
  return (
    <div style={{ padding: '36px 20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 12, fontFamily: "'JetBrains Mono', monospace" }}>
      Cargando resultados…
    </div>
  );
}

// ── StatsRow ───────────────────────────────────────────────────
function StatsRow({ stats = [], color }) {
  if (!stats.length) return null;
  return (
    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 20 }}>
      {stats.map((s, i) => (
        <StatCard key={i} label={s.label} value={s.value} color={color} />
      ))}
    </div>
  );
}

// ── ImagesList (miniaturas con link al backend) ─────────────────
function ImagesSection({ stepId, color }) {
  // Mapeo de step → imágenes esperadas en /imagenes
  const patterns = {
    pqc_analisis:      [/^latencia_.*\.png$/i, /^bytes_.*\.png$/i, /^delta_.*\.png$/i, /^ranking_.*\.png$/i],
    pqc_clasificacion: [/^clasificacion_.*\.png$/i],
    ech_latencia_ech:  [/^latencia_ech_vs_sin_ech\.png$/i],
    ech_latencia_pqc:  [/^latencia_pqc_.*\.png$/i],
  };
  const pats = patterns[stepId];
  const [imgs, setImgs] = useState(null);

  useEffect(() => {
    if (!pats) { setImgs([]); return; }
    API.fetchImages()
      .then(all => setImgs(all.filter(n => pats.some(p => p.test(n)))))
      .catch(() => setImgs([]));
  }, [stepId]);

  if (!pats || imgs === null || imgs.length === 0) return null;

  const accent = color === 'purple' ? 'var(--purple-border)' : 'var(--green-border)';
  return (
    <div style={{ marginTop: 18 }}>
      <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-dim)', marginBottom: 9, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
        Figuras generadas ({imgs.length})
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 8 }}>
        {imgs.map(name => (
          <a key={name} href={API.imageUrl(name)} target="_blank" rel="noreferrer"
             style={{ border: `1px solid ${accent}`, borderRadius: 8, padding: 6, background: 'var(--surface-2)', display: 'block', textDecoration: 'none' }}>
            <img src={API.imageUrl(name)} alt={name}
                 style={{ width: '100%', height: 'auto', borderRadius: 5, display: 'block' }} />
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 5, fontFamily: "'JetBrains Mono', monospace", wordBreak: 'break-all' }}>
              {name}
            </div>
          </a>
        ))}
      </div>
    </div>
  );
}

// ── Render genérico a partir de payload del backend ────────────
function ResultsRender({ stepId, data }) {
  const color = data.color || colorFor(stepId);

  const noteBg     = color === 'purple' ? 'var(--purple-bg)'     : 'var(--green-bg)';
  const noteBorder = color === 'purple' ? 'var(--purple-border)' : 'var(--green-border)';

  return (
    <div style={{ animation: 'fadeUp 0.3s ease' }}>
      <StatsRow stats={data.stats} color={color} />

      {data.h_bars && data.h_bars.length > 0 && (
        <HBarChart title={data.title} data={data.h_bars} color={color} unit={data.unit || '%'} />
      )}

      {data.v_bars && data.v_bars.length > 0 && (
        <VBarChart title={data.title} data={data.v_bars} color={color} unit={data.unit || 'ms'} note={data.note_inline} />
      )}

      {data.grouped && data.grouped.groups && data.grouped.groups.length > 0 && (
        <GroupedBar title={data.grouped_title} groups={data.grouped.groups} series={data.grouped.series} />
      )}

      {data.conf_matrix && data.conf_matrix.labels && (
        <div style={{ marginTop: 18 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-dim)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Matriz de confusión — mejor modelo
          </div>
          <ConfMatrix
            color={color}
            labels={data.conf_matrix.labels}
            data={data.conf_matrix.matrix}
          />
        </div>
      )}

      <ImagesSection stepId={stepId} color={color} />

      {data.note && (
        <div style={{ marginTop: 14, padding: '10px 14px', background: noteBg, border: `1px solid ${noteBorder}`, borderRadius: 8, fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.5 }}>
          {data.note}
        </div>
      )}
    </div>
  );
}

// ── ResultsView: fetches desde el backend real ──────────────────
function ResultsView({ stepId, reloadKey }) {
  const [data, setData]   = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    setData(null);
    setError(null);
    API.fetchResults(stepId)
      .then(payload => { if (!cancelled) setData(payload); })
      .catch(e => { if (!cancelled) setError(e.message || String(e)); });
    return () => { cancelled = true; };
  }, [stepId, reloadKey]);

  if (error) {
    return (
      <EmptyState
        title="No se pudieron cargar los resultados"
        hint={error}
      />
    );
  }
  if (data === null) return <LoadingState />;

  if (data.error) {
    return (
      <EmptyState
        title="Aún no hay resultados"
        hint={data.hint || data.error}
      />
    );
  }

  return <ResultsRender stepId={stepId} data={data} />;
}

Object.assign(window, { ResultsView });
})();
