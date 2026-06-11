import React, { useState } from 'react';

const API_URL = 'http://localhost:8000/api/analyze';

const MODES = [
  { value: 'live', label: 'Live Check' },
  { value: 'benign', label: 'Sample: Safe' },
  { value: 'phishing', label: 'Sample: Phishing' },
  { value: 'prompt_injection', label: 'Sample: AI Prompt Injection' },
];

// Strip the trailing "[+N]." / "[-N]." scoring annotation for readability.
const clean = (s) => (s || '').replace(/\s*\[[+-]?\d+\]\.?$/, '').replace(/\s*\[[+-]?\d+\]/, '');

function bandClass(label) {
  if (label === 'Likely Safe') return 'safe';
  if (label === 'Needs Caution') return 'warning';
  if (label === 'High Risk') return 'danger';
  return '';
}

function bandColor(label) {
  if (label === 'Likely Safe') return 'var(--safe)';
  if (label === 'Needs Caution') return 'var(--warn)';
  if (label === 'High Risk') return 'var(--danger)';
  return 'var(--accent)';
}

/* ---------- Circular risk gauge ---------- */
function Gauge({ score, label }) {
  const r = 72;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const offset = c * (1 - pct);
  const color = bandColor(label);
  return (
    <div className="gauge">
      <svg width="168" height="168">
        <circle className="track" cx="84" cy="84" r={r} fill="none" strokeWidth="12" />
        <circle
          className="fill" cx="84" cy="84" r={r} fill="none" strokeWidth="12"
          stroke={color} strokeDasharray={c} strokeDashoffset={offset}
        />
      </svg>
      <div className="gauge-center">
        <div className="gauge-score" style={{ color }}>{score}</div>
        <div className="gauge-max">RISK / 100</div>
      </div>
    </div>
  );
}

/* ---------- Score breakdown bars ---------- */
function Breakdown({ breakdown }) {
  const entries = Object.entries(breakdown || {}).filter(([, v]) => v !== 0);
  if (!entries.length) return <p className="empty">No category contributed to the score.</p>;
  const max = Math.max(25, ...entries.map(([, v]) => Math.abs(v)));
  return (
    <div>
      {entries.map(([k, v]) => (
        <div className="bar-row" key={k}>
          <div className="bar-head">
            <span className="label">{k}</span>
            <span className={`val ${v > 0 ? 'pos' : v < 0 ? 'neg' : 'zero'}`}>
              {v > 0 ? `+${v}` : v}
            </span>
          </div>
          <div className="bar-track">
            <div
              className={`bar-fill ${v >= 0 ? 'pos' : 'neg'}`}
              style={{ width: `${(Math.abs(v) / max) * 100}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

function FactorList({ items, icon, emptyText }) {
  if (!items || !items.length) return <p className="empty">{emptyText}</p>;
  return (
    <ul className="factors">
      {items.map((f, i) => (
        <li key={i}><span className="ico">{icon}</span><span>{clean(f)}</span></li>
      ))}
    </ul>
  );
}

function KV({ k, v, tone }) {
  return (
    <div className="item">
      <div className="k">{k}</div>
      <div className={`v ${tone || ''}`}>{v}</div>
    </div>
  );
}

function App() {
  const [url, setUrl] = useState('');
  const [mode, setMode] = useState('live');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const analyze = async (e) => {
    e.preventDefault();
    if (mode === 'live' && !url.trim()) { setError('Please enter a URL to check.'); return; }
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, mode }),
      });
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(detail.detail || 'Analysis failed. Check the URL and try again.');
      }
      setResult(await res.json());
    } catch (err) {
      setError(err.message.includes('fetch') ? 'Could not reach the API on localhost:8000. Is the backend running?' : err.message);
    } finally {
      setLoading(false);
    }
  };

  const ra = result?.risk_assessment;
  const label = ra?.ui_label || result?.classification || '';
  const f = result?.url_features;
  const pi = result?.prompt_injection;
  const band = bandClass(label);

  return (
    <div className="container">
      <header className="header">
        <div className="brand-mark"><span className="logo">🛡️</span><h1>Sentinel</h1></div>
        <p>Evidence-grounded URL safety &amp; phishing analysis</p>
      </header>

      <form className="search-box" onSubmit={analyze}>
        <select value={mode} onChange={(e) => setMode(e.target.value)} disabled={loading}>
          {MODES.map((m) => <option key={m.value} value={m.value}>{m.label}</option>)}
        </select>
        <input
          type="text"
          placeholder="Enter a URL — e.g. amazon.com or paypal-login.example.net"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          disabled={loading || mode !== 'live'}
        />
        <button type="submit" className="btn-primary" disabled={loading}>
          {loading ? 'Analyzing…' : 'Analyze'}
        </button>
      </form>
      <p className="hint">
        {mode === 'live'
          ? 'Bare domains are checked over HTTPS first. URLs are crawled safely (read-only).'
          : 'Sample mode loads a bundled local page; the URL field is ignored.'}
      </p>

      {error && (
        <div className="panel error-box"><h3>Error</h3><p>{error}</p></div>
      )}

      {loading && (
        <div className="loading"><div className="spinner" /><p>Running multi-signal analysis…</p></div>
      )}

      {result && ra && (
        <div className="results">
          {/* Verdict hero */}
          <div className={`panel verdict ${band}`}>
            <Gauge score={result.risk_score} label={label} />
            <div className="verdict-body">
              <h2>{label}</h2>
              <div className="verdict-url">{result.requested_url || f?.normalized_url}</div>
              <div className="verdict-action">{ra.recommended_action}</div>
              <div className="pill-row">
                <span className="pill strong">Confidence: {result.confidence_label}</span>
                {f?.uses_https
                  ? <span className="pill">🔒 HTTPS</span>
                  : <span className="pill">⚠️ No HTTPS</span>}
                {result.is_trusted_domain && <span className="pill">✓ On trusted list</span>}
                {!result.crawl?.success && result.crawl?.source === 'live' &&
                  <span className="pill">⚠ Page didn’t load</span>}
              </div>
            </div>
          </div>

          {/* Breakdown + factors */}
          <div className="grid-2">
            <div className="panel">
              <h3 className="section-title">Score breakdown</h3>
              <Breakdown breakdown={ra.score_breakdown} />
            </div>
            <div className="panel">
              <h3 className="section-title">Why this verdict</h3>
              <FactorList items={ra.risk_factors} icon="⚠️" emptyText="No risk signals found." />
            </div>
          </div>

          <div className="grid-2">
            <div className="panel">
              <h3 className="section-title">Mitigating signals</h3>
              <FactorList items={ra.safe_factors} icon="✅" emptyText="No mitigating signals observed." />
            </div>

            {/* URL anatomy */}
            <div className="panel">
              <h3 className="section-title">URL anatomy</h3>
              <div className="kv">
                <KV k="Registered domain" v={f?.registered_domain || '—'} />
                <KV k="Scheme" v={f?.scheme || '—'} tone={f?.uses_https ? 'good' : 'bad'} />
                <KV k="Subdomains" v={f?.number_of_subdomains ?? '—'} tone={f?.number_of_subdomains > 3 ? 'bad' : ''} />
                <KV k="URL length" v={f?.url_length ?? '—'} />
                {f?.impersonated_brand && <KV k="Impersonates" v={f.impersonated_brand} tone="bad" />}
                {f?.lookalike_brand && <KV k="Looks like" v={f.lookalike_brand} tone="bad" />}
                <KV k="Suspicious TLD" v={f?.suspicious_tld ? 'yes' : 'no'} tone={f?.suspicious_tld ? 'bad' : 'good'} />
                <KV k="Raw IP host" v={f?.contains_ip_address ? 'yes' : 'no'} tone={f?.contains_ip_address ? 'bad' : 'good'} />
                <KV k="Punycode" v={f?.contains_punycode ? 'yes' : 'no'} tone={f?.contains_punycode ? 'bad' : 'good'} />
                <KV k="Shortener" v={f?.is_shortened_url ? 'yes' : 'no'} tone={f?.is_shortened_url ? 'bad' : 'good'} />
              </div>
            </div>
          </div>

          {/* Prompt injection */}
          <div className={`panel ${pi?.injection_detected ? 'alert' : 'alert clean'}`}>
            <h3 className="section-title">Hidden instruction check</h3>
            {pi?.injection_detected ? (
              <>
                <p>Hidden AI-manipulation instructions were detected
                  (severity: <strong>{pi.severity}</strong>{pi.found_in_hidden ? ', concealed in hidden content' : ''}).
                  This text was treated as untrusted evidence and was never followed.</p>
                {pi.matched_patterns?.length > 0 &&
                  <p style={{ marginTop: '.5rem', color: 'var(--text-dim)', fontSize: '.85rem' }}>
                    Patterns: {pi.matched_patterns.join(', ')}</p>}
                {pi.suspicious_snippets?.[0] && <div className="snippet">{pi.suspicious_snippets[0]}</div>}
              </>
            ) : (
              <p>No hidden AI-manipulation instructions were found on the page.</p>
            )}
          </div>

          {/* Retrieved knowledge */}
          {result.retrieved_evidence?.length > 0 && (
            <div className="panel">
              <h3 className="section-title">Retrieved security knowledge</h3>
              {result.retrieved_evidence.map((ev, i) => (
                <div className="kb-card" key={i}>
                  <div className="kb-top">
                    <h4>{ev.title}</h4>
                    <span className="sim">sim {ev.similarity_score}</span>
                  </div>
                  <p>{ev.content}</p>
                  {ev.recommended_action && <p className="rec">→ {ev.recommended_action}</p>}
                  {ev.category && <div style={{ marginTop: '.6rem' }}><span className="tag">{ev.category}</span></div>}
                </div>
              ))}
            </div>
          )}

          {/* Explanation */}
          <div className="panel explain">
            <h3 className="section-title">Explanation</h3>
            <p>{result.explanation}</p>
            <p className="src">Source: {result.explanation_source}</p>
          </div>

          <p className="disclaimer">
            Sentinel is a research prototype for decision support — it uses transparent
            heuristics and does not guarantee a site is safe. Always verify before
            entering passwords or payment details.
          </p>
        </div>
      )}
    </div>
  );
}

export default App;
