import React, { useEffect, useState } from 'react';

const API_BASE = 'http://localhost:8000/api';
const API_URL = `${API_BASE}/analyze`;
const CAPS_URL = `${API_BASE}/capabilities`;

const MODES = [
  { value: 'live', label: 'Live Check' },
  { value: 'benign', label: 'Sample: Safe' },
  { value: 'phishing', label: 'Sample: Phishing' },
  { value: 'prompt_injection', label: 'Sample: AI Prompt Injection' },
];

// Toggleable optional stages. `key` matches the /api/capabilities keys; the
// request-body translation lives in buildOverrides().
const STAGE_DEFS = [
  { key: 'threat_intel', label: 'Threat-intel feeds', desc: 'OpenPhish / PhishTank lookup' },
  { key: 'domain_intel', label: 'Domain reputation', desc: 'WHOIS age · DNS · TLS · conflicts' },
  { key: 'render_playwright', label: 'Playwright render', desc: 'Headless Chromium (vs plain GET)' },
  { key: 'dynamic', label: 'Dynamic analysis', desc: 'Post-interaction cloaking (needs render)' },
  { key: 'multimodal', label: 'Multimodal OCR', desc: 'Screenshot + OCR (needs render + Tesseract)' },
  { key: 'embedding', label: 'Embedding RAG', desc: 'Vector retrieval (vs TF-IDF)' },
  { key: 'llm', label: 'LLM explanation', desc: 'Rephrases wording only (needs API key)' },
];

// Strip the trailing "[+N]." / "[-N]." scoring annotation for readability.
const clean = (s) => (s || '').replace(/\s*\[[+-]?\d+\]\.?$/, '').replace(/\s*\[[+-]?\d+\]/, '');
const yesNo = (v) => (v === true ? 'yes' : v === false ? 'no' : '—');
const num = (v, d = 2) => (typeof v === 'number' ? v.toFixed(d) : '—');

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

// Translate toggle state -> analyze request overrides. Unavailable stages are
// forced off so the request never asks for a stage whose deps are missing.
function buildOverrides(toggles, caps) {
  const on = (k) => (caps?.[k]?.available ? !!toggles[k] : false);
  return {
    enable_threat_intel: on('threat_intel'),
    enable_domain_intel: on('domain_intel'),
    enable_multimodal: on('multimodal'),
    enable_dynamic: on('dynamic'),
    enable_llm: on('llm'),
    render_backend: on('render_playwright') ? 'playwright' : 'requests',
    retriever_backend: on('embedding') ? 'embedding' : 'tfidf',
  };
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

/* ---------- Stage toggles (interactive ablation) ---------- */
function StageToggles({ caps, toggles, setToggles, disabled }) {
  if (!caps || !toggles) return null;
  const flip = (k) => setToggles((t) => ({ ...t, [k]: !t[k] }));
  return (
    <div className="panel">
      <h3 className="section-title">Analysis stages · interactive ablation</h3>
      <div className="toggles">
        {STAGE_DEFS.map((s) => {
          const cap = caps[s.key] || {};
          const available = !!cap.available;
          const checked = available && !!toggles[s.key];
          return (
            <label className={`toggle-row ${checked ? '' : 'off'}`} key={s.key}>
              <input
                type="checkbox"
                checked={checked}
                disabled={disabled || !available}
                onChange={() => flip(s.key)}
              />
              <span className="t-body">
                <span className="t-label">{s.label}</span>
                <span className="t-desc">{s.desc}</span>
                {!available && <span className="t-reason">Unavailable — {cap.reason || 'dependency missing'}</span>}
              </span>
            </label>
          );
        })}
      </div>
      <p className="hint" style={{ margin: '1rem 0 0', textAlign: 'left' }}>
        Toggle stages off to see how the verdict and score change. Greyed-out stages
        need a dependency that isn’t installed. Sample modes skip live-only stages.
      </p>
    </div>
  );
}

/* ---------- Threat-intel detail ---------- */
function ThreatIntelPanel({ ti }) {
  return (
    <div className="panel">
      <div className="stage-head">
        <h3 className="section-title" style={{ margin: 0 }}>Threat-intel feeds</h3>
        {!ti?.checked ? <span className="badge">not run</span>
          : ti.listed ? <span className="badge bad">listed</span>
            : <span className="badge good">not listed</span>}
      </div>
      {!ti?.checked ? (
        <p className="stage-off">{ti?.confidence_note || 'Threat-intel lookup was disabled for this run.'}</p>
      ) : (
        <>
          {ti.listed ? (
            <FactorList
              items={[`Listed on ${ti.source || 'a feed'}${ti.matched_value ? `: ${ti.matched_value}` : ''}`]}
              icon="🚩" emptyText="" />
          ) : (
            <p className="empty" style={{ fontStyle: 'normal', color: 'var(--text-dim)' }}>
              Not found in any consulted feed.
            </p>
          )}
          <div className="kv" style={{ marginTop: '1rem' }}>
            <KV k="Sources checked" v={(ti.sources_checked || []).join(', ') || '—'} />
            <KV k="Matched feed" v={ti.source || '—'} tone={ti.listed ? 'bad' : ''} />
          </div>
          {ti.confidence_note && <p className="explain src" style={{ marginTop: '.8rem' }}>{ti.confidence_note}</p>}
        </>
      )}
    </div>
  );
}

/* ---------- Domain reputation detail ---------- */
function DomainIntelPanel({ di }) {
  return (
    <div className="panel">
      <div className="stage-head">
        <h3 className="section-title" style={{ margin: 0 }}>Domain reputation</h3>
        {!di?.checked ? <span className="badge">not run</span>
          : di.conflict_count > 0 ? <span className="badge bad">{di.conflict_count} conflict{di.conflict_count > 1 ? 's' : ''}</span>
            : <span className="badge good">no conflicts</span>}
      </div>
      {!di?.checked ? (
        <p className="stage-off">Domain reputation lookups (WHOIS / DNS / TLS) were not run for this analysis.</p>
      ) : (
        <>
          <div className="kv">
            {di.whois_available ? (
              <>
                <KV k="Registrar" v={di.registrar || '—'} />
                <KV k="Registered on" v={di.domain_created || '—'} />
                <KV k="Domain age (days)"
                  v={di.domain_age_days ?? '—'}
                  tone={di.is_newly_registered ? 'bad' : di.domain_age_days != null ? 'good' : ''} />
                <KV k="Registrant country" v={di.registrant_country || '—'} />
              </>
            ) : <KV k="WHOIS" v="unavailable" />}
            {di.dns_available ? (
              <>
                <KV k="Resolves (A record)" v={yesNo(di.resolves)} tone={di.resolves ? 'good' : di.resolves === false ? 'bad' : ''} />
                <KV k="Mail records (MX)" v={yesNo(di.has_mx)} />
              </>
            ) : <KV k="DNS" v="unavailable" />}
            {di.tls_available ? (
              <>
                <KV k="TLS issuer" v={di.cert_issuer || '—'} />
                <KV k="Cert org (OV/EV)" v={di.cert_org || '—'} />
                <KV k="Cert valid until" v={di.cert_valid_until || '—'} />
                <KV k="Cert currently valid" v={yesNo(di.cert_currently_valid)} tone={di.cert_currently_valid === false ? 'bad' : ''} />
                <KV k="Self-signed" v={yesNo(di.cert_self_signed)} tone={di.cert_self_signed ? 'bad' : ''} />
              </>
            ) : <KV k="TLS" v="not checked (HTTP or unavailable)" />}
            {di.asn_available && (
              <>
                <KV k="IP country" v={di.ip_country || '—'} />
                <KV k="Hosting ASN" v={di.asn_org || '—'} />
              </>
            )}
          </div>
          {di.conflict_count > 0 && (
            <div style={{ marginTop: '1.1rem' }}>
              <h4 style={{ fontSize: '.82rem', color: 'var(--text-dim)', marginBottom: '.5rem' }}>
                Cross-signal conflicts
              </h4>
              <FactorList items={di.conflicts} icon="⚠️" emptyText="" />
            </div>
          )}
        </>
      )}
    </div>
  );
}

/* ---------- Multimodal (screenshot + OCR) detail ---------- */
function MultimodalPanel({ mm }) {
  const ran = mm?.checked && mm?.available;
  return (
    <div className="panel">
      <div className="stage-head">
        <h3 className="section-title" style={{ margin: 0 }}>Multimodal (screenshot + OCR)</h3>
        {!mm?.checked ? <span className="badge">not run</span>
          : !mm.available ? <span className="badge warn">unavailable</span>
            : (mm.brand_in_image || mm.text_divergence || mm.injection_in_ocr)
              ? <span className="badge bad">signals</span>
              : <span className="badge good">clean</span>}
      </div>
      {!ran ? (
        <p className="stage-off">{mm?.note || 'Multimodal analysis was not run.'}</p>
      ) : (
        <>
          <div className="kv">
            <KV k="Brand seen in image" v={mm.brand_in_image || 'none'} tone={mm.brand_in_image ? 'bad' : 'good'} />
            <KV k="Text divergence" v={yesNo(mm.text_divergence)} tone={mm.text_divergence ? 'bad' : 'good'} />
            <KV k="Divergence ratio" v={num(mm.divergence_ratio)} />
            <KV k="Injection in OCR" v={yesNo(mm.injection_in_ocr)} tone={mm.injection_in_ocr ? 'bad' : 'good'} />
            {mm.injection_in_ocr && <KV k="Injection severity" v={mm.injection_severity} tone="bad" />}
            <KV k="OCR characters" v={mm.ocr_char_count ?? '—'} />
          </div>
          {mm.divergent_terms?.length > 0 && (
            <div className="tag-row">
              {mm.divergent_terms.map((t, i) => <span className="tag" key={i}>{t}</span>)}
            </div>
          )}
          {mm.ocr_text_excerpt && <div className="snippet">{mm.ocr_text_excerpt}</div>}
        </>
      )}
    </div>
  );
}

/* ---------- Dynamic (pre/post interaction) detail ---------- */
function DynamicPanel({ dy }) {
  const ran = dy?.checked && dy?.available;
  const pre = dy?.pre || {};
  const post = dy?.post || {};
  const rows = [
    ['Forms', 'forms', dy?.delta_forms],
    ['Inputs', 'inputs', dy?.delta_inputs],
    ['Password fields', 'password_fields', dy?.delta_password_fields],
    ['Visible password fields', 'visible_password_fields', dy?.delta_visible_password_fields],
  ];
  return (
    <div className="panel">
      <div className="stage-head">
        <h3 className="section-title" style={{ margin: 0 }}>Dynamic analysis (post-interaction)</h3>
        {!dy?.checked ? <span className="badge">not run</span>
          : !dy.available ? <span className="badge warn">unavailable</span>
            : dy.cloaking_detected ? <span className="badge bad">cloaking</span>
              : <span className="badge good">no cloaking</span>}
      </div>
      {!ran ? (
        <p className="stage-off">{dy?.note || 'Dynamic analysis was not run.'}</p>
      ) : (
        <>
          <table className="difftable">
            <thead>
              <tr><th>DOM element</th><th style={{ textAlign: 'right' }}>Before</th><th style={{ textAlign: 'right' }}>After</th><th style={{ textAlign: 'right' }}>Δ</th></tr>
            </thead>
            <tbody>
              {rows.map(([label, field, delta]) => (
                <tr key={field}>
                  <td>{label}</td>
                  <td className="num">{pre[field] ?? 0}</td>
                  <td className="num">{post[field] ?? 0}</td>
                  <td className={`num delta ${delta > 0 ? 'pos' : ''}`}>{delta > 0 ? `+${delta}` : (delta ?? 0)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="kv" style={{ marginTop: '1rem' }}>
            <KV k="Clicked login control" v={yesNo(dy.clicked_login)} />
            <KV k="Cloaking detected" v={yesNo(dy.cloaking_detected)} tone={dy.cloaking_detected ? 'bad' : 'good'} />
          </div>
          {dy.reasons?.length > 0 && (
            <div style={{ marginTop: '1rem' }}>
              <FactorList items={dy.reasons} icon="⚠️" emptyText="" />
            </div>
          )}
        </>
      )}
    </div>
  );
}

function App() {
  const [url, setUrl] = useState('');
  const [mode, setMode] = useState('live');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [caps, setCaps] = useState(null);
  const [toggles, setToggles] = useState(null);

  // Load stage capabilities once; initialise toggle state from each stage's
  // configured default (unavailable stages start off).
  useEffect(() => {
    let cancelled = false;
    fetch(CAPS_URL)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('caps'))))
      .then((c) => {
        if (cancelled) return;
        setCaps(c);
        const init = {};
        STAGE_DEFS.forEach((s) => { init[s.key] = !!(c[s.key]?.available && c[s.key]?.default); });
        setToggles(init);
      })
      .catch(() => { /* backend may be down; toggles simply stay hidden */ });
    return () => { cancelled = true; };
  }, []);

  const analyze = async (e) => {
    e.preventDefault();
    if (mode === 'live' && !url.trim()) { setError('Please enter a URL to check.'); return; }
    setLoading(true); setError(null); setResult(null);
    try {
      const body = { url, mode, ...(toggles ? buildOverrides(toggles, caps) : {}) };
      const res = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
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

      <StageToggles caps={caps} toggles={toggles} setToggles={setToggles} disabled={loading} />

      {error && (
        <div className="panel error-box" style={{ marginTop: '1.4rem' }}><h3>Error</h3><p>{error}</p></div>
      )}

      {loading && (
        <div className="loading"><div className="spinner" /><p>Running multi-signal analysis…</p></div>
      )}

      {result && ra && (
        <div className="results" style={{ marginTop: '1.4rem' }}>
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

          {/* Backend analysis stages */}
          <h3 className="stage-section-title">Backend analysis stages</h3>
          <div className="grid-2">
            <ThreatIntelPanel ti={result.threat_intel} />
            <DomainIntelPanel di={result.domain_intel} />
          </div>
          <div className="grid-2">
            <MultimodalPanel mm={result.multimodal} />
            <DynamicPanel dy={result.dynamic_analysis} />
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

          {/* Raw JSON (collapsible) */}
          <details className="panel raw">
            <summary>Raw analysis JSON</summary>
            <pre>{JSON.stringify(result, null, 2)}</pre>
          </details>

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
