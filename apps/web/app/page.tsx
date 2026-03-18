'use client';

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

type EmailListItem = {
  id: string;
  source: string;
  subject?: string | null;
  from_addr?: string | null;
  created_at: string;
};

type EmailDetail = {
  id: string;
  source?: string;
  created_at?: string;
  headers?: { subject?: string | null; from?: string | null };
  body?: { text?: string };
  links?: { defanged?: string[] };
  analysis?: any;
};

type Detection = { label: string; risk_score: number; reasons: string[] };
type Rewrite = { safe_subject?: string | null; safe_body: string; used_llm: boolean };

/* ------------------------------------------------------------------ */
/*  Inline SVG Icons                                                   */
/* ------------------------------------------------------------------ */

function IconShield() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

function IconUpload() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="17 8 12 3 7 8" />
      <line x1="12" y1="3" x2="12" y2="15" />
    </svg>
  );
}

function IconMail() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="4" width="20" height="16" rx="2" />
      <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
    </svg>
  );
}

function IconRefresh() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8" />
      <path d="M21 3v5h-5" />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function apiBase() {
  return process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:8000';
}

/* ------------------------------------------------------------------ */
/*  Page Component                                                     */
/* ------------------------------------------------------------------ */

export default function Home() {
  const base = useMemo(() => apiBase(), []);
  const fileInputRef = useRef<HTMLInputElement>(null);

  /* --- state --- */
  const [health, setHealth] = useState<any>(null);
  const [emails, setEmails] = useState<EmailListItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<EmailDetail | null>(null);

  const [detecting, setDetecting] = useState(false);
  const [detection, setDetection] = useState<Detection | null>(null);

  const [rewriting, setRewriting] = useState(false);
  const [rewrite, setRewrite] = useState<Rewrite | null>(null);
  const [useLlm, setUseLlm] = useState(false);

  const [busyMsg, setBusyMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [theme, setTheme] = useState<'light' | 'dark'>('dark');
  const [dragOver, setDragOver] = useState(false);

  const [openSafely, setOpenSafely] = useState<{
    open: boolean;
    loading: boolean;
    jobId?: string;
    desktopUrl?: string;
    mobileUrl?: string;
    iocsUrl?: string;
  }>({ open: false, loading: false });

  /* --- API calls (logic unchanged) --- */

  const refreshHealth = useCallback(async () => {
    try {
      const res = await fetch(`${base}/health`, { cache: 'no-store' });
      setHealth(await res.json());
    } catch {
      setHealth(null);
    }
  }, [base]);

  const refreshEmails = useCallback(
    async (selectFirst = false) => {
      const res = await fetch(`${base}/emails`, { cache: 'no-store' });
      if (!res.ok) throw new Error(`Failed to load emails: ${res.status}`);
      const data = (await res.json()) as EmailListItem[];
      setEmails(data);
      if (selectFirst && data.length) {
        setSelectedId((prev) => prev ?? data[0].id);
      }
    },
    [base],
  );

  const loadEmail = useCallback(
    async (id: string) => {
      setError(null);
      setBusyMsg('Loading email...');
      try {
        const res = await fetch(`${base}/emails/${id}`, { cache: 'no-store' });
        const d = (await res.json()) as EmailDetail;
        setDetail(d);
        setDetection(d?.analysis?.detection ?? null);
        setRewrite(d?.analysis?.rewrite ?? null);
      } catch (e: any) {
        setError(String(e));
      } finally {
        setBusyMsg(null);
      }
    },
    [base],
  );

  async function uploadEml(file: File) {
    setError(null);
    setBusyMsg('Uploading .eml...');
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res = await fetch(`${base}/ingest/upload-eml`, { method: 'POST', body: fd });
      if (!res.ok) throw new Error(`Upload failed: ${res.status}`);
      const data = await res.json();
      const id = data.email_id as string;

      setBusyMsg('Analyzing...');
      await refreshEmails(false);
      setSelectedId(id);
      await loadEmail(id);

      await fetch(`${base}/emails/${id}/detect`, { method: 'POST' });
      const qs = new URLSearchParams({ use_llm: useLlm ? 'true' : 'false' });
      await fetch(`${base}/emails/${id}/rewrite?${qs.toString()}`, { method: 'POST' });
      await loadEmail(id);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusyMsg(null);
    }
  }

  async function runDetect() {
    if (!selectedId) return;
    setDetecting(true);
    setError(null);
    try {
      const res = await fetch(`${base}/emails/${selectedId}/detect`, { method: 'POST' });
      if (!res.ok) throw new Error(`Detect failed: ${res.status}`);
      const d = (await res.json()) as Detection;
      setDetection(d);
      await loadEmail(selectedId);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setDetecting(false);
    }
  }

  async function runRewrite() {
    if (!selectedId) return;
    setRewriting(true);
    setError(null);
    try {
      const qs = new URLSearchParams({ use_llm: useLlm ? 'true' : 'false' });
      const res = await fetch(`${base}/emails/${selectedId}/rewrite?${qs.toString()}`, { method: 'POST' });
      if (!res.ok) throw new Error(`Rewrite failed: ${res.status}`);
      const d = (await res.json()) as Rewrite;
      setRewrite(d);
      await loadEmail(selectedId);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setRewriting(false);
    }
  }

  async function runOpenSafely(linkIndex: number, allowTargetOrigin: boolean) {
    if (!selectedId) return;
    setError(null);
    setOpenSafely({ open: true, loading: true });
    try {
      const res = await fetch(`${base}/emails/${selectedId}/open-safely`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ link_index: linkIndex, allow_target_origin: allowTargetOrigin }),
      });
      if (!res.ok) throw new Error(`Open Safely failed: ${res.status}`);
      const data = await res.json();

      let desktop = data?.artifacts?.desktop;
      let mobile = data?.artifacts?.mobile;
      let iocs = data?.artifacts?.iocs;

      if (!desktop || !mobile) {
        const aRes = await fetch(`${base}/open-safely/artifacts/${data.job_id}`, { cache: 'no-store' });
        if (aRes.ok) {
          const aData = await aRes.json();
          const list = (aData?.artifacts || []) as Array<{ name: string; url: string }>;
          const find = (n: string) => list.find((x) => x.name === n)?.url;
          desktop = find('desktop.png');
          mobile = find('mobile.png');
          iocs = find('iocs.json');
        }
      }

      setOpenSafely({
        open: true,
        loading: false,
        jobId: data.job_id,
        desktopUrl: desktop ? `${base}${desktop}` : undefined,
        mobileUrl: mobile ? `${base}${mobile}` : undefined,
        iocsUrl: iocs ? `${base}${iocs}` : undefined,
      });
    } catch (e: any) {
      setError(String(e));
      setOpenSafely({ open: true, loading: false });
    }
  }

  /* --- derived helpers --- */

  function riskLevel(): string {
    const score = detection?.risk_score;
    if (score === undefined || score === null) return 'min';
    if (score >= 70) return 'high';
    if (score >= 40) return 'med';
    if (score >= 20) return 'low';
    return 'min';
  }

  function riskBadge() {
    const score = detection?.risk_score;
    if (score === undefined || score === null) return null;
    const level = riskLevel();
    const labels: Record<string, string> = { high: 'HIGH', med: 'MED', low: 'LOW', min: 'MIN' };
    return <span className={`badge badge--${level}`}>{labels[level]} {score}</span>;
  }

  /* --- effects --- */

  useEffect(() => {
    (async () => {
      try {
        await refreshHealth();
        await refreshEmails(true);
      } catch {
        /* ignore */
      }
    })();
  }, [refreshHealth, refreshEmails]);

  useEffect(() => {
    if (selectedId) loadEmail(selectedId);
  }, [selectedId, loadEmail]);

  useEffect(() => {
    const stored = typeof window !== 'undefined' ? localStorage.getItem('phishnet-theme') : null;
    if (stored === 'light' || stored === 'dark') {
      setTheme(stored);
      document.documentElement.dataset.theme = stored;
      return;
    }
    const prefersLight =
      typeof window !== 'undefined' &&
      window.matchMedia?.('(prefers-color-scheme: light)').matches;
    const initial = prefersLight ? 'light' : 'dark';
    setTheme(initial);
    document.documentElement.dataset.theme = initial;
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('phishnet-theme', theme);
  }, [theme]);

  /* --- render --- */

  return (
    <main className="app">
      {/* ---- Top Navigation ---- */}
      <nav className="topnav">
        <div className="topnav-brand">
          <div className="topnav-logo"><IconShield /></div>
          <div>
            <div className="topnav-title">PhishNet</div>
            <div className="topnav-tagline">Phishing analysis &amp; sandboxed previews</div>
          </div>
        </div>
        <div className="topnav-right">
          <span className={`status-dot ${health?.ok ? 'status-dot--ok' : 'status-dot--err'}`}>
            {health?.ok ? 'Connected' : 'Disconnected'}
          </span>
          <button
            type="button"
            className={`theme-switch theme-switch--${theme}`}
            onClick={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
            aria-label="Toggle theme"
          >
            <span className="theme-switch-thumb">{theme === 'light' ? '☀️' : '🌙'}</span>
          </button>
        </div>
      </nav>

      {/* ---- Notifications ---- */}
      {busyMsg && (
        <div className="notification notification--busy">
          <span className="spinner" style={{ width: 14, height: 14, border: '2px solid var(--border)', borderTopColor: 'var(--accent)', borderRadius: '50%', animation: 'spin 0.6s linear infinite', flexShrink: 0 }} />
          {busyMsg}
        </div>
      )}
      {error && (
        <div className="notification notification--error">
          {error}
          <button className="notification-dismiss" onClick={() => setError(null)}>Dismiss</button>
        </div>
      )}

      {/* ---- Workspace ---- */}
      <div className="workspace">

        {/* ---- Sidebar ---- */}
        <div className="sidebar">
          {/* Upload drop zone */}
          <div
            className={`upload-zone${dragOver ? ' upload-zone--active' : ''}`}
            onClick={() => fileInputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              const f = e.dataTransfer.files[0];
              if (f) uploadEml(f);
            }}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".eml,message/rfc822"
              hidden
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) uploadEml(f);
              }}
            />
            <div className="upload-zone-icon"><IconUpload /></div>
            <div className="upload-zone-text">Drop .eml file here</div>
            <div className="upload-zone-hint">or click to browse</div>
            <label className="upload-zone-llm" onClick={(e) => e.stopPropagation()}>
              <input
                type="checkbox"
                checked={useLlm}
                onChange={(e) => setUseLlm(e.target.checked)}
              />
              Use LLM rewrite
            </label>
          </div>

          {/* Inbox */}
          <div className="inbox">
            <div className="inbox-header">
              <div className="inbox-title">
                Inbox <span className="inbox-count">({emails.length})</span>
              </div>
              <button
                className="btn btn--sm btn--icon"
                onClick={() => {
                  setError(null);
                  refreshEmails(false).catch((e) => setError(String(e)));
                }}
                aria-label="Refresh"
              >
                <IconRefresh />
              </button>
            </div>
            <div className="inbox-list">
              {emails.length === 0 ? (
                <div className="inbox-empty">
                  <div className="inbox-empty-title">No emails yet</div>
                  Upload an .eml file to get started.
                </div>
              ) : (
                emails.map((e) => (
                  <button
                    key={e.id}
                    className={`email-item${e.id === selectedId ? ' email-item--active' : ''}`}
                    onClick={() => setSelectedId(e.id)}
                  >
                    <div className="email-item-subject">{e.subject || '(no subject)'}</div>
                    <div className="email-item-from">{e.from_addr || '(unknown sender)'}</div>
                    <div className="email-item-meta">
                      <span>{e.source}</span>
                      <span>{new Date(e.created_at).toLocaleString()}</span>
                    </div>
                  </button>
                ))
              )}
            </div>
          </div>
        </div>

        {/* ---- Detail Panel ---- */}
        <section className="detail">
          {!detail ? (
            <div className="detail-empty">
              <div className="detail-empty-icon"><IconMail /></div>
              <div className="detail-empty-title">No email selected</div>
              <div className="detail-empty-hint">Select an email from the inbox to view its analysis.</div>
            </div>
          ) : (
            <div className="detail-inner" key={detail.id}>
              {/* Header */}
              <div className="detail-header">
                <div>
                  <div className="detail-subject">{detail.headers?.subject || '(no subject)'}</div>
                  <div className="detail-from">From: {detail.headers?.from || '(unknown)'}</div>
                  <div className="detail-id">ID: {detail.id}</div>
                </div>
                {riskBadge()}
              </div>

              {/* Toolbar */}
              <div className="toolbar">
                <button className="btn" onClick={runDetect} disabled={detecting}>
                  {detecting && <span className="spinner" />}
                  {detecting ? 'Detecting...' : 'Run detection'}
                </button>
                <button className="btn btn--primary" onClick={runRewrite} disabled={rewriting}>
                  {rewriting && <span className="spinner" />}
                  {rewriting ? 'Rewriting...' : 'Safe rewrite'}
                </button>
              </div>

              {/* Detection Results */}
              {detection && (
                <div className="detection">
                  <div className="detection-top">
                    <div className="detection-label">Detection Results</div>
                    {riskBadge()}
                  </div>
                  <div className="risk-meter">
                    <div
                      className={`risk-meter-fill risk-meter-fill--${riskLevel()}`}
                      style={{ width: `${detection.risk_score}%` }}
                    />
                  </div>
                  <ul className="detection-reasons">
                    {detection.reasons?.length ? (
                      detection.reasons.map((r, i) => <li key={i}>{r}</li>)
                    ) : (
                      <li>No reasons returned.</li>
                    )}
                  </ul>
                </div>
              )}

              {/* Dual panel: Original | Safe Rewrite */}
              <div className="dual-panel">
                <div className="content-block">
                  <div className="content-block-header">Original (text only)</div>
                  <pre>{detail.body?.text || '(empty)'}</pre>
                </div>
                <div className="content-block">
                  <div className="content-block-header">
                    Safe rewrite {rewrite ? `(LLM: ${rewrite.used_llm ? 'yes' : 'no'})` : ''}
                  </div>
                  <pre>{rewrite?.safe_body || 'Run "Safe rewrite" to generate a sanitized version.'}</pre>
                </div>
              </div>

              {/* Extracted Links */}
              {detail.links?.defanged?.length ? (
                <div className="links-section">
                  <div className="links-title">Extracted Links (defanged)</div>
                  {detail.links.defanged.map((u: string, idx: number) => (
                    <div key={idx} className="link-item">
                      <code className="link-url">{u}</code>
                      <button className="btn btn--sm" onClick={() => runOpenSafely(idx, false)}>
                        Open safely (isolated)
                      </button>
                      <button className="btn btn--sm btn--primary" onClick={() => runOpenSafely(idx, true)}>
                        Open safely (allow origin)
                      </button>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
          )}
        </section>
      </div>

      {/* ---- Open Safely Modal ---- */}
      {openSafely.open && (
        <div className="modal-overlay" onClick={() => setOpenSafely({ open: false, loading: false })}>
          <div className="modal-box" onClick={(e) => e.stopPropagation()}>
            <div className="modal-box-header">
              <div className="modal-box-title">Sandbox Preview</div>
              <button className="btn btn--sm" onClick={() => setOpenSafely({ open: false, loading: false })}>
                Close
              </button>
            </div>
            <div className="modal-box-body">
              {openSafely.loading && (
                <div className="spinner-block">
                  <span className="spinner" />
                  Rendering in sandbox...
                </div>
              )}
              {!openSafely.loading && openSafely.desktopUrl && (
                <div className="modal-grid">
                  <div>
                    <div className="modal-section-label">Desktop capture</div>
                    <img src={openSafely.desktopUrl} alt="desktop" className="modal-img" />
                  </div>
                  <div>
                    <div className="modal-section-label">Mobile capture</div>
                    <img src={openSafely.mobileUrl} alt="mobile" className="modal-img" />
                  </div>
                </div>
              )}
              {!openSafely.loading && openSafely.iocsUrl && (
                <div style={{ marginTop: 16 }}>
                  <div className="modal-section-label">Indicators of Compromise</div>
                  <pre className="modal-pre">Open in new tab: {openSafely.iocsUrl}</pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
