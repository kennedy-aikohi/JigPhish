import {
  Activity, AlertTriangle, Check, ChevronRight, Clock,
  Copy, Download, ExternalLink, FileSearch, Fingerprint,
  Globe, Info, Key, Link2, MapPinned, Server, Settings,
  Shield, ShieldAlert, ShieldCheck, ShieldX, UploadCloud,
  X, Zap,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties, ReactNode } from 'react';
import { AnalyzePaths, GetConfig, SaveAPIKeys, SelectEmailFiles, Version } from '../wailsjs/go/app/App';
import { OnFileDrop, OnFileDropOff } from '../wailsjs/runtime/runtime';

// ─── Meta ─────────────────────────────────────────────────────────────────────

const AUTHOR = 'KENNEDY AIKOHI';
const GITHUB = 'github.com/kennedy-aikohi/jigphish';

// ─── Types ────────────────────────────────────────────────────────────────────

type GeoIP = { country?: string; city?: string; asn?: string; org?: string; bulletproofRisk?: boolean };

type ReceivedHop = {
  index: number; raw: string; fromHost: string; byHost: string; ip: string;
  timestamp: string; deltaFromPrior: number; geo: GeoIP; anomalies?: string[];
  intel?: ReputationEntry[];
};

type AuthAssessment = {
  spfResult: string; dkimResult: string; dmarcResult: string;
  spfAligned: boolean; dkimAligned: boolean; dmarcAligned: boolean;
  fromDomain: string; returnPathDomain: string; signingDomains: string[];
  anomalies?: string[];
};

type URLArtifact = {
  original: string; normalized: string; defanged: string;
  finalUrl: string; finalDefanged: string; domain: string; ip?: string;
  redirectChain: string[]; intel?: ReputationEntry[]; extractionHint?: string;
};

type Attachment = {
  fileName: string; contentType: string; sizeBytes: number;
  md5: string; sha1: string; sha256: string; intel?: ReputationEntry[];
  barcodes?: BarcodeArtifact[];
};

type BarcodeArtifact = {
  format: string; data: string; isUrl: boolean;
  defanged?: string; domain?: string; source: string;
};

type BodyHeuristics = {
  urgencyScore: number; financialScore: number; obfuscationScore: number;
  homoglyphSuspicion: boolean; zeroFontDetected: boolean;
  encodedContentDensity: boolean; typosquatSuspicion: boolean;
  qrCodeDetected: boolean; clickFixDetected: boolean;
  typosquatMatches?: string[]; clickFixSignals?: string[]; matches?: string[];
};

type ReputationEntry = {
  provider: string; indicator: string; type: string; severity: string;
  score: number; found: boolean; reference?: string; message?: string; checkedAt: string;
};

type MCIComponent = { category: string; signal: string; points: number };

type RiskAssessment = {
  score: number; level: string; reasons: string[]; mciBreakdown?: MCIComponent[];
};

type ThreatIntelSummary = { lookups: ReputationEntry[]; skippedReason?: string[] };

type AnalysisResult = {
  id: string; fileName: string; sizeBytes: number; parsedAt: string;
  subject: string; from: string; to: string[]; date: string; messageId: string;
  headers: { key: string; value: string }[];
  receivedChain: ReceivedHop[];
  auth: AuthAssessment;
  urls: URLArtifact[];
  attachments: Attachment[];
  barcodes?: BarcodeArtifact[];
  bodyHeuristics: BodyHeuristics;
  threatIntel: ThreatIntelSummary;
  risk: RiskAssessment;
  stealthModeActive: boolean;
  watermark: string;
  errors?: string[];
};

type AppConfigView = {
  analystName: string; stealthMode: boolean; maxWorkers: number; redirectLimit: number;
  vtConfigured: boolean; haConfigured: boolean; aipdbConfigured: boolean; urlscanConfigured: boolean;
};

type APIKeyInput = {
  virustotal: string; hybridAnalysis: string; abuseipdb: string; urlscan: string;
  analystName: string; stealthMode: boolean;
};

// ─── Tabs ─────────────────────────────────────────────────────────────────────

const TABS = ['Summary', 'Routing', 'Authentication', 'URLs', 'Attachments', 'Heuristics', 'Threat Intel', 'Headers'] as const;
type Tab = typeof TABS[number];

// ─── Colour helpers ───────────────────────────────────────────────────────────

function riskColors(score: number) {
  if (score >= 75) return { stroke: '#f87171', text: 'text-rose-400', bg: 'bg-rose-500/10 border-rose-500/30', badge: 'bg-rose-500/20 text-rose-300 border-rose-500/30' };
  if (score >= 50) return { stroke: '#fb923c', text: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/30', badge: 'bg-orange-500/20 text-orange-300 border-orange-500/30' };
  if (score >= 25) return { stroke: '#fbbf24', text: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30', badge: 'bg-amber-500/20 text-amber-300 border-amber-500/30' };
  return { stroke: '#34d399', text: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30', badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' };
}

function verdictLabel(score: number): { label: string; icon: ReactNode; cls: string } {
  if (score >= 75) return { label: 'MALICIOUS', icon: <ShieldX size={15} />, cls: 'border-rose-500/40 bg-rose-500/10 text-rose-300' };
  if (score >= 50) return { label: 'SUSPICIOUS', icon: <ShieldAlert size={15} />, cls: 'border-orange-500/40 bg-orange-500/10 text-orange-300' };
  if (score >= 25) return { label: 'UNCERTAIN', icon: <AlertTriangle size={15} />, cls: 'border-amber-500/40 bg-amber-500/10 text-amber-300' };
  return { label: 'LIKELY BENIGN', icon: <ShieldCheck size={15} />, cls: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300' };
}

function authColor(val: string) {
  if (val === 'pass') return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
  if (val === 'fail' || val === 'permerror') return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
  if (val === 'softfail' || val === 'temperror') return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
  return 'text-slate-400 bg-slate-700/30 border-slate-600/30';
}

function severityColor(sev: string) {
  if (sev === 'critical') return 'text-rose-400 bg-rose-500/10 border-rose-500/20';
  if (sev === 'high') return 'text-orange-400 bg-orange-500/10 border-orange-500/20';
  if (sev === 'medium') return 'text-amber-400 bg-amber-500/10 border-amber-500/20';
  return 'text-slate-400 bg-slate-700/30 border-slate-600/20';
}

function categoryColor(cat: string) {
  const m: Record<string, string> = {
    auth: 'text-rose-300 bg-rose-500/10 border-rose-500/20',
    routing: 'text-orange-300 bg-orange-500/10 border-orange-500/20',
    content: 'text-blue-300 bg-blue-500/10 border-blue-500/20',
    obfuscation: 'text-purple-300 bg-purple-500/10 border-purple-500/20',
    social_engineering: 'text-amber-300 bg-amber-500/10 border-amber-500/20',
    spoofing: 'text-pink-300 bg-pink-500/10 border-pink-500/20',
  };
  return m[cat] ?? 'text-slate-400 bg-slate-700/30 border-slate-600/20';
}

function fmtBytes(n: number) {
  if (!n) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(2)} MB`;
}

function fmtDate(iso: string) {
  if (!iso || iso.startsWith('0001')) return '—';
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

// DeltaFromPrior comes from Go's time.Duration (nanoseconds as int64).
function fmtDelta(ns: number): string | null {
  const sec = Math.round(ns / 1e9);
  if (!sec || sec <= 0) return null;
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
  return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
}

// ─── Export ───────────────────────────────────────────────────────────────────

function downloadJSON(result: AnalysisResult) {
  const safe = (result.subject ?? 'analysis').replace(/[^a-z0-9]/gi, '_').slice(0, 40);
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `jigphish-${safe}-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ─── Clipboard ────────────────────────────────────────────────────────────────

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1800); }); }}
      title="Copy" className="ml-1 inline-grid h-5 w-5 shrink-0 place-items-center rounded border border-slate-600/50 bg-slate-800 text-slate-400 hover:border-cyan-500/50 hover:text-cyan-300 transition-colors">
      {copied ? <Check size={11} /> : <Copy size={11} />}
    </button>
  );
}

// ─── Logo ─────────────────────────────────────────────────────────────────────

function JigPhishLogo({ size = 34 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs><filter id="glow"><feGaussianBlur stdDeviation="1.5" result="coloredBlur"/>
        <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
      <path d="M20 2.5 L36 9 L36 22 C36 31 29 37 20 40 C11 37 4 31 4 22 L4 9 Z"
        fill="rgba(6,182,212,0.07)" stroke="#06B6D4" strokeWidth="1.4" strokeLinejoin="round" filter="url(#glow)" />
      <path d="M20 11 C24 11 28 13.5 28 18.5 C28 23 23.5 26 18 26 C15.5 26 14 24 15 22"
        fill="none" stroke="#06B6D4" strokeWidth="2.2" strokeLinecap="round" filter="url(#glow)"/>
      <path d="M15 22 L12.5 26 L16.5 24.5" fill="none" stroke="#06B6D4" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
      <circle cx="20" cy="11" r="2" fill="#06B6D4" filter="url(#glow)"/>
      <line x1="20" y1="7" x2="20" y2="9" stroke="#06B6D4" strokeWidth="1.5" strokeLinecap="round"/>
    </svg>
  );
}

// ─── Risk Gauge ───────────────────────────────────────────────────────────────

function RiskGauge({ score, level }: { score: number; level: string }) {
  const r = 42, sw = 9, nr = r - sw / 2;
  const arc = 2 * Math.PI * nr * 0.75, fill = arc * (score / 100);
  const { stroke, text } = riskColors(score);
  return (
    <div className="flex flex-col items-center">
      <svg width="110" height="110" viewBox="0 0 94 94">
        <circle cx="47" cy="47" r={nr} fill="none" stroke="#1e293b" strokeWidth={sw}
          strokeDasharray={arc} strokeLinecap="round" transform="rotate(135 47 47)" />
        <circle cx="47" cy="47" r={nr} fill="none" stroke={stroke} strokeWidth={sw}
          strokeDasharray={arc} strokeDashoffset={arc - fill} strokeLinecap="round"
          transform="rotate(135 47 47)"
          style={{ filter: `drop-shadow(0 0 5px ${stroke}90)`, transition: 'stroke-dashoffset 0.6s ease' }} />
        <text x="47" y="43" textAnchor="middle" fill={stroke} fontSize="24" fontWeight="700" fontFamily="system-ui,sans-serif">{score}</text>
        <text x="47" y="57" textAnchor="middle" fill="#475569" fontSize="8.5" fontFamily="system-ui,sans-serif" letterSpacing="1">MCI SCORE</text>
        <text x="47" y="70" textAnchor="middle" fill={stroke} fontSize="9" fontWeight="600" fontFamily="system-ui,sans-serif">{level.toUpperCase()}</text>
      </svg>
      <div className={`text-xs font-semibold uppercase tracking-widest ${text}`}>{level} Threat</div>
    </div>
  );
}

// ─── Verdict Banner ───────────────────────────────────────────────────────────

function VerdictBanner({ r }: { r: AnalysisResult }) {
  const v = verdictLabel(r.risk.score);
  const flagCount = (r.auth.anomalies?.length ?? 0)
    + (r.urls?.filter(u => u.intel?.some(e => e.found)).length ?? 0)
    + (r.attachments?.filter(a => a.intel?.some(e => e.found)).length ?? 0);
  return (
    <div className={`flex items-center gap-3 rounded-lg border px-4 py-2.5 mb-4 ${v.cls}`}>
      <div className="flex items-center gap-2 font-black text-sm tracking-widest uppercase">{v.icon} {v.label}</div>
      <div className="h-4 w-px bg-current opacity-20" />
      <div className="text-xs font-medium opacity-80">MCI {r.risk.score}/100</div>
      {flagCount > 0 && (<><div className="h-4 w-px bg-current opacity-20" />
        <div className="text-xs font-medium opacity-80">{flagCount} indicator{flagCount > 1 ? 's' : ''} detected</div></>)}
      {r.stealthModeActive && (<><div className="h-4 w-px bg-current opacity-20" />
        <div className="flex items-center gap-1 text-xs opacity-80"><Shield size={11} /> Stealth</div></>)}
      <div className="ml-auto text-[12px] opacity-40 font-mono truncate">{r.fileName}</div>
    </div>
  );
}

// ─── Panel ────────────────────────────────────────────────────────────────────

function Panel({ title, icon, children, className = '', action }: {
  title: string; icon: ReactNode; children: ReactNode; className?: string; action?: ReactNode;
}) {
  return (
    <div className={`mb-5 ${className}`}>
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-cyan-400">{icon}</span>
          <h3 className="text-sm font-semibold text-slate-200 tracking-wide">{title}</h3>
        </div>
        {action}
      </div>
      <div className="rounded-lg border border-slate-700/60 bg-[#0f172a] shadow-lg">{children}</div>
    </div>
  );
}

function AuthBadge({ label, value, aligned }: { label: string; value: string; aligned?: boolean }) {
  return (
    <div className={`rounded-lg border p-3 text-center ${authColor(value)}`}>
      <div className="text-[12px] font-semibold uppercase tracking-widest text-slate-400 mb-1">{label}</div>
      <div className="text-sm font-bold uppercase">{value || 'none'}</div>
      {aligned !== undefined && (
        <div className={`mt-1 text-[12px] font-medium ${aligned ? 'text-emerald-400' : 'text-rose-400'}`}>
          {aligned ? '✓ Aligned' : '✗ Misaligned'}
        </div>
      )}
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return (
    <div className="flex min-h-[160px] items-center justify-center rounded-lg border border-dashed border-slate-700/50 bg-[#0f172a]">
      <p className="text-sm text-slate-500">{text}</p>
    </div>
  );
}

function StatCard({ icon, label, value, sub }: { icon: ReactNode; label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-lg border border-slate-700/60 bg-[#0f172a] p-3 flex items-center gap-3">
      <span className="text-cyan-400">{icon}</span>
      <div>
        <div className="text-[13px] text-slate-500 font-medium uppercase tracking-wider">{label}</div>
        <div className="text-xl font-bold text-white">{value}</div>
        {sub && <div className="text-[12px] text-slate-500">{sub}</div>}
      </div>
    </div>
  );
}

// ─── Tab: Summary ─────────────────────────────────────────────────────────────

function SummaryTab({ r }: { r: AnalysisResult }) {
  const { bg } = riskColors(r.risk.score);
  const top6 = r.risk.mciBreakdown?.slice(0, 6) ?? [];
  return (
    <div>
      <VerdictBanner r={r} />
      <div className="grid grid-cols-[auto_1fr] gap-5">
        <div className="w-72 space-y-5">
          <div className={`rounded-lg border p-4 ${bg} flex flex-col items-center gap-3`}>
            <RiskGauge score={r.risk.score} level={r.risk.level} />
          </div>
          <Panel title="Email Metadata" icon={<FileSearch size={14} />}>
            <div className="p-3 space-y-2.5 text-xs">
              {([['From', r.from], ['To', r.to?.join(', ')], ['Subject', r.subject],
                ['Date', fmtDate(r.date)], ['Message-ID', r.messageId],
                ['File Size', fmtBytes(r.sizeBytes)], ['Analyzed', fmtDate(r.parsedAt)]] as [string, string][])
                .map(([k, v]) => (
                  <div key={k} className="flex gap-2 min-w-0">
                    <span className="shrink-0 w-20 text-slate-500 font-medium">{k}</span>
                    <span className="text-slate-300 break-all">{v || '—'}</span>
                  </div>
                ))}
            </div>
          </Panel>
        </div>
        <div className="space-y-5">
          <Panel title="Authentication Summary" icon={<ShieldCheck size={14} />}>
            <div className="p-4 grid grid-cols-3 gap-3">
              <AuthBadge label="SPF" value={r.auth.spfResult} aligned={r.auth.spfAligned} />
              <AuthBadge label="DKIM" value={r.auth.dkimResult} aligned={r.auth.dkimAligned} />
              <AuthBadge label="DMARC" value={r.auth.dmarcResult} aligned={r.auth.dmarcAligned} />
            </div>
            {(r.auth.anomalies?.length ?? 0) > 0 && (
              <div className="border-t border-slate-700/50 p-3 space-y-1.5">
                {r.auth.anomalies!.map((a, i) => (
                  <div key={i} className="flex gap-2 items-start text-xs text-amber-200">
                    <AlertTriangle size={12} className="shrink-0 mt-0.5 text-amber-400" /> {a}
                  </div>
                ))}
              </div>
            )}
          </Panel>
          {top6.length > 0 && (
            <Panel title="Top Risk Signals" icon={<Zap size={14} />}>
              <div className="divide-y divide-slate-800">
                {top6.map((c, i) => (
                  <div key={i} className="flex items-start gap-3 px-4 py-2.5">
                    <span className={`shrink-0 mt-0.5 rounded border px-1.5 py-0.5 text-[12px] font-semibold uppercase tracking-wide ${categoryColor(c.category)}`}>
                      {c.category.replace('_', ' ')}
                    </span>
                    <span className="flex-1 text-xs text-slate-300">{c.signal}</span>
                    <span className="shrink-0 text-xs font-bold text-rose-400">+{c.points}</span>
                  </div>
                ))}
              </div>
            </Panel>
          )}
          <div className="grid grid-cols-3 gap-3">
            <StatCard icon={<Link2 size={16} />} label="URL Artifacts" value={String(r.urls?.length ?? 0)}
              sub={`${r.urls?.filter(u => u.intel?.some(e => e.found)).length ?? 0} flagged`} />
            <StatCard icon={<Fingerprint size={16} />} label="Attachments" value={String(r.attachments?.length ?? 0)}
              sub={`${r.attachments?.filter(a => a.intel?.some(e => e.found)).length ?? 0} flagged`} />
            <StatCard icon={<Server size={16} />} label="Routing Hops" value={String(r.receivedChain?.length ?? 0)}
              sub={`${r.receivedChain?.filter(h => (h.anomalies?.length ?? 0) > 0).length ?? 0} anomalous`} />
          </div>
          {(r.errors?.length ?? 0) > 0 && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-500/5 p-3 space-y-1">
              {r.errors!.map((e, i) => <p key={i} className="text-xs text-rose-300">{e}</p>)}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Tab: Routing ─────────────────────────────────────────────────────────────

function RoutingTab({ r }: { r: AnalysisResult }) {
  if (!r.receivedChain?.length) return <Empty text="No Received headers found." />;
  const maxDelta = Math.max(...r.receivedChain.map(h => h.deltaFromPrior ?? 0), 1);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-4 gap-3">
        <StatCard icon={<Server size={16} />} label="Total Hops" value={String(r.receivedChain.length)} />
        <StatCard icon={<AlertTriangle size={16} />} label="Anomalous" value={String(r.receivedChain.filter(h => (h.anomalies?.length ?? 0) > 0).length)} />
        <StatCard icon={<ShieldX size={16} />} label="Bulletproof ASN" value={String(r.receivedChain.filter(h => h.geo?.bulletproofRisk).length)} />
        <StatCard icon={<Activity size={16} />} label="IPs Flagged" value={String(r.receivedChain.filter(h => h.intel?.some(e => e.found && e.score > 0)).length)} sub="by OSINT providers" />
      </div>
      <Panel title="Received Chain (oldest → newest)" icon={<MapPinned size={14} />}>
        <div className="divide-y divide-slate-800">
          {r.receivedChain.map(hop => {
            const hasBP = hop.geo?.bulletproofRisk;
            const hasA = (hop.anomalies?.length ?? 0) > 0;
            const hasIntelHit = hop.intel?.some(e => e.found && e.score > 0) ?? false;
            const df = fmtDelta(hop.deltaFromPrior ?? 0);
            const dpct = Math.min(((hop.deltaFromPrior ?? 0) / maxDelta) * 100, 100);
            const longDelay = (hop.deltaFromPrior ?? 0) > 300 * 1e9; // 5 min in ns
            return (
              <div key={hop.index} className={`p-4 ${hasBP || hasIntelHit ? 'bg-rose-500/5' : ''}`}>
                <div className="flex items-start gap-3">
                  <div className={`shrink-0 h-8 w-8 grid place-items-center rounded-lg border text-sm font-bold
                    ${hasBP ? 'border-rose-500/50 bg-rose-500/10 text-rose-400'
                      : hasA ? 'border-amber-500/50 bg-amber-500/10 text-amber-400'
                      : 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300'}`}>
                    {hop.index}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center flex-wrap gap-2 text-sm">
                      <span className="font-medium text-white truncate">{hop.fromHost || '(unknown)'}</span>
                      <ChevronRight size={14} className="text-slate-600 shrink-0" />
                      <span className="text-slate-300 truncate">{hop.byHost || '(unknown)'}</span>
                    </div>
                    <div className="mt-1.5 flex flex-wrap gap-3 text-xs text-slate-400">
                      {hop.ip && (
                        <span className="flex items-center gap-1"><Globe size={11} className="text-cyan-500" />
                          <span className="font-mono">{hop.ip}</span><CopyBtn text={hop.ip} /></span>
                      )}
                      {hop.geo?.country && <span>📍 {hop.geo.city ? `${hop.geo.city}, ` : ''}{hop.geo.country}</span>}
                      {hop.geo?.asn && <span className="font-mono text-slate-500">{hop.geo.asn}</span>}
                      {hop.geo?.org && <span className="text-slate-500 truncate">{hop.geo.org}</span>}
                      {hop.timestamp && !hop.timestamp.startsWith('0001') && (
                        <span className="flex items-center gap-1 text-slate-500">
                          <Clock size={10} />{fmtDate(hop.timestamp)}
                        </span>
                      )}
                    </div>
                    {df && (
                      <div className="mt-2 flex items-center gap-2">
                        <span className={`text-[12px] font-medium ${longDelay ? 'text-amber-400' : 'text-slate-500'}`}>+{df}</span>
                        <div className="flex-1 h-1 rounded-full bg-slate-800 max-w-[100px]">
                          <div className={`h-1 rounded-full ${longDelay ? 'bg-amber-500' : 'bg-cyan-600'}`}
                            style={{ width: `${dpct}%` }} />
                        </div>
                        {longDelay && <span className="text-[12px] text-amber-400 font-semibold">Suspicious delay</span>}
                      </div>
                    )}
                    {hasA && (
                      <div className="mt-2 space-y-1">
                        {hop.anomalies!.map((a, i) => (
                          <div key={i} className="flex gap-2 items-start text-xs text-amber-200">
                            <AlertTriangle size={11} className="shrink-0 mt-0.5 text-amber-400" /> {a}
                          </div>
                        ))}
                      </div>
                    )}
                    {(hop.intel?.length ?? 0) > 0 && (
                      <div className="mt-2 rounded border border-slate-700/50 bg-[#080d18] divide-y divide-slate-800/60">
                        {hop.intel!.map((e, j) => (
                          <div key={j} className="flex items-center gap-2 px-3 py-1.5 text-xs">
                            <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[11px] font-semibold uppercase ${severityColor(e.severity)}`}>{e.provider}</span>
                            <span className={`shrink-0 font-mono text-[11px] ${e.found && e.score > 0 ? 'text-rose-300 font-semibold' : 'text-slate-500'}`}>{e.type}</span>
                            <span className="text-slate-400 truncate">{e.message || (e.found ? 'flagged' : 'clean')}</span>
                            {e.score > 0 && <span className="ml-auto shrink-0 font-bold text-rose-400">score {e.score}</span>}
                            {e.reference && <a href={e.reference} target="_blank" rel="noopener" className="shrink-0 text-cyan-400 hover:text-cyan-300"><ExternalLink size={11} /></a>}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="flex flex-col items-end gap-1 shrink-0">
                    {hasBP && <span className="rounded border border-rose-500/40 bg-rose-500/15 px-2 py-1 text-[13px] font-semibold text-rose-300 uppercase">Bulletproof ASN</span>}
                    {hasIntelHit && <span className="rounded border border-rose-500/40 bg-rose-500/10 px-2 py-1 text-[13px] font-semibold text-rose-300 uppercase">OSINT Hit</span>}
                    {!hasBP && !hasIntelHit && hasA && <span className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-[13px] font-semibold text-amber-300 uppercase">Anomaly</span>}
                    {!hasBP && !hasIntelHit && !hasA && <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-[13px] font-semibold text-emerald-400 uppercase">Clean</span>}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}

// ─── Tab: Authentication ──────────────────────────────────────────────────────

function AuthTab({ r }: { r: AnalysisResult }) {
  return (
    <div className="space-y-5">
      <Panel title="Authentication Results" icon={<ShieldCheck size={14} />}>
        <div className="p-4 grid grid-cols-3 gap-4">
          {[{ label: 'SPF', value: r.auth.spfResult, aligned: r.auth.spfAligned },
            { label: 'DKIM', value: r.auth.dkimResult, aligned: r.auth.dkimAligned },
            { label: 'DMARC', value: r.auth.dmarcResult, aligned: r.auth.dmarcAligned }]
            .map(({ label, value, aligned }) => (
              <div key={label} className={`rounded-xl border p-5 text-center space-y-2 ${authColor(value)}`}>
                <div className="text-xs font-semibold uppercase tracking-widest text-slate-400">{label}</div>
                <div className="text-3xl font-black">{(value || 'none').toUpperCase()}</div>
                <div className={`text-xs font-semibold ${aligned ? 'text-emerald-400' : 'text-rose-400'}`}>
                  {aligned ? '✓ Aligned' : '✗ Not Aligned'}
                </div>
              </div>
            ))}
        </div>
      </Panel>
      <Panel title="Domain Forensics" icon={<Globe size={14} />}>
        <div className="p-4 space-y-3 text-sm">
          {([['From Domain', r.auth.fromDomain],
            ['Return-Path Domain', r.auth.returnPathDomain],
            ['DKIM Signing Domains', r.auth.signingDomains?.join(', ')]] as [string, string][])
            .map(([k, v]) => (
              <div key={k} className="flex gap-3 min-w-0 items-start">
                <span className="shrink-0 w-44 text-slate-500 text-xs font-medium pt-0.5">{k}</span>
                <span className="font-mono text-slate-300 text-xs break-all">{v || '—'}</span>
                {v && <CopyBtn text={v} />}
              </div>
            ))}
        </div>
      </Panel>
      {(r.auth.anomalies?.length ?? 0) > 0 && (
        <Panel title="Authentication Anomalies" icon={<ShieldAlert size={14} />}>
          <div className="divide-y divide-slate-800">
            {r.auth.anomalies!.map((a, i) => (
              <div key={i} className="flex gap-3 items-start p-3">
                <AlertTriangle size={14} className="shrink-0 mt-0.5 text-amber-400" />
                <p className="text-xs text-slate-300">{a}</p>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}

// ─── Tab: URLs ────────────────────────────────────────────────────────────────

function URLsTab({ r }: { r: AnalysisResult }) {
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const urls = r.urls ?? [];
  const flaggedCount = urls.filter(u => u.intel?.some(e => e.found)).length;
  const displayed = flaggedOnly ? urls.filter(u => u.intel?.some(e => e.found)) : urls;

  const copyAll = () => navigator.clipboard.writeText(urls.map(u => u.defanged).filter(Boolean).join('\n'));

  if (!urls.length) return <Empty text="No URL artifacts extracted." />;
  return (
    <Panel
      title={`URL Artifacts (${displayed.length}${flaggedOnly ? ` of ${urls.length}` : ''})`}
      icon={<Link2 size={14} />}
      action={
        <div className="flex items-center gap-2">
          {flaggedCount > 0 && (
            <button onClick={() => setFlaggedOnly(f => !f)}
              className={`flex items-center gap-1.5 rounded border px-2 py-1 text-[13px] font-semibold transition-colors
                ${flaggedOnly ? 'border-rose-500/50 bg-rose-500/15 text-rose-300' : 'border-slate-700/60 bg-slate-800/50 text-slate-400 hover:text-rose-300'}`}>
              <ShieldX size={11} />{flaggedOnly ? 'Show All' : `Flagged (${flaggedCount})`}
            </button>
          )}
          <button onClick={copyAll}
            className="flex items-center gap-1.5 rounded border border-slate-700/60 bg-slate-800/50 px-2 py-1 text-[13px] text-slate-400 hover:text-cyan-300 hover:border-cyan-500/30 transition-colors">
            <Copy size={11} /> Copy All Defanged
          </button>
        </div>
      }>
      <div className="divide-y divide-slate-800">
        {displayed.map((u, i) => {
          const isFlagged = (u.intel?.filter(e => e.found).length ?? 0) > 0;
          return (
            <div key={i} className={`p-4 ${isFlagged ? 'bg-rose-500/5' : ''}`}>
              <div className="flex-1 min-w-0 space-y-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-cyan-300 font-semibold text-sm">{u.domain}</span>
                  {isFlagged && <span className="rounded border border-rose-500/40 bg-rose-500/10 px-1.5 py-0.5 text-[12px] font-semibold text-rose-300 uppercase">Flagged</span>}
                  {u.extractionHint?.includes('stealth') && <span className="rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 text-[12px] text-cyan-400">stealth</span>}
                </div>
                <div className="font-mono text-xs text-slate-400 break-all flex items-start gap-1">
                  <span>{u.defanged}</span><CopyBtn text={u.defanged} />
                </div>
                {u.finalDefanged && u.finalDefanged !== u.defanged && (
                  <div className="flex items-center gap-2 text-xs text-slate-500">
                    <ChevronRight size={12} /><span className="font-mono break-all text-slate-400">{u.finalDefanged}</span>
                    <CopyBtn text={u.finalDefanged} />
                  </div>
                )}
                {(u.redirectChain?.length ?? 0) > 0 && (
                  <details className="text-xs text-slate-500">
                    <summary className="cursor-pointer hover:text-slate-300">{u.redirectChain.length} redirect(s)</summary>
                    <div className="mt-1 ml-3 space-y-1">{u.redirectChain.map((h, j) => <div key={j} className="font-mono">{h}</div>)}</div>
                  </details>
                )}
                {u.intel?.filter(e => e.found).map((e, j) => (
                  <div key={j} className="flex items-center gap-2 text-xs">
                    <span className={`rounded border px-1.5 py-0.5 text-[12px] font-semibold uppercase ${severityColor(e.severity)}`}>{e.severity}</span>
                    <span className="text-slate-400">{e.provider}:</span>
                    <span className="text-slate-300">{e.message}</span>
                    {e.reference && <a href={e.reference} target="_blank" rel="noopener" className="text-cyan-400"><ExternalLink size={11} /></a>}
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

// ─── Tab: Attachments ─────────────────────────────────────────────────────────

function AttachmentsTab({ r }: { r: AnalysisResult }) {
  if (!r.attachments?.length) return <Empty text="No attachments found." />;
  return (
    <div className="space-y-4">
      {r.attachments.map((a, i) => {
        const isFlagged = (a.intel?.filter(e => e.found).length ?? 0) > 0;
        return (
          <Panel key={i} title={a.fileName} icon={<Fingerprint size={14} />}>
            <div className="p-4 space-y-3">
              <div className="flex gap-4 flex-wrap text-xs text-slate-400">
                <span>Type: <span className="text-slate-300 font-mono">{a.contentType || '—'}</span></span>
                <span>Size: <span className="text-slate-300">{fmtBytes(a.sizeBytes)}</span></span>
                {isFlagged && <span className="text-rose-400 font-semibold">⚠ Flagged</span>}
              </div>
              {([['MD5', a.md5], ['SHA-1', a.sha1], ['SHA-256', a.sha256]] as [string, string][]).map(([label, hash]) => (
                <div key={label} className="flex items-center gap-2 font-mono text-xs">
                  <span className="w-14 shrink-0 text-slate-500 font-sans">{label}</span>
                  <span className="text-slate-300 break-all">{hash}</span>
                  {hash && <CopyBtn text={hash} />}
                </div>
              ))}
              {a.intel?.filter(e => e.found).map((e, j) => (
                <div key={j} className={`rounded border px-3 py-2 text-xs flex items-center gap-3 ${severityColor(e.severity)}`}>
                  <span className="font-semibold uppercase">{e.provider}</span>
                  <span>{e.message}</span>
                  <span className="text-slate-400">Score: {e.score}/100</span>
                  {e.reference && <a href={e.reference} target="_blank" rel="noopener" className="text-cyan-400"><ExternalLink size={11} /></a>}
                </div>
              ))}
              {(a.barcodes?.length ?? 0) > 0 && (
                <div className="rounded border border-amber-500/30 bg-amber-500/5 p-3 space-y-2">
                  <div className="text-xs font-semibold text-amber-300 flex items-center gap-1.5">
                    <AlertTriangle size={12} /> {a.barcodes!.length} barcode(s) decoded from image
                  </div>
                  {a.barcodes!.map((bc, j) => (
                    <div key={j} className="flex items-center gap-2 text-xs">
                      <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[11px] text-amber-400">{bc.format}</span>
                      {bc.isUrl
                        ? <span className="font-mono text-amber-200 break-all flex-1">{bc.defanged}</span>
                        : <span className="font-mono text-slate-400 break-all flex-1">{bc.data}</span>}
                      <CopyBtn text={bc.defanged ?? bc.data} />
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Panel>
        );
      })}
    </div>
  );
}

// ─── Tab: Heuristics ─────────────────────────────────────────────────────────

function ScoreBar({ label, score, max, color }: { label: string; score: number; max: number; color: string }) {
  const pct = Math.min((score / max) * 100, 100);
  return (
    <div className="rounded-lg border border-slate-700/60 bg-[#0f172a] p-3">
      <div className="flex justify-between text-xs mb-2">
        <span className="text-slate-400 font-medium">{label}</span>
        <span className="font-bold" style={{ color }}>{score}</span>
      </div>
      <div className="h-1.5 rounded-full bg-slate-800">
        <div className="h-1.5 rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color, boxShadow: `0 0 6px ${color}80` }} />
      </div>
    </div>
  );
}

function HeuristicsTab({ r }: { r: AnalysisResult }) {
  const h = r.bodyHeuristics;
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-3 gap-3">
        <ScoreBar label="Urgency Language" score={h.urgencyScore} max={100} color="#f87171" />
        <ScoreBar label="Financial Language" score={h.financialScore} max={100} color="#fb923c" />
        <ScoreBar label="Obfuscation" score={h.obfuscationScore} max={100} color="#c084fc" />
      </div>
      <Panel title="Detection Flags" icon={<ShieldAlert size={14} />}>
        <div className="p-3 grid grid-cols-2 gap-2">
          {([
            ['Zero-Font / Invisible CSS', h.zeroFontDetected],
            ['Homoglyph / Mixed Script', h.homoglyphSuspicion],
            ['High-Density Encoded Content', h.encodedContentDensity],
            ['Typosquat / Lookalike Domain', h.typosquatSuspicion],
            ['QR Code Detected (Quishing)', h.qrCodeDetected],
            ['ClickFix Social Engineering', h.clickFixDetected],
          ] as [string, boolean][]).map(([label, active]) => (
            <div key={label} className={`flex items-center gap-2 rounded border p-2 text-xs
              ${active
                ? label.includes('ClickFix') ? 'border-purple-500/40 bg-purple-500/10 text-purple-300'
                : label.includes('QR') ? 'border-amber-500/40 bg-amber-500/10 text-amber-300'
                : 'border-rose-500/30 bg-rose-500/10 text-rose-300'
                : 'border-slate-700/40 bg-slate-800/30 text-slate-500'}`}>
              {active
                ? label.includes('ClickFix') ? <Zap size={13} className="text-purple-400 shrink-0" />
                : label.includes('QR') ? <AlertTriangle size={13} className="text-amber-400 shrink-0" />
                : <ShieldX size={13} className="text-rose-400 shrink-0" />
                : <Shield size={13} className="shrink-0" />}
              {label}
            </div>
          ))}
        </div>
        {h.clickFixDetected && (h.clickFixSignals?.length ?? 0) > 0 && (
          <div className="border-t border-purple-500/20 bg-purple-500/5 px-3 py-3">
            <div className="text-xs font-semibold text-purple-300 mb-2 flex items-center gap-2">
              <Zap size={12} /> ClickFix Signals ({h.clickFixSignals!.length})
            </div>
            <div className="space-y-1.5">
              {h.clickFixSignals!.map((s, i) => (
                <div key={i} className="flex gap-2 items-start text-xs text-purple-200/80">
                  <span className="shrink-0 text-purple-400 mt-0.5">›</span>{s}
                </div>
              ))}
            </div>
          </div>
        )}
        {(h.typosquatMatches?.length ?? 0) > 0 && (
          <div className="border-t border-slate-700/50 px-3 pb-3">
            <div className="mt-2 text-xs text-slate-400 mb-1">
              Matches against sender domain <span className="font-mono text-cyan-300">{r.auth.fromDomain}</span>:
            </div>
            <div className="flex flex-wrap gap-2">
              {h.typosquatMatches!.map(m => <span key={m} className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 font-mono text-xs text-rose-300">{m}</span>)}
            </div>
          </div>
        )}
        {(h.matches?.length ?? 0) > 0 && (
          <div className="border-t border-slate-700/50 p-3 flex flex-wrap gap-1.5">
            {h.matches!.map(m => <span key={m} className="rounded border border-cyan-500/20 bg-cyan-500/10 px-2 py-0.5 text-[13px] text-cyan-300 font-mono">{m}</span>)}
          </div>
        )}
      </Panel>
      {(r.barcodes?.length ?? 0) > 0 && (
        <Panel title={`Barcode / QR Artifacts (${r.barcodes!.length})`} icon={<Fingerprint size={14} />}>
          <div className="divide-y divide-slate-800">
            {r.barcodes!.map((bc, i) => (
              <div key={i} className={`px-4 py-3 ${bc.isUrl ? 'bg-amber-500/5' : ''}`}>
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span className="rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[11px] font-semibold text-amber-300 font-mono">{bc.format}</span>
                  {bc.isUrl && <span className="rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 text-[11px] text-rose-300">URL payload</span>}
                  <span className="text-[11px] text-slate-500">{bc.source}</span>
                </div>
                {bc.isUrl ? (
                  <div className="font-mono text-xs text-amber-200 break-all flex items-start gap-1">
                    <Globe size={11} className="shrink-0 mt-0.5 text-amber-400" />
                    <span>{bc.defanged}</span><CopyBtn text={bc.defanged ?? bc.data} />
                  </div>
                ) : (
                  <div className="font-mono text-xs text-slate-400 break-all">{bc.data}</div>
                )}
              </div>
            ))}
          </div>
        </Panel>
      )}
      {(r.risk.mciBreakdown?.length ?? 0) > 0 && (
        <Panel title="Full MCI Breakdown" icon={<Zap size={14} />}>
          <div className="divide-y divide-slate-800">
            <div className="grid grid-cols-[140px_1fr_60px] gap-3 px-4 py-2 text-[12px] font-semibold uppercase tracking-wider text-slate-500">
              <span>Category</span><span>Signal</span><span className="text-right">Points</span>
            </div>
            {r.risk.mciBreakdown!.map((c, i) => (
              <div key={i} className="grid grid-cols-[140px_1fr_60px] gap-3 px-4 py-2.5 items-start">
                <span className={`self-start mt-0.5 rounded border px-1.5 py-0.5 text-[12px] font-semibold uppercase tracking-wide ${categoryColor(c.category)}`}>
                  {c.category.replace('_', ' ')}
                </span>
                <span className="text-xs text-slate-300">{c.signal}</span>
                <span className="text-xs font-bold text-right text-rose-400">+{c.points}</span>
              </div>
            ))}
            <div className="grid grid-cols-[140px_1fr_60px] gap-3 px-4 py-2.5 border-t border-slate-700">
              <span className="text-xs text-slate-500 font-semibold col-span-2">Total (capped at 100)</span>
              <span className="text-sm font-black text-right text-white">{r.risk.score}</span>
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}

// ─── Tab: Threat Intel ────────────────────────────────────────────────────────

function ThreatIntelTab({ r }: { r: AnalysisResult }) {
  const lookups = r.threatIntel?.lookups ?? [];
  const skipped = r.threatIntel?.skippedReason ?? [];
  if (!lookups.length && !skipped.length) return <Empty text="No threat intelligence providers queried. Configure API keys in Settings (Ctrl+,)." />;
  return (
    <div className="space-y-5">
      {skipped.length > 0 && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 space-y-1">
          <div className="text-xs font-semibold text-amber-400 mb-1">Unconfigured Providers</div>
          {skipped.map((s, i) => <p key={i} className="text-xs text-amber-300/80">{s}</p>)}
        </div>
      )}
      {lookups.length > 0 && (
        <Panel title={`Intelligence Lookups (${lookups.length})`} icon={<Activity size={14} />}>
          <div className="divide-y divide-slate-800 overflow-x-auto">
            <div className="grid grid-cols-[110px_160px_70px_60px_90px_1fr] gap-3 px-4 py-2 text-[12px] font-semibold uppercase tracking-wider text-slate-500">
              <span>Provider</span><span>Indicator</span><span>Type</span><span>Found</span><span>Severity</span><span>Message</span>
            </div>
            {lookups.map((e, i) => (
              <div key={i} className={`grid grid-cols-[110px_160px_70px_60px_90px_1fr] gap-3 px-4 py-2.5 items-center text-xs ${e.found && e.score > 0 ? 'bg-rose-500/5' : ''}`}>
                <span className="font-semibold text-slate-300">{e.provider}</span>
                <span className="font-mono text-cyan-300 truncate">{e.indicator}</span>
                <span className="rounded border border-slate-600/40 bg-slate-700/30 px-1.5 py-0.5 text-[12px] text-slate-400 text-center">{e.type}</span>
                <span className={`text-center font-semibold ${e.found ? 'text-rose-400' : 'text-emerald-400'}`}>{e.found ? 'Yes' : 'No'}</span>
                <span className={`rounded border px-1.5 py-0.5 text-[12px] font-semibold uppercase text-center ${severityColor(e.severity)}`}>{e.severity}</span>
                <div className="flex items-center gap-2">
                  <span className="text-slate-400 truncate">{e.message || '—'}</span>
                  {e.reference && <a href={e.reference} target="_blank" rel="noopener" className="shrink-0 text-cyan-400 hover:text-cyan-300"><ExternalLink size={11} /></a>}
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}

// ─── Tab: Headers ─────────────────────────────────────────────────────────────

const SEC_HEADERS = new Set([
  'authentication-results', 'dkim-signature', 'arc-authentication-results',
  'arc-message-signature', 'arc-seal', 'received-spf', 'x-originating-ip',
  'x-mailer', 'x-spam-status', 'x-spam-score', 'x-forwarded-to',
]);

function HeadersTab({ r }: { r: AnalysisResult }) {
  const [filter, setFilter] = useState('');
  const [secOnly, setSecOnly] = useState(false);
  const filtered = (r.headers ?? []).filter(h => {
    const kl = h.key.toLowerCase();
    if (secOnly && !SEC_HEADERS.has(kl) && !kl.startsWith('received')) return false;
    if (!filter) return true;
    return kl.includes(filter.toLowerCase()) || h.value.toLowerCase().includes(filter.toLowerCase());
  });
  return (
    <Panel
      title={`Raw Headers (${filtered.length}${filtered.length !== (r.headers?.length ?? 0) ? ` of ${r.headers?.length}` : ''})`}
      icon={<FileSearch size={14} />}
      action={
        <button onClick={() => setSecOnly(s => !s)}
          className={`flex items-center gap-1.5 rounded border px-2 py-1 text-[13px] font-semibold transition-colors
            ${secOnly ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-300' : 'border-slate-700/60 bg-slate-800/50 text-slate-400 hover:text-cyan-300'}`}>
          <ShieldCheck size={11} /> Security only
        </button>
      }>
      <div className="border-b border-slate-700/50 p-3">
        <input type="text" placeholder="Filter by header name or value…" value={filter} onChange={e => setFilter(e.target.value)}
          className="w-full rounded border border-slate-700/60 bg-slate-800/80 px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-500/50 focus:outline-none" />
      </div>
      <div className="max-h-[calc(100vh-320px)] overflow-y-auto">
        {filtered.map((h, i) => {
          const isSec = SEC_HEADERS.has(h.key.toLowerCase()) || h.key.toLowerCase().startsWith('received');
          return (
            <div key={i} className={`flex min-w-0 border-b border-slate-800/60 px-4 py-1.5 hover:bg-slate-800/30 ${isSec ? 'bg-cyan-500/[0.03]' : ''}`}>
              <span className={`w-56 shrink-0 text-xs font-semibold font-mono pr-3 pt-0.5 ${isSec ? 'text-cyan-400' : 'text-slate-500'}`}>{h.key}:</span>
              <span className="text-xs text-slate-300 font-mono break-all whitespace-pre-wrap leading-relaxed">{h.value}</span>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

// ─── Settings Modal ───────────────────────────────────────────────────────────

function SettingsModal({ cfg, onClose }: { cfg: AppConfigView; onClose: () => void }) {
  const [keys, setKeys] = useState<APIKeyInput>({
    virustotal: '', hybridAnalysis: '', abuseipdb: '', urlscan: '',
    analystName: cfg.analystName, stealthMode: cfg.stealthMode,
  });
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');
  const set = (k: keyof APIKeyInput, v: string | boolean) => setKeys(p => ({ ...p, [k]: v }));

  const save = async () => {
    setSaving(true); setMsg('');
    try { await SaveAPIKeys(keys); setMsg('Saved. API key changes take effect on restart.'); }
    catch (e) { setMsg(`Error: ${e instanceof Error ? e.message : String(e)}`); }
    finally { setSaving(false); }
  };

  const providers = [
    { key: 'virustotal' as const, label: 'VirusTotal', ok: cfg.vtConfigured, ph: 'Enter VirusTotal API key…' },
    { key: 'hybridAnalysis' as const, label: 'Hybrid Analysis', ok: cfg.haConfigured, ph: 'Enter Hybrid Analysis key…' },
    { key: 'abuseipdb' as const, label: 'AbuseIPDB', ok: cfg.aipdbConfigured, ph: 'Enter AbuseIPDB key…' },
    { key: 'urlscan' as const, label: 'urlscan.io', ok: cfg.urlscanConfigured, ph: 'Enter urlscan.io key…' },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="w-[520px] rounded-xl border border-slate-700/60 bg-[#0d1424] shadow-2xl">
        <div className="flex items-center justify-between border-b border-slate-700/50 px-5 py-4">
          <div className="flex items-center gap-3">
            <Key size={18} className="text-cyan-400" />
            <div>
              <h2 className="text-sm font-semibold text-white">API Keys & Settings</h2>
              <p className="text-xs text-slate-500">Keys stored locally — never transmitted externally</p>
            </div>
          </div>
          <button onClick={onClose} className="rounded-md p-1 text-slate-400 hover:text-white hover:bg-slate-700/50"><X size={16} /></button>
        </div>
        <div className="p-5 space-y-4 max-h-[70vh] overflow-y-auto">
          <div>
            <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Analyst Name</label>
            <input type="text" value={keys.analystName} onChange={e => set('analystName', e.target.value)}
              className="mt-1.5 w-full rounded border border-slate-700/60 bg-slate-800/80 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-cyan-500/50 focus:outline-none" />
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 block">Threat Intelligence Providers</label>
            <div className="space-y-3">
              {providers.map(({ key, label, ok, ph }) => (
                <div key={key}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium text-slate-300">{label}</span>
                    <span className={`text-[12px] font-semibold px-1.5 py-0.5 rounded border ${ok ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400' : 'border-slate-600/30 bg-slate-700/30 text-slate-500'}`}>
                      {ok ? '● Configured' : '○ Not set'}
                    </span>
                  </div>
                  <input type="password" placeholder={ok ? '••••••••••• (leave blank to keep)' : ph}
                    value={keys[key] as string} onChange={e => set(key, e.target.value)}
                    className="w-full rounded border border-slate-700/60 bg-slate-800/80 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-cyan-500/50 focus:outline-none font-mono" />
                </div>
              ))}
            </div>
          </div>
          <div className="flex items-center justify-between rounded-lg border border-slate-700/50 bg-slate-800/30 px-4 py-3">
            <div>
              <div className="text-sm font-medium text-slate-200">Stealth Mode</div>
              <div className="text-xs text-slate-500 mt-0.5">Suppresses live HTTP to attacker URLs — redirect following and ASN lookups disabled</div>
            </div>
            <button onClick={() => set('stealthMode', !keys.stealthMode)}
              className={`relative shrink-0 h-6 w-11 rounded-full border transition-colors ${keys.stealthMode ? 'border-cyan-500/50 bg-cyan-600' : 'border-slate-600 bg-slate-700'}`}>
              <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform ${keys.stealthMode ? 'translate-x-5' : 'translate-x-0'}`} />
            </button>
          </div>
          {msg && (
            <div className={`rounded border px-3 py-2 text-xs ${msg.startsWith('Error') ? 'border-rose-500/30 bg-rose-500/10 text-rose-300' : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'}`}>
              {msg}
            </div>
          )}
        </div>
        <div className="flex justify-end gap-2 border-t border-slate-700/50 px-5 py-4">
          <button onClick={onClose} className="rounded-lg border border-slate-700/60 px-4 py-2 text-sm text-slate-400 hover:text-white hover:border-slate-600 transition-colors">Cancel</button>
          <button onClick={save} disabled={saving} className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-500 disabled:opacity-50 transition-colors">
            {saving ? 'Saving…' : 'Save Settings'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── About Modal ──────────────────────────────────────────────────────────────

function AboutModal({ version, onClose }: { version: string; onClose: () => void }) {
  const capabilities = [
    'Deep MIME parsing with multipart support',
    'Full Received-chain routing forensics with hop delta analysis',
    'SPF / DKIM / DMARC with PSL-correct organizational domain alignment',
    'Typosquatting detection via Levenshtein distance + homoglyph normalization',
    'Bulletproof hosting ASN detection (14+ known bad networks)',
    'Zero-font and hidden CSS obfuscation detection',
    'Executable attachment classification (35+ MIME types)',
    'Weighted MCI scoring with per-signal audit trail',
    'Stealth Mode — zero live contact with attacker infrastructure',
    'VirusTotal · Hybrid Analysis · AbuseIPDB · urlscan.io integration',
    'Full JSON export for incident documentation',
  ];
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="w-[560px] rounded-xl border border-slate-700/60 bg-[#0d1424] shadow-2xl">
        <div className="flex items-center justify-between border-b border-slate-700/50 px-5 py-4">
          <div className="flex items-center gap-3">
            <JigPhishLogo size={28} />
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-black text-white">JigPhish</span>
                <span className="rounded border border-cyan-500/40 bg-cyan-500/10 px-1.5 py-0.5 text-[12px] font-semibold text-cyan-300">v{version}</span>
              </div>
              <p className="text-xs text-slate-500">Open-Source Phishing Intelligence Platform</p>
            </div>
          </div>
          <button onClick={onClose} className="rounded-md p-1 text-slate-400 hover:text-white hover:bg-slate-700/50"><X size={16} /></button>
        </div>
        <div className="p-6 space-y-5 max-h-[75vh] overflow-y-auto">
          <div className="rounded-lg border border-cyan-500/20 bg-[#080d18] p-6 text-center">
            <div className="text-[12px] text-slate-500 uppercase tracking-widest font-semibold mb-3">Built by</div>
            <div className="text-3xl font-black text-white tracking-widest leading-tight">{AUTHOR}</div>
            <div className="mt-3 text-base font-semibold text-cyan-400">{GITHUB}</div>
          </div>
          <div>
            <div className="text-[12px] text-slate-500 uppercase tracking-wider font-semibold mb-2">Detection Capabilities</div>
            <div className="space-y-1.5">
              {capabilities.map((c, i) => (
                <div key={i} className="flex gap-2 text-xs text-slate-300">
                  <span className="shrink-0 text-cyan-500 mt-0.5">›</span> {c}
                </div>
              ))}
            </div>
          </div>
          <div className="rounded-lg border border-slate-700/40 bg-slate-800/20 p-4 text-xs text-slate-500 space-y-1.5 leading-relaxed">
            <p>All analysis is performed locally on your machine. Email content and attachments are never uploaded to external services. Hash-based threat intelligence lookups contact configured provider APIs only — raw email data is never transmitted.</p>
            <p>Released under the MIT License. Intended for defensive security, SOC operations, and forensic analysis. Use responsibly.</p>
          </div>
        </div>
        <div className="flex justify-end border-t border-slate-700/50 px-5 py-4">
          <button onClick={onClose} className="rounded-lg bg-slate-700 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-600 transition-colors">Close</button>
        </div>
      </div>
    </div>
  );
}

// ─── KPI Chip ─────────────────────────────────────────────────────────────────

function KpiChip({ label, value, tone = 'neutral' }: { label: string; value: string; tone?: string }) {
  const color = tone === 'critical' ? 'text-rose-400' : tone === 'high' ? 'text-orange-400'
    : tone === 'medium' ? 'text-amber-400' : tone === 'ok' ? 'text-emerald-400'
    : tone === 'warn' ? 'text-rose-400' : tone === 'low' ? 'text-emerald-400' : 'text-slate-300';
  return (
    <div className="rounded border border-slate-700/50 bg-slate-800/40 px-2 py-1 shrink-0">
      <div className="text-[13px] uppercase tracking-wider text-slate-500">{label}</div>
      <div className={`text-[13px] font-bold uppercase ${color}`}>{value}</div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────

export default function App() {
  const [results, setResults] = useState<AnalysisResult[]>([]);
  const [selectedID, setSelectedID] = useState('');
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const [tab, setTab] = useState<Tab>('Summary');
  const [showSettings, setShowSettings] = useState(false);
  const [showAbout, setShowAbout] = useState(false);
  const [appCfg, setAppCfg] = useState<AppConfigView | null>(null);
  const [version, setVersion] = useState('1.0.0');
  const dropRef = useRef<HTMLDivElement>(null);

  const selected = useMemo(
    () => results.find(r => r.id === selectedID) ?? results[0] ?? null,
    [results, selectedID],
  );

  const analyze = useCallback(async (paths?: string[]) => {
    setError(''); setLoading(true);
    setStatus(paths?.length ? `Analyzing ${paths.length} file(s)…` : 'Opening file selector…');
    try {
      const data = paths?.length ? await AnalyzePaths(paths) : await SelectEmailFiles();
      if (data?.length) {
        setResults(data); setSelectedID(data[0].id); setTab('Summary');
        setStatus(`${data.length} file(s) analyzed`);
      } else { setStatus('No files selected.'); }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStatus('Analysis failed.');
    } finally { setLoading(false); }
  }, []);

  useEffect(() => {
    OnFileDrop((_x, _y, paths) => void analyze(paths), false);
    return () => OnFileDropOff();
  }, [analyze]);

  useEffect(() => {
    GetConfig().then(setAppCfg).catch(() => null);
    Version().then(setVersion).catch(() => null);
  }, []);

  // Keyboard shortcuts
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 'o') { e.preventDefault(); void analyze(); }
      if (e.ctrlKey && e.key === ',') { e.preventDefault(); setShowSettings(true); }
    };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [analyze]);

  const providers = appCfg ? [
    { name: 'VT', ok: appCfg.vtConfigured },
    { name: 'HA', ok: appCfg.haConfigured },
    { name: 'AIPDB', ok: appCfg.aipdbConfigured },
    { name: 'URLSCAN', ok: appCfg.urlscanConfigured },
  ] : [];

  const urlFlagged = selected?.urls?.filter(u => u.intel?.some(e => e.found)).length ?? 0;
  const attFlagged = selected?.attachments?.filter(a => a.intel?.some(e => e.found)).length ?? 0;

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-[#080d18] text-slate-100 select-none">
      {/* Header */}
      <header className="flex shrink-0 items-center gap-4 border-b border-slate-700/50 bg-[#0b101e] px-4 py-2.5 shadow-lg shadow-black/30">
        <div className="flex items-center gap-2.5 shrink-0">
          <JigPhishLogo size={32} />
          <div>
            <div className="flex items-center gap-1.5">
              <span className="text-base font-black tracking-tight text-white">JigPhish</span>
              <span className="text-[13px] font-semibold text-slate-500 border border-slate-700/60 rounded px-1 py-0.5">v{version}</span>
            </div>
            <div className="text-[12px] text-cyan-400 tracking-widest uppercase leading-none">Phishing Intelligence</div>
          </div>
        </div>
        <div className="mx-3 h-8 w-px bg-slate-700/60" />
        {selected ? (
          <div className="flex items-center gap-2 flex-1 min-w-0 overflow-hidden">
            <KpiChip label="Risk" value={`${selected.risk.score} — ${selected.risk.level}`}
              tone={selected.risk.score >= 75 ? 'critical' : selected.risk.score >= 50 ? 'high' : selected.risk.score >= 25 ? 'medium' : 'low'} />
            <KpiChip label="SPF" value={selected.auth.spfResult || 'none'} tone={selected.auth.spfResult === 'pass' ? 'ok' : 'warn'} />
            <KpiChip label="DKIM" value={selected.auth.dkimResult || 'none'} tone={selected.auth.dkimResult === 'pass' ? 'ok' : 'warn'} />
            <KpiChip label="DMARC" value={selected.auth.dmarcResult || 'none'} tone={selected.auth.dmarcResult === 'pass' ? 'ok' : 'warn'} />
            <KpiChip label="URLs" value={String(selected.urls?.length ?? 0)} />
            <KpiChip label="Attachments" value={String(selected.attachments?.length ?? 0)} />
            {selected.stealthModeActive && (
              <div className="flex items-center gap-1 rounded border border-cyan-500/40 bg-cyan-500/10 px-2 py-1 text-xs text-cyan-300 shrink-0">
                <Shield size={11} /> Stealth
              </div>
            )}
          </div>
        ) : (
          <div className="flex-1 text-xs text-slate-500 italic">Drop an .eml file or press Ctrl+O to open</div>
        )}
        <div className="flex items-center gap-1">
          {providers.map(p => (
            <span key={p.name} title={p.ok ? `${p.name} configured` : `${p.name} — not configured`}
              className={`rounded border px-1.5 py-0.5 text-[12px] font-bold tracking-wide cursor-default
              ${p.ok ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400' : 'border-slate-600/30 bg-slate-800/50 text-slate-600'}`}>
              {p.name}
            </span>
          ))}
        </div>
        <div className="ml-2 flex items-center gap-1.5">
          <button onClick={() => void analyze()} disabled={loading}
            className="flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-600/20 px-3 py-1.5 text-xs font-semibold text-cyan-300 hover:bg-cyan-600/30 hover:text-cyan-100 disabled:opacity-50 transition-colors">
            <Activity size={14} />{loading ? 'Analyzing…' : 'Analyze'}
          </button>
          {selected && (
            <button onClick={() => downloadJSON(selected)} title="Export analysis as JSON"
              className="grid h-8 w-8 place-items-center rounded-lg border border-slate-700/60 bg-slate-800/50 text-slate-400 hover:border-emerald-500/40 hover:text-emerald-300 transition-colors">
              <Download size={15} />
            </button>
          )}
          <button onClick={() => setShowAbout(true)} title="About JigPhish"
            className="grid h-8 w-8 place-items-center rounded-lg border border-slate-700/60 bg-slate-800/50 text-slate-400 hover:border-slate-600 hover:text-white transition-colors">
            <Info size={15} />
          </button>
          <button onClick={() => setShowSettings(true)} title="Settings (Ctrl+,)"
            className="grid h-8 w-8 place-items-center rounded-lg border border-slate-700/60 bg-slate-800/50 text-slate-400 hover:border-slate-600 hover:text-white transition-colors">
            <Settings size={15} />
          </button>
        </div>
      </header>

      {/* Body */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside className="flex w-64 shrink-0 flex-col border-r border-slate-700/40 bg-[#0b101e]">
          <div ref={dropRef} style={{ '--wails-drop-target': 'drop' } as CSSProperties}
            onClick={() => void analyze()}
            className="m-3 flex cursor-pointer items-center gap-3 rounded-xl border border-dashed border-slate-600/50 bg-[#080d18] px-3 py-3 hover:border-cyan-500/40 hover:bg-cyan-500/5 transition-colors group">
            <UploadCloud size={22} className="shrink-0 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            <div className="min-w-0">
              <p className="text-xs font-semibold text-slate-300">{loading ? 'Analyzing…' : 'Drop .eml or click'}</p>
              <p className="text-[12px] text-slate-500 mt-0.5">{status || 'Ctrl+O to open'}</p>
            </div>
          </div>
          {error && <div className="mx-3 mb-2 rounded border border-rose-500/30 bg-rose-500/10 px-2.5 py-2 text-[13px] text-rose-300">{error}</div>}
          <div className="px-3 pb-1">
            <div className="text-[12px] font-semibold uppercase tracking-widest text-slate-500">In-Tray ({results.length})</div>
          </div>
          <div className="flex-1 overflow-y-auto px-3 pb-3 space-y-1.5">
            {results.length === 0 ? (
              <div className="mt-2 rounded-lg border border-dashed border-slate-700/40 bg-[#080d18] p-4 text-center text-[13px] text-slate-600">No evidence analyzed</div>
            ) : results.map(item => {
              const { badge, stroke } = riskColors(item.risk.score);
              const isActive = item.id === (selected?.id ?? '');
              const authFails = [item.auth.spfResult, item.auth.dkimResult, item.auth.dmarcResult].filter(v => v === 'fail').length;
              return (
                <button key={item.id} onClick={() => { setSelectedID(item.id); setTab('Summary'); }}
                  className={`relative w-full rounded-lg border p-2.5 text-left transition-colors
                    ${isActive ? 'border-cyan-500/40 bg-cyan-500/10' : 'border-slate-700/40 bg-[#0f172a] hover:border-slate-600/50'}`}>
                  {isActive && <div className="absolute left-0 top-2 bottom-2 w-0.5 rounded-r bg-cyan-400" />}
                  <div className="flex items-start justify-between gap-2 min-w-0">
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-xs font-semibold text-white">{item.subject || '(No subject)'}</p>
                      <p className="mt-0.5 truncate text-[12px] text-slate-500">{item.from}</p>
                    </div>
                    <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[12px] font-bold uppercase ${badge}`}>{item.risk.level}</span>
                  </div>
                  <div className="mt-2 h-1 rounded-full bg-slate-800">
                    <div className="h-1 rounded-full" style={{ width: `${item.risk.score}%`, background: stroke, transition: 'width 0.4s' }} />
                  </div>
                  {authFails > 0 && (
                    <div className="mt-1.5 flex gap-1">
                      {item.auth.spfResult === 'fail' && <span className="rounded bg-rose-500/15 px-1 py-0.5 text-[13px] text-rose-400 font-semibold">SPF</span>}
                      {item.auth.dkimResult === 'fail' && <span className="rounded bg-rose-500/15 px-1 py-0.5 text-[13px] text-rose-400 font-semibold">DKIM</span>}
                      {item.auth.dmarcResult === 'fail' && <span className="rounded bg-rose-500/15 px-1 py-0.5 text-[13px] text-rose-400 font-semibold">DMARC</span>}
                    </div>
                  )}
                </button>
              );
            })}
          </div>
          {/* Footer watermark */}
          <div className="border-t border-slate-800/60 px-3 py-2.5">
            <div className="flex items-center gap-1.5">
              <JigPhishLogo size={14} />
              <div>
                <div className="text-[13px] text-slate-400 font-bold leading-tight tracking-wide">{AUTHOR}</div>
                <div className="text-[13px] text-slate-600 leading-tight">JigPhish v{version} · Open-Source</div>
              </div>
            </div>
          </div>
        </aside>

        {/* Main panel */}
        <main className="flex flex-1 flex-col overflow-hidden">
          {!selected ? (
            <div className="flex flex-1 flex-col items-center justify-center gap-5 text-center p-10">
              <div className="opacity-15"><JigPhishLogo size={90} /></div>
              <div className="space-y-2">
                <p className="text-2xl font-black text-white tracking-tight">JigPhish Analysis Workbench</p>
                <p className="text-sm text-slate-500 max-w-md mx-auto leading-relaxed">
                  Drop an .eml file anywhere or press{' '}
                  <kbd className="rounded border border-slate-700 bg-slate-800 px-1 py-0.5 text-xs font-mono">Ctrl+O</kbd>{' '}
                  to open the file dialog. All analysis runs locally — nothing leaves your machine.
                </p>
              </div>
              <div className="grid grid-cols-3 gap-3 mt-2 max-w-lg w-full">
                {['SPF / DKIM / DMARC', 'Routing & ASN Forensics', 'Typosquat Detection',
                  'Weighted MCI Scoring', 'Threat Intel Lookups', 'Stealth Mode'].map(f => (
                  <div key={f} className="rounded border border-slate-800 bg-[#0b101e] px-3 py-2 text-[13px] text-slate-500 text-center">{f}</div>
                ))}
              </div>
            </div>
          ) : (
            <>
              <div className="shrink-0 border-b border-slate-700/40 bg-[#0b101e] px-5 py-2">
                <p className="text-sm font-semibold text-white truncate">{selected.subject || '(No Subject)'}</p>
                <p className="text-[13px] text-slate-500 truncate">From: {selected.from} · {fmtDate(selected.date)}</p>
              </div>
              <div className="shrink-0 flex items-center gap-0.5 border-b border-slate-700/40 bg-[#0b101e] px-4">
                {TABS.map(t => (
                  <button key={t} onClick={() => setTab(t)}
                    className={`relative px-3 py-2.5 text-xs font-semibold transition-colors border-b-2 -mb-px
                      ${tab === t ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-500 hover:text-slate-300'}`}>
                    {t}
                    {t === 'URLs' && urlFlagged > 0 && (
                      <span className="ml-1 rounded-full bg-rose-500 px-1.5 text-[13px] font-bold text-white">{urlFlagged}</span>
                    )}
                    {t === 'Attachments' && attFlagged > 0 && (
                      <span className="ml-1 rounded-full bg-rose-500 px-1.5 text-[13px] font-bold text-white">{attFlagged}</span>
                    )}
                  </button>
                ))}
              </div>
              <div className="flex-1 overflow-y-auto p-5">
                {tab === 'Summary'        && <SummaryTab r={selected} />}
                {tab === 'Routing'        && <RoutingTab r={selected} />}
                {tab === 'Authentication' && <AuthTab r={selected} />}
                {tab === 'URLs'           && <URLsTab r={selected} />}
                {tab === 'Attachments'    && <AttachmentsTab r={selected} />}
                {tab === 'Heuristics'     && <HeuristicsTab r={selected} />}
                {tab === 'Threat Intel'   && <ThreatIntelTab r={selected} />}
                {tab === 'Headers'        && <HeadersTab r={selected} />}
              </div>
            </>
          )}
        </main>
      </div>

      {showSettings && appCfg && (
        <SettingsModal cfg={appCfg} onClose={() => { setShowSettings(false); GetConfig().then(setAppCfg).catch(() => null); }} />
      )}
      {showAbout && <AboutModal version={version} onClose={() => setShowAbout(false)} />}
    </div>
  );
}
