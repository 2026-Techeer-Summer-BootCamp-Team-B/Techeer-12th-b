import React, { useEffect, useRef, useState, useCallback } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import {
  ShieldCheck,
  ShieldAlert,
  Activity,
  Ban,
  Radio,
  LogOut,
} from "lucide-react";
import { apiFetch, getWebSocketUrl } from "../lib/api";

// ── 백엔드 AttackType(20종) 기준 라벨/색상 매핑 ──────────────────────────
const ATTACK_META = {
  sqli: { label: "SQL Injection", color: "#fb7185" },
  xss: { label: "XSS", color: "#f59e0b" },
  os_command_injection: { label: "OS 커맨드 인젝션", color: "#fb923c" },
  path_traversal: { label: "경로 탐색", color: "#38bdf8" },
  rfi: { label: "원격 파일 포함", color: "#22d3ee" },
  file_upload: { label: "악성 파일 업로드", color: "#f472b6" },
  ssti: { label: "SSTI", color: "#c084fc" },
  xxe: { label: "XXE", color: "#4ade80" },
  ssrf: { label: "SSRF", color: "#2dd4bf" },
  hpp: { label: "파라미터 오염", color: "#a3e635" },
  csrf: { label: "CSRF", color: "#fbbf24" },
  nosqli: { label: "NoSQL Injection", color: "#f87171" },
  insecure_deserialization: { label: "안전하지 않은 역직렬화", color: "#e879f9" },
  open_redirect: { label: "오픈 리다이렉트", color: "#60a5fa" },
  crlf_injection: { label: "CRLF Injection", color: "#fdba74" },
  ldap_injection: { label: "LDAP Injection", color: "#5eead4" },
  xpath_injection: { label: "XPath Injection", color: "#d8b4fe" },
  cors_abuse: { label: "CORS 악용", color: "#fca5a5" },
  jwt_forgery: { label: "JWT 위조", color: "#a78bfa" },
  brute_force: { label: "무차별 대입", color: "#facc15" },
};

function attackMeta(key) {
  return ATTACK_META[key] || { label: key, color: "#94a3b8" };
}

const RISK_STYLE = {
  CRITICAL: "text-rose-400 bg-rose-500/10 border-rose-500/30",
  MEDIUM: "text-amber-400 bg-amber-500/10 border-amber-500/30",
  LOW: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
};

function fmtTime(d) {
  return d.toLocaleTimeString("ko-KR", { hour12: false });
}

function toDisplayLog(raw) {
  const meta = attackMeta(raw.attack_type);
  return {
    id: raw.id,
    time: new Date(raw.timestamp),
    ip: raw.source_ip,
    endpoint: raw.target_endpoint,
    type: raw.attack_type,
    typeLabel: meta.label,
    color: meta.color,
    risk: raw.risk_level,
    blocked: raw.blocked,
  };
}

export default function SecurityDashboard({ onLogout }) {
  const [connected, setConnected] = useState(false);
  const [logs, setLogs] = useState([]);
  const [ticker, setTicker] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [totals, setTotals] = useState({ today: 0, blocked: 0 });
  const [typeCounts, setTypeCounts] = useState({});
  const [toast, setToast] = useState(null);
  const [reduceMotion, setReduceMotion] = useState(false);
  const [loadError, setLoadError] = useState("");
  const bucketRef = useRef({ count: 0, critical: 0 });
  const wsRef = useRef(null);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduceMotion(mq.matches);
    const handler = (e) => setReduceMotion(e.matches);
    mq.addEventListener?.("change", handler);
    return () => mq.removeEventListener?.("change", handler);
  }, []);

  // ── 초기 데이터 로딩 (Stats API + 최근 로그) ────────────────────────
  useEffect(() => {
    let cancelled = false;

    async function loadInitialData() {
      try {
        const [summary, byType, timelineRes, recentLogs] = await Promise.all([
          apiFetch("/api/stats/summary?range=24h"),
          apiFetch("/api/stats/by-attack-type?range=24h"),
          apiFetch("/api/stats/timeline?range=24h&interval=1h"),
          apiFetch("/api/logs?page=1&page_size=8"),
        ]);
        if (cancelled) return;

        setTotals({ today: summary.total_blocked, blocked: summary.total_blocked });

        const counts = {};
        byType.items.forEach((item) => {
          counts[item.attack_type] = item.count;
        });
        setTypeCounts(counts);

        setTimeline(
          timelineRes.points.map((p, i) => ({
            t: i,
            count: p.count,
            critical: 0, // 과거 시점의 critical 세부 구분은 timeline API에 없어 0으로 초기화
          }))
        );

        setLogs((recentLogs.results || []).map(toDisplayLog));
      } catch (err) {
        if (!cancelled) setLoadError(err.message);
      }
    }

    loadInitialData();
    return () => {
      cancelled = true;
    };
  }, []);

  // ── WebSocket 연결 - 공격 탐지 시 실시간 수신 ───────────────────────
  useEffect(() => {
    const ws = new WebSocket(getWebSocketUrl());
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);

    ws.onmessage = (event) => {
      let payload;
      try {
        payload = JSON.parse(event.data);
      } catch {
        return;
      }
      const raw = payload.data;
      if (!raw) return;

      const displayLog = toDisplayLog(raw);

      setTicker((prev) => [...prev.slice(-39), displayLog]);
      setLogs((prev) => [displayLog, ...prev].slice(0, 8));
      setTotals((prev) => ({ today: prev.today + 1, blocked: prev.blocked + 1 }));
      setTypeCounts((prev) => ({
        ...prev,
        [displayLog.type]: (prev[displayLog.type] || 0) + 1,
      }));

      bucketRef.current.count += 1;
      if (payload.event === "critical_alert") {
        bucketRef.current.critical += 1;
        setToast(displayLog);
      }
    };

    return () => ws.close();
  }, []);

  // 타임라인 버킷 롤링 (2.5초마다 최근 버킷에 실시간 집계 반영)
  useEffect(() => {
    const id = setInterval(() => {
      setTimeline((prev) => {
        if (prev.length === 0) return prev;
        const next = [...prev.slice(1)];
        next.push({
          t: prev[prev.length - 1].t + 1,
          count: bucketRef.current.count,
          critical: bucketRef.current.critical,
        });
        return next;
      });
      bucketRef.current = { count: 0, critical: 0 };
    }, 2500);
    return () => clearInterval(id);
  }, []);

  // 토스트 자동 소멸
  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(null), 4200);
    return () => clearTimeout(id);
  }, [toast]);

  const pieData = Object.entries(typeCounts)
    .map(([key, value]) => {
      const meta = attackMeta(key);
      return { name: meta.label, value, color: meta.color };
    })
    .filter((d) => d.value > 0);

  const topIp = (() => {
    const counts = {};
    logs.forEach((l) => (counts[l.ip] = (counts[l.ip] || 0) + 1));
    const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    return entries[0];
  })();

  const motionCls = reduceMotion ? "" : "animate-pulse";

  return (
    <div className="min-h-screen w-full bg-slate-950 text-slate-200 font-sans p-4 md:p-6 relative overflow-hidden">
      {/* 상단 바 */}
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-6 h-6 text-cyan-400" />
          <div>
            <h1 className="text-lg font-semibold tracking-tight text-slate-100">
              실시간 침입 탐지 플랫폼
            </h1>
            <p className="text-xs text-slate-500">
              Blue Team SIEM Console · Team-F
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className={`flex items-center gap-1.5 text-xs ${connected ? "text-emerald-400" : "text-slate-600"}`}>
            <Radio className={`w-3.5 h-3.5 ${connected ? motionCls : ""}`} />
            <span className="font-mono">{connected ? "LIVE" : "연결 끊김"}</span>
          </div>
          <button
            onClick={onLogout}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-slate-700 bg-slate-900 hover:bg-slate-800 focus:outline-none focus:ring-2 focus:ring-cyan-400 transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            로그아웃
          </button>
        </div>
      </div>

      {loadError && (
        <div className="mb-4 text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 rounded-md px-3 py-2">
          데이터 로딩 실패: {loadError}
        </div>
      )}

      {/* KPI 카드 */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
        <KpiCard
          label="오늘 탐지된 공격"
          value={totals.today.toLocaleString()}
          icon={<Activity className="w-4 h-4 text-cyan-400" />}
        />
        <KpiCard
          label="차단 처리"
          value={totals.blocked.toLocaleString()}
          icon={<Ban className="w-4 h-4 text-rose-400" />}
        />
        <KpiCard
          label="가장 많은 공격 유형"
          value={
            pieData.length
              ? pieData.reduce((a, b) => (b.value > a.value ? b : a)).name
              : "-"
          }
          icon={<ShieldAlert className="w-4 h-4 text-amber-400" />}
        />
        <KpiCard
          label="Top 공격 IP"
          value={topIp ? `${topIp[0]} (${topIp[1]})` : "-"}
          mono
          icon={<ShieldAlert className="w-4 h-4 text-violet-400" />}
        />
      </div>

      {/* 메인 그리드: 타임라인 + 도넛 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-5">
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <h2 className="text-sm font-medium text-slate-300 mb-3">
            실시간 공격 타임라인
          </h2>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={timeline}>
              <defs>
                <linearGradient id="fillCount" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="fillCritical" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#fb7185" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="#fb7185" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="t" hide />
              <YAxis hide />
              <Tooltip
                contentStyle={{
                  background: "#0f172a",
                  border: "1px solid #1e293b",
                  borderRadius: 8,
                  fontSize: 12,
                }}
                labelFormatter={() => ""}
              />
              <Area
                type="monotone"
                dataKey="count"
                stroke="#22d3ee"
                fill="url(#fillCount)"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="critical"
                stroke="#fb7185"
                fill="url(#fillCritical)"
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
          <div className="flex gap-4 mt-1 text-xs text-slate-500">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-cyan-400 inline-block" />
              전체 탐지
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-rose-400 inline-block" />
              CRITICAL
            </span>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <h2 className="text-sm font-medium text-slate-300 mb-3">
            공격 유형 분포
          </h2>
          {pieData.length ? (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie
                  data={pieData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={45}
                  outerRadius={70}
                  paddingAngle={3}
                >
                  {pieData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} stroke="none" />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#0f172a",
                    border: "1px solid #1e293b",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[180px] flex items-center justify-center text-xs text-slate-600">
              데이터 수집 중…
            </div>
          )}
          <div className="grid grid-cols-2 gap-x-3 gap-y-1 mt-2">
            {pieData.map((d) => (
              <div key={d.name} className="flex items-center gap-1.5 text-[11px] text-slate-400">
                <span
                  className="w-2 h-2 rounded-full inline-block shrink-0"
                  style={{ background: d.color }}
                />
                <span className="truncate">{d.name}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 최근 로그 테이블 */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden mb-16">
        <div className="px-4 py-3 border-b border-slate-800">
          <h2 className="text-sm font-medium text-slate-300">최근 차단 로그</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-slate-500 border-b border-slate-800">
                <th className="text-left font-normal px-4 py-2">시각</th>
                <th className="text-left font-normal px-4 py-2">출발 IP</th>
                <th className="text-left font-normal px-4 py-2">공격 유형</th>
                <th className="text-left font-normal px-4 py-2">대상 경로</th>
                <th className="text-left font-normal px-4 py-2">위험도</th>
                <th className="text-left font-normal px-4 py-2">처리</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-600">
                    아직 탐지된 공격이 없습니다
                  </td>
                </tr>
              )}
              {logs.map((l) => (
                <tr
                  key={l.id}
                  className="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors"
                >
                  <td className="px-4 py-2 font-mono text-slate-400">
                    {fmtTime(l.time)}
                  </td>
                  <td className="px-4 py-2 font-mono text-slate-300">{l.ip}</td>
                  <td className="px-4 py-2">
                    <span
                      className="inline-flex items-center gap-1.5"
                      style={{ color: l.color }}
                    >
                      <span
                        className="w-1.5 h-1.5 rounded-full inline-block"
                        style={{ background: l.color }}
                      />
                      {l.typeLabel}
                    </span>
                  </td>
                  <td className="px-4 py-2 font-mono text-slate-400">
                    {l.endpoint}
                  </td>
                  <td className="px-4 py-2">
                    <span
                      className={`px-2 py-0.5 rounded border text-[11px] font-medium ${RISK_STYLE[l.risk]}`}
                    >
                      {l.risk}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-rose-400">
                    {l.blocked ? "차단됨" : "허용됨"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 하단 실시간 공격 스트림 티커 */}
      <div className="fixed bottom-0 left-0 right-0 bg-slate-950/95 border-t border-slate-800 backdrop-blur">
        <div className="flex items-center gap-2 px-4 py-2 overflow-hidden">
          <span className="text-[10px] uppercase tracking-wider text-slate-600 shrink-0 font-mono">
            attacks
          </span>
          <div className="flex gap-3 overflow-x-hidden">
            {ticker.slice(-24).map((ev) => (
              <span
                key={ev.id}
                className="flex items-center gap-1 text-[10px] font-mono whitespace-nowrap shrink-0"
              >
                <span
                  className="w-1.5 h-1.5 rounded-full inline-block"
                  style={{ background: ev.color }}
                />
                <span className="text-slate-600">{fmtTime(ev.time)}</span>
                <span className="text-slate-300">{ev.ip}</span>
                <span style={{ color: ev.color }}>{ev.typeLabel}</span>
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* CRITICAL 알림 토스트 */}
      {toast && (
        <div
          role="alert"
          className={`fixed top-6 right-6 max-w-sm bg-slate-900 border border-rose-500/50 rounded-xl shadow-2xl shadow-rose-950/50 p-4 ${
            reduceMotion ? "" : "animate-in"
          }`}
        >
          <div className="flex items-start gap-3">
            <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-semibold text-rose-300">
                CRITICAL 공격 탐지
              </p>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                {toast.ip} → {toast.endpoint}
              </p>
              <p className="text-xs text-slate-500 mt-0.5">
                {toast.typeLabel} · {fmtTime(toast.time)}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function KpiCard({ label, value, icon, mono }) {
  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-slate-500">{label}</span>
        {icon}
      </div>
      <p
        className={`text-xl font-semibold text-slate-100 truncate ${
          mono ? "font-mono text-base" : ""
        }`}
      >
        {value}
      </p>
    </div>
  );
}
