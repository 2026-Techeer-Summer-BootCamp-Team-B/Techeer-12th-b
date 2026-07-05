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
  Pause,
  Play,
  Radio,
} from "lucide-react";

// ── 시뮬레이션용 상수 (실제 연동 시 이 부분을 API 응답으로 교체) ─────────────
const ATTACK_TYPES = [
  { key: "sqli", label: "SQL Injection", color: "#fb7185" },
  { key: "xss", label: "XSS", color: "#f59e0b" },
  { key: "jwt_forgery", label: "JWT 위조", color: "#a78bfa" },
  { key: "os_command_injection", label: "OS 커맨드 인젝션", color: "#fb923c" },
  { key: "path_traversal", label: "경로 탐색", color: "#38bdf8" },
  { key: "file_upload", label: "악성 파일 업로드", color: "#f472b6" },
  { key: "brute_force", label: "무차별 대입", color: "#facc15" },
];

const RISK_STYLE = {
  CRITICAL: "text-rose-400 bg-rose-500/10 border-rose-500/30",
  MEDIUM: "text-amber-400 bg-amber-500/10 border-amber-500/30",
  LOW: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
};

const ENDPOINTS = [
  "/rest/user/login",
  "/rest/products/search",
  "/api/comments",
  "/rest/admin/config",
  "/upload",
  "/rest/basket",
];

function randomIp() {
  return `${1 + Math.floor(Math.random() * 223)}.${Math.floor(
    Math.random() * 255
  )}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

function makeEvent(forceAttack) {
  const isAttack = forceAttack ?? Math.random() < 0.38;
  if (!isAttack) {
    return {
      id: crypto.randomUUID(),
      time: new Date(),
      ip: randomIp(),
      endpoint: ENDPOINTS[Math.floor(Math.random() * ENDPOINTS.length)],
      type: null,
      risk: null,
      blocked: false,
    };
  }
  const attack = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];
  const risk =
    Math.random() < 0.3 ? "CRITICAL" : Math.random() < 0.6 ? "MEDIUM" : "LOW";
  return {
    id: crypto.randomUUID(),
    time: new Date(),
    ip: randomIp(),
    endpoint: ENDPOINTS[Math.floor(Math.random() * ENDPOINTS.length)],
    type: attack.key,
    typeLabel: attack.label,
    color: attack.color,
    risk,
    blocked: true,
  };
}

function fmtTime(d) {
  return d.toLocaleTimeString("ko-KR", { hour12: false });
}

export default function SecurityDashboard() {
  const [running, setRunning] = useState(true);
  const [logs, setLogs] = useState([]);
  const [ticker, setTicker] = useState([]);
  const [timeline, setTimeline] = useState(() =>
    Array.from({ length: 18 }, (_, i) => ({
      t: i,
      count: 0,
      critical: 0,
    }))
  );
  const [totals, setTotals] = useState({ today: 0, blocked: 0 });
  const [typeCounts, setTypeCounts] = useState({});
  const [toast, setToast] = useState(null);
  const [reduceMotion, setReduceMotion] = useState(false);
  const bucketRef = useRef({ count: 0, critical: 0 });

  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduceMotion(mq.matches);
    const handler = (e) => setReduceMotion(e.matches);
    mq.addEventListener?.("change", handler);
    return () => mq.removeEventListener?.("change", handler);
  }, []);

  const pushEvent = useCallback((ev) => {
    setTicker((prev) => [...prev.slice(-39), ev]);

    if (ev.type) {
      setLogs((prev) => [ev, ...prev].slice(0, 8));
      setTotals((prev) => ({
        today: prev.today + 1,
        blocked: prev.blocked + (ev.blocked ? 1 : 0),
      }));
      setTypeCounts((prev) => ({
        ...prev,
        [ev.type]: (prev[ev.type] || 0) + 1,
      }));
      bucketRef.current.count += 1;
      if (ev.risk === "CRITICAL") {
        bucketRef.current.critical += 1;
        setToast(ev);
      }
    }
  }, []);

  // 이벤트 생성 루프 (틱커용, 빠르게)
  useEffect(() => {
    if (!running) return;
    const id = setInterval(() => pushEvent(makeEvent()), 900);
    return () => clearInterval(id);
  }, [running, pushEvent]);

  // 타임라인 버킷 롤링 (2.5초마다 한 칸씩 밀기)
  useEffect(() => {
    if (!running) return;
    const id = setInterval(() => {
      setTimeline((prev) => {
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
  }, [running]);

  // 토스트 자동 소멸
  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(null), 4200);
    return () => clearTimeout(id);
  }, [toast]);

  const pieData = ATTACK_TYPES.map((t) => ({
    name: t.label,
    value: typeCounts[t.key] || 0,
    color: t.color,
  })).filter((d) => d.value > 0);

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
          <div className="flex items-center gap-1.5 text-xs text-emerald-400">
            <Radio className={`w-3.5 h-3.5 ${motionCls}`} />
            <span className="font-mono">{running ? "LIVE" : "PAUSED"}</span>
          </div>
          <button
            onClick={() => setRunning((r) => !r)}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-slate-700 bg-slate-900 hover:bg-slate-800 focus:outline-none focus:ring-2 focus:ring-cyan-400 transition-colors"
          >
            {running ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            {running ? "일시정지" : "재개"}
          </button>
        </div>
      </div>

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
                  <td className="px-4 py-2 text-rose-400">차단됨</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 하단 실시간 패킷 스트림 티커 (시그니처 요소) */}
      <div className="fixed bottom-0 left-0 right-0 bg-slate-950/95 border-t border-slate-800 backdrop-blur">
        <div className="flex items-center gap-2 px-4 py-2 overflow-hidden">
          <span className="text-[10px] uppercase tracking-wider text-slate-600 shrink-0 font-mono">
            traffic
          </span>
          <div className="flex gap-3 overflow-x-hidden">
            {ticker.slice(-24).map((ev) => (
              <span
                key={ev.id}
                className="flex items-center gap-1 text-[10px] font-mono whitespace-nowrap shrink-0"
              >
                <span
                  className="w-1.5 h-1.5 rounded-full inline-block"
                  style={{ background: ev.type ? ev.color : "#334155" }}
                />
                <span className="text-slate-600">{fmtTime(ev.time)}</span>
                <span className={ev.type ? "text-slate-300" : "text-slate-600"}>
                  {ev.ip}
                </span>
                {ev.type && (
                  <span style={{ color: ev.color }}>{ev.typeLabel}</span>
                )}
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
