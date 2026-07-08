import React, { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { apiFetch, setToken } from "../lib/api";

export default function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      
      // 백엔드가 token 혹은 access_token 어떤 키로 주든 안전하게 파싱합니다.
      const targetToken = data.token || data.access_token;
      
      if (!targetToken) {
        throw new Error("서버 응답에 유효한 인증 토큰이 포함되어 있지 않습니다.");
      }

      setToken(targetToken); // ids_platform_token 키로 올바르게 저장
      onLogin();             // App.jsx에 로그인 완료 통보 (이제 data를 구태여 넘기지 않아도 App이 직접 최신 토큰을 읽어옵니다)
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen w-full bg-slate-950 text-slate-200 font-sans flex items-center justify-center p-4">
      <div className="w-full max-w-sm bg-slate-900/60 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center gap-2 mb-6">
          <ShieldCheck className="w-6 h-6 text-cyan-400" />
          <div>
            <h1 className="text-base font-semibold text-slate-100">
              실시간 침입 탐지 플랫폼
            </h1>
            <p className="text-xs text-slate-500">관리자 로그인</p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="text-xs text-slate-500 block mb-1">아이디</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-400"
              autoComplete="username"
              required
            />
          </div>
          <div>
            <label className="text-xs text-slate-500 block mb-1">비밀번호</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-400"
              autoComplete="current-password"
              required
            />
          </div>

          {error && (
            <p className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 rounded-md px-3 py-2">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full text-sm font-medium px-3 py-2 rounded-md bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 transition-colors disabled:opacity-50"
          >
            {loading ? "로그인 중..." : "로그인"}
          </button>
        </form>
      </div>
    </div>
  );
}
