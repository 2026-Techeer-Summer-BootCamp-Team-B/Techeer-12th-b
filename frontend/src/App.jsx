// C:\Users\daum0\python\Techeer-12th-b\frontend\src\App.jsx
import React, { useState } from "react";
import SecurityDashboard from "./components/SecurityDashboard";
import LoginScreen from "./components/LoginScreen";
import { getToken, clearToken } from "./lib/api";

function App() {
  // api.js에 정의된 ids_platform_token 키값을 바라보도록 상태를 초기화합니다.
  const [token, setToken] = useState(getToken() || "");

  // 토큰 문자열이 실제로 존재할 때만 인증된 상태로 판단합니다.
  const isAuthed = !!token;

  function handleLogin() {
    // LoginScreen 내부에서 로그인이 성공하여 토큰이 정상 저장된 직후,
    // 최신 토큰 값을 읽어와 리액트 State를 동기화합니다.
    const latestToken = getToken() || "";
    setToken(latestToken);
  }

  function handleLogout() {
    clearToken(); // 로컬스토리지에서 토큰 삭제
    setToken(""); // 리액트 토큰 State 비우기 -> 대시보드가 언마운트되면서 소켓 자동 클린업
  }

  if (!isAuthed) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  // SecurityDashboard에 새로 생성된 token 상태를 Prop으로 안전하게 토스합니다.
  return <SecurityDashboard onLogout={handleLogout} token={token} />;
}

export default App;