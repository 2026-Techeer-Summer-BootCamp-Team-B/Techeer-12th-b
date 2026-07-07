import React, { useState } from "react";
import SecurityDashboard from "./components/SecurityDashboard";
import LoginScreen from "./components/LoginScreen";
import { getToken, clearToken } from "./lib/api";

function App() {
  const [authed, setAuthed] = useState(!!getToken());

  function handleLogin() {
    setAuthed(true);
  }

  function handleLogout() {
    clearToken();
    setAuthed(false);
  }

  if (!authed) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  return <SecurityDashboard onLogout={handleLogout} />;
}

export default App;
