const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8001";

const TOKEN_KEY = "ids_platform_token";

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

export async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };

  const response = await fetch(`${API_BASE_URL}${path}`, { ...options, headers });

  if (response.status === 401) {
    clearToken();
    throw new Error("세션이 만료되었습니다. 다시 로그인해주세요.");
  }

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `요청 실패 (${response.status})`);
  }

  if (response.status === 204) return null;
  return response.json();
}

export function getWebSocketUrl() {
  const token = getToken();
  const wsBase = API_BASE_URL.replace(/^http/, "ws");
  return `${wsBase}/ws/alerts?token=${encodeURIComponent(token || "")}`;
}

export { API_BASE_URL };