import { useState, useEffect, useRef, useCallback } from "react";
import { API_BASE_URL } from "../lib/api";

const MAX_RECONNECT_ATTEMPTS = 10;
const RECONNECT_BASE_DELAY = 1000; // 1초

export const useWebSocket = (token, onMessageCallback) => {
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState(null);
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const retryCountRef = useRef(0);

  // 최신 콜백 함수를 실시간으로 추적하는 Ref 생성
  // 이 설계를 통해 대시보드의 상태가 바뀌어도 웹소켓이 끊어지지 않습니다.
  const callbackRef = useRef(onMessageCallback);
  useEffect(() => {
    callbackRef.current = onMessageCallback;
  }, [onMessageCallback]);

  const connect = useCallback(() => {
    if (!token) {
      setError("No authentication token provided.");
      console.warn("WebSocket: Connection not attempted, no token available.");
      return;
    }

    // 이미 연결 중이거나 연결된 상태라면 중복 연결을 엄격히 차단합니다.
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    // API_BASE_URL(lib/api.js, VITE_API_URL로 설정)을 그대로 ws(s)로 바꿔서 써야
    // REST 호출과 같은 백엔드를 가리킨다. 예전에는 "ws://localhost:8000"으로 하드코딩되어 있어서
    // 백엔드가 다른 포트/도메인(예: VITE_API_URL이 가리키는 배포 환경)에 떠 있으면
    // REST API는 정상 동작해도 실시간 알림 웹소켓만 조용히 연결 실패했다.
    const wsBase = API_BASE_URL.replace(/^http/, "ws");
    const wsUrl = `${wsBase}/ws/alerts?token=${encodeURIComponent(token)}`;
    const ws = new WebSocket(wsUrl);
    // React StrictMode의 개발 모드 mount->unmount->remount 시, 아직 CONNECTING인
    // 소켓을 바로 close()하면 "WebSocket is closed before the connection is
    // established" 경고가 뜨므로, 대신 이 플래그로 표시해두고 onopen에서 닫는다.
    ws.shouldCloseOnOpen = false;
    wsRef.current = ws;

    ws.onopen = () => {
      if (ws.shouldCloseOnOpen) {
        ws.close(1000, "Cancelled before connection was needed.");
        return;
      }
      console.log("WebSocket: Connected.");
      setIsConnected(true);
      setError(null);
      retryCountRef.current = 0;
      clearTimeout(reconnectTimeoutRef.current);
    };

    ws.onmessage = (event) => {
      // 💡 최신 저장된 상위 컴포넌트의 핸들러를 안전하게 호출
      if (callbackRef.current) {
        callbackRef.current(event);
      }
    };

    ws.onclose = (event) => {
      if (wsRef.current !== ws) return; // 이미 교체된(stray) 소켓의 close는 무시
      setIsConnected(false);
      console.log("WebSocket: Disconnected. Code:", event.code, "Reason:", event.reason);

      if (event.code === 1000) {
        setError(null);
      } else if (event.code === 4001) {
        setError("Authentication failed. Please log in again.");
        console.error("WebSocket: Authentication failed. No reconnect.");
      } else {
        // Strict Mode나 순간적인 언마운트로 인한 중복 타이머 생성을 방지합니다.
        clearTimeout(reconnectTimeoutRef.current);

        if (retryCountRef.current < MAX_RECONNECT_ATTEMPTS) {
          const delay = RECONNECT_BASE_DELAY * Math.pow(2, retryCountRef.current);
          console.log(`WebSocket: Attempting to reconnect in ${delay / 1000} seconds... (attempt ${retryCountRef.current + 1})`);
          
          reconnectTimeoutRef.current = setTimeout(() => {
            retryCountRef.current++;
            connect();
          }, delay);
        } else {
          setError("Failed to reconnect after multiple attempts.");
          console.error("WebSocket: Max reconnect attempts reached.");
        }
      }
    };

    ws.onerror = (event) => {
      console.error("WebSocket: Error occurred.", event);
      setError("WebSocket connection error.");
      // 브라우저가 에러 직후 자동으로 클로즈 이벤트를 유도하므로 내버려 두는 것이 레이스 컨디션을 막습니다.
    };
  }, [token]);

  const disconnect = useCallback(() => {
    clearTimeout(reconnectTimeoutRef.current);
    const ws = wsRef.current;
    if (ws) {
      console.log("WebSocket: Disconnecting...");

      if (ws.readyState === WebSocket.CONNECTING) {
        // 아직 연결이 확립되지 않았으므로 지금 close()하면 브라우저 경고가 뜬다.
        // onopen에서 대신 닫도록 표시만 해두고, 재연결 로직이 트리거되지 않게
        // close/error 핸들러만 미리 제거해둔다 (onopen은 살려둬야 위 플래그를 본다).
        ws.shouldCloseOnOpen = true;
        ws.onmessage = null;
        ws.onclose = null;
        ws.onerror = null;
      } else {
        ws.onopen = null;
        ws.onmessage = null;
        ws.onclose = null;
        ws.onerror = null;
        if (ws.readyState === WebSocket.OPEN) {
          ws.close(1000, "Component unmounted or token changed.");
        }
      }
      wsRef.current = null;
    }
    setIsConnected(false);
    retryCountRef.current = 0;
  }, []);

  useEffect(() => {
    connect();

    return () => {
      disconnect();
    };
  }, [token, connect, disconnect]);

  return { isConnected, error, disconnect };
};