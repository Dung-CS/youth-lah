import type { Agent, AgentRun, Message, SystemInfo } from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
  }
}

const AUTH_STORAGE_KEY = "launchpad_auth_token";

let authToken = "";
try {
  if (typeof window !== "undefined" && window.sessionStorage) {
    authToken = window.sessionStorage.getItem(AUTH_STORAGE_KEY) ?? "";
  }
} catch {
  // Ignore sessionStorage access exceptions
}

let unauthorizedListeners: Array<() => void> = [];

export function onUnauthorized(callback: () => void): () => void {
  unauthorizedListeners.push(callback);
  return () => {
    unauthorizedListeners = unauthorizedListeners.filter((cb) => cb !== callback);
  };
}

export function getAuthToken(): string {
  return authToken;
}

export function setAuthToken(token: string): void {
  authToken = token.trim();
  try {
    if (typeof window !== "undefined" && window.sessionStorage) {
      if (authToken) {
        window.sessionStorage.setItem(AUTH_STORAGE_KEY, authToken);
      } else {
        window.sessionStorage.removeItem(AUTH_STORAGE_KEY);
      }
    }
  } catch {
    // Ignore sessionStorage write exceptions
  }
}

export function clearAuthToken(): void {
  setAuthToken("");
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const headers = {
    ...(options?.body ? { "Content-Type": "application/json" } : {}),
    ...(authToken ? { Authorization: "Bearer " + authToken } : {}),
    "X-Launchpad-Client": "web",
    ...options?.headers,
  };
  const response = await fetch(url, {
    ...options,
    headers,
  });
const data = (await response.json().catch(() => ({}))) as T & {error?: string;message?: string; retryAfterMs?: number;};
if (!response.ok) {
  if (response.status === 401) {
    clearAuthToken();
    for (const listener of unauthorizedListeners) {
      try {
        listener();
      } catch {
        // Ignore listener errors
      }
    }}

  if (response.status === 429) {
    const seconds =
      typeof data.retryAfterMs === "number"
        ? Math.ceil(data.retryAfterMs / 1000)
        : undefined;

    throw new ApiError(
      seconds
        ? `Rate limit reached. Try again in ${seconds} seconds.`
        : "Rate limit reached. Please try again shortly.",
      response.status
    );
  }

  // Keep the normal error handling
  const errorMessage =
    (typeof data.message === "string" && data.message
      ? data.message
      : undefined) ||
    data.error ||
    "Request failed";

  throw new ApiError(errorMessage, response.status);
}

  return data;
}

export const api = {
  auth: () => request<{ required: boolean }>("/api/auth"),
  system: () => request<SystemInfo>("/api/system"),
  listAgents: () => request<{ agents: Agent[] }>("/api/agents"),
  createAgent: (body: {
    name: string;
    description: string;
    instructions: string;
  }) =>
    request<{ agent: Agent }>("/api/agents", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateAgent: (
    id: string,
    body: { name: string; description: string; instructions: string },
  ) =>
    request<{ agent: Agent }>("/api/agents/" + id, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteAgent: (id: string) =>
    request<{ archivedWorkspace: string }>("/api/agents/" + id, {
      method: "DELETE",
    }),
  startAgent: (id: string) =>
    request<{ agent: Agent }>("/api/agents/" + id + "/start", {
      method: "POST",
    }),
  stopAgent: (id: string) =>
    request<{ agent: Agent }>("/api/agents/" + id + "/stop", {
      method: "POST",
    }),
  messages: (id: string) =>
    request<{ messages: Message[] }>("/api/agents/" + id + "/messages"),
  runs: (id: string) =>
    request<{ runs: AgentRun[] }>("/api/agents/" + id + "/runs"),
  sendMessage: (id: string, content: string) =>
    request<{ run: AgentRun; message: Message }>(
      "/api/agents/" + id + "/messages",
      {
        method: "POST",
        body: JSON.stringify({ content }),
      },
    ),
  run: (id: string) => request<{ run: AgentRun }>("/api/runs/" + id),
};
