// Minimal API client. The session cookie is HttpOnly; only the CSRF token is
// kept in memory and sent on unsafe requests (M2, AT-F08-04).

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string;

  constructor(status: number, code: string, message: string, requestId = "") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

let csrfToken: string | null = null;
let unauthenticatedHandler: (() => void) | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

export function onUnauthenticated(handler: (() => void) | null): void {
  unauthenticatedHandler = handler;
}

const SAFE_METHODS = new Set(["GET", "HEAD"]);

export async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (!SAFE_METHODS.has(method) && csrfToken) headers["X-CSRF-Token"] = csrfToken;

  let res: Response;
  try {
    res = await fetch(`/api/v1${path}`, {
      method,
      headers,
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "network_error", "The server could not be reached. Check your connection.");
  }

  if (res.status === 204) return undefined as T;
  const isJSON = (res.headers.get("Content-Type") ?? "").includes("application/json");
  const data: unknown = isJSON ? await res.json().catch(() => null) : null;

  if (!res.ok) {
    const err = (data as { error?: { code?: string; message?: string; request_id?: string } } | null)?.error;
    const apiErr = new ApiError(
      res.status,
      err?.code ?? "http_error",
      err?.message ?? `Request failed (HTTP ${res.status})`,
      err?.request_id ?? "",
    );
    if (res.status === 401 && apiErr.code === "unauthenticated") unauthenticatedHandler?.();
    throw apiErr;
  }
  return data as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  put: <T>(path: string, body: unknown) => request<T>("PUT", path, body),
  patch: <T>(path: string, body: unknown) => request<T>("PATCH", path, body),
  del: <T = void>(path: string) => request<T>("DELETE", path),
};

/** errorMessage turns any thrown value into a user-facing sentence. */
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return "An unexpected error occurred.";
}

/** putBinary sends raw bytes (upload chunks) with the CSRF token. */
export async function putBinary<T>(path: string, body: Blob): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api/v1${path}`, {
      method: "PUT",
      headers: { Accept: "application/json", "Content-Type": "application/octet-stream", ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}) },
      credentials: "same-origin",
      body,
    });
  } catch {
    throw new ApiError(0, "network_error", "The server could not be reached. Check your connection.");
  }
  const data: unknown = await res.json().catch(() => null);
  if (!res.ok) {
    const err = (data as { error?: { code?: string; message?: string; request_id?: string } } | null)?.error;
    throw new ApiError(res.status, err?.code ?? "http_error", err?.message ?? `Request failed (HTTP ${res.status})`, err?.request_id ?? "");
  }
  return data as T;
}
