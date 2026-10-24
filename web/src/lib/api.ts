// The dashboard's only way to talk to Warden: same-origin fetch with the session cookie (httpOnly, set by
// the backend; never readable here) and the X-Warden header every state-changing request needs.

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

export class Offline extends Error {
  name = "Offline";
}

/** Tells the live connection a request couldn't reach Warden, so the offline banner shows at once. */
function offline(): Offline {
  if (typeof window !== "undefined") window.dispatchEvent(new Event("warden:offline"));
  return new Offline("Can’t reach Warden");
}

type Method = "GET" | "POST" | "PUT";

export async function api<T>(path: string, opts: { method?: Method; body?: unknown; signal?: AbortSignal } = {}): Promise<T> {
  const method = opts.method ?? (opts.body === undefined ? "GET" : "POST");
  let res: Response;
  try {
    res = await fetch(`/api${path}`, {
      method,
      credentials: "same-origin",
      cache: "no-store",
      signal: opts.signal,
      headers: { "X-Warden": "1", ...(opts.body !== undefined ? { "Content-Type": "application/json" } : {}) },
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    });
  } catch (e) {
    if ((e as Error).name === "AbortError") throw e;
    throw offline();
  }
  if (res.status === 502 || res.status === 503 || res.status === 504) throw offline();
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const d = data?.detail;
    const code = typeof d === "object" && d ? String(d.code ?? res.status) : String(res.status);
    const msg = typeof d === "object" && d ? String(d.message ?? "") : typeof d === "string" ? d : res.statusText;
    if (res.status === 401 && typeof window !== "undefined" && !location.pathname.startsWith("/sign-in")) {
      const next = encodeURIComponent(location.pathname + location.search);
      location.assign(`/sign-in?next=${next}&expired=1`);
    }
    throw new ApiError(res.status, code, msg);
  }
  return data as T;
}

export const post = <T,>(path: string, body: unknown = {}) => api<T>(path, { method: "POST", body });
export const put = <T,>(path: string, body: unknown) => api<T>(path, { method: "PUT", body });
