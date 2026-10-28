import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, onUnauthenticated, setCsrfToken } from "./api";

function mockFetch(status: number, body: unknown, contentType = "application/json") {
  const fn = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
    new Response(status === 204 ? null : JSON.stringify(body), {
      status,
      headers: { "Content-Type": contentType },
    }),
  );
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrfToken(null);
  onUnauthenticated(null);
});

describe("api client", () => {
  it("sends the CSRF token only on unsafe methods", async () => {
    setCsrfToken("tok");
    const f = mockFetch(200, {});
    await api.get("/users");
    await api.post("/users", { a: 1 });
    const getInit = f.mock.calls[0]?.[1] as RequestInit;
    const postInit = f.mock.calls[1]?.[1] as RequestInit;
    expect((getInit.headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();
    expect((postInit.headers as Record<string, string>)["X-CSRF-Token"]).toBe("tok");
    expect(postInit.credentials).toBe("same-origin");
    expect(f.mock.calls[1]?.[0]).toBe("/api/v1/users");
  });

  it("maps the uniform error body", async () => {
    mockFetch(409, { error: { code: "conflict", message: "exists", request_id: "r1" } });
    await expect(api.post("/users", {})).rejects.toMatchObject({ status: 409, code: "conflict", message: "exists", requestId: "r1" });
  });

  it("notifies on unauthenticated responses", async () => {
    const handler = vi.fn();
    onUnauthenticated(handler);
    mockFetch(401, { error: { code: "unauthenticated", message: "authentication required" } });
    await expect(api.get("/auth/session")).rejects.toBeInstanceOf(ApiError);
    expect(handler).toHaveBeenCalledOnce();
  });

  it("does not treat failed logins as session loss", async () => {
    const handler = vi.fn();
    onUnauthenticated(handler);
    mockFetch(401, { error: { code: "invalid_credentials", message: "invalid username or password" } });
    await expect(api.post("/auth/login", {})).rejects.toMatchObject({ code: "invalid_credentials" });
    expect(handler).not.toHaveBeenCalled();
  });

  it("returns undefined for 204", async () => {
    mockFetch(204, null);
    await expect(api.del("/auth/sessions/x")).resolves.toBeUndefined();
  });

  it("reports network failures", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("offline"); }));
    await expect(api.get("/jobs")).rejects.toMatchObject({ code: "network_error" });
  });
});

describe("step-up", () => {
  it("asks once and repeats the request", async () => {
    const { setStepUpHandler, api } = await import("./api");
    let calls = 0;
    const fetchMock = vi.fn(async () => {
      calls++;
      if (calls === 1) return new Response(JSON.stringify({ error: { code: "step_up_required", message: "confirm" } }), { status: 403, headers: { "Content-Type": "application/json" } });
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    vi.stubGlobal("fetch", fetchMock);
    const handler = vi.fn(async () => true);
    setStepUpHandler(handler);
    await expect(api.post("/x")).resolves.toEqual({ ok: true });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(calls).toBe(2);
    setStepUpHandler(async () => false);
    calls = 0;
    await expect(api.post("/x")).rejects.toMatchObject({ code: "step_up_required" });
    setStepUpHandler(null);
    vi.unstubAllGlobals();
  });
});
