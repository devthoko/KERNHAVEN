import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, onUnauthenticated, setCsrfToken } from "./api";
import { applyTheme } from "./theme";
import type { Permission, Preferences, Role, SessionInfo, Theme } from "./types";

type State =
  | { status: "loading" }
  | { status: "setup" }
  | { status: "anonymous"; reason?: "expired" | "logged_out" }
  | { status: "authenticated"; session: SessionInfo };

interface SessionValue {
  state: State;
  theme: Theme;
  login: (username: string, password: string) => Promise<void>;
  completeSetup: (input: { token: string; username: string; display_name: string; password: string }) => Promise<void>;
  logout: () => Promise<void>;
  setTheme: (theme: Theme) => Promise<void>;
  can: (p: Permission) => boolean;
}

const SessionContext = createContext<SessionValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<State>({ status: "loading" });
  const [theme, setThemeState] = useState<Theme>("system");

  const enter = useCallback(async (session: SessionInfo) => {
    setCsrfToken(session.csrf_token);
    setState({ status: "authenticated", session });
    try {
      const prefs = await api.get<Preferences>("/auth/preferences");
      setThemeState(prefs.theme);
    } catch {
      setThemeState("system");
    }
  }, []);

  useEffect(() => {
    onUnauthenticated(() => {
      setCsrfToken(null);
      setState((s) => (s.status === "authenticated" ? { status: "anonymous", reason: "expired" } : s));
    });
    (async () => {
      try {
        const setup = await api.get<{ required: boolean }>("/setup");
        if (setup.required) {
          setState({ status: "setup" });
          return;
        }
        await enter(await api.get<SessionInfo>("/auth/session"));
      } catch {
        setState({ status: "anonymous" });
      }
    })();
    return () => onUnauthenticated(null);
  }, [enter]);

  useEffect(() => applyTheme(theme), [theme]);

  const value = useMemo<SessionValue>(() => {
    const permissions = state.status === "authenticated" ? new Set(state.session.permissions) : new Set<Permission>();
    return {
      state,
      theme,
      login: async (username, password) => enter(await api.post<SessionInfo>("/auth/login", { username, password })),
      completeSetup: async (input) => enter(await api.post<SessionInfo>("/setup", input)),
      logout: async () => {
        try {
          await api.post("/auth/logout");
        } finally {
          setCsrfToken(null);
          setThemeState("system");
          setState({ status: "anonymous", reason: "logged_out" });
        }
      },
      // Optimistic: apply immediately, roll back if the server rejects it.
      setTheme: async (t) => {
        const previous = theme;
        setThemeState(t);
        try {
          const saved = await api.put<Preferences>("/auth/preferences", { theme: t });
          setThemeState(saved.theme);
        } catch (err) {
          setThemeState(previous);
          throw err;
        }
      },
      can: (p) => permissions.has(p),
    };
  }, [state, theme, enter]);

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionValue {
  const v = useContext(SessionContext);
  if (!v) throw new Error("useSession outside SessionProvider");
  return v;
}

/** useCurrentUser returns the authenticated session; only use inside the app shell. */
export function useCurrentSession(): SessionInfo {
  const { state } = useSession();
  if (state.status !== "authenticated") throw new Error("not authenticated");
  return state.session;
}

/** canManage mirrors the server rule (authz.CanManage) to hide controls. */
export function canManage(actor: Role, target: Role): boolean {
  if (actor === "owner") return true;
  if (actor === "admin") return target === "operator" || target === "viewer";
  return false;
}
