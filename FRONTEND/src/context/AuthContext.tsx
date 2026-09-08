import {
  createContext,
  useContext,
  useState,
  useMemo,
  useCallback,
  useEffect,
  type ReactNode,
} from 'react';
import { getAuthStatus, login as apiLogin, logout as apiLogout } from '@/api/api';

/**
 * Frontend F5 — session-cookie auth against Backend Batch 5
 * (POST /auth/login, POST /auth/logout, GET /auth/me). Single fixed
 * analyst credential set via backend env vars — no "remember me",
 * no password reset, no registration, by design (see routes/auth.ts).
 *
 * `loading` is true only for the initial GET /auth/me check on mount —
 * every consumer of this context (the route gate in App.tsx, in
 * particular) must treat loading as a third state distinct from both
 * authenticated and unauthenticated, so nothing flashes the login page
 * or protected content before the real session state is known.
 */
interface AuthContextValue {
  authenticated: boolean;
  username: string | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [authenticated, setAuthenticated] = useState(false);
  const [username, setUsername] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    getAuthStatus()
      .then((status) => {
        if (cancelled) return;
        setAuthenticated(status.authenticated);
        setUsername(status.username);
      })
      .catch((err) => {
        // A failed session check is never treated as "authenticated" —
        // fail closed, not open.
        console.error('Failed to check session state:', err);
        if (!cancelled) {
          setAuthenticated(false);
          setUsername(null);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (user: string, password: string): Promise<boolean> => {
    try {
      const status = await apiLogin(user, password);
      setAuthenticated(status.authenticated);
      setUsername(status.username);
      return status.authenticated;
    } catch (err) {
      // Wrong credentials or a network failure both land here — either
      // way, login did not succeed. Never leave stale authenticated
      // state from a previous session hanging around on a failed
      // attempt.
      setAuthenticated(false);
      setUsername(null);
      return false;
    }
  }, []);

  const logout = useCallback(async (): Promise<void> => {
    try {
      await apiLogout();
    } catch (err) {
      // Even if the network call to destroy the server-side session
      // fails, the user's intent was to log out — leaving the app
      // showing authenticated content after they clicked "logout"
      // would be the worse failure mode. Local state is always
      // cleared below regardless of this call's outcome.
      console.error('Logout request failed:', err);
    } finally {
      setAuthenticated(false);
      setUsername(null);
    }
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({ authenticated, username, loading, login, logout }),
    [authenticated, username, loading, login, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);

  if (!ctx) {
    throw new Error('useAuth must be used within AuthProvider');
  }

  return ctx;
}
