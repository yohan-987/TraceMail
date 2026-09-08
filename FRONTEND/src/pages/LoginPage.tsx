import { useState, type FormEvent } from 'react';
import { useNavigate, useLocation, Navigate } from 'react-router-dom';
import { ShieldCheck, Loader2 } from 'lucide-react';
import { Card, SectionLabel } from '@/components/ui/Primitives';
import { useAuth } from '@/context/AuthContext';

// Frontend F5 — intentionally minimal per Backend Batch 5: no "remember
// me", no password reset, no registration. A single fixed analyst
// credential set lives in the backend's env vars.
export function LoginPage() {
  const { authenticated, loading, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const redirectTo = (location.state as { from?: string } | null)?.from ?? '/';

  // Reaching /login while already authenticated (e.g. typed the URL
  // directly, or navigated back after logging in) — leave immediately
  // rather than showing the form again.
  if (!loading && authenticated) {
    return <Navigate to={redirectTo} replace />;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!username.trim() || !password || submitting) return;

    setSubmitting(true);
    setError(null);

    const ok = await login(username.trim(), password);

    setSubmitting(false);

    if (ok) {
      navigate(redirectTo, { replace: true });
    } else {
      setError('Invalid username or password.');
    }
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-base-950 bg-grid-subtle bg-grid-sm px-4">
      <Card className="w-full max-w-sm p-6">
        <div className="flex items-center gap-2 mb-1">
          <ShieldCheck className="w-4 h-4 text-accent-500" />
          <SectionLabel>SIH26106 Analyst Access</SectionLabel>
        </div>
        <h1 className="text-lg font-bold text-ink-50 mb-5">Sign in</h1>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="login-username"
              className="block text-[10px] font-semibold uppercase tracking-wider text-ink-500 mb-1.5"
            >
              Username
            </label>
            <input
              id="login-username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              autoFocus
              className="w-full px-3 py-2 rounded-lg bg-base-900/60 border border-base-500/40 text-[13px] text-ink-100 placeholder:text-ink-600 focus:outline-none focus:ring-2 focus:ring-accent-600/40 focus:border-accent-600/50 transition-colors"
              placeholder="analyst username"
            />
          </div>

          <div>
            <label
              htmlFor="login-password"
              className="block text-[10px] font-semibold uppercase tracking-wider text-ink-500 mb-1.5"
            >
              Password
            </label>
            <input
              id="login-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              className="w-full px-3 py-2 rounded-lg bg-base-900/60 border border-base-500/40 text-[13px] text-ink-100 placeholder:text-ink-600 focus:outline-none focus:ring-2 focus:ring-accent-600/40 focus:border-accent-600/50 transition-colors"
              placeholder="••••••••"
            />
          </div>

          {error && <p className="text-[11px] text-accent-400">{error}</p>}

          <button
            type="submit"
            disabled={submitting || !username.trim() || !password}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-[11px] font-bold uppercase tracking-wider text-accent-400 bg-accent-700/10 border border-accent-700/30 hover:bg-accent-700/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {submitting ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <ShieldCheck className="w-3.5 h-3.5" />
            )}
            {submitting ? 'Signing in\u2026' : 'Sign in'}
          </button>
        </form>
      </Card>
    </div>
  );
}
