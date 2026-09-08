import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { User, Sun, Moon, LogOut, ShieldCheck } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';
import { useAuth } from '@/context/AuthContext';
import { cn } from '@/lib/utils';

// Frontend F5 — Backend Batch 5 shipped real session-cookie auth, so
// this is no longer a fake "local/demo" profile (see the removed
// banner this file used to show — it was correct when there was no
// authentication at all, and would now be actively misleading). Role
// and workspace stay as fixed display labels since Batch 5 is a
// single-analyst account with no role/workspace concept server-side —
// only username is real, backend-sourced identity.
const STATIC_LABELS = {
  role: 'Analyst',
  workspace: 'SIH26106 — Email Threat Detection',
};

export function ProfilePanel() {
  const { theme, toggleTheme } = useTheme();
  const { username, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [loggingOut, setLoggingOut] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onOutside(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', onOutside);
    return () => document.removeEventListener('mousedown', onOutside);
  }, []);

  async function handleLogout() {
    setLoggingOut(true);
    await logout();
    navigate('/login', { replace: true });
  }

  return (
    <div className="relative" ref={containerRef}>
      <button
        onClick={() => setOpen((v) => !v)}
        className={cn(
          'flex items-center gap-2 pl-1 pr-3 py-1 rounded-lg transition-colors',
          open ? 'bg-base-800' : 'hover:bg-base-800/60'
        )}
      >
        <div className="flex items-center justify-center w-7 h-7 rounded-md bg-base-700 border border-base-500/40">
          <User className="w-3.5 h-3.5 text-ink-400" />
        </div>
        <div className="flex flex-col items-start">
          <span className="text-[11px] font-medium text-ink-200 leading-none">{username ?? 'Analyst'}</span>
          <span className="text-[9px] text-ink-600 leading-none mt-0.5">{STATIC_LABELS.role}</span>
        </div>
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-72 rounded-xl border border-base-500/40 bg-base-800/95 backdrop-blur-md shadow-2xl overflow-hidden z-30 animate-fade-in">
          <div className="flex items-center gap-2 px-3.5 py-2.5 border-b border-base-500/30 bg-emerald-900/10">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            <span className="text-[10px] font-semibold text-emerald-400 uppercase tracking-wider">
              Signed In — Session Active
            </span>
          </div>

          <div className="p-3.5 space-y-3">
            <ProfileField label="Username" value={username ?? 'Unknown'} />
            <ProfileField label="Role" value={STATIC_LABELS.role} />
            <ProfileField label="Workspace" value={STATIC_LABELS.workspace} />

            <div className="panel-2 p-2.5 flex items-center justify-between">
              <div>
                <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mb-0.5">
                  Current Theme
                </div>
                <div className="text-[12px] text-ink-200 capitalize">{theme}</div>
              </div>
              <button
                onClick={toggleTheme}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[10px] font-medium text-ink-300 bg-base-700/60 border border-base-500/30 hover:bg-base-700 transition-colors uppercase tracking-wider"
              >
                {theme === 'dark' ? <Sun className="w-3 h-3" /> : <Moon className="w-3 h-3" />}
                Switch
              </button>
            </div>

            <button
              onClick={handleLogout}
              disabled={loggingOut}
              className="w-full flex items-center justify-center gap-1.5 px-2.5 py-2 rounded-lg text-[10px] font-bold uppercase tracking-wider text-accent-400 bg-accent-700/10 border border-accent-700/30 hover:bg-accent-700/20 transition-colors disabled:opacity-50"
            >
              <LogOut className="w-3 h-3" />
              {loggingOut ? 'Signing out\u2026' : 'Sign Out'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function ProfileField({ label, value }: { label: string; value: string }) {
  return (
    <div className="panel-2 p-2.5">
      <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mb-0.5">{label}</div>
      <div className="text-[12px] text-ink-200">{value}</div>
    </div>
  );
}
