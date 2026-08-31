import { useState, useEffect, useRef } from 'react';
import { User, Sun, Moon, ShieldQuestion } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';
import { cn } from '@/lib/utils';

/**
 * A local/demo profile only — there is no authentication in this app
 * (Part C.3: "Do NOT add authentication... Clearly label this as a
 * local/demo profile. Do not pretend it represents an authenticated
 * account."). Analyst name/role/workspace are static demo values, not
 * backend-sourced identity; theme is the one genuinely live value.
 */
const DEMO_PROFILE = {
  analystName: 'M. Chen',
  role: 'Analyst L3',
  workspace: 'SIH26106 — Email Threat Detection',
};

export function ProfilePanel() {
  const { theme, toggleTheme } = useTheme();
  const [open, setOpen] = useState(false);
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
          <span className="text-[11px] font-medium text-ink-200 leading-none">{DEMO_PROFILE.analystName}</span>
          <span className="text-[9px] text-ink-600 leading-none mt-0.5">{DEMO_PROFILE.role}</span>
        </div>
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-72 rounded-xl border border-base-500/40 bg-base-800/95 backdrop-blur-md shadow-2xl overflow-hidden z-30 animate-fade-in">
          <div className="flex items-center gap-2 px-3.5 py-2.5 border-b border-base-500/30 bg-amber-900/10">
            <ShieldQuestion className="w-3.5 h-3.5 text-amber-400 shrink-0" />
            <span className="text-[10px] font-semibold text-amber-400 uppercase tracking-wider">
              Local / Demo Profile — Not an Authenticated Account
            </span>
          </div>

          <div className="p-3.5 space-y-3">
            <ProfileField label="Analyst Name" value={DEMO_PROFILE.analystName} />
            <ProfileField label="Role" value={DEMO_PROFILE.role} />
            <ProfileField label="Workspace" value={DEMO_PROFILE.workspace} />

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
