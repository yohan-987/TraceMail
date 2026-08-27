import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Mail,
  Crosshair,
  FileSearch,
  Flag,
  Network,
  Brain,
  FolderKanban,
  FileText,
  Shield,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { StatusDot } from '@/components/ui/Primitives';

const navItems = [
  { to: '/', label: 'Overview', icon: LayoutDashboard },
  { to: '/scanner', label: 'Email Scanner', icon: Mail },
  { to: '/investigation', label: 'Investigation', icon: Crosshair },
  { to: '/forensics', label: 'Email Forensics', icon: FileSearch },
  { to: '/indicators', label: 'Indicators', icon: Flag },
  { to: '/infrastructure', label: 'Infrastructure', icon: Network },
  { to: '/ai-investigation', label: 'AI Investigation', icon: Brain },
  { to: '/cases', label: 'Cases', icon: FolderKanban },
  { to: '/reports', label: 'Reports', icon: FileText },
];

export function Sidebar() {
  return (
    <aside className="w-60 shrink-0 h-screen sticky top-0 bg-base-900 border-r border-base-500/30 flex flex-col print:hidden">
      {/* Logo / Brand */}
      <div className="px-5 pt-5 pb-6 border-b border-base-500/20">
        <div className="flex items-center gap-2.5">
          <div className="relative flex items-center justify-center w-8 h-8 rounded-lg bg-accent-700/15 border border-accent-700/30">
            <Shield className="w-4 h-4 text-accent-500" />
            <div className="absolute inset-0 rounded-lg bg-accent-700/5 blur-sm" />
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-bold text-ink-100 tracking-tight">SIH26106</span>
            <span className="text-[9px] font-medium uppercase tracking-[0.15em] text-ink-500">
              Threat Detection
            </span>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto scrollbar-thin">
        <div className="px-2 pb-2 section-label">Investigation</div>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 px-2.5 py-2 rounded-lg text-[13px] font-medium transition-all duration-150 group relative',
                  isActive
                    ? 'bg-accent-700/10 text-ink-50'
                    : 'text-ink-400 hover:text-ink-200 hover:bg-base-800/50'
                )
              }
            >
              {({ isActive }) => (
                <>
                  {isActive && (
                    <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[2px] h-5 rounded-full bg-accent-600" />
                  )}
                  <Icon
                    className={cn(
                      'w-4 h-4 shrink-0 transition-colors',
                      isActive ? 'text-accent-500' : 'text-ink-500 group-hover:text-ink-300'
                    )}
                  />
                  {item.label}
                </>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* System status */}
      <div className="px-4 py-3.5 border-t border-base-500/20 space-y-2.5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <StatusDot status="online" />
            <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-400">
              System Online
            </span>
          </div>
        </div>
        <div className="flex items-center justify-between text-[9px] text-ink-600 mono">
          <span>ENGINE v4.2.1</span>
          <span>SIG: 2026.08.23</span>
        </div>
      </div>
    </aside>
  );
}
