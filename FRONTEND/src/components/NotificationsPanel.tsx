import { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, ShieldAlert, ScanLine, Brain, Radar, CheckCheck } from 'lucide-react';
import { useActiveCase } from '@/context/ActiveCaseContext';
import type { ScannedEmail } from '@/types/email';
import { cn } from '@/lib/utils';

type NotificationKind =
  | 'critical_threat'
  | 'new_scan'
  | 'ai_unavailable'
  | 'ml_unavailable';

interface AppNotification {
  id: string;
  kind: NotificationKind;
  title: string;
  message: string;
  timestamp: string;
  emailId: string;
}

const KIND_META: Record<NotificationKind, { icon: typeof Bell; color: string }> = {
  critical_threat: { icon: ShieldAlert, color: 'text-accent-400 bg-accent-700/10 border-accent-700/25' },
  new_scan: { icon: ScanLine, color: 'text-sky-400 bg-sky-900/10 border-sky-700/25' },
  ai_unavailable: { icon: Brain, color: 'text-amber-400 bg-amber-900/10 border-amber-700/25' },
  ml_unavailable: { icon: Radar, color: 'text-ink-400 bg-ink-800/20 border-ink-600/25' },
};

const READ_STORAGE_KEY = 'sih26106.notifications.read';

function loadReadIds(): Set<string> {
  try {
    const raw = window.localStorage.getItem(READ_STORAGE_KEY);
    if (!raw) return new Set();
    const arr = JSON.parse(raw);
    return new Set(Array.isArray(arr) ? arr : []);
  } catch {
    return new Set();
  }
}

/**
 * Derived entirely from real, already-fetched application data
 * (availableEmails, via ActiveCaseContext) — no push infrastructure,
 * no fabricated events, no second dataset. Read/unread state persists
 * locally so it survives a refresh; it is purely a client-side
 * convenience, same as the theme preference.
 */
function buildNotifications(emails: ScannedEmail[]): AppNotification[] {
  const notifications: AppNotification[] = [];

  // Most recently scanned email.
  const mostRecent = emails[0];
  if (mostRecent) {
    notifications.push({
      id: `new_scan:${mostRecent.id}`,
      kind: 'new_scan',
      title: 'New email scanned',
      message: `${mostRecent.subject || 'No subject'} — ${mostRecent.classification}`,
      timestamp: mostRecent.date,
      emailId: mostRecent.id,
    });
  }

  for (const email of emails) {
    if (email.status === 'malicious' || email.riskLevel?.toLowerCase() === 'critical') {
      notifications.push({
        id: `critical_threat:${email.id}`,
        kind: 'critical_threat',
        title: 'Critical threat detected',
        message: `${email.subject || 'No subject'} — score ${email.threatScore}`,
        timestamp: email.date,
        emailId: email.id,
      });
    }
    if (email.aiStatus && String(email.aiStatus).toUpperCase() === 'UNAVAILABLE') {
      notifications.push({
        id: `ai_unavailable:${email.id}`,
        kind: 'ai_unavailable',
        title: 'AI analysis unavailable',
        message: `${email.subject || 'No subject'} — AI interpretation could not be produced`,
        timestamp: email.date,
        emailId: email.id,
      });
    }
    if (email.mlStatus && String(email.mlStatus).toUpperCase() === 'UNAVAILABLE') {
      notifications.push({
        id: `ml_unavailable:${email.id}`,
        kind: 'ml_unavailable',
        title: 'External intelligence unavailable',
        message: `${email.subject || 'No subject'} — ML classifier produced no result`,
        timestamp: email.date,
        emailId: email.id,
      });
    }
  }

  // Most recent first, capped so the panel stays scannable.
  return notifications
    .sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1))
    .slice(0, 15);
}

export function NotificationsPanel() {
  const navigate = useNavigate();
  const { availableEmails } = useActiveCase();
  const [open, setOpen] = useState(false);
  const [readIds, setReadIds] = useState<Set<string>>(() => loadReadIds());
  const containerRef = useRef<HTMLDivElement>(null);

  const notifications = useMemo(() => buildNotifications(availableEmails), [availableEmails]);
  const unreadCount = notifications.filter((n) => !readIds.has(n.id)).length;

  useEffect(() => {
    window.localStorage.setItem(READ_STORAGE_KEY, JSON.stringify(Array.from(readIds)));
  }, [readIds]);

  useEffect(() => {
    function onOutside(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', onOutside);
    return () => document.removeEventListener('mousedown', onOutside);
  }, []);

  const markAllRead = () => {
    setReadIds(new Set(notifications.map((n) => n.id)));
  };

  const openNotification = (n: AppNotification) => {
    setReadIds((prev) => new Set(prev).add(n.id));
    setOpen(false);
    navigate('/investigation', { state: { emailId: n.emailId } });
  };

  return (
    <div className="relative" ref={containerRef}>
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label="Notifications"
        className={cn(
          'relative flex items-center justify-center w-8 h-8 rounded-lg transition-colors',
          open ? 'text-ink-100 bg-base-800' : 'text-ink-500 hover:text-ink-200 hover:bg-base-800/60'
        )}
      >
        <Bell className="w-4 h-4" />
        {unreadCount > 0 && (
          <span className="absolute top-1 right-1 min-w-[13px] h-[13px] px-[3px] rounded-full bg-accent-600 accent-glow-sm text-[8px] font-bold text-white flex items-center justify-center leading-none">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-96 rounded-xl border border-base-500/40 bg-base-800/95 backdrop-blur-md shadow-2xl overflow-hidden z-30 animate-fade-in">
          <div className="flex items-center justify-between px-3.5 py-2.5 border-b border-base-500/30">
            <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-400">
              Notifications
            </span>
            {unreadCount > 0 && (
              <button
                onClick={markAllRead}
                className="flex items-center gap-1 text-[10px] font-medium text-accent-400 hover:text-accent-300 transition-colors"
              >
                <CheckCheck className="w-3 h-3" /> Mark all as read
              </button>
            )}
          </div>

          <div className="max-h-96 overflow-y-auto scrollbar-thin">
            {notifications.length === 0 ? (
              <div className="py-8 text-center text-[11px] text-ink-600">
                No notifications yet — scan an email to get started.
              </div>
            ) : (
              notifications.map((n) => {
                const meta = KIND_META[n.kind];
                const Icon = meta.icon;
                const isRead = readIds.has(n.id);
                return (
                  <button
                    key={n.id}
                    onClick={() => openNotification(n)}
                    className={cn(
                      'w-full text-left px-3.5 py-3 flex items-start gap-2.5 border-b border-base-500/15 last:border-b-0 transition-colors hover:bg-base-700/40',
                      !isRead && 'bg-base-700/20'
                    )}
                  >
                    <div className={cn('flex items-center justify-center w-7 h-7 rounded-lg border shrink-0 mt-0.5', meta.color)}>
                      <Icon className="w-3.5 h-3.5" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5">
                        <span className={cn('text-[12px] leading-snug', isRead ? 'text-ink-300' : 'text-ink-100 font-semibold')}>
                          {n.title}
                        </span>
                        {!isRead && <span className="w-1.5 h-1.5 rounded-full bg-accent-500 shrink-0" />}
                      </div>
                      <div className="text-[11px] text-ink-500 truncate mt-0.5">{n.message}</div>
                      <div className="mono text-[9px] text-ink-600 mt-1">{n.timestamp || 'unknown time'}</div>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
