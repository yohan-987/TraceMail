import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, X, Loader2 } from 'lucide-react';
import { getEmails } from '@/api/api';
import { mapApiEmailToUiEmail } from '@/api/emailMapper';
import type { ScannedEmail } from '@/data/mockData';
import { cn } from '@/lib/utils';

/**
 * Global search — queries the real GET /api/v1/emails?search=... list
 * endpoint (backend already matches sender/senderDomain/subject/
 * recipient/emailId/caseId server-side per emailQuery.ts). Never a
 * second/local search dataset. Selecting a result opens the full
 * Investigation Overview for that email, same as every other
 * "Investigate" action in the app.
 */
export function GlobalSearch() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<ScannedEmail[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    inputRef.current?.focus();
  }, [open]);

  useEffect(() => {
    function onOutside(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    function onEscape(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', onOutside);
    document.addEventListener('keydown', onEscape);
    return () => {
      document.removeEventListener('mousedown', onOutside);
      document.removeEventListener('keydown', onEscape);
    };
  }, []);

  useEffect(() => {
    const trimmed = query.trim();
    if (trimmed === '') {
      setResults([]);
      setError(null);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    const timer = setTimeout(() => {
      getEmails({ search: trimmed, limit: 8 })
        .then((res) => {
          if (cancelled) return;
          setResults(res.items.map((item) => mapApiEmailToUiEmail(item)));
        })
        .catch((err) => {
          if (cancelled) return;
          setError(err instanceof Error ? err.message : 'Search failed');
          setResults([]);
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    }, 250);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [query]);

  const openEmail = (email: ScannedEmail) => {
    setOpen(false);
    setQuery('');
    navigate('/investigation', { state: { emailId: email.id } });
  };

  return (
    <div className="relative" ref={containerRef}>
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label="Search emails"
        className={cn(
          'flex items-center justify-center w-8 h-8 rounded-lg transition-colors',
          open ? 'text-ink-100 bg-base-800' : 'text-ink-500 hover:text-ink-200 hover:bg-base-800/60'
        )}
      >
        <Search className="w-4 h-4" />
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-80 rounded-xl border border-base-500/40 bg-base-800/95 backdrop-blur-md shadow-2xl overflow-hidden z-30 animate-fade-in">
          <div className="flex items-center gap-2 px-3 py-2.5 border-b border-base-500/30">
            <Search className="w-3.5 h-3.5 text-ink-500 shrink-0" />
            <input
              ref={inputRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Sender, domain, subject, emailId, caseId..."
              className="flex-1 bg-transparent text-[12px] text-ink-100 placeholder:text-ink-600 outline-none"
            />
            {query && (
              <button onClick={() => setQuery('')} className="text-ink-600 hover:text-ink-300">
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <div className="max-h-80 overflow-y-auto scrollbar-thin">
            {loading ? (
              <div className="flex items-center justify-center gap-2 py-6 text-[11px] text-ink-500">
                <Loader2 className="w-3.5 h-3.5 animate-spin" /> Searching...
              </div>
            ) : error ? (
              <div className="py-6 text-center text-[11px] text-accent-500">{error}</div>
            ) : query.trim() === '' ? (
              <div className="py-6 text-center text-[11px] text-ink-600">
                Search by sender, domain, subject, recipient, email ID, or case ID.
              </div>
            ) : results.length === 0 ? (
              <div className="py-6 text-center text-[11px] text-ink-600">No matching emails.</div>
            ) : (
              results.map((email) => (
                <button
                  key={email.id}
                  onClick={() => openEmail(email)}
                  className="w-full text-left px-3 py-2.5 hover:bg-base-700/50 border-b border-base-500/15 last:border-b-0 transition-colors"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[12px] font-medium text-ink-200 truncate">
                      {email.subject || 'No Subject'}
                    </span>
                    <span className="mono text-[9px] text-ink-600 shrink-0">{email.classification}</span>
                  </div>
                  <div className="flex items-center gap-1.5 mt-0.5 text-[10px] text-ink-500 truncate">
                    <span className="mono">{email.sender || 'unknown sender'}</span>
                    <span className="text-ink-700">·</span>
                    <span className="mono">{email.caseId || email.id}</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
