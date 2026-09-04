import { useEffect, useRef } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { Sidebar } from '@/components/layout/Sidebar';
import { Header } from '@/components/layout/Header';

export function Layout() {
  // `main` is the app's single real scroll container — it must have a
  // BOUNDED height (via h-screen + overflow-hidden on this shell, plus
  // min-h-0 threaded down through every flex ancestor) for its own
  // overflow-y-auto to ever actually engage. Without min-h-0, a flex
  // item's default `min-height: auto` lets it grow past its allotted
  // space instead of clipping/scrolling — so `main` would just grow
  // taller than the viewport and the BROWSER WINDOW would scroll the
  // whole shell (sidebar included) instead of `main` scrolling
  // internally. That silently broke two things at once: this
  // pathname-based reset (resetting scrollTop on an element that
  // never actually held any offset) and the investigation workspace's
  // independent left/right scroll panes (real, but invisible while
  // the whole page scrolls together above them).
  //
  // Layout persists across route changes (only the Outlet's child
  // swaps), so `main`'s scrollTop is NOT reset by the browser the way
  // a full page load would be — switching investigation tabs (Overview
  // / Forensics / Indicators / Infrastructure / AI Investigation /
  // Report) would otherwise keep whatever scroll position the previous
  // tab was left at. This pathname-keyed effect covers ordinary
  // top-level navigation; InvestigationShell additionally resets on
  // investigation-section identity specifically (see there) since
  // that's the more precise signal for tab switches within a single
  // full-investigation view.
  const mainRef = useRef<HTMLElement>(null);
  const location = useLocation();

  useEffect(() => {
    mainRef.current?.scrollTo({ top: 0 });
  }, [location.pathname]);

  return (
    <div className="flex h-screen overflow-hidden bg-base-950 bg-grid-subtle bg-grid-sm">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0 min-h-0">
        <Header />
        <main id="app-main-scroll" ref={mainRef} className="flex-1 min-h-0 overflow-y-auto scrollbar-thin">
          <Outlet />
        </main>
      </div>
    </div>
  );
}