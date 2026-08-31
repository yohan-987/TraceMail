import { useEffect, useRef } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { Sidebar } from '@/components/layout/Sidebar';
import { Header } from '@/components/layout/Header';

export function Layout() {
  // `main` below is the app's single scroll container (Layout persists
  // across route changes — only the Outlet's child swaps — so its
  // scrollTop is NOT reset by the browser the way a full page load
  // would be). Without this, switching investigation tabs (Overview /
  // Forensics / Indicators / Infrastructure / AI Investigation /
  // Report) keeps whatever scroll position the previous tab was left
  // at. Implemented once here, centrally, rather than duplicated in
  // every page.
  const mainRef = useRef<HTMLElement>(null);
  const location = useLocation();

  useEffect(() => {
    mainRef.current?.scrollTo({ top: 0 });
  }, [location.pathname]);

  return (
    <div className="flex min-h-screen bg-base-950 bg-grid-subtle bg-grid-sm">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <Header />
        <main ref={mainRef} className="flex-1 overflow-y-auto scrollbar-thin">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
