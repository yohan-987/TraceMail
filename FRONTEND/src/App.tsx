import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AuthProvider, useAuth } from '@/context/AuthContext';
import { ActiveCaseProvider } from '@/context/ActiveCaseContext';
import { ThemeProvider } from '@/context/ThemeContext';
import { Layout } from '@/components/layout/Layout';
import { LoginPage } from '@/pages/LoginPage';
import { OverviewPage } from '@/pages/OverviewPage';
import { ScannerPage } from '@/pages/ScannerPage';
import { InvestigationPage } from '@/pages/InvestigationPage';
import { ForensicsPage } from '@/pages/ForensicsPage';
import { IndicatorsPage } from '@/pages/IndicatorsPage';
import { InfrastructurePage } from '@/pages/InfrastructurePage';
import { AIInvestigationPage } from '@/pages/AIInvestigationPage';
import { CasesPage } from '@/pages/CasesPage';
import { ReportsPage } from '@/pages/ReportsPage';

// Frontend F5 — simple full-screen loading state while the initial
// GET /auth/me check is in flight. Deliberately plain: this must never
// look like either the login page or protected content, since briefly
// showing either before the real session state is known is exactly
// the flash this exists to prevent.
function AuthLoadingScreen() {
  return (
    <div className="flex items-center justify-center min-h-screen bg-base-950">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-ink-600">
        Checking session…
      </div>
    </div>
  );
}

// Frontend F5 — everything that needs a real session gates through
// here. ActiveCaseProvider (and the getEmails() fetch its mount effect
// fires) is only ever mounted once authenticated is true — not merely
// nested "underneath" auth in JSX order, but conditionally rendered on
// it, so nothing in the protected app can fetch before auth state is
// actually known.
function ProtectedApp() {
  const { authenticated, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return <AuthLoadingScreen />;
  }

  if (!authenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  return (
    <ActiveCaseProvider>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<OverviewPage />} />
          <Route path="scanner" element={<ScannerPage />} />
          <Route path="investigation" element={<InvestigationPage />} />
          <Route path="forensics" element={<ForensicsPage />} />
          <Route path="indicators" element={<IndicatorsPage />} />
          <Route path="infrastructure" element={<InfrastructurePage />} />
          <Route path="ai-investigation" element={<AIInvestigationPage />} />
          <Route path="cases" element={<CasesPage />} />
          <Route path="reports" element={<ReportsPage />} />
        </Route>
      </Routes>
    </ActiveCaseProvider>
  );
}

// Frontend F5 — the one route that must exist OUTSIDE the auth gate
// above, since it's the only page reachable while unauthenticated.
// While loading, render nothing here yet either — LoginPage itself
// checks `loading`/`authenticated` via useAuth() and redirects away if
// a session already turns out to be valid, so this route doesn't need
// its own separate loading branch.
function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/*" element={<ProtectedApp />} />
    </Routes>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </BrowserRouter>
    </ThemeProvider>
  );
}