import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ActiveCaseProvider } from '@/context/ActiveCaseContext';
import { ThemeProvider } from '@/context/ThemeContext';
import { Layout } from '@/components/layout/Layout';
import { OverviewPage } from '@/pages/OverviewPage';
import { ScannerPage } from '@/pages/ScannerPage';
import { InvestigationPage } from '@/pages/InvestigationPage';
import { ForensicsPage } from '@/pages/ForensicsPage';
import { IndicatorsPage } from '@/pages/IndicatorsPage';
import { InfrastructurePage } from '@/pages/InfrastructurePage';
import { AIInvestigationPage } from '@/pages/AIInvestigationPage';
import { CasesPage } from '@/pages/CasesPage';
import { ReportsPage } from '@/pages/ReportsPage';

export default function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
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
      </BrowserRouter>
    </ThemeProvider>
  );
}