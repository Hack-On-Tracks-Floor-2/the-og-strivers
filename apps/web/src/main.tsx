import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import { AuthProvider } from './features/auth';
import { Landing } from './pages/Landing';
import { AuthPage } from './pages/Auth';
import { Dashboard } from './layouts/Dashboard';
import { OverviewPage } from './pages/Overview';
import { RepositoriesPage, RepositoryDetailPage } from './pages/Repositories';
import { ScannerPage } from './pages/Scanner';
import { ArtifactsPage } from './pages/Artifacts';
import { ReviewsPage } from './pages/Reviews';
import { SettingsPage } from './pages/Settings';
import { SubmissionsPage } from './pages/Submissions';
import { MLIntelligencePage } from './pages/MLIntelligence';
import { RegressionVerificationPage, PatchStudioPage } from './pages/RegressionVerification';
import './styles/index.css';
createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/" element={<Landing />} />
          {(['developer', 'reviewer'] as const).map((role) => (
            <React.Fragment key={role}>
              <Route path={`/${role}`} element={<Landing role={role} />} />
              <Route path={`/${role}/login`} element={<AuthPage role={role} />} />
              <Route path={`/${role}/app`} element={<Dashboard role={role} />}>
                <Route path="ml" element={<MLIntelligencePage />} />
                <Route path="regression" element={<RegressionVerificationPage />} />
                {role === 'developer' ? (
                  // Repository findings, patches and evidence remain reviewer-only.
                  <Route index element={<SubmissionsPage />} />
                ) : (
                  <>
                    <Route index element={<OverviewPage />} />
                    <Route path="repositories" element={<RepositoriesPage />} />
                    <Route path="repositories/:id" element={<RepositoryDetailPage />} />
                    <Route path="scanner" element={<ScannerPage />} />
                    <Route path="queue" element={<ReviewsPage />} />
                    <Route path="findings" element={<ArtifactsPage kind="findings" />} />
                    <Route path="patches" element={<PatchStudioPage />} />
                    <Route path="evidence" element={<ArtifactsPage kind="evidence" />} />
                    <Route path="decisions" element={<ReviewsPage decisions />} />
                    <Route path="settings" element={<SettingsPage />} />
                  </>
                )}
              </Route>
            </React.Fragment>
          ))}
          <Route path="/developer/register" element={<AuthPage role="developer" register />} />
          <Route
            path="*"
            element={
              <div className="not-found">
                <h1>PAGE NOT FOUND.</h1>
                <Link className="button primary" to="/">
                  Back to ProofPatch ↗
                </Link>
              </div>
            }
          />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
);
