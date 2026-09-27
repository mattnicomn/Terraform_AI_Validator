import { Routes, Route, Navigate } from "react-router-dom";
import { AppBar } from "./components/AppBar";
import { AuthGuard } from "./auth/AuthGuard";
import { Landing } from "./pages/Landing";
import { Callback } from "./pages/Callback";
import { Workspace } from "./pages/Workspace";
import { Account } from "./pages/Account";

/**
 * Application routes:
 *   /         Landing
 *   /callback OAuth callback placeholder (5C)
 *   /app      Workspace (guarded)
 *   /account  Account placeholder (guarded)
 */
export default function App() {
  return (
    <div className="app-root">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <AppBar />
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/callback" element={<Callback />} />
        <Route
          path="/app"
          element={
            <AuthGuard>
              <Workspace />
            </AuthGuard>
          }
        />
        <Route
          path="/account"
          element={
            <AuthGuard>
              <Account />
            </AuthGuard>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  );
}
