/**
 * AuthGuard — real route protection (Phase 5C).
 *
 * Behavior:
 *   - loading        -> loading UI
 *   - authenticated  -> render the protected route
 *   - unauthenticated-> redirect to Landing ("/")
 *
 * UX choice: unauthenticated access redirects to the Landing page rather than
 * auto-initiating a Cognito redirect. This is the less surprising option — the
 * user lands on the product page and explicitly presses "Sign in" — and it
 * avoids redirect loops if the OIDC round-trip fails (a failed callback returns
 * the user to Landing, not back into an automatic redirect).
 */

import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "./AuthProvider";

export function AuthGuard({ children }: { children: ReactNode }) {
  const { isLoading, isAuthenticated } = useAuth();

  if (isLoading) {
    return (
      <section className="state-panel" role="status" aria-busy="true">
        <p className="state-panel__text">Loading…</p>
      </section>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}
