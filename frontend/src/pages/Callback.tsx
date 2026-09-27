/**
 * OAuth callback page.
 *
 * Completes the Cognito authorization-code + PKCE exchange via the auth
 * manager (which validates OIDC state and consumes the transient PKCE
 * transaction from sessionStorage), then redirects to /app on success.
 *
 * On failure it shows a safe, generic message. It never renders the
 * authorization code, tokens, or raw provider error text.
 */

import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { completeSignIn } from "../auth/authManager";

type Status = "processing" | "error";

export function Callback() {
  const navigate = useNavigate();
  const [status, setStatus] = useState<Status>("processing");
  const ran = useRef(false);

  useEffect(() => {
    // Guard against double-invocation (React 18 StrictMode double effect).
    if (ran.current) return;
    ran.current = true;

    completeSignIn()
      .then(() => {
        // Success: userLoaded event updates AuthProvider state.
        navigate("/app", { replace: true });
      })
      .catch(() => {
        // Do not surface code/tokens/provider error detail.
        setStatus("error");
      });
  }, [navigate]);

  if (status === "error") {
    return (
      <main className="page" id="main">
        <section className="state-panel" role="alert">
          <h1 className="state-panel__title">Sign-in failed</h1>
          <p className="state-panel__text">
            We couldn't complete sign-in. Please return to the start page and
            try again.
          </p>
          <button
            type="button"
            className="btn btn--primary"
            onClick={() => navigate("/", { replace: true })}
          >
            Back to start
          </button>
        </section>
      </main>
    );
  }

  return (
    <main className="page" id="main">
      <section className="state-panel" role="status" aria-busy="true">
        <h1 className="state-panel__title">Completing sign-in…</h1>
        <p className="state-panel__text">One moment while we sign you in.</p>
      </section>
    </main>
  );
}
