import { useAuth } from "../auth/AuthProvider";
import { ErrorBanner } from "../components/ErrorBanner";

/**
 * Landing / sign-in screen.
 *
 * Claims are limited to backend-supported behavior. "Sign in" initiates the
 * Cognito authorization-code + PKCE flow (full-page redirect). If a user is
 * already authenticated, a link into the workspace is offered instead.
 */
export function Landing() {
  const { isAuthenticated, signIn, error } = useAuth();

  return (
    <main className="landing" id="main">
      <section className="landing__hero">
        <p className="landing__eyebrow">USMISSIONHERO</p>
        <h1 className="landing__title">AI Validator</h1>
        <p className="landing__lede">
          Inspect and safely transfer data with AI-assisted security
          classification. Authorized users work through a guided assistant that
          scans files and buckets for sensitive information and enforces
          transfer rules.
        </p>

        <ErrorBanner message={error} />

        <div className="landing__actions">
          {isAuthenticated ? (
            <a className="btn btn--primary" href="/app">
              Go to workspace
            </a>
          ) : (
            <button
              type="button"
              className="btn btn--primary"
              onClick={() => void signIn()}
            >
              Sign in
            </button>
          )}
        </div>
      </section>
    </main>
  );
}
