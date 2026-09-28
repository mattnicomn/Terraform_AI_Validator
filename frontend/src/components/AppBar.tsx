import { Link } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider";

/**
 * Top application bar.
 *
 * When authenticated, shows a minimal safe identity (email >
 * preferred_username > "Signed in") and a Sign out action. It never renders
 * tokens or subject IDs.
 */
export function AppBar() {
  const { isAuthenticated, user, signOut } = useAuth();

  return (
    <header className="appbar">
      <div className="appbar__brand">
        <Link to="/" className="appbar__brandlink">
          <span className="appbar__mark" aria-hidden="true">
            USMH
          </span>
          <span className="appbar__title">AI Validator</span>
        </Link>
      </div>
      <nav className="appbar__nav" aria-label="Primary">
        <Link to="/app" className="appbar__navlink">
          Workspace
        </Link>
        <Link to="/account" className="appbar__navlink">
          Account
        </Link>
        {isAuthenticated && (
          <>
            <span className="appbar__identity" title="Signed in">
              {user?.username ?? "Signed in"}
            </span>
            <button
              type="button"
              className="appbar__navlink appbar__signout"
              onClick={() => void signOut()}
            >
              Sign out
            </button>
          </>
        )}
      </nav>
    </header>
  );
}
