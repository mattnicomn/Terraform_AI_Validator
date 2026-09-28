/**
 * AuthProvider — Cognito OIDC (authorization-code + PKCE) via oidc-client-ts.
 *
 * Exposes the app's AuthContextValue contract. UI components use `useAuth()`
 * and never import oidc-client-ts directly (that lives in authManager.ts).
 *
 * Token lifecycle:
 *  - On mount, load any in-memory user (present only after a callback in the
 *    same page-load session; in-memory store means a fresh reload starts
 *    unauthenticated).
 *  - Subscribe to UserManager events: accessTokenExpired -> clear session;
 *    userLoaded (e.g. after refresh) -> update state; silentRenewError /
 *    userSignedOut -> clear.
 *  - Renewal uses refresh_token (signinSilent) only in response to expiry
 *    events; there is NO hidden-iframe silent auth and NO silent_redirect_uri.
 */

import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type { User } from "oidc-client-ts";
import type { AuthContextValue, AuthState } from "./types";
import {
  getUserManager,
  beginSignIn,
  beginSignOut,
  loadUser,
  toAuthUser,
  isUserValid,
} from "./authManager";

const AuthContext = createContext<AuthContextValue | null>(null);

const GENERIC_AUTH_ERROR =
  "We couldn't complete sign-in. Please try again.";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    isAuthenticated: false,
    isLoading: true,
    user: null,
    error: null,
  });

  // Keep the latest valid access token out of React state / DOM.
  const accessTokenRef = useRef<string | null>(null);

  function applyUser(user: User | null) {
    const valid = isUserValid(user);
    accessTokenRef.current = valid ? (user?.access_token ?? null) : null;
    setState({
      isAuthenticated: valid,
      isLoading: false,
      user: valid ? toAuthUser(user) : null,
      error: null,
    });
  }

  function clearSession() {
    accessTokenRef.current = null;
    setState({
      isAuthenticated: false,
      isLoading: false,
      user: null,
      error: null,
    });
  }

  useEffect(() => {
    const mgr = getUserManager();
    let active = true;

    loadUser()
      .then((user) => {
        if (active) applyUser(user);
      })
      .catch(() => {
        if (active) clearSession();
      });

    const onLoaded = (user: User) => applyUser(user);
    const onExpired = () => {
      // Try a refresh-token renewal; on failure, clear the session.
      mgr
        .signinSilent()
        .then((user) => applyUser(user))
        .catch(() => clearSession());
    };
    const onSignedOut = () => clearSession();

    mgr.events.addUserLoaded(onLoaded);
    mgr.events.addAccessTokenExpired(onExpired);
    mgr.events.addUserSignedOut(onSignedOut);

    return () => {
      active = false;
      mgr.events.removeUserLoaded(onLoaded);
      mgr.events.removeAccessTokenExpired(onExpired);
      mgr.events.removeUserSignedOut(onSignedOut);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      ...state,
      signIn: async () => {
        try {
          await beginSignIn();
        } catch {
          setState((s) => ({ ...s, isLoading: false, error: GENERIC_AUTH_ERROR }));
        }
      },
      signOut: async () => {
        try {
          await beginSignOut();
        } catch {
          // Even if provider logout redirect fails, drop local session.
          clearSession();
        }
      },
      getAccessToken: () => accessTokenRef.current,
    }),
    [state],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an <AuthProvider>.");
  }
  return ctx;
}

/** Exposed for the callback page to set authenticated state post-exchange. */
export { GENERIC_AUTH_ERROR };
