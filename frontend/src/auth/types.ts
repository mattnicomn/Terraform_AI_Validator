/**
 * Frontend-facing authentication contract for the AI Validator SPA.
 *
 * UI components depend ONLY on this interface, never directly on
 * oidc-client-ts. Phase 5C implements it with a Cognito OIDC
 * authorization-code + PKCE adapter (see authManager.ts / AuthProvider.tsx).
 */

export interface AuthUser {
  /** Best available display label (email > preferred_username > "Signed in"). */
  username: string;
  email?: string;
}

export interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: AuthUser | null;
  /** Set when a sign-in / callback / renewal error occurs (safe, generic text). */
  error: string | null;
}

export interface AuthContextValue extends AuthState {
  /** Begin authorization-code + PKCE sign-in via Cognito (full-page redirect). */
  signIn: () => Promise<void>;
  /** Begin provider sign-out via Cognito Hosted UI /logout (full-page redirect). */
  signOut: () => Promise<void>;
  /**
   * Return a currently-valid access token for calling the application API
   * (Phase 5D). Returns null when unauthenticated or expired. NOT called in 5C.
   */
  getAccessToken: () => string | null;
}
