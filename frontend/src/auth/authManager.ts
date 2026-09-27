/**
 * Auth manager — the ONLY module that talks to oidc-client-ts directly.
 *
 * Design (Phase 5C):
 *  - Cognito User Pool via OIDC discovery on the issuer/authority.
 *  - OAuth 2.0 authorization-code + PKCE (response_type "code"); no implicit,
 *    no client secret, no Identity Pool, no browser AWS SDK credentials.
 *  - Token/user object held IN MEMORY for the active session
 *    (InMemoryWebStorage). Tokens are NOT persisted to localStorage.
 *  - Transient OAuth transaction state (PKCE code_verifier + state/nonce) is
 *    kept in sessionStorage ONLY, under the "oidc." key prefix, and is
 *    consumed/removed by the library when the callback completes.
 *  - Refresh via refresh_token when Cognito issues one (offline_access-style
 *    behaviour is provided by Cognito's refresh token for the "code" flow).
 *  - NO automatic hidden-iframe silent renew, NO silent_redirect_uri.
 */

import {
  UserManager,
  InMemoryWebStorage,
  WebStorageStateStore,
  type User,
  type UserManagerSettings,
} from "oidc-client-ts";
import { config } from "../config";
import type { AuthUser } from "./types";

let _userManager: UserManager | null = null;

/** Build the oidc-client-ts settings from non-secret app config. */
export function buildSettings(): UserManagerSettings {
  return {
    authority: config.cognitoIssuer,
    client_id: config.cognitoClientId,
    redirect_uri: config.cognitoRedirectUri,
    post_logout_redirect_uri: config.cognitoLogoutUri,
    response_type: "code", // authorization-code + PKCE (PKCE on by default)
    scope: config.cognitoScopes,

    // Tokens/user held in memory only — not persisted to localStorage.
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),

    // Transient auth-request transaction state (PKCE verifier, state, nonce)
    // in sessionStorage only. Consumed and removed on callback completion.
    stateStore: new WebStorageStateStore({ store: window.sessionStorage }),

    // Refresh via refresh_token when available. No hidden-iframe silent auth.
    automaticSilentRenew: false,

    // Clean the ?code&state query params from the URL after callback.
    // (Handled explicitly in the callback page; kept default here.)
  };
}

/** Lazily construct a singleton UserManager. */
export function getUserManager(): UserManager {
  if (!_userManager) {
    _userManager = new UserManager(buildSettings());
  }
  return _userManager;
}

/** Test-only reset hook (never used in production paths). */
export function __resetUserManagerForTests(): void {
  _userManager = null;
}

/** Map OIDC profile claims to a minimal, safe display identity. */
export function toAuthUser(user: User | null | undefined): AuthUser | null {
  if (!user) {
    return null;
  }
  const profile = user.profile ?? {};
  const email = typeof profile.email === "string" ? profile.email : undefined;
  const preferred =
    typeof profile.preferred_username === "string"
      ? profile.preferred_username
      : undefined;
  return {
    username: email ?? preferred ?? "Signed in",
    email,
  };
}

/** A user is authenticated only when present AND not expired. */
export function isUserValid(user: User | null | undefined): boolean {
  return !!user && !user.expired;
}

// ── Thin operations the provider composes over. Each is a single library call
// so the rest of the app never imports oidc-client-ts. ───────────────────────

export async function loadUser(): Promise<User | null> {
  return getUserManager().getUser();
}

export async function beginSignIn(): Promise<void> {
  // Full-page redirect to Cognito Hosted UI authorize endpoint (code + PKCE).
  await getUserManager().signinRedirect();
}

export async function completeSignIn(): Promise<User> {
  // Validates state, completes PKCE, exchanges code for tokens.
  return getUserManager().signinRedirectCallback();
}

export async function beginSignOut(): Promise<void> {
  const mgr = getUserManager();
  // Clear local in-memory session first, then redirect to provider logout.
  await mgr.removeUser();
  await mgr.signoutRedirect();
}
