/**
 * Typed frontend configuration for the AI Validator SPA.
 *
 * Rules (5B/5C):
 *  - Reads only public, non-secret VITE_* build-time values.
 *  - Does NOT throw at import time: the static scaffold must build and render
 *    before any deployment configuration exists. Validation is available via
 *    `getConfigStatus()` / `assertConfigured()` so that runtime/deployment
 *    misconfiguration can fail clearly LATER, not at module load.
 *  - No secrets, no AWS credentials, no account IDs.
 *
 * Phase 5C note on the Cognito OIDC authority:
 *  oidc-client-ts performs OIDC discovery against an `authority` (issuer) URL.
 *  For a Cognito User Pool the issuer is
 *    https://cognito-idp.<region>.amazonaws.com/<userPoolId>
 *  which CANNOT be derived from the Hosted UI domain (the domain does not
 *  contain the region+userPoolId). It is therefore a distinct, non-secret
 *  config value: VITE_COGNITO_ISSUER. The Hosted UI domain
 *  (VITE_COGNITO_DOMAIN) is still required separately because Cognito's
 *  /logout endpoint lives on the Hosted UI domain, not the issuer.
 */

export interface AppConfig {
  apiBaseUrl: string;
  /** OIDC issuer/authority: https://cognito-idp.<region>.amazonaws.com/<userPoolId> */
  cognitoIssuer: string;
  /** Hosted UI domain base (used for the /logout endpoint). */
  cognitoDomain: string;
  cognitoClientId: string;
  cognitoRedirectUri: string;
  cognitoLogoutUri: string;
  cognitoScopes: string;
}

const DEFAULT_SCOPES = "openid email profile";

function readEnv(name: string): string {
  const value = import.meta.env[name as keyof ImportMetaEnv];
  return typeof value === "string" ? value.trim() : "";
}

/** Raw config as read from the environment (may contain empty strings). */
export const config: AppConfig = {
  apiBaseUrl: readEnv("VITE_API_BASE_URL"),
  cognitoIssuer: readEnv("VITE_COGNITO_ISSUER"),
  cognitoDomain: readEnv("VITE_COGNITO_DOMAIN"),
  cognitoClientId: readEnv("VITE_COGNITO_CLIENT_ID"),
  cognitoRedirectUri: readEnv("VITE_COGNITO_REDIRECT_URI"),
  cognitoLogoutUri: readEnv("VITE_COGNITO_LOGOUT_URI"),
  cognitoScopes: readEnv("VITE_COGNITO_SCOPES") || DEFAULT_SCOPES,
};

/** Config keys required before auth features may operate (5C). */
export const REQUIRED_KEYS: ReadonlyArray<keyof AppConfig> = [
  "cognitoIssuer",
  "cognitoDomain",
  "cognitoClientId",
  "cognitoRedirectUri",
  "cognitoLogoutUri",
];

/** Config keys required before API features may operate (5D). */
export const REQUIRED_API_KEYS: ReadonlyArray<keyof AppConfig> = ["apiBaseUrl"];

export interface ConfigStatus {
  configured: boolean;
  missing: string[];
}

/** Non-throwing status check; safe to call during render. */
export function getConfigStatus(cfg: AppConfig = config): ConfigStatus {
  const missing = REQUIRED_KEYS.filter((k) => !cfg[k]).map((k) => String(k));
  return { configured: missing.length === 0, missing };
}

/**
 * Throwing assertion for later phases (auth/API). NOT called during the
 * Phase 5B scaffold render/build.
 */
export function assertConfigured(cfg: AppConfig = config): void {
  const { configured, missing } = getConfigStatus(cfg);
  if (!configured) {
    throw new Error(
      `AI Validator frontend is not configured. Missing: ${missing.join(", ")}`,
    );
  }
}
