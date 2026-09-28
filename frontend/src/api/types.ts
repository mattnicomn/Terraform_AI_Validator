/**
 * API contract types + application error model for the AI Validator public
 * endpoint.
 *
 * The only modeled public application route is POST /BedrockPromptHandler.
 * The four Processor operations (scan-file / transfer-file /
 * classification-report / scan-bucket) are Bedrock Agent action-group
 * operations and are intentionally NOT represented as frontend REST contracts.
 */

/** Request body accepted by POST /BedrockPromptHandler. */
export interface PromptRequest {
  prompt: string;
}

/** Success response body from POST /BedrockPromptHandler. */
export interface PromptResponse {
  response: string;
}

/** Error body shape the handler may return on failure. */
export interface ApiErrorResponse {
  error: string;
}

/** Application-level error categories (mapped from status / failure mode). */
export type ApiErrorKind =
  | "VALIDATION"
  | "AUTH"
  | "UPSTREAM_AI"
  | "SERVER"
  | "NETWORK"
  | "CONFIGURATION"
  | "UNKNOWN";

/** A safe, user-facing API error. Never carries raw server/provider detail. */
export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  /** Safe, user-facing message suitable for direct display. */
  readonly userMessage: string;

  constructor(kind: ApiErrorKind, userMessage: string) {
    super(`${kind}: ${userMessage}`);
    this.name = "ApiError";
    this.kind = kind;
    this.userMessage = userMessage;
  }
}

/** Safe user-facing messages per error kind. */
export const USER_MESSAGES: Record<ApiErrorKind, string> = {
  VALIDATION: "Check your request and try again.",
  AUTH: "Your session has expired. Sign in again.",
  UPSTREAM_AI: "The AI service is temporarily unavailable. Try again.",
  SERVER: "AI Validator encountered an error. Try again.",
  NETWORK: "Unable to reach AI Validator. Check your connection and try again.",
  CONFIGURATION: "AI Validator is not configured for API access.",
  UNKNOWN: "Something went wrong. Try again.",
};

export function makeApiError(kind: ApiErrorKind): ApiError {
  return new ApiError(kind, USER_MESSAGES[kind]);
}
