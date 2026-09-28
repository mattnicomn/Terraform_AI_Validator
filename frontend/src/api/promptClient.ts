/**
 * promptClient — the ONLY module that performs an application API request.
 *
 * Endpoint: POST {VITE_API_BASE_URL}/BedrockPromptHandler
 * Auth:     Authorization: Bearer <access token> (caller-supplied; obtained
 *           only via the auth layer's getAccessToken()).
 * Body:     { "prompt": <string> }
 * Success:  200 { "response": <string> }
 *
 * Uses the browser fetch API only. No axios, no AWS SDK, no API Gateway SDK.
 * No direct clients for /scan-file, /transfer-file, /classification-report, or
 * /scan-bucket (those are Bedrock Agent action-group operations, not routes).
 *
 * All failures surface as an ApiError with a safe user-facing message; raw
 * server/provider detail is never propagated to the UI.
 */

import { config } from "../config";
import {
  ApiError,
  makeApiError,
  type PromptRequest,
  type PromptResponse,
} from "./types";

const PROMPT_PATH = "/BedrockPromptHandler";

/** Join base + path without producing "//" or dropping a segment. */
export function buildPromptUrl(baseUrl: string): string {
  const trimmedBase = baseUrl.replace(/\/+$/, ""); // drop trailing slashes
  return `${trimmedBase}${PROMPT_PATH}`;
}

/** Narrow unknown JSON to a valid PromptResponse (string `response`). */
function isPromptResponse(value: unknown): value is PromptResponse {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { response?: unknown }).response === "string"
  );
}

/** Map an HTTP status to the application error model. */
function errorForStatus(status: number): ApiError {
  if (status === 400) return makeApiError("VALIDATION");
  if (status === 401 || status === 403) return makeApiError("AUTH");
  if (status === 502) return makeApiError("UPSTREAM_AI");
  if (status === 500) return makeApiError("SERVER");
  return makeApiError("UNKNOWN");
}

export interface SendPromptArgs {
  prompt: string;
  /** Valid bearer access token from the auth layer's getAccessToken(). */
  accessToken: string;
  /** Optional AbortSignal for cancellation. */
  signal?: AbortSignal;
}

/**
 * Send a prompt to the AI Validator backend and return the response text.
 * Throws ApiError (with a safe userMessage) on any failure.
 */
export async function sendPrompt({
  prompt,
  accessToken,
  signal,
}: SendPromptArgs): Promise<string> {
  // Configuration guard: fail clearly before attempting any network call.
  if (!config.apiBaseUrl) {
    throw makeApiError("CONFIGURATION");
  }

  const url = buildPromptUrl(config.apiBaseUrl);
  const body: PromptRequest = { prompt };

  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify(body),
      signal,
    });
  } catch {
    // fetch rejects on network failure / abort / DNS / CORS-at-network level.
    throw makeApiError("NETWORK");
  }

  if (!res.ok) {
    throw errorForStatus(res.status);
  }

  let json: unknown;
  try {
    json = await res.json();
  } catch {
    // 200 with a malformed/non-JSON body.
    throw makeApiError("UNKNOWN");
  }

  if (!isPromptResponse(json)) {
    throw makeApiError("UNKNOWN");
  }

  return json.response;
}
