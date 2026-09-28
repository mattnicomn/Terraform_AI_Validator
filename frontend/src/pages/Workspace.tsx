import { useState } from "react";
import { PromptComposer } from "../components/PromptComposer";
import { ResponsePanel } from "../components/ResponsePanel";
import { ErrorBanner } from "../components/ErrorBanner";
import { useAuth } from "../auth/AuthProvider";
import { sendPrompt } from "../api/promptClient";
import { ApiError, makeApiError } from "../api/types";

/**
 * Workspace — V1 conversational shell wired to the prompt API.
 *
 * State model: idle | loading | success | error.
 *  - loading disables submit and shows progress (prevents duplicate submits).
 *  - success renders ONLY the response text (plain text) in ResponsePanel.
 *  - error surfaces a safe user-facing message in the ErrorBanner.
 *
 * Conversation: V1 keeps ONLY the most recent prompt+response in memory (see
 * decision note below). No localStorage / sessionStorage / persistence.
 *
 * Token: obtained solely via useAuth().getAccessToken(). If no valid token,
 * the request is not sent; the user is returned to sign-in via signOut()
 * (the auth boundary), avoiding a retry loop.
 */

type Phase = "idle" | "loading" | "success" | "error";

export function Workspace() {
  const { getAccessToken, signOut } = useAuth();
  const [phase, setPhase] = useState<Phase>("idle");
  const [responseText, setResponseText] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  // Memory-only "most recent" transcript (decision: single turn in V1).
  const [lastPrompt, setLastPrompt] = useState<string | null>(null);

  async function handleSubmit(prompt: string) {
    if (phase === "loading") {
      return; // extra guard against duplicate submission
    }

    const token = getAccessToken();
    if (!token) {
      // Treat as an authentication/session condition: do not send.
      setPhase("error");
      setError(makeApiError("AUTH").userMessage);
      // Return the user to sign-in through the auth boundary (no retry loop).
      void signOut();
      return;
    }

    setPhase("loading");
    setError(null);
    setLastPrompt(prompt);

    try {
      const text = await sendPrompt({ prompt, accessToken: token });
      setResponseText(text);
      setPhase("success");
    } catch (err) {
      const apiErr =
        err instanceof ApiError ? err : makeApiError("UNKNOWN");
      setError(apiErr.userMessage);
      setPhase("error");
      // On auth failure, stop and return to sign-in via the auth boundary.
      if (apiErr.kind === "AUTH") {
        void signOut();
      }
    }
  }

  return (
    <main className="workspace" id="main">
      <div className="workspace__header">
        <h1 className="workspace__title">Assistant workspace</h1>
        <p className="workspace__subtitle">
          Ask the AI Validator to scan or safely transfer data. Requests are
          handled conversationally.
        </p>
      </div>

      <ErrorBanner message={error} />

      <div className="workspace__grid">
        <PromptComposer
          onSubmit={handleSubmit}
          isLoading={phase === "loading"}
        />
        <ResponsePanel
          text={phase === "success" ? responseText : undefined}
          isLoading={phase === "loading"}
          prompt={phase === "success" ? lastPrompt ?? undefined : undefined}
        />
      </div>
    </main>
  );
}
