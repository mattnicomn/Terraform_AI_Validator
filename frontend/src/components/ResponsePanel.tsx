/**
 * ResponsePanel — renders the AI Validator response.
 *
 * SECURITY (Phase 5A decision): model output is UNTRUSTED and rendered as
 * PLAIN TEXT only. This component MUST NOT use dangerouslySetInnerHTML, raw
 * HTML injection, a Markdown renderer, or any HTML-parsing library. React's
 * default text rendering escapes content; `white-space: pre-wrap` preserves
 * formatting without interpreting markup.
 *
 * V1 shows the most recent turn only (optional prompt echo + response).
 */

export interface ResponsePanelProps {
  /** Completed response text. Empty/undefined shows the empty state. */
  text?: string;
  /** Optional echo of the prompt that produced `text` (plain text). */
  prompt?: string;
  /** Loading state (submit -> loading -> complete). */
  isLoading?: boolean;
}

export function ResponsePanel({ text, prompt, isLoading }: ResponsePanelProps) {
  if (isLoading) {
    return (
      <section className="response-panel" aria-busy="true" aria-live="polite">
        <p className="response-panel__loading">Working on it…</p>
      </section>
    );
  }

  if (!text) {
    return (
      <section className="response-panel response-panel--empty" aria-live="polite">
        <p className="response-panel__empty">
          Responses will appear here after you send a prompt.
        </p>
      </section>
    );
  }

  // Plain-text rendering only. Values are inserted as text nodes (escaped).
  return (
    <section className="response-panel" aria-live="polite">
      {prompt && (
        <div className="response-panel__turn">
          <p className="response-panel__role">You</p>
          <p className="response-panel__text">{prompt}</p>
        </div>
      )}
      <div className="response-panel__turn">
        <p className="response-panel__role">AI Validator</p>
        <p className="response-panel__text">{text}</p>
      </div>
    </section>
  );
}
