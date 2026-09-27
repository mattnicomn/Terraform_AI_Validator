import { useState, type FormEvent } from "react";

/**
 * PromptComposer — prompt input + submit.
 *
 * The component owns the input text and trimming/empty-guard. It does NOT call
 * the API directly; it invokes `onSubmit(prompt)` and the parent (Workspace)
 * performs the request. Submit is disabled while loading and for empty/
 * whitespace-only input, which prevents duplicate submissions.
 */

export interface PromptComposerProps {
  onSubmit: (prompt: string) => void;
  isLoading?: boolean;
}

export function PromptComposer({ onSubmit, isLoading }: PromptComposerProps) {
  const [prompt, setPrompt] = useState("");

  const trimmed = prompt.trim();
  const canSubmit = trimmed.length > 0 && !isLoading;

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canSubmit) {
      return; // guard: empty/whitespace or already loading
    }
    onSubmit(trimmed);
  }

  return (
    <form className="composer" onSubmit={handleSubmit} noValidate>
      <label className="composer__label" htmlFor="prompt-input">
        Ask the AI Validator
      </label>
      <textarea
        id="prompt-input"
        className="composer__textarea"
        name="prompt"
        rows={5}
        value={prompt}
        disabled={isLoading}
        placeholder="e.g. Scan object reports/q3.csv in the source bucket for sensitive data."
        onChange={(e) => setPrompt(e.target.value)}
      />
      <div className="composer__actions">
        <button type="submit" className="btn btn--primary" disabled={!canSubmit}>
          {isLoading ? "Working…" : "Submit"}
        </button>
      </div>
    </form>
  );
}
