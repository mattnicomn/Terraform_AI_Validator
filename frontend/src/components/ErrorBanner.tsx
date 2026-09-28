/**
 * ErrorBanner — accessible error/status surface.
 * Renders text content only (no HTML injection).
 */
export function ErrorBanner({ message }: { message: string | null }) {
  if (!message) {
    return null;
  }
  return (
    <div className="error-banner" role="alert">
      {message}
    </div>
  );
}
