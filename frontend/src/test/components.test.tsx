import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { ResponsePanel } from "../components/ResponsePanel";
import { PromptComposer } from "../components/PromptComposer";

describe("ResponsePanel — plain-text rendering", () => {
  it("renders provided text as escaped text, not HTML", () => {
    const payload = "<script>alert(1)</script> plain output";
    const { container } = render(<ResponsePanel text={payload} />);
    expect(screen.getByText(/plain output/)).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
  });

  it("shows an empty state when no text is provided", () => {
    render(<ResponsePanel />);
    expect(screen.getByText(/responses will appear here/i)).toBeInTheDocument();
  });
});

describe("PromptComposer", () => {
  it("does not fetch directly and calls onSubmit with the trimmed prompt", () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(() => {
      throw new Error("composer must not fetch directly");
    });
    const onSubmit = vi.fn();
    render(<PromptComposer onSubmit={onSubmit} />);
    fireEvent.change(screen.getByLabelText(/ask the ai validator/i), {
      target: { value: "  scan a file  " },
    });
    fireEvent.click(screen.getByRole("button", { name: /submit/i }));
    expect(onSubmit).toHaveBeenCalledWith("scan a file");
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("does not call onSubmit for whitespace-only input", () => {
    const onSubmit = vi.fn();
    render(<PromptComposer onSubmit={onSubmit} />);
    fireEvent.change(screen.getByLabelText(/ask the ai validator/i), {
      target: { value: "   " },
    });
    // Submit button is disabled; attempting form submit is a no-op.
    fireEvent.click(screen.getByRole("button", { name: /submit/i }));
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("disables submit while loading (prevents duplicate submit)", () => {
    const onSubmit = vi.fn();
    render(<PromptComposer onSubmit={onSubmit} isLoading />);
    fireEvent.change(screen.getByLabelText(/ask the ai validator/i), {
      target: { value: "hello" },
    });
    fireEvent.click(screen.getByRole("button", { name: /working/i }));
    expect(onSubmit).not.toHaveBeenCalled();
  });
});
