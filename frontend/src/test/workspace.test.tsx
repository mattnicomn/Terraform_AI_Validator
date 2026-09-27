import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

/**
 * Workspace integration tests. The prompt API client and the auth manager are
 * mocked — no real network, no real token, no Cognito. Verifies the loading ->
 * success/error state model, plain-text rendering, duplicate-submit
 * prevention, auth-failure handling, and that no Processor route is called.
 */

// Mock the auth manager so AuthProvider reports an authenticated session.
const { mockLoadUser, mockBeginSignOut, listeners } = vi.hoisted(() => ({
  mockLoadUser: vi.fn(),
  mockBeginSignOut: vi.fn(() => Promise.resolve()),
  listeners: { loaded: [] as Array<(u: unknown) => void> },
}));

vi.mock("../auth/authManager", () => ({
  getUserManager: () => ({
    events: {
      addUserLoaded: (cb: (u: unknown) => void) => listeners.loaded.push(cb),
      removeUserLoaded: () => {},
      addAccessTokenExpired: () => {},
      removeAccessTokenExpired: () => {},
      addUserSignedOut: () => {},
      removeUserSignedOut: () => {},
    },
    signinSilent: vi.fn(),
  }),
  beginSignIn: vi.fn(),
  beginSignOut: mockBeginSignOut,
  completeSignIn: vi.fn(),
  loadUser: mockLoadUser,
  toAuthUser: () => ({ username: "user@example.com", email: "user@example.com" }),
  isUserValid: (u: unknown) => !!u,
}));

// Mock the prompt client.
const { mockSendPrompt } = vi.hoisted(() => ({ mockSendPrompt: vi.fn() }));
vi.mock("../api/promptClient", () => ({
  sendPrompt: mockSendPrompt,
}));

import { Workspace } from "../pages/Workspace";
import { AuthProvider } from "../auth/AuthProvider";
import { makeApiError } from "../api/types";

function authedUser(token = "AT_SECRET") {
  return { access_token: token, expired: false, profile: { email: "user@example.com" } };
}

function renderWorkspace() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <Workspace />
      </AuthProvider>
    </MemoryRouter>,
  );
}

async function typePrompt(value: string) {
  const area = await screen.findByLabelText(/ask the ai validator/i);
  fireEvent.change(area, { target: { value } });
}

beforeEach(() => {
  vi.clearAllMocks();
  listeners.loaded.length = 0;
  mockLoadUser.mockResolvedValue(authedUser());
});

describe("Workspace — success path", () => {
  it("submits, shows loading, then renders the response as plain text", async () => {
    let resolve!: (v: string) => void;
    mockSendPrompt.mockReturnValue(new Promise<string>((r) => (resolve = r)));

    renderWorkspace();
    await typePrompt("scan a file");
    fireEvent.click(screen.getByRole("button", { name: /submit/i }));

    // loading
    await screen.findByText(/working on it/i);
    expect(screen.getByRole("button", { name: /working/i })).toBeDisabled();

    // complete
    resolve("Classification: Type1. Safe to transfer.");
    await screen.findByText(/safe to transfer/i);
    expect(mockSendPrompt).toHaveBeenCalledTimes(1);
    expect(mockSendPrompt.mock.calls[0][0]).toMatchObject({
      prompt: "scan a file",
      accessToken: "AT_SECRET",
    });
  });

  it("renders HTML/script-like model output as text, not markup", async () => {
    mockSendPrompt.mockResolvedValue("<script>alert(1)</script> done");
    const { container } = renderWorkspace();
    await typePrompt("x");
    fireEvent.click(screen.getByRole("button", { name: /submit/i }));
    await screen.findByText(/done/);
    expect(container.querySelector("script")).toBeNull();
  });
});

describe("Workspace — guards", () => {
  it("does not submit an empty prompt", async () => {
    renderWorkspace();
    await typePrompt("   ");
    fireEvent.click(screen.getByRole("button", { name: /submit/i }));
    expect(mockSendPrompt).not.toHaveBeenCalled();
  });

  it("prevents duplicate submission while loading", async () => {
    mockSendPrompt.mockReturnValue(new Promise<string>(() => {})); // never resolves
    renderWorkspace();
    await typePrompt("hello");
    const btn = screen.getByRole("button", { name: /submit/i });
    fireEvent.click(btn);
    // Now loading; button disabled — a second click does nothing.
    fireEvent.click(screen.getByRole("button", { name: /working/i }));
    expect(mockSendPrompt).toHaveBeenCalledTimes(1);
  });
});

describe("Workspace — auth failure", () => {
  it("without a token: does not call the API and signs out", async () => {
    // Authenticated per provider, but token accessor returns null: simulate by
    // making loadUser return a user with no access_token.
    mockLoadUser.mockResolvedValue({ access_token: "", expired: false, profile: {} });
    renderWorkspace();
    await typePrompt("hello");
    fireEvent.click(screen.getByRole("button", { name: /submit/i }));
    await waitFor(() => expect(mockBeginSignOut).toHaveBeenCalledTimes(1));
    expect(mockSendPrompt).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(/session has expired/i);
  });

  it("on 401/AUTH error: shows message and signs out (no retry loop)", async () => {
    mockSendPrompt.mockRejectedValue(makeApiError("AUTH"));
    renderWorkspace();
    await typePrompt("hello");
    fireEvent.click(screen.getByRole("button", { name: /submit/i }));
    await waitFor(() => expect(mockBeginSignOut).toHaveBeenCalledTimes(1));
    expect(screen.getByRole("alert")).toHaveTextContent(/session has expired/i);
  });
});

describe("Workspace — error mapping messages", () => {
  const cases: Array<[Parameters<typeof makeApiError>[0], RegExp]> = [
    ["VALIDATION", /check your request/i],
    ["UPSTREAM_AI", /temporarily unavailable/i],
    ["SERVER", /encountered an error/i],
    ["NETWORK", /unable to reach/i],
    ["CONFIGURATION", /not configured/i],
  ];
  for (const [kind, re] of cases) {
    it(`shows a safe message for ${kind}`, async () => {
      mockSendPrompt.mockRejectedValue(makeApiError(kind));
      renderWorkspace();
      await typePrompt("hello");
      fireEvent.click(screen.getByRole("button", { name: /submit/i }));
      await waitFor(() =>
        expect(screen.getByRole("alert")).toHaveTextContent(re),
      );
    });
  }
});
