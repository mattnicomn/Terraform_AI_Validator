import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

/**
 * All auth tests are LOCAL and MOCKED. The auth manager (the only module that
 * touches oidc-client-ts) is mocked, so no Cognito network access occurs and
 * no real tokens are created. The application API is never called.
 */

// A controllable fake "User" (subset used by the provider).
interface FakeUser {
  access_token: string;
  expired: boolean;
  profile: Record<string, unknown>;
}

// Hoisted so the vi.mock factory (also hoisted) can safely reference them.
const {
  mockBeginSignIn,
  mockBeginSignOut,
  mockCompleteSignIn,
  mockLoadUser,
  mockSigninSilent,
  listeners,
} = vi.hoisted(() => ({
  mockBeginSignIn: vi.fn(() => Promise.resolve()),
  mockBeginSignOut: vi.fn(() => Promise.resolve()),
  mockCompleteSignIn: vi.fn(),
  mockLoadUser: vi.fn(),
  mockSigninSilent: vi.fn(),
  listeners: {
    loaded: [] as Array<(u: unknown) => void>,
    expired: [] as Array<() => void>,
    signedOut: [] as Array<() => void>,
  },
}));

vi.mock("../auth/authManager", () => {
  return {
    getUserManager: () => ({
      events: {
        addUserLoaded: (cb: (u: unknown) => void) => listeners.loaded.push(cb),
        removeUserLoaded: () => {},
        addAccessTokenExpired: (cb: () => void) => listeners.expired.push(cb),
        removeAccessTokenExpired: () => {},
        addUserSignedOut: (cb: () => void) => listeners.signedOut.push(cb),
        removeUserSignedOut: () => {},
      },
      signinSilent: mockSigninSilent,
    }),
    beginSignIn: mockBeginSignIn,
    beginSignOut: mockBeginSignOut,
    completeSignIn: mockCompleteSignIn,
    loadUser: mockLoadUser,
    toAuthUser: (u: FakeUser | null) => {
      if (!u) return null;
      const email =
        typeof u.profile.email === "string" ? u.profile.email : undefined;
      const preferred =
        typeof u.profile.preferred_username === "string"
          ? u.profile.preferred_username
          : undefined;
      return { username: email ?? preferred ?? "Signed in", email };
    },
    isUserValid: (u: FakeUser | null) => !!u && !u.expired,
  };
});

// Imported AFTER the mock is declared.
import App from "../App";
import { AuthProvider, useAuth } from "../auth/AuthProvider";

function authedUser(profile: Record<string, unknown> = { email: "user@example.com" }): FakeUser {
  return { access_token: "AT_SECRET_VALUE", expired: false, profile };
}

function renderApp(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  listeners.loaded.length = 0;
  listeners.expired.length = 0;
  listeners.signedOut.length = 0;
  mockLoadUser.mockResolvedValue(null); // default: unauthenticated
});

// ---- Landing / sign-in ------------------------------------------------------
describe("Landing sign-in", () => {
  it("renders Landing and initiates the auth adapter on Sign in", async () => {
    renderApp("/");
    const btn = await screen.findByRole("button", { name: /sign in/i });
    expect(btn).toBeEnabled();
    fireEvent.click(btn);
    await waitFor(() => expect(mockBeginSignIn).toHaveBeenCalledTimes(1));
  });
});

// ---- Callback ---------------------------------------------------------------
describe("Callback", () => {
  it("on success establishes authenticated state and routes to /app", async () => {
    const user = authedUser();
    mockCompleteSignIn.mockResolvedValue(user);
    // Represent an established session: the manager now returns the user, so
    // when the guard re-checks after navigation the route is authenticated.
    mockLoadUser.mockResolvedValue(user);

    renderApp("/callback");

    await waitFor(() => expect(mockCompleteSignIn).toHaveBeenCalledTimes(1));
    // The manager fires userLoaded post-exchange.
    listeners.loaded.forEach((cb) => cb(user));

    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: /assistant workspace/i }),
      ).toBeInTheDocument(),
    );
  });

  it("on failure shows a safe error and does not leak details", async () => {
    mockCompleteSignIn.mockRejectedValue(
      new Error("authorization_code=abc123&access_token=leaky"),
    );
    const { container } = renderApp("/callback");
    await waitFor(() =>
      expect(screen.getByText(/sign-in failed/i)).toBeInTheDocument(),
    );
    // No code/token leaked into the DOM.
    expect(container.innerHTML).not.toContain("abc123");
    expect(container.innerHTML).not.toContain("leaky");
  });
});

// ---- Protected routes -------------------------------------------------------
describe("AuthGuard", () => {
  it("redirects unauthenticated /app access to Landing", async () => {
    mockLoadUser.mockResolvedValue(null);
    renderApp("/app");
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { level: 1, name: /ai validator/i }),
      ).toBeInTheDocument(),
    );
    expect(
      screen.queryByRole("heading", { name: /assistant workspace/i }),
    ).not.toBeInTheDocument();
  });

  it("renders Workspace when authenticated", async () => {
    mockLoadUser.mockResolvedValue(authedUser());
    renderApp("/app");
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: /assistant workspace/i }),
      ).toBeInTheDocument(),
    );
  });

  it("renders Account when authenticated and shows safe identity", async () => {
    mockLoadUser.mockResolvedValue(authedUser({ email: "person@example.com" }));
    renderApp("/account");
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: /account/i }),
      ).toBeInTheDocument(),
    );
    // Identity appears both in the AppBar and the Account definition list.
    expect(screen.getAllByText("person@example.com").length).toBeGreaterThan(0);
  });
});

// ---- Sign-out ---------------------------------------------------------------
describe("Sign out", () => {
  it("calls the auth adapter signOut", async () => {
    mockLoadUser.mockResolvedValue(authedUser());
    renderApp("/account");
    const buttons = await screen.findAllByRole("button", { name: /sign out/i });
    fireEvent.click(buttons[0]);
    await waitFor(() => expect(mockBeginSignOut).toHaveBeenCalledTimes(1));
  });
});

// ---- Expiry -----------------------------------------------------------------
describe("Session expiry", () => {
  it("clears the session on token expiry when renewal fails", async () => {
    mockLoadUser.mockResolvedValue(authedUser());
    mockSigninSilent.mockRejectedValue(new Error("no refresh"));
    renderApp("/account");
    await waitFor(() =>
      expect(screen.getAllByText(/user@example.com/i).length).toBeGreaterThan(0),
    );
    // Fire the accessTokenExpired event; renewal rejects -> session cleared.
    listeners.expired.forEach((cb) => cb());
    await waitFor(() =>
      // Guard redirects to Landing once unauthenticated.
      expect(
        screen.getByRole("heading", { level: 1, name: /ai validator/i }),
      ).toBeInTheDocument(),
    );
  });
});

// ---- Token / API safety -----------------------------------------------------
describe("Token and API safety", () => {
  it("does not render any token value into the DOM", async () => {
    mockLoadUser.mockResolvedValue(authedUser());
    const { container } = renderApp("/account");
    await waitFor(() =>
      expect(screen.getAllByText(/user@example.com/i).length).toBeGreaterThan(0),
    );
    expect(container.innerHTML).not.toContain("AT_SECRET_VALUE");
  });

  it("makes no application API network call during auth", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(() => {
        throw new Error("no network in 5C");
      });
    mockLoadUser.mockResolvedValue(authedUser());
    renderApp("/app");
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: /assistant workspace/i }),
      ).toBeInTheDocument(),
    );
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("exposes getAccessToken through the auth layer", async () => {
    mockLoadUser.mockResolvedValue(authedUser());
    let token: string | null = "unset";
    function Probe(): ReactNode {
      const { getAccessToken, isAuthenticated } = useAuth();
      if (isAuthenticated) token = getAccessToken();
      return null;
    }
    render(
      <MemoryRouter>
        <AuthProvider>
          <Probe />
        </AuthProvider>
      </MemoryRouter>,
    );
    await waitFor(() => expect(token).toBe("AT_SECRET_VALUE"));
  });
});

// Workspace API integration is covered in workspace.test.tsx (Phase 5D).
