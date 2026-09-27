import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * promptClient tests — all HTTP is mocked; no real network.
 *
 * config is mocked so we control VITE_API_BASE_URL (present vs missing).
 */

const { mockConfig } = vi.hoisted(() => ({
  mockConfig: { apiBaseUrl: "https://api.example.test/" } as { apiBaseUrl: string },
}));
vi.mock("../config", () => ({ config: mockConfig }));

import { sendPrompt, buildPromptUrl } from "../api/promptClient";
import { ApiError } from "../api/types";

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  } as unknown as Response;
}

function badJsonResponse(status: number): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.reject(new SyntaxError("Unexpected token")),
  } as unknown as Response;
}

beforeEach(() => {
  mockConfig.apiBaseUrl = "https://api.example.test/";
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe("buildPromptUrl", () => {
  it("joins base and path without double slashes", () => {
    expect(buildPromptUrl("https://api.example.test/")).toBe(
      "https://api.example.test/BedrockPromptHandler",
    );
    expect(buildPromptUrl("https://api.example.test")).toBe(
      "https://api.example.test/BedrockPromptHandler",
    );
    expect(buildPromptUrl("https://api.example.test///")).toBe(
      "https://api.example.test/BedrockPromptHandler",
    );
  });
});

describe("sendPrompt — request shape", () => {
  it("POSTs to the correct URL with JSON + bearer token and exact body", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(jsonResponse(200, { response: "ok" }));

    const text = await sendPrompt({ prompt: "hi", accessToken: "TOKEN123" });
    expect(text).toBe("ok");

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe("https://api.example.test/BedrockPromptHandler");
    expect(init?.method).toBe("POST");
    const headers = init?.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/json");
    expect(headers["Authorization"]).toBe("Bearer TOKEN123");
    expect(init?.body).toBe(JSON.stringify({ prompt: "hi" }));
  });
});

describe("sendPrompt — status mapping", () => {
  const cases: Array<[number, string]> = [
    [400, "VALIDATION"],
    [401, "AUTH"],
    [403, "AUTH"],
    [502, "UPSTREAM_AI"],
    [500, "SERVER"],
    [418, "UNKNOWN"],
  ];
  for (const [status, kind] of cases) {
    it(`maps HTTP ${status} -> ${kind}`, async () => {
      vi.spyOn(globalThis, "fetch").mockResolvedValue(
        jsonResponse(status, { error: "x" }),
      );
      await expect(
        sendPrompt({ prompt: "hi", accessToken: "T" }),
      ).rejects.toMatchObject({ kind });
    });
  }

  it("maps network/fetch rejection -> NETWORK", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("failed"));
    await expect(
      sendPrompt({ prompt: "hi", accessToken: "T" }),
    ).rejects.toMatchObject({ kind: "NETWORK" });
  });

  it("maps malformed 200 JSON -> UNKNOWN", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(badJsonResponse(200));
    await expect(
      sendPrompt({ prompt: "hi", accessToken: "T" }),
    ).rejects.toMatchObject({ kind: "UNKNOWN" });
  });

  it("maps 200 with non-string response -> UNKNOWN", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse(200, { response: 123 }),
    );
    await expect(
      sendPrompt({ prompt: "hi", accessToken: "T" }),
    ).rejects.toMatchObject({ kind: "UNKNOWN" });
  });
});

describe("sendPrompt — configuration guard", () => {
  it("throws CONFIGURATION and does not fetch when API base URL is missing", async () => {
    mockConfig.apiBaseUrl = "";
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    await expect(
      sendPrompt({ prompt: "hi", accessToken: "T" }),
    ).rejects.toMatchObject({ kind: "CONFIGURATION" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("ApiError", () => {
  it("carries a safe user message and never the raw server body", () => {
    const err = new ApiError("SERVER", "AI Validator encountered an error. Try again.");
    expect(err.userMessage).toContain("encountered an error");
    expect(err.userMessage).not.toContain("stack");
  });
});
