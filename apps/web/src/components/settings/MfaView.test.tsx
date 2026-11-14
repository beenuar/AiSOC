/**
 * The console's second-factor page, depth 8.1.
 *
 * Two things are asserted and neither is cosmetic.
 *
 * **Every control performs a real action.** The role buttons are the kind
 * of surface this repository has shipped as a toast and nothing else, so
 * each one is clicked and the resulting request body is read. A button
 * that flipped only local state would pass a render test and change
 * nothing on the server.
 *
 * **Clearing a role actually clears it.** The policy write replaces the
 * role set rather than merging into it, and a merge is the easy mistake:
 * the page would be able to add a requirement and never remove one, so an
 * administrator would believe they had turned something off.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { mfaApi } from "@/lib/api";
import { MfaView } from "./MfaView";

const status = vi.fn();
const setPolicy = vi.fn();
const registerBegin = vi.fn();

vi.mock("@/lib/api", () => ({
  mfaApi: {
    status: (...args: unknown[]) => status(...args),
    setPolicy: (...args: unknown[]) => setPolicy(...args),
    enrollBegin: vi.fn(),
    enrollConfirm: vi.fn(),
    disable: vi.fn(),
  },
  passkeyApi: {
    registerBegin: (...args: unknown[]) => registerBegin(...args),
    registerFinish: vi.fn(),
  },
}));

vi.mock("@/lib/responder/webauthn", () => ({
  createPasskey: vi.fn(async () => ({ id: "c" })),
  isWebAuthnSupported: () => true,
}));

function aStatus(overrides: Record<string, unknown> = {}) {
  return {
    enrolled: false,
    tenant_requires_totp: false,
    recovery_codes_remaining: 0,
    has_totp: false,
    has_webauthn: false,
    require_for_roles: [],
    required_for_me: false,
    ...overrides,
  };
}

describe("MfaView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    status.mockResolvedValue(aStatus());
    setPolicy.mockResolvedValue({ require_totp: false, require_for_roles: [] });
  });

  it("sends a real policy write when a role is selected", async () => {
    render(<MfaView />);
    await waitFor(() => expect(status).toHaveBeenCalled());

    await userEvent.click(await screen.findByRole("button", { name: /soc analyst/i }));

    await waitFor(() => expect(setPolicy).toHaveBeenCalledWith(false, ["soc_analyst"]));
  });

  it("removes a role rather than merging it back in", async () => {
    status.mockResolvedValue(aStatus({ require_for_roles: ["soc_analyst", "viewer"] }));
    render(<MfaView />);
    await waitFor(() => expect(status).toHaveBeenCalled());

    await userEvent.click(await screen.findByRole("button", { name: /soc analyst/i }));

    await waitFor(() => expect(setPolicy).toHaveBeenCalledWith(false, ["viewer"]));
  });

  it("keeps the tenant-wide switch when only a role changes", async () => {
    status.mockResolvedValue(aStatus({ tenant_requires_totp: true }));
    render(<MfaView />);
    await waitFor(() => expect(status).toHaveBeenCalled());

    await userEvent.click(await screen.findByRole("button", { name: /threat hunter/i }));

    // `true`, not `false`. Sending the toggle's own default here would
    // silently turn tenant-wide enforcement off as a side effect of
    // editing a role.
    await waitFor(() => expect(setPolicy).toHaveBeenCalledWith(true, ["threat_hunter"]));
  });

  it("reports a selected role to assistive technology", async () => {
    status.mockResolvedValue(aStatus({ require_for_roles: ["viewer"] }));
    render(<MfaView />);

    const selected = await screen.findByRole("button", { name: /viewer/i });
    expect(selected).toHaveAttribute("aria-pressed", "true");
    expect(await screen.findByRole("button", { name: /threat hunter/i })).toHaveAttribute(
      "aria-pressed",
      "false"
    );
  });

  it("starts a real registration when a security key is added", async () => {
    registerBegin.mockResolvedValue({ publicKey: {}, challenge: "ch", device_name_default: "k" });
    render(<MfaView />);
    await waitFor(() => expect(status).toHaveBeenCalled());

    await userEvent.click(await screen.findByRole("button", { name: /add a security key/i }));

    await waitFor(() => expect(registerBegin).toHaveBeenCalled());
  });

  it("offers no role the console cannot assign", async () => {
    render(<MfaView />);
    await waitFor(() => expect(status).toHaveBeenCalled());

    // `admin` and `platform_admin` carry the wildcard permission and are
    // unreachable from every tenant-scoped route. Listing either would
    // tell an administrator they can reach something they cannot.
    expect(screen.queryByRole("button", { name: /^platform admin$/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /^admin$/i })).toBeNull();
  });

  it("enrolment walks begin → secret shown → confirm → recovery codes shown once", async () => {
    status.mockResolvedValue(aStatus());
    vi.mocked(mfaApi.enrollBegin).mockResolvedValue({
      secret: "JBSWY3DPEHPK3PXP",
      otpauth_uri: "otpauth://totp/AiSOC:alice?secret=JBSWY3DPEHPK3PXP",
    });
    vi.mocked(mfaApi.enrollConfirm).mockResolvedValue({
      recovery_codes: ["aaaa-bbbb", "cccc-dddd"],
    });
    const user = userEvent.setup();
    render(<MfaView />);
    await user.click(await screen.findByRole("button", { name: "Set up" }));

    // The shared secret is rendered for the authenticator, then the code
    // the app shows is what confirms — not the secret itself.
    expect(await screen.findByText("JBSWY3DPEHPK3PXP")).toBeInTheDocument();
    await user.type(screen.getByPlaceholderText("123456"), "000000");
    await user.click(screen.getByRole("button", { name: "Confirm" }));

    expect(vi.mocked(mfaApi.enrollConfirm)).toHaveBeenCalledWith("000000");
    expect(await screen.findByText(/Save these recovery codes/)).toBeInTheDocument();
    expect(screen.getByText("aaaa-bbbb")).toBeInTheDocument();
  });

  it("removing the factor requires a current code and sends it", async () => {
    status.mockResolvedValue(aStatus({ enrolled: true, has_totp: true, recovery_codes_remaining: 7 }));
    vi.mocked(mfaApi.disable).mockResolvedValue(undefined as never);
    const user = userEvent.setup();
    render(<MfaView />);

    expect(await screen.findByText(/7 recovery codes left/)).toBeInTheDocument();
    const remove = screen.getByRole("button", { name: "Remove" });
    // No code, no removal: a stolen session cannot strip the factor.
    expect(remove).toBeDisabled();
    await user.type(screen.getByPlaceholderText("Code or recovery code"), "11112222");
    await user.click(remove);
    await waitFor(() => expect(vi.mocked(mfaApi.disable)).toHaveBeenCalledWith("11112222"));
  });

  it("a refused confirmation surfaces an actionable alert, not silence", async () => {
    status.mockResolvedValue(aStatus());
    vi.mocked(mfaApi.enrollBegin).mockResolvedValue({ secret: "S", otpauth_uri: "otpauth://x" });
    vi.mocked(mfaApi.enrollConfirm).mockRejectedValue(new Error("422"));
    const user = userEvent.setup();
    render(<MfaView />);
    await user.click(await screen.findByRole("button", { name: "Set up" }));
    await user.type(await screen.findByPlaceholderText("123456"), "999999");
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    // The component deliberately translates the refusal into what to do
    // about it — the clock hint — rather than echoing a bare status.
    expect(await screen.findByRole("alert")).toHaveTextContent(/That code is not valid/);
  });
});
