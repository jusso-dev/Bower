import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GuidedPrivacyEditor } from "./GuidedPrivacyEditor";

const api = vi.hoisted(() => vi.fn());
vi.mock("../api", () => ({ useApi: () => api }));

const initial = "metadata:\n  id: example\n  version: 1.0.0\n";
const result = {
  form: { id: "example", version: "1.0.0", description: "Security fields", fields: [] },
  content: "metadata:\n  id: example\n  version: 1.0.1\nfields: []\n",
  validation: { valid: true, errors: [] },
  preview: { valid: true, redacted: '{"actor":{"username":"[REDACTED]"}}', findings: [], errors: [] }
};

function mount() {
  const submitted = vi.fn();
  render(<GuidedPrivacyEditor initialContent={initial} basedOn="example@1.0.0" onCancel={vi.fn()} onSubmitted={submitted} />);
  return submitted;
}

afterEach(() => { cleanup(); api.mockReset(); });

describe("Guided privacy editor", () => {
  it("reviews a field action and submits exactly the server-generated YAML", async () => {
    api.mockResolvedValueOnce(result).mockResolvedValueOnce(result).mockResolvedValueOnce({ id: "created" });
    const submitted = mount();
    fireEvent.change(await screen.findByLabelText("New version"), { target: { value: "1.0.1" } });
    fireEvent.click(screen.getByRole("button", { name: "Add a field" }));
    fireEvent.change(screen.getByLabelText("Field path"), { target: { value: "actor.username" } });
    fireEvent.change(screen.getByLabelText("How to protect it"), { target: { value: "hmac" } });
    fireEvent.click(screen.getByRole("button", { name: "Review changes" }));
    expect(await screen.findByLabelText("Protected privacy example")).toBeTruthy();
    expect(JSON.parse(api.mock.calls[1]![1].body).form.fields).toEqual([{ path: "actor.username", action: "hmac", maxLength: null }]);
    expect(screen.getByRole("region", { name: "Line diff" })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Why this change is needed"), { target: { value: "Protect usernames" } });
    fireEvent.click(screen.getByRole("button", { name: "Ask another person to approve" }));
    await waitFor(() => expect(submitted).toHaveBeenCalledWith({ id: "created" }));
    expect(api.mock.calls[2]![0]).toBe("/api/privacy-profiles");
    expect(JSON.parse(api.mock.calls[2]![1].body)).toEqual({ content: result.content, changeSummary: "Protect usernames" });
  });

  it("ignores a delayed review if the form changed while checking", async () => {
    let finish!: (value: typeof result) => void;
    api.mockResolvedValueOnce(result).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    mount();
    await screen.findByLabelText("New version");
    fireEvent.click(screen.getByRole("button", { name: "Review changes" }));
    fireEvent.change(screen.getByLabelText("New version"), { target: { value: "2.0.0" } });
    await act(async () => finish(result));
    expect(screen.queryByRole("region", { name: "Review privacy changes" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Ask another person to approve" })).toBeNull();
  });

  it("retains the error and allows retry when opening fails", async () => {
    api.mockRejectedValueOnce(new Error("Unavailable")).mockResolvedValueOnce(result);
    mount();
    expect(await screen.findByRole("alert")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Retry opening profile" }));
    expect(await screen.findByLabelText("Profile name")).toBeTruthy();
  });

  it("requires valid server checks and protected preview before submission", async () => {
    api.mockResolvedValueOnce(result).mockResolvedValueOnce({ ...result, validation: { valid: false, errors: ["Raise the version."] }, preview: { valid: false, redacted: null } });
    mount();
    await screen.findByLabelText("New version");
    fireEvent.click(screen.getByRole("button", { name: "Review changes" }));
    await screen.findByText("Raise the version.");
    fireEvent.change(screen.getByLabelText("Why this change is needed"), { target: { value: "Needs review" } });
    expect((screen.getByRole("button", { name: "Ask another person to approve" }) as HTMLButtonElement).disabled).toBe(true);
  });
});
