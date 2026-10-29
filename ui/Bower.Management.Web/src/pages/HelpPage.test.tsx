import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthenticationProvider } from "../auth";
import { HelpPage } from "./HelpPage";
import { GlossaryText, glossary } from "../components/glossary";

function response(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status }); }
function progress(state = "not-started", mode: string | null = null) {
  return { canChange: false, steps: [
    { id: "sign-in", state: "complete" }, { id: "destination", state }, { id: "proof", state }
  ], latestRun: mode ? { mode } : null };
}
function show(path = "/help") {
  return render(<AuthenticationProvider><MemoryRouter initialEntries={[path]}><HelpPage /></MemoryRouter></AuthenticationProvider>);
}
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("Local help and real setup progress", () => {
  it("loads server state on each visit and deep-links to the chosen step", async () => {
    const fetch = vi.fn().mockResolvedValueOnce(response(progress())).mockResolvedValueOnce(response(progress("complete", "verified")));
    vi.stubGlobal("fetch", fetch);
    let page = show();
    const checklist = within(screen.getByRole("region", { name: "Setup checklist" }));
    expect(await checklist.findByText("Viewing only. Ask a Bower administrator to complete the remaining steps.")).toBeTruthy();
    expect(checklist.getAllByText("Not started")).toHaveLength(2);
    expect(checklist.getByRole("link", { name: "Choose where events go" }).getAttribute("href")).toBe("/setup?step=destination");
    page.unmount(); page = show();
    await waitFor(() => expect(within(screen.getByRole("region", { name: "Setup checklist" })).getAllByText("Done")).toHaveLength(3));
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls.every(call => call[1].method === undefined || call[1].method === "GET")).toBe(true);
  });

  it("keeps a failed refresh visibly stale and recovers with updated server progress", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(response(progress()))
      .mockResolvedValueOnce(response({}, 503)).mockResolvedValueOnce(response(progress("complete", "verified"))));
    show();
    await screen.findByText(/Viewing only/);
    fireEvent.click(screen.getByRole("button", { name: "Refresh progress" }));
    expect(await screen.findByText(/Showing the last loaded progress; it may be out of date/)).toBeTruthy();
    expect(screen.getAllByText("Not started")).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "Refresh progress" }));
    await waitFor(() => expect(screen.queryByText(/Could not refresh setup progress/)).toBeNull());
    expect(screen.getAllByText("Done")).toHaveLength(3);
  });

  it("labels simulated proof even when the supplied step says complete", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(progress("complete", "simulated"))));
    show();
    expect(await screen.findByText("Simulated, not proof")).toBeTruthy();
    expect(screen.getAllByText("Done")).toHaveLength(2);
  });

  it.each([401, 403, 503])("keeps local help available when setup returns %s and supports retry", async status => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(response({}, status)).mockResolvedValueOnce(response(progress())));
    show();
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Glossary" })).toBeTruthy();
    expect(screen.queryByText("Done")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Refresh progress" }));
    expect(await screen.findByText("Done")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows loading and explains a genuinely empty response without inventing completion", async () => {
    let resolve!: (value: Response) => void;
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(done => { resolve = done; })));
    show();
    expect(screen.getByLabelText("Loading")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Glossary" })).toBeTruthy();
    await waitFor(() => expect(resolve).toBeTypeOf("function"));
    await act(async () => resolve(response({ canChange: false, steps: [], latestRun: null })));
    expect(await screen.findByText(/No setup steps were returned/)).toBeTruthy();
    expect(screen.queryByText("Done")).toBeNull();
  });

  it("focuses linked terms and tolerates a malformed fragment", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(() => Promise.resolve(response(progress()))));
    let page = show("/help#dcr");
    expect(document.activeElement?.id).toBe("dcr");
    page.unmount(); page = show("/help#%broken");
    expect(screen.getByRole("heading", { name: /^Help$/ })).toBeTruthy();
    await screen.findByText(/Viewing only/);
  });
});

describe("Glossary tooltips", () => {
  it("explains the required concepts on focus, dismisses with Escape and retains touch links", () => {
    render(<MemoryRouter><GlossaryText text="DCR pack policy redaction canary collector" /></MemoryRouter>);
    for (const term of ["DCR", "pack", "policy", "redaction", "canary", "collector"]) {
      const link = screen.getByRole("link", { name: term });
      fireEvent.focus(link);
      const tooltip = screen.getByRole("tooltip");
      expect(link.getAttribute("aria-describedby")).toBe(tooltip.id);
      expect(link.getAttribute("href")).toBe(`/help#${term.toLowerCase()}`);
      fireEvent.keyDown(window, { key: "Escape" });
      expect(screen.queryByRole("tooltip")).toBeNull();
    }
    expect(new Set(glossary.map(entry => entry.id)).size).toBe(glossary.length);
  });

  it("shows help on hover and escapes text without matching fragments inside words", () => {
    render(<MemoryRouter><GlossaryText text={'<script>collector collector collection packaging</script>'} /></MemoryRouter>);
    expect(screen.getAllByRole("link")).toHaveLength(1);
    const link = screen.getByRole("link");
    fireEvent.mouseEnter(link);
    expect(screen.getByRole("tooltip")).toBeTruthy();
    fireEvent.mouseLeave(link.parentElement!);
    expect(screen.queryByRole("tooltip")).toBeNull();
    expect(document.querySelector("script")).toBeNull();
  });
});
