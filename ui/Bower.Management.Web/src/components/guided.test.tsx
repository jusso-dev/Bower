import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CheckList, GuidedStep, PlainStatus, Stepper } from "./guided";

afterEach(cleanup);

describe("guided primitives", () => {
  it("states status in words, not colour alone", () => {
    render(
      <>
        <PlainStatus state="complete" />
        <PlainStatus state="attention" />
        <PlainStatus state="blocked" />
        <PlainStatus state="in-progress" label="Verified in Sentinel" />
      </>
    );

    expect(screen.getByText("Done")).toBeTruthy();
    expect(screen.getByText("Needs attention")).toBeTruthy();
    expect(screen.getByText("Waiting on earlier steps")).toBeTruthy();
    expect(screen.getByText("Verified in Sentinel")).toBeTruthy();
  });

  it("renders an ordered, keyboard-operable stepper with the current step marked", () => {
    const onSelect = vi.fn();
    render(
      <Stepper
        label="Setup steps"
        current="b"
        onSelect={onSelect}
        steps={[
          { id: "a", title: "Sign in", state: "complete" },
          { id: "b", title: "Choose where events go", state: "not-started" }
        ]}
      />
    );

    const nav = screen.getByRole("navigation", { name: "Setup steps" });
    const items = within(nav).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    const current = within(nav).getByRole("button", { name: /Step 2: Choose where events go/ });
    expect(current.getAttribute("aria-current")).toBe("step");
    const done = within(nav).getByRole("button", { name: "Step 1: Sign in, Done" });
    expect(done.getAttribute("aria-current")).toBeNull();
    expect(done.tagName).toBe("BUTTON");
    fireEvent.click(done);
    expect(onSelect).toHaveBeenCalledWith("a");
  });

  it("moves focus to the new step heading only when the step changes", () => {
    function Harness() {
      const [id, setId] = useState("one");
      return (
        <>
          <button type="button" onClick={() => setId("two")}>
            Change step
          </button>
          <GuidedStep id={id} number={1} total={2} title={`Step ${id}`} state="complete" why="Because.">
            <p>Body</p>
          </GuidedStep>
        </>
      );
    }
    render(<Harness />);
    expect(document.activeElement).toBe(document.body);
    expect(screen.getByText("Why this matters:")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Change step" }));

    expect(document.activeElement).toBe(screen.getByRole("heading", { name: "Step two" }));
    expect(screen.getByRole("region", { name: "Step two" })).toBeTruthy();
  });

  it("shows a suggested fix for every check that does not pass", () => {
    render(
      <CheckList
        label="Checks"
        checks={[
          { id: "ok", state: "pass", message: "Workspace saved.", fix: "Ignored for passing checks." },
          { id: "bad", state: "fail", message: "Rule unreadable.", fix: "Give the identity Reader." }
        ]}
      />
    );

    const list = screen.getByRole("list", { name: "Checks" });
    expect(within(list).getByText("Passed:")).toBeTruthy();
    expect(within(list).getByText("Problem:")).toBeTruthy();
    expect(within(list).getByText("Give the identity Reader.")).toBeTruthy();
    expect(within(list).queryByText("Ignored for passing checks.")).toBeNull();
  });
});
