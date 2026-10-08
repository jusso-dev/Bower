import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { Collector } from "../types";
import { CollectorTable } from "./ui";

const base: Collector = {
  id: "c1",
  machineName: "app-01",
  environment: "production",
  version: "0.1.0",
  status: "Active",
  principalObjectId: "p",
  firstSeenAt: "2026-10-08T00:00:00Z",
  lastSeenAt: "2026-10-08T00:00:00Z",
  configurationHash: "sha256:c",
  policyHash: "sha256:abcdef0123456789",
  queueDepth: 0,
  deliveryStatus: "healthy",
  sources: [],
  outputs: []
};

describe("Collector table policy and dead-letter state", () => {
  afterEach(() => cleanup());

  it("shows in-sync, drifted and unassigned policy states", () => {
    render(
      <CollectorTable
        collectors={[
          { ...base, id: "sync", desiredPolicyHash: base.policyHash, policyInSync: true },
          { ...base, id: "drift", desiredPolicyHash: "sha256:other", policyInSync: false, deadLettered: 3 },
          { ...base, id: "unset", policyInSync: null }
        ]}
      />
    );

    expect(screen.getByText("In sync · abcdef01")).toBeTruthy();
    expect(screen.getByText("Drift · abcdef01")).toBeTruthy();
    expect(screen.getByText("Unassigned · abcdef01")).toBeTruthy();
    expect(screen.getByText("3 dead-lettered")).toBeTruthy();
  });
});
